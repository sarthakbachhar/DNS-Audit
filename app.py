# Main Flask application for the ISO 27001 AD Audit tool.
# Handles routing, background audit threads, SSE log streaming,
# and report downloads. Auth and DB logic live in their own modules.

import os
import uuid
import queue
import logging
import threading
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

from flask import (
    Flask, render_template, request, session,
    redirect, url_for, flash, send_file, jsonify, Response, stream_with_context
)

from ad_audit_engine import ADAuditEngine
from report_generator import ReportGenerator
from auth import (
    auth_bp, login_required, admin_required, inject_current_user, init_db,
    create_user, get_user_by_id, get_all_users, delete_user,
    log_activity, get_all_logs, clear_logs,
)
from database import (
    load_all_audits, load_all_statuses,
    save_audit, delete_audit_row,
    get_playbook_settings, save_playbook_settings, get_enabled_controls,
)

app = Flask(__name__)

# Keep a fixed secret key so sessions don't break on reload.
# Change this in production or set SECRET_KEY in the environment.
app.secret_key = os.environ.get('SECRET_KEY', 'iso-audit-secret-key-change-in-production')
app.permanent_session_lifetime = timedelta(hours=8)

BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
REPORT_DIR = os.path.join(BASE_DIR, 'reports')
LOG_DIR    = os.path.join(BASE_DIR, 'logs')

os.makedirs(REPORT_DIR, exist_ok=True)
os.makedirs(LOG_DIR,    exist_ok=True)

# Set up rotating file log + console output
log_path = os.path.join(LOG_DIR, 'app.log')
_fmt = logging.Formatter(
    '%(asctime)s [%(levelname)-8s] %(name)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)
_file_handler = RotatingFileHandler(
    log_path, maxBytes=5 * 1024 * 1024, backupCount=3, encoding='utf-8'
)
_file_handler.setFormatter(_fmt)
_file_handler.setLevel(logging.INFO)

_console_handler = logging.StreamHandler()
_console_handler.setFormatter(_fmt)
_console_handler.setLevel(logging.INFO)

root_logger = logging.getLogger()
root_logger.setLevel(logging.INFO)
if not any(isinstance(h, RotatingFileHandler) for h in root_logger.handlers):
    root_logger.addHandler(_file_handler)
if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, RotatingFileHandler)
           for h in root_logger.handlers):
    root_logger.addHandler(_console_handler)

app.logger.setLevel(logging.INFO)

ad_engine  = ADAuditEngine()
report_gen = ReportGenerator(REPORT_DIR)

# These three dicts hold audit state in memory.
# Completed audits are also saved to MySQL so they survive restarts.
audit_store:  dict = {}   # audit_id -> result dict
audit_queues: dict = {}   # audit_id -> Queue (used for live log streaming)
audit_status: dict = {}   # audit_id -> 'in_progress' | 'complete' | 'error'


def _load_from_db():
    """Pull completed audits from MySQL into memory when the app starts."""
    try:
        audit_store.update(load_all_audits())
        audit_status.update(load_all_statuses())
        app.logger.info("Loaded %d audits from database.", len(audit_store))
    except Exception as exc:
        app.logger.warning("Could not load audits from DB: %s - starting fresh.", exc)


app.register_blueprint(auth_bp)
app.context_processor(inject_current_user)


@app.route('/')
@login_required
def index():
    past_audits = sorted(
        [v for v in audit_store.values() if 'summary' in v],
        key=lambda x: x['summary']['timestamp'],
        reverse=True,
    )
    in_progress = {aid for aid, s in audit_status.items() if s == 'in_progress'}
    return render_template('index.html', past_audits=past_audits, in_progress=in_progress)


@app.route('/online-audit')
@admin_required
def online_audit():
    playbook_count = len(ad_engine.playbooks)
    controls = [
        {
            'id':     pb.get('control', ''),
            'name':   pb.get('control_name', ''),
            'checks': len(pb.get('checks', [])),
        }
        for pb in ad_engine.playbooks
    ]
    return render_template('online_audit.html', playbook_count=playbook_count, controls=controls)


def _audit_worker(audit_id, host, username, password, transport,
                  created_by=None, enabled_controls=None):
    """Runs in a background thread. Executes the audit and pushes log lines to the SSE queue."""
    q = audit_queues[audit_id]

    def log_cb(msg):
        print(f"  [AUDIT {audit_id[:14]}] {msg}", flush=True)
        q.put(msg)

    try:
        app.logger.info("Audit started: %s -> %s", audit_id, host)
        results = ad_engine.run_audit(
            host=host,
            username=username,
            password=password,
            transport=transport,
            log_callback=log_cb,
            enabled_controls=enabled_controls,
        )
        results['audit_id'] = audit_id
        results['filename'] = f'Online AD Audit - {host}'

        audit_store[audit_id]  = results
        audit_status[audit_id] = 'complete'

        compliance = results['summary']['compliance_percentage']
        app.logger.info("Audit done: %s, compliance=%.1f%%", audit_id, compliance)
        log_activity(
            "Audit Completed", session.get("user", "system"),
            f"Audit {audit_id} on {host} — compliance: {compliance}%"
        )

        try:
            save_audit(audit_id, host, username, 'complete', results, created_by)
        except Exception as exc:
            app.logger.warning("DB save failed for %s: %s", audit_id, exc)

        # Pre-generate the HTML report so the download is instant
        try:
            report_gen.generate_html_report(results, audit_id)
        except Exception as exc:
            app.logger.warning("HTML pre-gen failed: %s", exc)

    except ConnectionError as exc:
        app.logger.warning("Connection error for %s: %s", audit_id, exc)
        err_data = {
            'audit_id': audit_id,
            'error':    str(exc),
            'filename': f'Online AD Audit - {host}',
            'summary':  {
                'hostname': host, 'timestamp': datetime.now().isoformat(),
                'os': 'N/A', 'audit_type': 'online_ad',
            },
        }
        audit_store[audit_id]  = err_data
        audit_status[audit_id] = 'error'
        q.put(f'ERROR: Connection failed - {exc}')
        log_activity("Audit Failed", session.get("user", "system"),
                     f"Audit {audit_id} on {host} — connection error: {exc}")
        try:
            save_audit(audit_id, host, username, 'error', err_data, created_by)
        except Exception:
            pass

    except Exception as exc:
        app.logger.exception("Unexpected error in audit %s", audit_id)
        err_data = {
            'audit_id': audit_id,
            'error':    str(exc),
            'filename': f'Online AD Audit - {host}',
            'summary':  {
                'hostname': host, 'timestamp': datetime.now().isoformat(),
                'os': 'N/A', 'audit_type': 'online_ad',
            },
        }
        audit_store[audit_id]  = err_data
        audit_status[audit_id] = 'error'
        q.put(f'ERROR: {exc}')
        log_activity("Audit Failed", session.get("user", "system"),
                     f"Audit {audit_id} on {host} — error: {exc}")
        try:
            save_audit(audit_id, host, username, 'error', err_data, created_by)
        except Exception:
            pass

    finally:
        q.put('__DONE__')
        print(f"\n{'='*60}\n  Audit finished: {audit_id}\n{'='*60}\n", flush=True)


@app.route('/online-audit/run', methods=['POST'])
@admin_required
def run_online_audit():
    host      = request.form.get('host',      '').strip()
    username  = request.form.get('username',  '').strip()
    password  = request.form.get('password',  '').strip()
    transport = request.form.get('transport', 'ntlm').strip()

    if not host:
        flash('Please enter the AD server IP or hostname.', 'error')
        return redirect(url_for('online_audit'))
    if not username:
        flash('Please enter the username.', 'error')
        return redirect(url_for('online_audit'))
    if not password:
        flash('Please enter the password.', 'error')
        return redirect(url_for('online_audit'))

    audit_id   = 'AD_' + datetime.now().strftime('%Y%m%d_%H%M%S') + '_' + uuid.uuid4().hex[:6]
    created_by = session.get('user_id')

    audit_queues[audit_id] = queue.Queue()
    audit_status[audit_id] = 'in_progress'
    audit_store[audit_id]  = {
        'audit_id': audit_id,
        'filename': f'Online AD Audit - {host}',
        'summary': {
            'hostname': host, 'timestamp': datetime.now().isoformat(),
            'os': 'Connecting...', 'audit_type': 'online_ad',
            'total': 0, 'passed': 0, 'failed': 0, 'errors': 0,
            'compliance_percentage': 0,
        },
    }

    try:
        save_audit(audit_id, host, username, 'in_progress', audit_store[audit_id], created_by)
    except Exception as exc:
        app.logger.warning("Could not write initial DB row: %s", exc)

    # Check which controls the admin has enabled. If nothing is saved yet, run all.
    try:
        enabled_controls = get_enabled_controls() or None
    except Exception as exc:
        app.logger.warning("Could not read control settings: %s - running all", exc)
        enabled_controls = None

    log_activity(
        "Audit Started", session.get("user", "system"),
        f"Audit {audit_id} initiated on {host} via {transport.upper()}"
    )

    print(f"\n{'='*60}", flush=True)
    print(f"  Starting ISO 27001 AD Audit",       flush=True)
    print(f"  Audit ID  : {audit_id}",            flush=True)
    print(f"  Target    : {host}",                flush=True)
    print(f"  User      : {username}",            flush=True)
    print(f"  Transport : {transport.upper()}",   flush=True)
    print(f"{'='*60}",                            flush=True)

    t = threading.Thread(
        target=_audit_worker,
        args=(audit_id, host, username, password, transport, created_by, enabled_controls),
        daemon=True,
    )
    t.start()

    return redirect(url_for('results', audit_id=audit_id))


@app.route('/results/<audit_id>')
@login_required
def results(audit_id):
    if audit_id not in audit_store:
        flash('Audit not found.', 'error')
        return redirect(url_for('index'))
    status = audit_status.get(audit_id, 'complete')
    data   = audit_store[audit_id]
    return render_template('results.html', data=data, audit_id=audit_id, status=status)


@app.route('/api/audit/<audit_id>')
@login_required
def api_audit(audit_id):
    if audit_id not in audit_store:
        return jsonify({'error': 'Audit not found'}), 404
    return jsonify(audit_store[audit_id])


@app.route('/api/audit/status/<audit_id>')
@login_required
def api_audit_status(audit_id):
    if audit_id not in audit_store:
        return jsonify({'error': 'Not found'}), 404
    status = audit_status.get(audit_id, 'complete')
    data   = audit_store.get(audit_id, {})
    return jsonify({'audit_id': audit_id, 'status': status, 'error': data.get('error')})


@app.route('/api/audit/logs/<audit_id>')
@login_required
def api_audit_logs(audit_id):
    """SSE endpoint - streams log lines to the browser while the audit is running."""
    def generate():
        q = audit_queues.get(audit_id)
        if q is None:
            yield 'data: __DONE__\n\n'
            return
        while True:
            try:
                msg  = q.get(timeout=30)
                safe = str(msg).replace('\r', '').replace('\n', ' ')
                yield f'data: {safe}\n\n'
                if msg == '__DONE__':
                    break
            except queue.Empty:
                yield ': keepalive\n\n'

    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'},
    )


@app.route('/download/<audit_id>/<fmt>')
@login_required
def download(audit_id, fmt):
    if audit_id not in audit_store:
        flash('Audit not found.', 'error')
        return redirect(url_for('index'))

    if audit_status.get(audit_id) == 'in_progress':
        flash('Audit is still running - please wait for it to finish.', 'info')
        return redirect(url_for('results', audit_id=audit_id))

    data = audit_store[audit_id]

    if fmt == 'html':
        filepath = os.path.join(REPORT_DIR, f'audit_report_{audit_id}.html')
        if not os.path.exists(filepath):
            filepath = report_gen.generate_html_report(data, audit_id)
        log_activity("Report Downloaded", session.get("user"), f"HTML report for audit {audit_id}")
        return send_file(filepath, as_attachment=True,
                         download_name=f'ISO27001_Audit_{audit_id}.html')

    elif fmt == 'pdf':
        filepath = os.path.join(REPORT_DIR, f'audit_report_{audit_id}.pdf')
        if not os.path.exists(filepath):
            filepath = report_gen.generate_pdf_report(data, audit_id)
        if filepath and os.path.exists(filepath):
            log_activity("Report Downloaded", session.get("user"), f"PDF report for audit {audit_id}")
            return send_file(filepath, as_attachment=True,
                             download_name=f'ISO27001_Audit_{audit_id}.pdf')
        flash('PDF generation failed - make sure xhtml2pdf is installed.', 'error')
        return redirect(url_for('results', audit_id=audit_id))

    flash('Invalid format.', 'error')
    return redirect(url_for('results', audit_id=audit_id))


@app.route('/delete/<audit_id>', methods=['POST'])
@admin_required
def delete_audit(audit_id):
    audit_store.pop(audit_id,  None)
    audit_status.pop(audit_id, None)
    audit_queues.pop(audit_id, None)

    for ext in ['html', 'pdf']:
        path = os.path.join(REPORT_DIR, f'audit_report_{audit_id}.{ext}')
        if os.path.exists(path):
            os.remove(path)

    try:
        delete_audit_row(audit_id)
    except Exception as exc:
        app.logger.warning("DB delete failed for %s: %s", audit_id, exc)

    log_activity("Audit Deleted", session.get("user"), f"Audit {audit_id} deleted")
    flash('Audit deleted.', 'info')
    return redirect(url_for('index'))


@app.route('/settings', methods=['GET', 'POST'])
@admin_required
def audit_settings():
    all_controls = [
        {
            'id':     pb.get('control', ''),
            'name':   pb.get('control_name', ''),
            'checks': len(pb.get('checks', [])),
        }
        for pb in ad_engine.playbooks
    ]

    if request.method == 'POST':
        # Unchecked checkboxes don't appear in form data, so anything missing = disabled
        new_settings = {ctrl['id']: (ctrl['id'] in request.form) for ctrl in all_controls}
        try:
            save_playbook_settings(new_settings)
            enabled_count = sum(1 for v in new_settings.values() if v)
            log_activity(
                "Settings Updated", session.get("user"),
                f"Control settings saved — {enabled_count}/{len(all_controls)} controls enabled"
            )
            flash(f'Saved - {enabled_count} of {len(all_controls)} controls enabled.', 'success')
        except Exception as exc:
            app.logger.warning("Failed to save control settings: %s", exc)
            flash('Could not save settings, please try again.', 'error')
        return redirect(url_for('audit_settings'))

    try:
        saved = get_playbook_settings()
    except Exception:
        saved = {}

    for ctrl in all_controls:
        ctrl['enabled'] = saved.get(ctrl['id'], True)

    enabled_count = sum(1 for c in all_controls if c['enabled'])
    return render_template('settings.html', controls=all_controls, enabled_count=enabled_count)


@app.route('/manage-users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    if request.method == 'POST':
        action       = request.form.get('action')
        admin_name   = session.get('user', 'admin')
        current_uid  = session.get('user_id')

        if action == 'create':
            username = request.form.get('username', '').strip()
            email    = request.form.get('email',    '').strip()
            password = request.form.get('password', '').strip()
            role     = request.form.get('role',     'user').strip()

            if not all([username, email, password]):
                flash('Username, email and password are all required.', 'error')
                return redirect(url_for('manage_users'))
            if len(username) < 3:
                flash('Username must be at least 3 characters.', 'error')
                return redirect(url_for('manage_users'))
            if len(password) < 8:
                flash('Password must be at least 8 characters.', 'error')
                return redirect(url_for('manage_users'))
            if role not in ('admin', 'user'):
                role = 'user'

            new_user = create_user(username, email, password, role)
            if new_user is None:
                flash('Username or email is already taken.', 'error')
            else:
                role_label = 'Admin' if role == 'admin' else 'User'
                flash(f"User '{username}' created with {role_label} role.", 'success')
                log_activity(
                    "User Created", admin_name,
                    f"Admin created user '{username}' with role: {role_label}"
                )

        elif action == 'delete':
            user_id = request.form.get('user_id', type=int)
            if user_id == current_uid:
                flash('You cannot delete your own account.', 'error')
            elif user_id:
                target = get_user_by_id(user_id)
                target_name = target['username'] if target else f'ID:{user_id}'
                delete_user(user_id)
                flash(f"User '{target_name}' has been deleted.", 'info')
                log_activity("User Deleted", admin_name, f"Admin deleted user '{target_name}'")

        return redirect(url_for('manage_users'))

    users       = get_all_users()
    current_uid = session.get('user_id')
    return render_template('manage_users.html', users=users, current_uid=current_uid)


@app.route('/logs')
@login_required
def activity_logs():
    logs = get_all_logs(limit=500)
    return render_template('logs.html', logs=logs)


@app.route('/logs/clear', methods=['POST'])
@admin_required
def clear_activity_logs():
    clear_logs()
    log_activity("Logs Cleared", session.get("user"), "All activity logs cleared by admin")
    flash('Activity logs cleared.', 'info')
    return redirect(url_for('activity_logs'))


if __name__ == '__main__':
    print('=' * 60)
    print('  ISO 27001 AD Audit - Active Directory Compliance Tool')
    print('  Setting up database...')

    try:
        init_db()
        _load_from_db()
        print('  Database ready.')
    except Exception as exc:
        print(f'  WARNING: Database not available - {exc}')
        print('  Audits will not be saved this session.')

    print('  http://localhost:5000')
    print('=' * 60)
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
