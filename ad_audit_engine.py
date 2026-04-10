# Active Directory audit engine for ISO 27001 Annex A.8 compliance checks.
# Connects to a Windows AD server over WinRM, runs PowerShell scripts defined
# in YAML playbooks, and returns structured results for the report generator.

import os
import yaml
import logging
from datetime import datetime

from evil_winrm_py.pypsrp_ewp.wsman import WSManEWP
from pypsrp.powershell import PowerShell, RunspacePool


logger = logging.getLogger(__name__)


class WinRMConnector:
    """Manages the WinRM connection to a remote Windows server."""

    def __init__(self, host, username, password, transport='ntlm', port=None):
        self.host = host
        self.username = username
        self.password = password
        self.transport = transport

        if port is None:
            self.port = 5986 if transport == 'ssl' else 5985
        else:
            self.port = port

        scheme = 'https' if transport == 'ssl' else 'http'
        self.endpoint = f'{scheme}://{host}:{self.port}/wsman'

        self._auth = 'ntlm' if transport == 'ntlm' else 'negotiate'
        self._ssl = transport == 'ssl'

        self._wsman = None
        self._runspace = None

    def connect(self):
        """Open a WinRM session and verify it works by retrieving the remote hostname."""
        logger.info(
            "Connecting via WinRM: endpoint=%s transport=%s port=%s user=%s",
            self.endpoint, self.transport, self.port, self.username,
        )
        try:
            self._wsman = WSManEWP(
                server=self.host,
                port=self.port,
                auth=self._auth,
                encryption='auto',
                username=self.username,
                password=self.password,
                ssl=self._ssl,
                cert_validation=False,
                path='wsman',
            )
            self._wsman.__enter__()

            self._runspace = RunspacePool(self._wsman)
            self._runspace.__enter__()

            stdout, _, had_errors = self._run_ps_cmd('$env:COMPUTERNAME')

            if had_errors or not stdout.strip():
                logger.error("WinRM connection test failed")
                self._cleanup()
                raise ConnectionError("WinRM connection failed: could not retrieve hostname")

            hostname = stdout.strip()
            logger.info("Connected successfully, remote hostname=%s", hostname)
            return hostname

        except ConnectionError:
            self._cleanup()
            raise
        except Exception as e:
            self._cleanup()
            logger.exception("Failed to establish WinRM session to %s", self.host)
            raise ConnectionError(f"Failed to connect to {self.host}: {str(e)}") from e

    def _run_ps_cmd(self, command):
        # Uses evil-winrm-py's internal pypsrp API so we don't need an interactive console
        ps = PowerShell(self._runspace)
        ps.add_cmdlet("Invoke-Expression").add_parameter("Command", command)
        ps.add_cmdlet("Out-String").add_parameter("Stream")
        ps.invoke()
        return "\n".join(str(line) for line in ps.output), ps.streams, ps.had_errors

    def run_powershell(self, script):
        logger.debug("Running PS script: %s", script[:500])
        try:
            stdout, streams, had_errors = self._run_ps_cmd(script)

            stderr = ''
            if streams and streams.error:
                stderr = '\n'.join(str(e) for e in streams.error)

            return_code = 1 if had_errors else 0
            return stdout.strip(), stderr.strip(), return_code

        except Exception as e:
            logger.exception("Error running PowerShell script")
            return '', str(e), -1

    def _cleanup(self):
        try:
            if self._runspace is not None:
                self._runspace.__exit__(None, None, None)
        except Exception:
            pass
        try:
            if self._wsman is not None:
                self._wsman.__exit__(None, None, None)
        except Exception:
            pass
        self._runspace = None
        self._wsman = None

    def __del__(self):
        self._cleanup()


class ADPlaybookRunner:
    """Loads YAML playbooks and runs their checks against the connected AD server."""

    def __init__(self, playbooks_dir=None):
        if playbooks_dir is None:
            playbooks_dir = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                'playbooks'
            )
        self.playbooks_dir = playbooks_dir
        self.playbooks = self._load_playbooks()

    def _load_playbooks(self):
        playbooks = []
        if not os.path.isdir(self.playbooks_dir):
            return playbooks

        for filename in sorted(os.listdir(self.playbooks_dir)):
            if filename.endswith(('.yaml', '.yml')):
                filepath = os.path.join(self.playbooks_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8') as f:
                        data = yaml.safe_load(f)
                    if data and 'checks' in data:
                        data['_filename'] = filename
                        playbooks.append(data)
                except Exception as e:
                    print(f"[WARNING] Failed to load playbook {filename}: {e}")
        return playbooks

    def run_playbook(self, playbook, connector, log_fn=None):
        results = []
        control = playbook.get('control', '')
        control_name = playbook.get('control_name', '')

        for check in playbook.get('checks', []):
            if log_fn:
                log_fn(f"  CHECK {check.get('id', '')} — {check.get('title', '')}")
            result = self._run_check(check, connector, control, control_name)
            if log_fn:
                symbol = '✓' if result['status'] == 'PASS' else ('✗' if result['status'] == 'FAIL' else '!')
                log_fn(f"    {symbol} {result['status']}  [{check.get('severity', 'medium').upper()}]")
            results.append(result)

        return results

    def _run_check(self, check, connector, control, control_name):
        ps_script = check.get('powershell', '')
        check_config = check.get('check', {})
        operator = check_config.get('operator', 'equals')
        expected = str(check_config.get('expected', ''))

        try:
            stdout, stderr, return_code = connector.run_powershell(ps_script)

            if return_code != 0 and not stdout:
                actual = f"Error: {stderr}" if stderr else "Command failed"
                status = 'ERROR'
            else:
                actual = stdout
                status = 'PASS' if self._apply_operator(actual, operator, expected) else 'FAIL'
        except Exception as e:
            actual = f"Error: {str(e)}"
            status = 'ERROR'

        return {
            'id': check.get('id', ''),
            'control': control,
            'control_name': control_name,
            'title': check.get('title', ''),
            'description': check.get('description', ''),
            'severity': check.get('severity', 'medium'),
            'status': status,
            'actual_value': actual if actual else 'Not Found',
            'expected_value': expected,
            'operator': operator,
            'remediation': check.get('remediation', '').strip() if status == 'FAIL' else '',
            'field': f"AD:{control}",
        }

    def _apply_operator(self, actual, operator, expected):
        if actual is None or actual == '':
            if operator == 'not_exists':
                return True
            return False

        actual_str = str(actual).strip().lower()
        expected_str = str(expected).strip().lower()

        if operator == 'equals':
            return actual_str == expected_str
        elif operator == 'not_equals':
            return actual_str != expected_str
        elif operator == 'less_than_equal':
            try:
                return float(actual.strip()) <= float(expected)
            except (ValueError, TypeError):
                return False
        elif operator == 'greater_than_equal':
            try:
                return float(actual.strip()) >= float(expected)
            except (ValueError, TypeError):
                return False
        elif operator == 'greater_than':
            try:
                return float(actual.strip()) > float(expected)
            except (ValueError, TypeError):
                return False
        elif operator == 'less_than':
            try:
                return float(actual.strip()) < float(expected)
            except (ValueError, TypeError):
                return False
        elif operator == 'contains':
            return expected_str in actual_str
        elif operator == 'not_contains':
            return expected_str not in actual_str
        elif operator == 'is_true':
            return actual_str in ('true', 'yes', '1')
        elif operator == 'is_false':
            return actual_str in ('false', 'no', '0')
        elif operator == 'exists':
            return actual_str != '' and actual_str != 'not found'
        elif operator == 'not_exists':
            return actual_str == '' or actual_str == 'not found'
        else:
            return False


class ADAuditEngine:
    """
    Top-level orchestrator. Connects to the AD server, runs the selected
    playbooks, and returns a structured result dict ready for report generation.
    """

    def __init__(self, playbooks_dir=None):
        self.runner = ADPlaybookRunner(playbooks_dir)
        self.playbooks = self.runner.playbooks

    def run_audit(self, host, username, password, transport='ntlm', port=None,
                  log_callback=None, enabled_controls=None):
        """
        Run the full audit. If enabled_controls is provided, only those control
        IDs will run. Passing None or an empty set means run everything.
        """

        def _log(msg: str) -> None:
            logger.info(msg)
            if log_callback:
                try:
                    log_callback(msg)
                except Exception:
                    pass

        _log(f"Starting AD audit — host={host}  transport={transport.upper()}  user={username}")

        _log(f"Connecting to {host} via WinRM ({transport.upper()})…")
        connector = WinRMConnector(host, username, password, transport, port)
        hostname = connector.connect()
        _log(f"Connected — remote hostname: {hostname}")

        _log("Gathering system information…")
        sys_info = self._get_system_info(connector, _log)
        sys_info['hostname'] = hostname
        _log(f"OS: {sys_info.get('os', 'Unknown')}  |  Domain: {sys_info.get('domain', 'Unknown')}")

        # Only run the controls the admin has enabled (if a filter was given)
        if enabled_controls:
            active_playbooks = [
                pb for pb in self.playbooks
                if pb.get('control', '') in enabled_controls
            ]
            skipped = len(self.playbooks) - len(active_playbooks)
            if skipped:
                _log(f"Skipping {skipped} disabled control(s) per settings.")
        else:
            active_playbooks = self.playbooks

        all_results = []
        total_playbooks = len(active_playbooks)
        for idx, playbook in enumerate(active_playbooks, start=1):
            control = playbook.get('control', '')
            control_name = playbook.get('control_name', '')
            check_count = len(playbook.get('checks', []))
            _log(f"[{idx}/{total_playbooks}] {control} — {control_name}  ({check_count} checks)")
            pb_results = self.runner.run_playbook(playbook, connector, _log)
            pb_passed = sum(1 for r in pb_results if r['status'] == 'PASS')
            pb_failed = sum(1 for r in pb_results if r['status'] == 'FAIL')
            _log(f"  → {control}: {pb_passed} passed, {pb_failed} failed")
            all_results.extend(pb_results)

        passed = sum(1 for r in all_results if r['status'] == 'PASS')
        failed = sum(1 for r in all_results if r['status'] == 'FAIL')
        errors = sum(1 for r in all_results if r['status'] == 'ERROR')
        total = len(all_results)
        compliance_pct = round((passed / total * 100), 1) if total > 0 else 0

        _log(
            f"Audit complete — total={total}  passed={passed}  "
            f"failed={failed}  errors={errors}  compliance={compliance_pct}%"
        )

        # Group results by control for easier rendering in the report
        controls: dict = {}
        for r in all_results:
            ctrl = r['control']
            if ctrl not in controls:
                controls[ctrl] = {
                    'control': ctrl,
                    'control_name': r['control_name'],
                    'checks': [],
                }
            controls[ctrl]['checks'].append(r)

        return {
            'summary': {
                'total': total,
                'passed': passed,
                'failed': failed,
                'errors': errors,
                'compliance_percentage': compliance_pct,
                'timestamp': datetime.now().isoformat(),
                'hostname': sys_info.get('hostname', 'Unknown'),
                'os': sys_info.get('os', 'Windows Server'),
                'collection_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'domain': sys_info.get('domain', 'Unknown'),
                'audit_type': 'online_ad',
            },
            'results': all_results,
            'controls': list(controls.values()),
            'severity_summary': {
                'high': {
                    'passed': sum(1 for r in all_results if r['severity'] == 'high' and r['status'] == 'PASS'),
                    'failed': sum(1 for r in all_results if r['severity'] == 'high' and r['status'] == 'FAIL'),
                },
                'medium': {
                    'passed': sum(1 for r in all_results if r['severity'] == 'medium' and r['status'] == 'PASS'),
                    'failed': sum(1 for r in all_results if r['severity'] == 'medium' and r['status'] == 'FAIL'),
                },
                'low': {
                    'passed': sum(1 for r in all_results if r['severity'] == 'low' and r['status'] == 'PASS'),
                    'failed': sum(1 for r in all_results if r['severity'] == 'low' and r['status'] == 'FAIL'),
                },
            },
        }

    def _get_system_info(self, connector, _log=None):
        def maybe_log(msg):
            if _log:
                _log(msg)

        info = {}

        maybe_log("  Querying OS version…")
        stdout, _, _ = connector.run_powershell(
            '(Get-CimInstance Win32_OperatingSystem).Caption'
        )
        info['os'] = stdout if stdout else 'Windows Server'

        maybe_log("  Querying domain DNS root…")
        stdout, _, _ = connector.run_powershell('(Get-ADDomain).DNSRoot')
        info['domain'] = stdout if stdout else 'Unknown'

        maybe_log("  Querying forest functional level…")
        stdout, _, _ = connector.run_powershell('(Get-ADForest).ForestMode')
        info['forest_level'] = stdout if stdout else 'Unknown'

        maybe_log("  Querying domain functional level…")
        stdout, _, _ = connector.run_powershell('(Get-ADDomain).DomainMode')
        info['domain_level'] = stdout if stdout else 'Unknown'

        return info
