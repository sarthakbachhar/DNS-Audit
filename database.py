# Handles reading and writing audit data and playbook settings to MySQL.
# Imports DB_CONFIG from auth.py so credentials only need to be changed in one place.

import json
import logging

import mysql.connector
import mysql.connector.errors

from auth import DB_CONFIG

logger = logging.getLogger(__name__)


def _get_db():
    return mysql.connector.connect(**DB_CONFIG)


def save_audit(audit_id: str, host: str, ad_username: str,
               status: str, results: dict,
               created_by: int | None = None) -> None:
    # Use INSERT ... ON DUPLICATE KEY UPDATE so we can call this for both
    # initial creation and status updates without worrying about duplicates
    results_json = json.dumps(results)
    conn = _get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            INSERT INTO audits
                (audit_id, host, ad_username, status, results_json, created_by)
            VALUES (%s, %s, %s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE
                status       = VALUES(status),
                results_json = VALUES(results_json)
        """, (audit_id, host, ad_username, status, results_json, created_by))
        conn.commit()
    finally:
        cursor.close()
        conn.close()


def load_all_audits() -> dict:
    # Pull every finished audit from the DB and reconstruct the in-memory store.
    # In-progress rows are skipped since those threads are gone after a restart.
    conn = _get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT audit_id, results_json FROM audits "
            "WHERE status IN ('complete', 'error') "
            "ORDER BY created_at"
        )
        rows = cursor.fetchall()
        store = {}
        for row in rows:
            if row.get("results_json"):
                try:
                    store[row["audit_id"]] = json.loads(row["results_json"])
                except (json.JSONDecodeError, TypeError):
                    pass
        return store
    finally:
        cursor.close()
        conn.close()


def load_all_statuses() -> dict:
    conn = _get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT audit_id, status FROM audits")
        return {r["audit_id"]: r["status"] for r in cursor.fetchall()}
    finally:
        cursor.close()
        conn.close()


def delete_audit_row(audit_id: str) -> None:
    conn = _get_db()
    cursor = conn.cursor()
    try:
        cursor.execute("DELETE FROM audits WHERE audit_id = %s", (audit_id,))
        conn.commit()
    finally:
        cursor.close()
        conn.close()


def get_playbook_settings() -> dict:
    # Returns what the admin has saved. Any control not in the table is treated as enabled.
    conn = _get_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT control_id, enabled FROM playbook_settings")
        return {r["control_id"]: bool(r["enabled"]) for r in cursor.fetchall()}
    finally:
        cursor.close()
        conn.close()


def save_playbook_settings(settings: dict) -> None:
    # Upsert each control — this way adding new playbooks later doesn't break anything
    conn = _get_db()
    cursor = conn.cursor()
    try:
        for control_id, enabled in settings.items():
            cursor.execute(
                """
                INSERT INTO playbook_settings (control_id, enabled)
                VALUES (%s, %s)
                ON DUPLICATE KEY UPDATE enabled = VALUES(enabled)
                """,
                (control_id, bool(enabled)),
            )
        conn.commit()
    finally:
        cursor.close()
        conn.close()


def get_enabled_controls() -> set:
    # Returns only the controls that are switched on.
    # An empty set here means nothing has been saved yet, which the caller treats as "run all".
    settings = get_playbook_settings()
    return {cid for cid, enabled in settings.items() if enabled}
