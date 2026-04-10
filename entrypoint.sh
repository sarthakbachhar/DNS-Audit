#!/bin/bash
# Wait for MySQL to be ready, then start the Flask app.
set -e

DB_HOST="${DB_HOST:-localhost}"
DB_PORT="${DB_PORT:-3306}"
DB_USER="${DB_USER:-root}"
DB_PASSWORD="${DB_PASSWORD:-mysql@toor}"

echo "============================================================"
echo "  ISO 27001 AD Audit Tool"
echo "  Waiting for MySQL at ${DB_HOST}:${DB_PORT} ..."
echo "============================================================"

# Retry until MySQL accepts connections (up to ~60 seconds)
until python - <<EOF
import sys, mysql.connector
try:
    mysql.connector.connect(
        host="${DB_HOST}", port=${DB_PORT},
        user="${DB_USER}", password="${DB_PASSWORD}"
    ).close()
    print("  MySQL is ready.")
except Exception as e:
    print(f"  Not ready yet: {e}", file=sys.stderr)
    sys.exit(1)
EOF
do
  sleep 3
done

exec python app.py
