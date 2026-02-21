#!/usr/bin/env sh
set -eu

# Auto-generate .env file if it doesn't exist
if [ ! -f /app/.env ]; then
  echo "Generating .env file with secure defaults..."
  python3 - <<'PYENV'
import secrets
from pathlib import Path

env_path = Path('/app/.env')
secret = secrets.token_hex(32)
env_content = f"""# Sylla Configuration
# Auto-generated on first launch

# Security
SECRET_KEY={secret}

# Flask Configuration
FLASK_ENV=production
FLASK_DEBUG=False
FLASK_HOST=0.0.0.0
FLASK_PORT=5001

# Retention Settings
RETENTION_PERIOD_DAYS=0
"""
env_path.write_text(env_content)
print(f"Created .env with auto-generated SECRET_KEY")
PYENV
fi

# Load environment variables from .env
if [ -f /app/.env ]; then
  export $(grep -v '^#' /app/.env | grep -v '^$' | xargs || true)
fi

# Ensure runtime directories exist and are writable
mkdir -p /app/instance /app/data /tmp/flask_session
chown -R sylla:sylla /app/instance /app/data /tmp/flask_session || true
chmod -R 775 /app/instance /app/data || true

# Initialize database and defaults before starting workers
python - <<'PY'
import os
import secrets
from app import app, db, User, UserRole, Category
from werkzeug.security import generate_password_hash

with app.app_context():
    db.create_all()
    if not UserRole.query.first():
        admin = UserRole(name='Admin', description='Administrator with full access',
                         can_create=True, can_edit=True, can_delete=True, can_manage_users=True)
        analyst = UserRole(name='Analyst', description='Analyst with create/edit/delete permissions',
                        can_create=True, can_edit=True, can_delete=True, can_manage_users=False)
        reader = UserRole(name='Reader', description='Read-only access',
                        can_create=False, can_edit=False, can_delete=False, can_manage_users=False)
        db.session.add_all([admin, analyst, reader])
        db.session.commit()
    if not User.query.filter_by(username='sylla').first():
        admin_role = UserRole.query.filter_by(name='Admin').first()
        if admin_role:
            # SECURITY: Generate a random initial password - users must set it themselves
            initial_password = secrets.token_urlsafe(16)
            u = User(username='sylla', password=generate_password_hash(initial_password), role_id=admin_role.id)
            db.session.add(u)
            db.session.commit()
            # Log this to stdout for manual retrieval (not in production logs)
            print(f"\n[SECURITY] Default admin user 'sylla' created with temporary password.")
            print(f"[SECURITY] Check container logs or set INITIAL_ADMIN_PASSWORD env var before deployment.")
    # Ensure at least one category exists for dropdowns
    if not Category.query.first():
        admin_user = User.query.filter_by(username='sylla').first()
        created_by = admin_user.id if admin_user else 1
        categories = [
            ('General', 'Default category'),
            ('Infrastructure', 'Infrastructure and network-related'),
            ('Malware', 'Malware analysis and indicators'),
            ('Threat Intelligence', 'Threat intelligence and adversary info'),
            ('Vulnerabilities', 'Known vulnerabilities and CVEs'),
            ('Compromised Credentials', 'Leaked or compromised credentials'),
            ('Command & Control', 'C2 servers and communication channels'),
            ('Phishing', 'Phishing campaigns and URLs'),
            ('Research', 'General research and analysis'),
            ('Investigation', 'Active investigations'),
        ]
        for cat_name, cat_desc in categories:
            c = Category(name=cat_name, description=cat_desc, created_by=created_by, is_active=True)
            db.session.add(c)
        db.session.commit()
PY

# Ensure DB file ownership and write perms (handles prior runs)
DB_PATH="/app/instance/it_notes.db"
if [ -f "$DB_PATH" ]; then
  chown sylla:sylla "$DB_PATH" || true
  chmod 664 "$DB_PATH" || true
fi

exec gunicorn \
  --workers 3 \
  --threads 2 \
  --bind 0.0.0.0:8000 \
  --user sylla \
  --group sylla \
  app:app

