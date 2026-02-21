from app import app, db, User, UserRole, Note, IPAddress, URL, Hash, UserLog, AppConfig, Anomaly, Alert
from werkzeug.security import generate_password_hash
import secrets
import os

def init_database():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        
        # Create all tables
        db.create_all()
        print("Database tables created successfully!")

        # Define roles
        roles = [
            {
                'name': 'Admin',
                'description': 'Full access to all features',
                'can_create': True,
                'can_edit': True,
                'can_delete': True,
                'can_manage_users': True
            },
            {
                'name': 'Analyst',
                'description': 'Can create/edit/delete everywhere except admin areas',
                'can_create': True,
                'can_edit': True,
                'can_delete': True,
                'can_manage_users': False
            },
            {
                'name': 'Reader',
                'description': 'Read-only access',
                'can_create': False,
                'can_edit': False,
                'can_delete': False,
                'can_manage_users': False
            }
        ]

        # Create roles if they don't exist
        for role_data in roles:
            role = UserRole.query.filter_by(name=role_data['name']).first()
            if not role:
                role = UserRole(**role_data)
                db.session.add(role)
                print(f"Created role: {role_data['name']}")
            else:
                print(f"Role already exists: {role_data['name']}")

        # Create admin user if it doesn't exist
        admin_role = UserRole.query.filter_by(name='Admin').first()
        if not admin_role:
            print("Admin role not found!")
            return

        admin = User.query.filter_by(username='sylla').first()
        if not admin:
            # SECURITY: Generate random password, don't hardcode
            initial_password = os.environ.get('INITIAL_ADMIN_PASSWORD') or secrets.token_urlsafe(16)
            admin = User(
                username='sylla',
                password=generate_password_hash(initial_password),
                role_id=admin_role.id
            )
            db.session.add(admin)
            print(f"[SECURITY] Created admin user 'sylla' with temporary password.")
            if not os.environ.get('INITIAL_ADMIN_PASSWORD'):
                print(f"[SECURITY] Password: {initial_password}")
        else:
            print("Admin user already exists")

        # Commit all changes
        db.session.commit()
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_database() 