from app import app, db, User, UserRole
from werkzeug.security import generate_password_hash
import secrets
import os

def update_admin():
    with app.app_context():
        # First, ensure the Admin role exists
        admin_role = UserRole.query.filter_by(name='Admin').first()
        if not admin_role:
            admin_role = UserRole(
                name='Admin',
                description='Full system access with all permissions',
                can_create=True,
                can_edit=True,
                can_delete=True,
                can_manage_users=True
            )
            db.session.add(admin_role)
            db.session.commit()
            print("Created Admin role")

        # Update or create the admin user
        admin_user = User.query.filter_by(username='sylla').first()
        if admin_user:
            # Update existing admin user
            admin_user.role_id = admin_role.id
            admin_user.is_active = True
            print("Updated existing admin user")
        else:
            # Create new admin user with secure random password
            initial_password = os.environ.get('INITIAL_ADMIN_PASSWORD') or secrets.token_urlsafe(16)
            admin_user = User(
                username='sylla',
                password=generate_password_hash(initial_password),
                role_id=admin_role.id,
                is_active=True
            )
            db.session.add(admin_user)
            print("[SECURITY] Created new admin user 'sylla'")
            if not os.environ.get('INITIAL_ADMIN_PASSWORD'):
                print(f"[SECURITY] Initial password (save this): {initial_password}")

        db.session.commit()
        print("Admin user setup completed!")

if __name__ == '__main__':
    update_admin() 