from app import app, db, User, UserRole
from werkzeug.security import generate_password_hash
import secrets
import os

with app.app_context():
    # Create the database tables
    db.create_all()
    
    # Get or create Admin role
    admin_role = UserRole.query.filter_by(name='Admin').first()
    if not admin_role:
        admin_role = UserRole(
            name='Admin',
            description='Full system administrator',
            can_create=True,
            can_edit=True,
            can_delete=True,
            can_manage_users=True
        )
        db.session.add(admin_role)
        db.session.commit()
    
    initial_password = os.environ.get('INITIAL_ADMIN_PASSWORD') or secrets.token_urlsafe(16)
    
    # Create admin user
    admin = User(
        username='sylla',
        password=generate_password_hash(initial_password, method='pbkdf2:sha256'),
        role_id=admin_role.id,
        is_active=True
    )
    
    # Add admin to database
    db.session.add(admin)
    db.session.commit()
    
    print("[SECURITY] Admin user created successfully!")
    print("Username: sylla")
    if not os.environ.get('INITIAL_ADMIN_PASSWORD'):
        print(f"[SECURITY] Initial password (save this): {initial_password}")
    else:
        print("[SECURITY] Password set from INITIAL_ADMIN_PASSWORD environment variable") 