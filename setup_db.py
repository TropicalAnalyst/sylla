from app import app, db, User
from werkzeug.security import generate_password_hash
import secrets
import os

def setup_database():
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Check if admin user exists
        admin = User.query.filter_by(username='sylla').first()
        if not admin:
            # SECURITY: Use environment variable or generate random password
            initial_password = os.environ.get('INITIAL_ADMIN_PASSWORD') or secrets.token_urlsafe(16)
            
            # Create admin user
            admin = User(
                username='sylla',
                password=generate_password_hash(initial_password),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            print("[SECURITY] Admin user created successfully!")
            if not os.environ.get('INITIAL_ADMIN_PASSWORD'):
                print(f"[SECURITY] Initial password (save this): {initial_password}")
        else:
            print("Admin user already exists!")

if __name__ == '__main__':
    setup_database() 