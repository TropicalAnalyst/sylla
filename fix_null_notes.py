import os
from app import app, db, Note, User

with app.app_context():
    admin = User.query.filter_by(username='admin').first()
    if admin:
        updated = db.session.query(Note).filter(Note.user_id == None).update({Note.user_id: admin.id})
        db.session.commit()
        print(f"Assigned {updated} notes with user_id=None to admin user (id={admin.id}).")
    else:
        print("Admin user not found. No notes updated.") 