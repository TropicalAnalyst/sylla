from app import app, db, UserRole

def setup_roles():
    with app.app_context():
        # Create default roles if they don't exist
        roles = [
            {
                'name': 'Admin',
                'description': 'Full system access with all permissions',
                'can_create': True,
                'can_edit': True,
                'can_delete': True,
                'can_manage_users': True
            },
            {
                'name': 'Analyst',
                'description': 'Create/edit/delete everywhere except admin areas',
                'can_create': True,
                'can_edit': True,
                'can_delete': True,
                'can_manage_users': False
            },
            {
                'name': 'User',
                'description': 'Regular user',
                'can_create': True,
                'can_edit': True,
                'can_delete': False,
                'can_manage_users': False
            },
            {
                'name': 'Reader',
                'description': 'Can only view sources',
                'can_create': False,
                'can_edit': False,
                'can_delete': False,
                'can_manage_users': False
            }
        ]

        for role_data in roles:
            role = UserRole.query.filter_by(name=role_data['name']).first()
            if not role:
                role = UserRole(**role_data)
                db.session.add(role)
                print(f"Created role: {role_data['name']}")
            else:
                role.description = role_data['description']
                role.can_create = role_data['can_create']
                role.can_edit = role_data['can_edit']
                role.can_delete = role_data['can_delete']
                role.can_manage_users = role_data['can_manage_users']
                print(f"Updated role: {role_data['name']}")

        db.session.commit()
        print("Role setup completed!")

if __name__ == '__main__':
    setup_roles() 