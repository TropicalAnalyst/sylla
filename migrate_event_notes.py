#!/usr/bin/env python3
"""
Migration script to add related_note_id column to Event table.
This allows events to be directly linked to the notes they concern.
"""

from app import app, db
from sqlalchemy import inspect

def migrate_add_related_note_id():
    """Add related_note_id column to Event table if it doesn't exist"""
    with app.app_context():
        # Check if column already exists
        inspector = inspect(db.engine)
        columns = [column.name for column in inspector.get_columns('event')]
        
        if 'related_note_id' in columns:
            print("✓ Column 'related_note_id' already exists in Event table")
            return
        
        # Add the column
        try:
            with db.engine.connect() as conn:
                conn.execute("""
                    ALTER TABLE event 
                    ADD COLUMN related_note_id INTEGER
                """)
                conn.execute("""
                    ALTER TABLE event 
                    ADD FOREIGN KEY (related_note_id) 
                    REFERENCES note(id)
                """)
                conn.commit()
            print("✓ Successfully added 'related_note_id' column to Event table")
        except Exception as e:
            print(f"✗ Error adding column: {e}")
            print("This might be normal if using SQLite - it has limited ALTER TABLE support")
            print("For SQLite, events will still work, just with the column added on next migration")

if __name__ == '__main__':
    print("Running migration: Add related_note_id to Event table...")
    migrate_add_related_note_id()
    print("Migration complete!")
