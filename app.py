from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, Response, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import os
import json
import csv
import io
import time
import threading
import shutil
import secrets
import pandas as pd
import requests
from functools import wraps
from werkzeug.security import check_password_hash, generate_password_hash
from sqlalchemy import or_, Text, func, distinct, text, inspect
from sqlalchemy.exc import IntegrityError
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import SubmitField, PasswordField, StringField, TextAreaField, SelectField, BooleanField
from wtforms.validators import DataRequired, EqualTo, Optional

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'instance', 'it_notes.db')

app = Flask(__name__, instance_relative_config=True)
# SECURITY: AUTO-GENERATE SECRET_KEY if not provided
_secret_key = os.environ.get('SECRET_KEY')
if not _secret_key:
    # Auto-generate a secure key for development/first-run
    _secret_key = secrets.token_hex(32)
    print(f"[WARNING] SECRET_KEY not set. Generated temporary key: {_secret_key}")
    print("[WARNING] For production, set SECRET_KEY environment variable to persist sessions across restarts")
app.config['SECRET_KEY'] = _secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', f"sqlite:///{DB_PATH}")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['RETENTION_PERIOD_DAYS'] = int(os.environ.get('RETENTION_PERIOD_DAYS', 365))

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.session_protection = 'strong'


def admin_required(f):
    """Route decorator to restrict access to admins or users with manage permission."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.has_permission('can_manage_users'):
            flash('Access denied!', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function


def has_incident_write_access(user):
    return user.is_authenticated and (user.has_permission('can_create') or user.has_permission('can_edit'))
def run_event_rules_core():
    """Shared logic for evaluating event rules. Returns number of events created."""
    from datetime import timedelta
    rules = EventRule.query.filter_by(is_active=True).all()
    events_created = 0
    for rule in rules:
        conditions = json.loads(rule.conditions)
        if rule.rule_type == 'ioc_frequency':
            time_window = datetime.utcnow() - timedelta(hours=conditions.get('time_window_hours', 24))
            ioc_type = conditions.get('ioc_type')
            min_count = conditions.get('min_count', 1)
            if ioc_type:
                ioc_counts = db.session.query(IOC.value, db.func.count(IOC.id)).join(Note).filter(
                    IOC.type == ioc_type,
                    Note.created_at >= time_window
                ).group_by(IOC.value).having(db.func.count(IOC.id) >= min_count).all()
                for ioc_value, count in ioc_counts:
                    # Check for existing event that is not resolved/acknowledged
                    existing_event = Event.query.filter_by(
                        triggered_by_rule=rule.id,
                        event_type='ioc_frequency'
                    ).filter(Event.description.contains(f'"ioc_value": "{ioc_value}"')).order_by(Event.created_at.desc()).first()
                    
                    # Skip if event exists and is in terminal state (resolved/acknowledged/false_positive)
                    if existing_event and existing_event.is_resolved_or_acknowledged():
                        continue
                    
                    # Don't create duplicate if event already exists in new state
                    if existing_event and existing_event.status == 'new':
                        continue
        elif rule.rule_type == 'about_to_expire':
            days_before_expiry = conditions.get('days_before_expiry', 7)
            now = datetime.utcnow()
            for note in Note.query.all():
                if note.keep:
                    continue
                note_expiry = note.created_at + timedelta(days=app.config['RETENTION_PERIOD_DAYS'])
                if 0 <= (note_expiry - now).days <= days_before_expiry:
                    # Check for existing event tied to this specific note
                    existing_event = Event.query.filter_by(
                        triggered_by_rule=rule.id,
                        event_type='about_to_expire',
                        related_note_id=note.id
                    ).order_by(Event.created_at.desc()).first()
                    
                    if existing_event and existing_event.is_resolved_or_acknowledged():
                        continue
                    
                    if existing_event and existing_event.status == 'new':
                        continue
                    
                    event = Event(
                        title=f"Note about to expire: {note.title}",
                        description=json.dumps({'note_id': note.id, 'title': note.title}),
                        event_type='about_to_expire',
                        triggered_by_rule=rule.id,
                        related_note_id=note.id
                    )
                    db.session.add(event)
                    events_created += 1
        elif rule.rule_type == 'ioc_monitor':
            ioc_type = conditions.get('ioc_type')
            ioc_value = conditions.get('ioc_value')
            if ioc_type and ioc_value:
                found_iocs = IOC.query.filter_by(type=ioc_type, value=ioc_value).all()
                for ioc in found_iocs:
                    # Get related note for this IOC
                    note_id = ioc.note_id if ioc.note_id else None
                    
                    existing_event = Event.query.filter_by(
                        triggered_by_rule=rule.id,
                        event_type='ioc_monitor',
                        related_note_id=note_id
                    ).filter(Event.description.contains(f'"ioc_value": "{ioc_value}"')).order_by(Event.created_at.desc()).first()
                    
                    # Skip if event exists and is in terminal state
                    if existing_event and existing_event.is_resolved_or_acknowledged():
                        continue
                    
                    # Don't create duplicate if event already exists in new state
                    if existing_event and existing_event.status == 'new':
                        continue
                    
                    event = Event(
                        title=f"Monitored IOC detected: {ioc_type.upper()} {ioc_value}",
                        description=json.dumps({'ioc_type': ioc_type, 'ioc_value': ioc_value}),
                        event_type='ioc_monitor',
                        triggered_by_rule=rule.id,
                        related_note_id=note_id
                    )
                    db.session.add(event)
                    events_created += 1
        elif rule.rule_type == 'incident_monitor':
            incident_id = conditions.get('incident_id')
            if incident_id:
                incident = Incident.query.get(incident_id)
                if incident and incident.incident_iocs:
                    incident_ioc_values = [ioc.value for ioc in incident.incident_iocs]
                    matching_sources = IOC.query.filter(
                        IOC.value.in_(incident_ioc_values),
                        IOC.note_id.isnot(None)
                    ).all()

                    for source_ioc in matching_sources:
                        if source_ioc.tags and f"incident:{incident.id}" in source_ioc.tags:
                            continue

                        event_key = f"{rule.id}_{source_ioc.note_id}_{source_ioc.value}"
                        note_id = source_ioc.note_id
                        
                        # Check for existing event tied to this specific note
                        existing_event = Event.query.filter_by(
                            triggered_by_rule=rule.id,
                            event_type='incident_monitor',
                            related_note_id=note_id
                        ).filter(Event.description.contains(event_key)).order_by(Event.created_at.desc()).first()

                        # Skip if event exists and is in terminal state
                        if existing_event and existing_event.is_resolved_or_acknowledged():
                            continue
                        
                        # Don't create duplicate if event already exists in new state
                        if existing_event and existing_event.status == 'new':
                            continue

                        try:
                            source_title = source_ioc.note.title if source_ioc.note else 'Unknown Source'
                            event = Event(
                                title=f"Incident {incident_id} IOC found in source: {source_title}",
                                description=json.dumps({
                                    'incident_id': incident_id,
                                    'ioc_value': source_ioc.value,
                                    'source_id': source_ioc.note_id,
                                    'event_key': event_key
                                }),
                                event_type='incident_monitor',
                                triggered_by_rule=rule.id,
                                related_note_id=note_id
                            )
                            db.session.add(event)
                            events_created += 1
                        except Exception as e:
                            print(f"Error creating incident_monitor event: {e}")
                            continue
    db.session.commit()
    return events_created

@app.route('/admin/run_event_rules')
@login_required
@admin_required
def run_event_rules():
    """Run event rules to generate events."""
    events_created = run_event_rules_core()
    flash(f'Event rules executed. {events_created} new events created.', 'success')
    return redirect(url_for('events'))

class CSVUploadForm(FlaskForm):
    file = FileField('CSV File', validators=[
        FileRequired(),
        FileAllowed(['csv'], 'Only CSV files are allowed!')
    ])
    submit = SubmitField('Upload')

class ChangePasswordForm(FlaskForm):
    old_password = PasswordField('Old Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Change Password')

class AdminResetPasswordForm(FlaskForm):
    new_password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired(), EqualTo('new_password')])
    submit = SubmitField('Reset Password')

class UserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password (leave blank to keep unchanged)')
    role = SelectField('Role', coerce=int, validators=[DataRequired()])
    is_active = BooleanField('Active', default=True)
    submit = SubmitField('Submit')


class UserRole(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    can_create = db.Column(db.Boolean, default=False)
    can_edit = db.Column(db.Boolean, default=False)
    can_delete = db.Column(db.Boolean, default=False)
    can_manage_users = db.Column(db.Boolean, default=False)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role_id = db.Column(db.Integer, db.ForeignKey('user_role.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    role = db.relationship('UserRole')

    def has_permission(self, perm):
        if not self.role:
            return False
        return getattr(self.role, perm, False)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    category = db.Column(db.String(50), nullable=True)
    keep = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    custom_identifier = db.Column(db.String(100), unique=True, nullable=True)

    user = db.relationship('User', backref=db.backref('notes', lazy=True))


class IOC(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(32), nullable=False)
    value = db.Column(db.String(256), nullable=False, index=True)
    tags = db.Column(db.String(256))
    note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    note = db.relationship('Note', backref=db.backref('iocs', lazy=True, cascade="all, delete-orphan"))

    def to_dict(self):
        return {"type": self.type, "value": self.value, "tags": self.tags}

    @staticmethod
    def is_valid_type(ioc_type):
        allowed = {"ip", "domain", "url", "hash", "email address", "username"}
        return ioc_type in allowed


class SessionData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(255), unique=True, nullable=False)
    data = db.Column(db.LargeBinary, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)

class UserLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class AppConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.Text, nullable=True)


class APIKey(db.Model):
    """Stores API keys that can be used to interact with the public endpoints.
    Admins generate keys via the admin interface and can revoke them later.

    Fields:
        id           - primary key
        key          - actual token string (stored in plaintext for simplicity)
        description  - optional human-readable description
        created_by   - user id of the admin who generated the key
        created_at   - timestamp for auditing
        is_active    - whether the key is still valid
    """
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(128), unique=True, nullable=False, index=True)
    description = db.Column(db.String(200))
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)

    creator = db.relationship('User')


def get_config_value(key, default=None):
    config_entry = AppConfig.query.filter_by(key=key).first()
    return config_entry.value if config_entry else default

def get_config_bool(key, default=False):
    raw = get_config_value(key)
    if raw is None:
        return default
    return str(raw).lower() in ['1', 'true', 'yes', 'on']


def set_config_value(key, value):
    config_entry = AppConfig.query.filter_by(key=key).first()
    if config_entry:
        config_entry.value = value
    else:
        config_entry = AppConfig(key=key, value=value)
        db.session.add(config_entry)
    db.session.commit()


def get_time_format():
    return get_config_value('time_format', '24h')


def get_date_format():
    return get_config_value('date_format', 'ymd')


def format_display_datetime(dt, include_time=True, include_seconds=False):
    if not dt:
        return ''
    time_format_pref = get_time_format()
    date_format_pref = get_date_format()

    if date_format_pref == 'mdy':
        date_fmt = '%m/%d/%Y'
    elif date_format_pref == 'dmy':
        date_fmt = '%d/%m/%Y'
    else:
        date_fmt = '%Y-%m-%d'

    time_fmt = '%H:%M:%S' if include_seconds else '%H:%M'
    if time_format_pref == '12h':
        time_fmt = '%I:%M:%S %p' if include_seconds else '%I:%M %p'
    if include_time:
        return dt.strftime(f'{date_fmt} {time_fmt}')
    return dt.strftime(date_fmt)


def record_audit(action, details, user_id=None):
    try:
        resolved_user_id = user_id or (current_user.id if current_user.is_authenticated else None)
        if resolved_user_id is None:
            return
        log_entry = UserLog(user_id=resolved_user_id, action=action, details=details)
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print(f"[WARNING] Failed to record audit log '{action}': {e}")


@app.context_processor
def inject_formatters():
    def format_dt(value, include_time=True, include_seconds=False):
        return format_display_datetime(value, include_time, include_seconds)
    return dict(format_dt=format_dt, time_format_preference=get_time_format, date_format_preference=get_date_format)

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    is_active = db.Column(db.Boolean, default=True)

class EventRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    rule_type = db.Column(db.String(50), nullable=False)  # 'ioc_frequency', 'note_frequency', 'category_pattern', 'keep_pattern', 'content_pattern'
    conditions = db.Column(db.Text, nullable=False)  # JSON string with rule conditions
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    event_type = db.Column(db.String(50), nullable=False)
    status = db.Column(db.String(20), default='new')  # new, acknowledged, resolved, false_positive
    triggered_by_rule = db.Column(db.Integer, db.ForeignKey('event_rule.id'), nullable=True)
    related_note_id = db.Column(db.Integer, db.ForeignKey('note.id'), nullable=True, index=True)  # Direct link to related note
    related_notes = db.Column(db.Text)  # JSON string with note IDs (for historical reasons)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    acknowledged_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    resolved_at = db.Column(db.DateTime, nullable=True)
    resolved_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    
    def is_resolved_or_acknowledged(self):
        """Check if event is in a terminal acknowledged/resolved state"""
        return self.status in ['acknowledged', 'resolved', 'false_positive']

class Incident(db.Model):
    """Live incident response canvas for collaborative IOC logging"""
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(50), nullable=True)
    status = db.Column(db.String(20), default='active')  # active, completed, archived
    severity = db.Column(db.String(20), default='medium')  # low, medium, high, critical
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    incident_iocs = db.relationship('IncidentIOC', backref='incident', lazy=True, cascade="all, delete-orphan")
    participants = db.relationship('User', secondary='incident_participant', backref='incidents')
    owner = db.relationship('User', foreign_keys=[created_by])

    def is_owner(self, user_id):
        return self.created_by == user_id

    def is_participant(self, user_id):
        return any(p.id == user_id for p in self.participants)

class IncidentIOC(db.Model):
    """IOCs logged during live incident"""
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False, index=True)
    type = db.Column(db.String(32), nullable=False)  # ip, domain, url, hash, email address, username
    value = db.Column(db.String(512), nullable=False, index=True)
    analyst_note = db.Column(db.Text, nullable=True)
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    converted_to_ioc_id = db.Column(db.Integer, db.ForeignKey('ioc.id'), nullable=True)  # Link to final IOC in main DB

    def to_dict(self):
        creator = User.query.get(self.added_by)
        return {
            "id": self.id,
            "type": self.type,
            "value": self.value,
            "analyst_note": self.analyst_note,
            "added_by": self.added_by,
            "added_by_name": creator.username if creator else "Unknown",
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "converted_to_ioc_id": self.converted_to_ioc_id
        }

class IncidentNote(db.Model):
    """Team announcements/notes for an incident"""
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    priority = db.Column(db.String(20), default='normal')  # low, normal, high, critical
    
    def to_dict(self):
        creator = User.query.get(self.created_by)
        return {
            "id": self.id,
            "title": self.title,
            "content": self.content,
            "created_by": creator.username if creator else "Unknown",
            "created_at": self.created_at.isoformat(),
            "priority": self.priority
        }

class IncidentLink(db.Model):
    """Quick reference links for incident"""
    id = db.Column(db.Integer, primary_key=True)
    incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False, index=True)
    title = db.Column(db.String(200), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    link_type = db.Column(db.String(50), default='reference')  # article, ticket, report, malware_db, threat_intel, other
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    
    def to_dict(self):
        creator = User.query.get(self.created_by)
        return {
            "id": self.id,
            "title": self.title,
            "url": self.url,
            "link_type": self.link_type,
            "created_by": creator.username if creator else "Unknown",
            "created_at": self.created_at.isoformat()
        }

# Association table for incident participants
incident_participant = db.Table('incident_participant',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('incident_id', db.Integer, db.ForeignKey('incident.id'), primary_key=True)
)

@login_manager.user_loader
def load_user(user_id):
    print(f"[DEBUG] load_user called with user_id={user_id}")
    user = User.query.get(int(user_id))
    if user:
        print(f"[DEBUG] User found: {user.username} (active={user.is_active})")
    else:
        print(f"[DEBUG] No user found with id={user_id}")
    return user

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            if not user.is_active:
                flash('Please contact your admin. Your account is not active', 'danger')
                return render_template('login.html')
            login_user(user)
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            # Don't reveal whether username exists (timing attack prevention)
            flash('Invalid credentials. Please try again.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def welcome():
    # --- Statistics (Testing) ---
    total_sources = Note.query.count()
    total_iocs = IOC.query.count()
    total_users = User.query.count()
    
    # Calculate total relationships (notes that share IOCs)
    # only count IOC values that appear in more than one distinct note; duplicates
    # within the same note should not contribute.
    total_relationships = db.session.query(
        func.count(distinct(IOC.value))
    ).join(Note).group_by(IOC.value).having(func.count(distinct(Note.id)) > 1).count()

    stats = {
        'total_sources': total_sources,
        'total_iocs': total_iocs,
        'total_users': total_users,
        'total_relationships': total_relationships
    }

    # --- Top 5 entries for different IOC types ---
    top_entries = {}
    ioc_types = ['url', 'ip', 'hash', 'domain']
    plural_mapping = {'url': 'urls', 'ip': 'ips', 'hash': 'hashes', 'domain': 'domains'}
    for ioc_type in ioc_types:
        top_entries[plural_mapping[ioc_type]] = db.session.query(
            IOC.value, func.count(IOC.value)
        ).filter_by(type=ioc_type).group_by(IOC.value).order_by(
            func.count(IOC.value).desc()
        ).limit(5).all()

    # --- Recent Sources ---
    notes = Note.query.order_by(Note.created_at.desc()).limit(5).all()
    for note in notes:
        # Truncate title by words for display
        title_words = note.title.split()
        note.truncated_title = ' '.join(title_words[:15]) + ('...' if len(title_words) > 15 else '')

    # --- Recent Relationships ---
    subquery = db.session.query(
        IOC.value,
        func.min(Note.id).label('note_id_1'),
        func.max(Note.id).label('note_id_2'),
        func.count(distinct(Note.id)).label('link_count'),
        func.max(Note.created_at).label('last_linked_at')
    ).join(Note).group_by(IOC.value).having(func.count(distinct(Note.id)) > 1).subquery()

    recent_relationships_query = db.session.query(
        subquery.c.note_id_1,
        Note.title.label('note_title_1'),
        subquery.c.note_id_2,
        Note.title.label('note_title_2'),
        subquery.c.value
    ).join(
        Note, Note.id == subquery.c.note_id_1
    ).order_by(subquery.c.last_linked_at.desc()).limit(5).all()
    recent_relationships = []
    for rel in recent_relationships_query:
        note2_title = db.session.query(Note.title).filter_by(id=rel.note_id_2).scalar()
        # Truncate by words
        rel1_words = rel.note_title_1.split()
        rel1_trunc = ' '.join(rel1_words[:15]) + ('...' if len(rel1_words) > 15 else '')
        if note2_title:
            rel3_words = note2_title.split()
            rel3_trunc = ' '.join(rel3_words[:15]) + ('...' if len(rel3_words) > 15 else '')
            recent_relationships.append((rel.note_id_1, rel1_trunc, rel.note_id_2, rel3_trunc, rel.value))

    return render_template('welcome.html',
                           stats=stats,
                           notes=notes,
                           top_entries=top_entries,
                           recent_relationships=recent_relationships)

@app.route('/notes')
@login_required
def index():
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('search', '').strip()
    category_filter = request.args.get('category', '').strip()
    
    # Advanced search parameters
    user_query = request.args.get('user', '').strip()
    date_from_str = request.args.get('date_from', '').strip()
    date_to_str = request.args.get('date_to', '').strip()
    ioc_type = request.args.get('ioc_type', '').strip()
    ioc_value = request.args.get('ioc_value', '').strip()
    ioc_tags = request.args.get('ioc_tags', '').strip()
    keep_only_str = request.args.get('keep_only', '').strip().lower()
    
    # Start with base query
    query = Note.query
    
    # Initialize search_filter variable
    search_filter = None
    
    # Apply basic search filter if provided
    if search_query:
        # Search in title, content, and IOCs
        search_filter = or_(
            Note.title.ilike(f'%{search_query}%'),
            Note.content.ilike(f'%{search_query}%'),
            Note.id.in_(
                db.session.query(IOC.note_id).filter(
                    or_(
                        IOC.value.ilike(f'%{search_query}%'),
                        IOC.tags.ilike(f'%{search_query}%')
                    )
                )
            )
        )
        query = query.filter(search_filter)
    
    # Apply category filter if provided
    if category_filter:
        query = query.filter(Note.category == category_filter)
        
    # Apply advanced search filters
    if user_query:
        query = query.join(User).filter(User.username.ilike(f'%{user_query}%'))
    
    if date_from_str:
        try:
            date_from = datetime.strptime(date_from_str, '%Y-%m-%d')
            query = query.filter(Note.created_at >= date_from)
        except ValueError:
            flash('Invalid "from" date format. Please use YYYY-MM-DD.', 'warning')
    
    if date_to_str:
        try:
            date_to = datetime.strptime(date_to_str, '%Y-%m-%d')
            query = query.filter(Note.created_at <= date_to)
        except ValueError:
            flash('Invalid "to" date format. Please use YYYY-MM-DD.', 'warning')
    
    if ioc_type or ioc_value or ioc_tags:
        query = query.join(IOC)
        if ioc_type:
            query = query.filter(IOC.type.ilike(f'%{ioc_type}%'))
        if ioc_value:
            query = query.filter(IOC.value.ilike(f'%{ioc_value}%'))
        if ioc_tags:
            query = query.filter(IOC.tags.ilike(f'%{ioc_tags}%'))
    
    if keep_only_str == 'true':
        query = query.filter(Note.keep == True)
    elif keep_only_str == 'false':
        query = query.filter(Note.keep == False)
    
    # Order by creation date and paginate
    notes = query.order_by(Note.created_at.desc()).paginate(page=page, per_page=20)
    
    # Process notes for display
    for note in notes.items:
        title_words = note.title.split()
        note.truncated_title = ' '.join(title_words[:20]) + ('...' if len(title_words) > 20 else '')
        note.title_overflow = len(title_words) > 20

        # Prepare content preview for listings (300 chars)
        note.content_overflows = len(note.content) > 300
        if note.content_overflows:
            note.truncated_content = note.content[:300] + '...'
        else:
            note.truncated_content = note.content
    
    # Get categories for filter dropdown
    categories = get_categories()
    
    # Get all users for advanced search
    users = User.query.order_by(User.username).all()
    
    # Get retention statistics for the current filtered results
    retention_days = app.config['RETENTION_PERIOD_DAYS']
    if retention_days == 0:
        expiring_soon = 0
        expired = 0
    else:
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        # Apply the same filters to get retention stats for filtered results
        retention_query = Note.query
        if search_filter is not None:
            retention_query = retention_query.filter(search_filter)
        if category_filter:
            retention_query = retention_query.filter(Note.category == category_filter)
        if user_query:
            retention_query = retention_query.join(User).filter(User.username.ilike(f'%{user_query}%'))
        if date_from_str:
            try:
                date_from = datetime.strptime(date_from_str, '%Y-%m-%d')
                retention_query = retention_query.filter(Note.created_at >= date_from)
            except ValueError:
                pass
        if date_to_str:
            try:
                date_to = datetime.strptime(date_to_str, '%Y-%m-%d')
                retention_query = retention_query.filter(Note.created_at <= date_to)
            except ValueError:
                pass
        if ioc_type or ioc_value or ioc_tags:
            retention_query = retention_query.join(IOC)
            if ioc_type:
                retention_query = retention_query.filter(IOC.type.ilike(f'%{ioc_type}%'))
            if ioc_value:
                retention_query = retention_query.filter(IOC.value.ilike(f'%{ioc_value}%'))
            if ioc_tags:
                retention_query = retention_query.filter(IOC.tags.ilike(f'%{ioc_tags}%'))
        if keep_only_str == 'true':
            retention_query = retention_query.filter(Note.keep == True)
        elif keep_only_str == 'false':
            retention_query = retention_query.filter(Note.keep == False)
        # Calculate retention statistics for filtered results
        expiring_soon = retention_query.filter(
            Note.keep == False,
            Note.created_at >= cutoff_date,
            Note.created_at < cutoff_date + timedelta(days=7)
        ).count()
        expired = retention_query.filter(
            Note.keep == False,
            Note.created_at < cutoff_date
        ).count()
    
    return render_template('notes.html', 
                         notes=notes, 
                         categories=categories,
                         users=users,
                         search_query=search_query, 
                         category_filter=category_filter,
                         user_query=user_query,
                         date_from=date_from_str,
                         date_to=date_to_str,
                         ioc_type=ioc_type,
                         ioc_value=ioc_value,
                         ioc_tags=ioc_tags,
                         keep_only=keep_only_str,
                         expiring_soon=expiring_soon,
                         expired=expired)

@app.route('/note/new', methods=['GET', 'POST'])
@login_required
def new_note():
    if not current_user.has_permission('can_create'):
        flash('You do not have permission to create a new source.', 'danger')
        return redirect(url_for('index'))
    
    categories = get_categories()

    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        category = request.form.get('category')
        
        keep = 'keep' in request.form
        
        if not title or not content or not category:
            flash('Title, content, and category are required.', 'danger')
            return render_template('new_note.html', categories=categories, title=title, content=content, category=category, keep=keep)

        # Enforce word limit for title and content
        if len(title.split()) > 300:
            flash('Title cannot exceed 300 words.', 'danger')
            return render_template('new_note.html', categories=categories, title=title, content=content, category=category, keep=keep)
        if len(content.split()) > 10000:
            flash('Content cannot exceed 10,000 words.', 'danger')
            return render_template('new_note.html', categories=categories, title=title, content=content, category=category, keep=keep)

        new_note = Note(
            title=title,
            content=content,
            category=category,
            user_id=current_user.id,
            keep=keep
        )
        db.session.add(new_note)
        
        try:
            db.session.flush() # Assigns an ID to new_note

            # Process IOCs
            ioc_types = request.form.getlist('types[]')
            ioc_values = request.form.getlist('values[]')
            ioc_tags_list = request.form.getlist('tags[]')

            for i, ioc_type in enumerate(ioc_types):
                ioc_value = ioc_values[i].strip()
                ioc_tags = ioc_tags_list[i].strip()
                if ioc_value and IOC.is_valid_type(ioc_type):
                    new_ioc = IOC(
                        type=ioc_type,
                        value=ioc_value,
                        tags=ioc_tags,
                        note_id=new_note.id
                    )
                    db.session.add(new_ioc)
            
            db.session.commit()
            record_audit('create_source', f'Created source "{title}"')
            flash('Source created successfully!', 'success')
            return redirect(url_for('view_note', note_id=new_note.id))

        except IntegrityError:
            db.session.rollback()
            flash('Oops.... Your custom identifier must be unique', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')

    return render_template('new_note.html', categories=categories)

@app.route('/note/<int:note_id>')
@login_required
def view_note(note_id):
    note = Note.query.get_or_404(note_id)

    # Prepare content for "View More" functionality (1000 chars)
    note.content_overflows = len(note.content) > 1000
    if note.content_overflows:
        note.truncated_content = note.content[:1000] + '...'
    else:
        note.truncated_content = note.content

    page = request.args.get('page', 1, type=int)
    iocs = IOC.query.filter_by(note_id=note.id).paginate(page=page, per_page=24)
    total_iocs = IOC.query.filter_by(note_id=note.id).count()
    
    # Calculate actual expiry date
    retention_days = app.config['RETENTION_PERIOD_DAYS']
    if note.keep:
        expiry_display = 'Never (Protected)'
        expiry_date = None
    elif retention_days == 0:
        expiry_display = 'Never (Retention Disabled)'
        expiry_date = None
    else:
        expiry_date = note.created_at + timedelta(days=retention_days)
        days_until_expiry = (expiry_date - datetime.utcnow()).days
        if days_until_expiry < 0:
            expiry_display = f'Expired ({abs(days_until_expiry)} days ago)'
        elif days_until_expiry == 0:
            expiry_display = 'Expires today'
        elif days_until_expiry == 1:
            expiry_display = 'Expires tomorrow'
        else:
            expiry_display = f'Expires in {days_until_expiry} days'

    return render_template('view_note.html', 
                         note=note, 
                         iocs=iocs, 
                         total_iocs=total_iocs, 
                         expiry_display=expiry_display,
                         expiry_date=expiry_date)

@app.route('/note/<int:note_id>/iocs')
@login_required
def note_iocs(note_id):
    note = Note.query.get_or_404(note_id)
    page = request.args.get('page', 1, type=int)
    iocs = IOC.query.filter_by(note_id=note.id).paginate(page=page, per_page=100)
    return render_template('note_iocs.html', note=note, iocs=iocs)

@app.route('/note/<int:note_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_note(note_id):
    note = Note.query.get_or_404(note_id)
    if not (current_user.has_permission('can_edit') or current_user.id == note.user_id):
        flash('You do not have permission to edit this source.', 'danger')
        return redirect(url_for('index'))

    categories = get_categories()

    if request.method == 'POST':
        note.title = request.form.get('title')
        note.content = request.form.get('content')
        note.category = request.form.get('category')
        note.keep = 'keep' in request.form

        # Enforce word limit for title and content
        if len(note.title.split()) > 300:
            flash('Title cannot exceed 300 words.', 'danger')
            return render_template('edit_note.html', note=note, categories=categories, ioc_json=json.dumps([ioc.to_dict() for ioc in note.iocs]))
        if len(note.content.split()) > 2000:
            flash('Content cannot exceed 2000 words.', 'danger')
            return render_template('edit_note.html', note=note, categories=categories, ioc_json=json.dumps([ioc.to_dict() for ioc in note.iocs]))
            
        try:
            IOC.query.filter_by(note_id=note.id).delete()
            ioc_types = request.form.getlist('types[]')
            ioc_values = request.form.getlist('values[]')
            ioc_tags_list = request.form.getlist('tags[]')
            for i, ioc_type in enumerate(ioc_types):
                ioc_value = ioc_values[i].strip()
                ioc_tags = ioc_tags_list[i].strip()
                if ioc_value and IOC.is_valid_type(ioc_type):
                    new_ioc = IOC(
                        type=ioc_type,
                        value=ioc_value,
                        tags=ioc_tags,
                        note_id=note.id
                    )
                    db.session.add(new_ioc)
            db.session.commit()
            record_audit('edit_source', f'Edited source "{note.title}" (ID: {note.id})')
            flash('Source updated successfully!', 'success')
            return redirect(url_for('view_note', note_id=note.id))
        except IntegrityError:
            db.session.rollback()
            flash('Oops.... Your custom identifier must be unique', 'danger')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred while updating IOCs: {e}', 'danger')

    iocs = IOC.query.filter_by(note_id=note.id).all()
    ioc_dicts = [ioc.to_dict() for ioc in iocs]
    ioc_json = json.dumps(ioc_dicts)
    return render_template('edit_note.html', note=note, categories=categories, ioc_json=ioc_json)


@app.route('/note/<int:note_id>/delete', methods=['POST'])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    if not (current_user.has_permission('can_delete') or current_user.id == note.user_id):
        flash('You do not have permission to delete this source.', 'danger')
        return redirect(url_for('index'))

    try:
        db.session.delete(note)
        db.session.commit()
        record_audit('delete_source', f'Deleted source "{note.title}" (ID: {note.id})')
        flash('Source deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting source: {e}', 'danger')
        
    return redirect(url_for('index'))

@app.route('/notes/bulk_delete', methods=['POST'])
@login_required
def bulk_delete_notes():
    if not current_user.has_permission('can_delete'):
        return jsonify({'error': 'Access denied'}), 403
    try:
        payload = request.get_json(force=True)
        note_ids = payload.get('note_ids', []) if isinstance(payload, dict) else []
    except Exception:
        note_ids = []
    if not note_ids:
        return jsonify({'error': 'No notes provided'}), 400

    deleted = 0
    skipped = []
    for nid in note_ids:
        note = Note.query.get(nid)
        if not note:
            skipped.append({'id': nid, 'reason': 'not_found'})
            continue
        db.session.delete(note)
        deleted += 1
    db.session.commit()
    record_audit('bulk_delete_notes', f'Deleted {deleted} notes; skipped {len(skipped)}')
    return jsonify({'deleted': deleted, 'skipped': skipped})


@app.route('/note/<int:note_id>/toggle_keep', methods=['POST'])
@login_required
def toggle_keep(note_id):
    note = Note.query.get_or_404(note_id)
    if not (current_user.has_permission('can_edit') or current_user.id == note.user_id):
        flash('You do not have permission to modify this source.', 'danger')
        return redirect(url_for('view_note', note_id=note.id))
    
    note.keep = not note.keep
    if note.keep:
        flash('Source is now protected from automatic deletion.', 'success')
    else:
        flash('Source is no longer protected.', 'info')
    
    db.session.commit()
    return redirect(url_for('view_note', note_id=note.id))

@app.route('/admin')
@login_required
@admin_required
def admin():
    users = User.query.all()
    roles = UserRole.query.all()
    retention_period = app.config['RETENTION_PERIOD_DAYS']
    time_format_pref = get_time_format()
    date_format_pref = get_date_format()
    # Stats
    total_notes = Note.query.count()
    total_iocs = IOC.query.count()
    total_users = User.query.count()
    # Categories for quick management in admin dashboard
    categories = Category.query.order_by(Category.name).all()
    return render_template('admin/dashboard.html', 
                           users=users, 
                           roles=roles,
                           categories=categories,
                           retention_period=retention_period,
                           time_format_pref=time_format_pref,
                           date_format_pref=date_format_pref,
                           total_notes=total_notes,
                           total_iocs=total_iocs,
                           total_users=total_users)


def get_retention_stats():
    """Get statistics about note retention"""
    try:
        retention_days = app.config['RETENTION_PERIOD_DAYS']
        if retention_days == 0:
            total_notes = Note.query.count()
            protected_notes = Note.query.filter(Note.keep == True).count()
            expired_notes = 0
            expiring_soon = 0
            cutoff_date = None
        else:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            total_notes = Note.query.count()
            protected_notes = Note.query.filter(Note.keep == True).count()
            expired_notes = Note.query.filter(
                Note.keep == False,
                Note.created_at < cutoff_date
            ).count()
            expiring_soon = Note.query.filter(
                Note.keep == False,
                Note.created_at >= cutoff_date,
                Note.created_at < cutoff_date + timedelta(days=7)
            ).count()
        return {
            'total_notes': total_notes,
            'protected_notes': protected_notes,
            'expired_notes': expired_notes,
            'expiring_soon': expiring_soon,
            'retention_days': retention_days,
            'cutoff_date': cutoff_date
        }
    except Exception as e:
        print(f"Error getting retention stats: {e}")
        return {
            'total_notes': 0,
            'protected_notes': 0,
            'expired_notes': 0,
            'expiring_soon': 0,
            'retention_days': app.config.get('RETENTION_PERIOD_DAYS', 0),
            'cutoff_date': None
        }

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_settings():
    if request.method == 'POST':
        action = request.form.get('action', 'update_retention')
        if action == 'update_retention':
            disable_retention = request.form.get('disable_retention')
            if disable_retention == '1':
                app.config['RETENTION_PERIOD_DAYS'] = 0
                record_audit('update_retention', 'Retention disabled via settings')
                flash('Retention disabled. Notes will never be deleted automatically.', 'success')
                return redirect(url_for('admin_settings'))
            retention_days = request.form.get('retention_days')
            if retention_days is not None:
                try:
                    retention_days = int(retention_days)
                    if retention_days == 0:
                        app.config['RETENTION_PERIOD_DAYS'] = 0
                        record_audit('update_retention', 'Retention disabled via settings')
                        flash('Retention disabled. Notes will never be deleted automatically.', 'success')
                        return redirect(url_for('admin_settings'))
                    elif retention_days < 30:
                        flash('Retention period must be at least 30 days (or 0 to disable retention).', 'danger')
                    else:
                        app.config['RETENTION_PERIOD_DAYS'] = retention_days
                        record_audit('update_retention', f'Retention set to {retention_days} days')
                        flash('Settings updated successfully!', 'success')
                        return redirect(url_for('admin_settings'))
                except ValueError:
                    flash('Please enter a valid retention period.', 'danger')
            else:
                flash('Please enter a valid retention period.', 'danger')
        elif action == 'update_time_format':
            next_url = request.form.get('next') or url_for('admin_settings')
            time_format = request.form.get('time_format')
            date_format = request.form.get('date_format')
            valid_time = time_format in ['24h', '12h']
            valid_date = date_format in ['ymd', 'mdy', 'dmy']
            if valid_time:
                set_config_value('time_format', time_format)
                record_audit('update_time_format', f'Time format set to {time_format}')
            if valid_date:
                set_config_value('date_format', date_format)
                record_audit('update_date_format', f'Date format set to {date_format}')
            if valid_time or valid_date:
                flash('Time and date format updated successfully.', 'success')
            else:
                flash('Invalid time or date format selection.', 'danger')
            return redirect(next_url)
        elif action == 'update_cleanup_scheduler':
            enabled = request.form.get('auto_cleanup_enabled') == 'on'
            interval = request.form.get('cleanup_interval_minutes') or '60'
            try:
                interval_int = max(5, int(interval))
            except ValueError:
                interval_int = 60
            set_config_value('auto_cleanup_enabled', 'true' if enabled else 'false')
            set_config_value('cleanup_interval_minutes', str(interval_int))
            record_audit('update_cleanup_scheduler', f'Auto-cleanup {"enabled" if enabled else "disabled"} (every {interval_int} min)')
            flash('Cleanup scheduler settings saved.', 'success')
            return redirect(url_for('admin_settings'))
        elif action == 'update_event_rule_scheduler':
            enabled = request.form.get('event_rule_scheduler_enabled') == 'on'
            interval = request.form.get('event_rule_interval_minutes') or '5'
            try:
                interval_int = max(1, int(interval))
            except ValueError:
                interval_int = 5
            set_config_value('event_rule_scheduler_enabled', 'true' if enabled else 'false')
            set_config_value('event_rule_interval_minutes', str(interval_int))
            record_audit('update_event_rule_scheduler', f'Rule runner {"enabled" if enabled else "disabled"} (every {interval_int} min)')
            flash('Event rule scheduler settings saved.', 'success')
            return redirect(url_for('admin_settings'))
    retention_days = app.config['RETENTION_PERIOD_DAYS']
    time_format_pref = get_time_format()
    date_format_pref = get_date_format()
    retention_stats = get_retention_stats()
    audit_cutoff = datetime.utcnow() - timedelta(days=30)
    audit_logs = UserLog.query.filter(UserLog.created_at >= audit_cutoff).order_by(UserLog.created_at.desc()).limit(50).all()
    users_map = {u.id: u.username for u in User.query.all()}
    cleanup_enabled = get_config_bool('auto_cleanup_enabled', False)
    cleanup_interval = int(get_config_value('cleanup_interval_minutes', 60))
    rule_scheduler_enabled = get_config_bool('event_rule_scheduler_enabled', False)
    rule_scheduler_interval = int(get_config_value('event_rule_interval_minutes', 5))
    
    return render_template('admin/settings.html', 
                         retention_days=retention_days,
                         retention_stats=retention_stats,
                         audit_logs=audit_logs,
                         time_format=time_format_pref,
                         date_format=date_format_pref,
                         users_map=users_map,
                         cleanup_enabled=cleanup_enabled,
                         cleanup_interval=cleanup_interval,
                         rule_scheduler_enabled=rule_scheduler_enabled,
                         rule_scheduler_interval=rule_scheduler_interval)


# --- API Key Management ---------------------------------------------------
@app.route('/admin/api_keys', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_api_keys():
    """Allow admins to view existing API keys and generate new ones."""
    if request.method == 'POST':
        description = request.form.get('description', '').strip()
        token = secrets.token_urlsafe(32)
        key = APIKey(key=token, description=description, created_by=current_user.id)
        db.session.add(key)
        db.session.commit()
        record_audit('create_api_key', f'Generated new API key (id={key.id})')
        flash(f'New API key created: {token}', 'success')
        # show token once only
        return redirect(url_for('manage_api_keys'))

    keys = APIKey.query.order_by(APIKey.created_at.desc()).all()
    return render_template('admin/api_keys.html', keys=keys)

@app.route('/admin/api_keys/<int:key_id>/revoke', methods=['POST'])
@login_required
@admin_required
def revoke_api_key(key_id):
    key = APIKey.query.get_or_404(key_id)
    key.is_active = False
    db.session.commit()
    record_audit('revoke_api_key', f'Revoked API key (id={key.id})')
    flash('API key revoked.', 'success')
    return redirect(url_for('manage_api_keys'))


@app.route('/admin/users/new', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        role_id = request.form.get('role_id')
        is_active = True if request.form.get('is_active') else False

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return render_template('admin/create_user.html', roles=UserRole.query.all())

        if not password:
            flash('Password is required for new users.', 'danger')
            return render_template('admin/create_user.html', roles=UserRole.query.all())

        new_user = User(
            username=username,
            password=generate_password_hash(password),
            role_id=role_id,
            is_active=is_active
        )
        db.session.add(new_user)
        db.session.commit()

        record_audit('create_user', f'Created user {username}')

        flash('User created successfully!', 'success')
        return redirect(url_for('admin'))

    return render_template('admin/create_user.html', roles=UserRole.query.all())

@app.route('/admin/edit_user/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == 'sylla':
        can_edit_role = False
    else:
        can_edit_role = True
    form = UserForm(obj=user)
    form.role.choices = [(r.id, r.name) for r in UserRole.query.order_by('name')]
    if request.method == 'POST' and form.validate_on_submit():
        if user.username != 'sylla' and can_edit_role:
            user.role_id = form.role.data
        if form.password.data:
            user.password = generate_password_hash(form.password.data)
        user.is_active = form.is_active.data
        db.session.commit()
        record_audit('edit_user', f'Updated user {user.username}')
        flash('User updated successfully.', 'success')
        return redirect(url_for('admin'))
    form.role.render_kw = {'disabled': not can_edit_role}
    return render_template('admin/edit_user.html', user=user, form=form, can_edit_role=can_edit_role)

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    if user.username == 'sylla':
        flash('The default sylla admin account cannot be deleted.', 'danger')
        return redirect(url_for('admin'))
    # Reassign notes to sylla admin before deleting user
    sylla_admin = User.query.filter_by(username='sylla').first()
    if sylla_admin:
        # Bulk update all related objects
        Note.query.filter_by(user_id=user.id).update({Note.user_id: sylla_admin.id})
        UserLog.query.filter_by(user_id=user.id).update({UserLog.user_id: sylla_admin.id})
        Event.query.filter_by(acknowledged_by=user.id).update({Event.acknowledged_by: sylla_admin.id})
        Event.query.filter_by(resolved_by=user.id).update({Event.resolved_by: sylla_admin.id})
        if hasattr(Anomaly, 'user_id'):
            Anomaly.query.filter_by(user_id=user.id).update({Anomaly.user_id: sylla_admin.id})
        if hasattr(Alert, 'acknowledged_by'):
            Alert.query.filter_by(acknowledged_by=user.username).update({Alert.acknowledged_by: sylla_admin.username})
        db.session.commit()
    db.session.delete(user)
    db.session.commit()
    record_audit('delete_user', f'Deleted user {user.username}')
    flash('User deleted successfully. Their notes have been reassigned to the sylla admin.', 'success')
    return redirect(url_for('admin'))

# Reactivate sylla admin if locked out (to be called after DB init)
def ensure_admin_active():
    try:
        sylla_admin = User.query.filter_by(username='sylla').first()
        if sylla_admin:
            admin_role = UserRole.query.filter_by(name='Admin').first()
            if admin_role:
                sylla_admin.role_id = admin_role.id
            sylla_admin.is_active = True
            db.session.commit()
    except Exception as e:
        print(f"[WARNING] ensure_admin_active skipped: {e}")

@app.route('/admin/clear-database', methods=['POST'])
@login_required
@admin_required
def clear_database():
    if request.form.get('confirm_text') == 'Confirm':
        try:
            # Only delete IOCs and Notes. Users, roles and other config remain.
            db.session.query(IOC).delete()
            db.session.query(Note).delete()
            db.session.commit()
            flash('Successfully cleared sources and IOCs from the database.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'An error occurred: {e}', 'danger')
    else:
        flash('Confirmation text did not match. Database was not cleared.', 'warning')
    return redirect(url_for('admin'))

@app.route('/admin/users/<int:user_id>/reset_password', methods=['GET', 'POST'])
@login_required
def admin_reset_password(user_id):
    if not current_user.has_permission('can_manage_users'):
        flash('Access denied!', 'danger')
        return redirect(url_for('admin'))
    user = User.query.get_or_404(user_id)
    form = AdminResetPasswordForm()
    if form.validate_on_submit():
        user.password = generate_password_hash(form.new_password.data)
        db.session.commit()
        record_audit('admin_reset_password', f'Reset password for user {user.username}')
        flash('Password reset successfully!', 'success')
        return redirect(url_for('admin'))
    return render_template('admin/reset_password.html', form=form, user=user)

@app.route('/admin/logs')
@login_required
def view_logs():
    if not current_user.has_permission('can_manage_users'):
        flash('Access denied!', 'danger')
        return redirect(url_for('admin'))
    cutoff = datetime.utcnow() - timedelta(days=30)
    logs = UserLog.query.filter(UserLog.created_at >= cutoff).order_by(UserLog.created_at.desc()).limit(200).all()
    users_map = {u.id: u.username for u in User.query.all()}
    return render_template('admin/logs.html', logs=logs, users_map=users_map)
@login_required
@login_required
def ai_feedback():
    if not current_user.has_permission('can_manage_users'):
        flash('Access denied!', 'danger')
        return redirect(url_for('admin'))
    status_filter = request.args.get('status', 'all')
    # Advanced anomaly detection
    notes = Note.query.all()
    users = {u.id: u.username for u in User.query.all()}
    data = []
    for note in notes:
        for ioc in note.iocs:
            data.append({'note_id': note.id, 'user': users.get(note.user_id, str(note.user_id)), 'ioc': ioc.value, 'type': ioc.type})
    df = pd.DataFrame(data)
    alerts = []
    # A. Multiple iocs on compromised users
    if not df.empty:
        ioc_counts = df[df['type']=='ip'].groupby('user')['ioc'].nunique()
        for user, count in ioc_counts.items():
            if count > 3:
                alerts.append(f"User '{user}' has {count} unique iocs associated (possible compromise or account sharing).")
    # B. Frequent user activity
    user_counts = df.groupby('user')['note_id'].nunique() if not df.empty else {}
    for user, count in user_counts.items():
        if count > 3:
            alerts.append(f"User '{user}' appears in {count} different sources (frequent/active user).")
    # C. Malware/IOC involved with multiple users
    if not df.empty:
        ioc_user_counts = df.groupby(['ioc', 'type'])['user'].nunique()
        for (ioc, typ), count in ioc_user_counts.items():
            if count > 1:
                alerts.append(f"{typ.upper()} '{ioc}' appears in sources from {count} different users (possible spreading or shared threat).")
    # Store new alerts in DB if not already present
    for desc in alerts:
        if not Alert.query.filter_by(description=desc, status='new').first():
            db.session.add(Alert(description=desc))
    db.session.commit()
    cutoff = datetime.utcnow() - timedelta(days=30)
    Alert.query.filter(Alert.created_at < cutoff).delete()
    db.session.commit()
    # Fetch all alerts for display, filtered by status
    if status_filter == 'all':
        all_alerts = Alert.query.order_by(Alert.created_at.desc()).all()
    else:
        all_alerts = Alert.query.filter_by(status=status_filter).order_by(Alert.created_at.desc()).all()
    return render_template('admin/ai_feedback.html', anomalies=[{'id': a.id, 'desc': a.description, 'status': a.status, 'ack_by': a.acknowledged_by} for a in all_alerts], status_filter=status_filter)

# Store latest anomalies in DB for all users to view
class Anomaly(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    acknowledged_by = db.Column(db.String(80), nullable=True)

def get_latest_anomalies():
    return [a.description for a in Anomaly.query.order_by(Anomaly.created_at.desc()).limit(20).all()]

@app.route('/anomalies')
@login_required
def anomalies():
    anomalies = get_latest_anomalies()
    return render_template('anomalies.html', anomalies=anomalies)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def user_settings():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if check_password_hash(current_user.password, form.old_password.data):
            current_user.password = generate_password_hash(form.new_password.data, method='pbkdf2:sha256')
            db.session.commit()
            record_audit('change_password', 'User changed their password')
            flash('Your password has been changed successfully!', 'success')
            return redirect(url_for('user_settings'))
        else:
            flash('Incorrect old password.', 'danger')
    return render_template('settings.html', form=form)

@app.route('/export_csv')
@login_required
def export_csv():
    if current_user.role.name != 'Admin':
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))
    import csv
    from io import StringIO
    notes = Note.query.all()
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['title', 'content', 'category', 'keep', 'user', 'ioc', 'tags'])
    for note in notes:
        user = User.query.get(note.user_id)
        iocs = ', '.join([f"{ioc.value} ({ioc.type})" for ioc in note.iocs]) if note.iocs else ''
        tags = ', '.join([ioc.tags for ioc in note.iocs]) if note.iocs else ''
        
        writer.writerow([
            note.title,
            note.content,
            note.category,
            'Yes' if note.keep else 'No',
            user.username if user else '',
            iocs,
            tags
        ])
    output = si.getvalue()
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=notes_export.csv"})

@app.route('/note/<int:note_id>/relations', methods=['GET'])
@login_required
def note_relations(note_id):
    note = Note.query.get_or_404(note_id)
    # Collect IOCs (IPs, URLs, hashes) from the given note
    iocs = set()
    iocs.update(ioc.value for ioc in note.iocs)
    if not iocs:
        return jsonify({})
    
    # For each IOC, find other notes (excluding the given note) that share it.
    # We also track notes we've already added so a single related source
    # only appears once even if multiple IOCs match.
    ioc_relations = {}
    seen_note_ids = set()
    for ioc in sorted(iocs):  # Sort IOCs for consistent ordering
        related_notes = set()
        # Find notes that share this IOC (excluding the current note)
        related_notes.update(
            Note.query.join(IOC)
            .filter(IOC.value == ioc, Note.id != note_id)
            .order_by(Note.created_at.desc())  # Stable ordering by creation date
            .all()
        )
        
        # remove any notes we've already reported under previous IOC keys
        related_notes = [n for n in related_notes if n.id not in seen_note_ids]
        if not related_notes:
            continue

        # Convert to list and sort for consistent ordering
        related_notes_list = sorted(related_notes, key=lambda x: (x.created_at, x.id))
        too_many = len(related_notes_list) > 10
        
        # remember ids so we don't duplicate later
        for n in related_notes_list:
            seen_note_ids.add(n.id)

        ioc_relations[ioc] = {
            'notes': [
                {
                    'id': n.id, 
                    'title': n.title, 
                    'created_at': n.created_at.strftime('%Y-%m-%d'),
                    'category': n.category
                } for n in related_notes_list[:10]
            ],
            'too_many': too_many,
            'total_count': len(related_notes_list)
        }
    
    return jsonify(ioc_relations)

@app.route('/search_by_ioc/<ioc_type>/<path:ioc_value>')
@login_required
def search_by_ioc(ioc_type, ioc_value):
    page = request.args.get('page', 1, type=int)
    base_query = Note.query.options(db.joinedload(Note.iocs), db.joinedload(Note.user))
    if ioc_type == 'ip':
        notes = base_query.join(IOC).filter(IOC.value == ioc_value)
    elif ioc_type == 'url':
        notes = base_query.join(IOC).filter(IOC.value == ioc_value)
    elif ioc_type == 'hash':
        notes = base_query.join(IOC).filter(IOC.value == ioc_value)
    else:
        notes = base_query.filter(False)  # Empty result
    notes = notes.order_by(Note.created_at.desc()).paginate(page=page, per_page=20)
    return render_template('search_by_ioc.html', notes=notes, ioc_type=ioc_type, ioc_value=ioc_value)

@app.route('/admin/export_logs')
@login_required
def export_logs():
    if not current_user.has_permission('can_manage_users'):
        flash('Access denied!', 'danger')
        return redirect(url_for('admin'))
    
    import csv
    from io import StringIO
    
    cutoff = datetime.utcnow() - timedelta(days=30)
    logs = UserLog.query.join(User).filter(UserLog.created_at >= cutoff).order_by(UserLog.created_at.desc()).all()
    record_audit('export_logs', 'Exported audit logs (last 30 days)')
    si = StringIO()
    writer = csv.writer(si)
    writer.writerow(['User', 'Action', 'Details', 'Created At'])
    
    for log in logs:
        user = User.query.get(log.user_id)
        writer.writerow([
            user.username if user else 'Unknown',
            log.action,
            log.details,
            log.created_at.strftime('%Y-%m-%d %H:%M:%S')
        ])
    
    output = si.getvalue()
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment;filename=user_logs.csv"})

@app.route('/admin/export_sources', methods=['GET'])
@login_required
@admin_required
def export_sources():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        'ID', 'Title', 'Content', 'Category', 'Keep', 'Created At', 'Updated At', 'User', 'IOCs'
    ])
    for note in Note.query.all():
        iocs_json = json.dumps([
            {'type': ioc.type, 'value': ioc.value, 'tags': ioc.tags} for ioc in note.iocs
        ])
        user = User.query.get(note.user_id)
        writer.writerow([
            note.id,
            note.title,
            note.content,
            note.category,
            'Yes' if note.keep else 'No',
            note.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            note.updated_at.strftime('%Y-%m-%d %H:%M:%S') if note.updated_at else '',
            user.username if user else '',
            iocs_json
        ])
    output.seek(0)
    return Response(output, mimetype='text/csv', headers={
        'Content-Disposition': 'attachment; filename=sources_export.csv'
    })

@app.route('/admin/import_sources', methods=['POST'])
@login_required
@admin_required
def import_sources():
    file = request.files.get('csv_file')
    if not file or not file.filename.endswith('.csv'):
        flash('Please upload a valid CSV file.', 'danger')
        return redirect(url_for('admin_settings'))
    try:
        df = pd.read_csv(file)
        # Normalize column names (case-insensitive)
        df.columns = [col.strip().lower() for col in df.columns]
        def get_col(row, name):
            name = name.lower()
            return row[name] if name in row and pd.notnull(row[name]) else None

        skipped_rows = 0
        imported_rows = 0
        errors = []
        max_errors = 10

        # Helper: resolve default user (admin fallback)
        def resolve_user(username: str):
            if username:
                found = User.query.filter_by(username=username).first()
                if found:
                    return found
            admin_user = User.query.filter_by(username='sylla').first() or User.query.filter_by(username='admin').first()
            if admin_user:
                return admin_user
            admin_role = UserRole.query.filter_by(name='Admin').first()
            if admin_role:
                fallback = User.query.filter_by(role_id=admin_role.id).first()
                if fallback:
                    return fallback
            return current_user

        # Helper: resolve category with default
        def resolve_category(cat_name: str):
            fallback = 'General'
            name = (cat_name or '').strip()
            if not name:
                return fallback
            exists = Category.query.filter_by(name=name).first()
            return name if exists else fallback

        def parse_keep(value):
            if value is None:
                return False, None
            s = str(value).strip().lower()
            if s in ['yes', 'true', '1']:
                return True, None
            if s in ['no', 'false', '0']:
                return False, None
            return False, f"Invalid keep value '{value}' - defaulted to No"

        def add_error(idx, message):
            if len(errors) < max_errors:
                errors.append(f"Row {idx + 1}: {message}")

        for idx, row in df.iterrows():
            title = get_col(row, 'title') or ''
            content = get_col(row, 'content') or ''
            category = resolve_category(get_col(row, 'category'))
            keep, keep_warn = parse_keep(get_col(row, 'keep'))
            created_at_raw = get_col(row, 'created at')
            updated_at_raw = get_col(row, 'updated at')
            created_at = pd.to_datetime(created_at_raw, errors='coerce') if created_at_raw else pd.NaT
            updated_at = pd.to_datetime(updated_at_raw, errors='coerce') if updated_at_raw else pd.NaT
            if pd.isna(created_at):
                created_at = datetime.utcnow()
                add_error(idx, 'Created At missing/invalid - defaulted to now')
            if pd.isna(updated_at):
                updated_at = created_at
                add_error(idx, 'Updated At missing/invalid - defaulted to Created At')
            if keep_warn:
                add_error(idx, keep_warn)

            user = resolve_user(get_col(row, 'user'))
            user_id = user.id
            if not title or not content:
                skipped_rows += 1
                add_error(idx, 'Missing required title or content - row skipped')
                continue
            note = Note(
                title=title,
                content=content,
                category=category,
                keep=keep,
                created_at=created_at,
                updated_at=updated_at,
                user_id=user_id
            )
            db.session.add(note)
            db.session.flush()  # Assigns ID
            # Handle IOCs
            iocs_json = get_col(row, 'iocs')
            print(f"Row {idx} IOCs column: {iocs_json}")  # DEBUG
            if iocs_json:
                try:
                    iocs = json.loads(iocs_json)
                    print(f"Parsed IOCs: {iocs}")  # DEBUG
                    for ioc in iocs:
                        if 'type' in ioc and 'value' in ioc:
                            db.session.add(IOC(
                                type=ioc['type'],
                                value=ioc['value'],
                                tags=ioc.get('tags', ''),
                                note_id=note.id
                            ))
                        else:
                            add_error(idx, 'IOC entry missing type or value - skipped that IOC')
                except Exception as e:
                    print(f"Error parsing IOCs for row {idx}: {e}")  # DEBUG
                    add_error(idx, f'Invalid IOCs JSON - skipped IOCs ({e})')
            imported_rows += 1
        db.session.commit()
        msg = f'Sources imported: {imported_rows}.'
        if skipped_rows:
            msg += f' Skipped: {skipped_rows} row(s).'
        flash(msg, 'success')
        if errors:
            flash('Import notes: ' + ' | '.join(errors), 'warning')
    except Exception as e:
        db.session.rollback()
        flash(f'Oops.... There was an issue with importing: {e}', 'danger')
    return redirect(url_for('admin_settings'))

@app.route('/admin/reset_database', methods=['POST'])
@login_required
@admin_required
def reset_database():
    confirm_text = request.form.get('confirm_text', '')
    if confirm_text != 'Confirm':
        flash('You must type Confirm to reset the database.', 'danger')
        return redirect(url_for('admin_settings'))
    # Only remove notes, IOCs, and event rules. Preserve users, roles, categories and other config.
    from sqlalchemy import text
    db.session.execute(text('DELETE FROM ioc'))
    db.session.execute(text('DELETE FROM note'))
    db.session.execute(text('DELETE FROM event'))
    db.session.execute(text('DELETE FROM event_rule'))
    db.session.commit()
    flash('Database reset: notes, IOCs, events, and event rules deleted. Users and categories preserved.', 'success')
    return redirect(url_for('admin_settings'))

@app.route('/events')
@login_required
def events():
    status_filter = request.args.get('status', 'new')
    page = request.args.get('page', 1, type=int)

    base_query = Event.query

    if status_filter != 'all':
        events_list = base_query.filter_by(status=status_filter).order_by(Event.created_at.desc()).paginate(page=page, per_page=20)
    else:
        events_list = base_query.order_by(Event.created_at.desc()).paginate(page=page, per_page=20)

    # Get counts for each status
    new_events_count = Event.query.filter_by(status='new').count()
    acknowledged_events_count = Event.query.filter_by(status='acknowledged').count()
    resolved_events_count = Event.query.filter_by(status='resolved').count()
    
    return render_template('events.html', 
                           events=events_list, 
                           status_filter=status_filter,
                           new_events_count=new_events_count,
                           acknowledged_events_count=acknowledged_events_count,
                           resolved_events_count=resolved_events_count)

@app.route('/admin/event_rules')
@login_required
@admin_required
def event_rules():
    """Manage event rules - admin only"""
    rules = EventRule.query.order_by(EventRule.created_at.desc()).all()
    return render_template('admin/event_rules.html', rules=rules)

@app.route('/admin/event_rules/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_event_rule():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        rule_type = request.form.get('rule_type')
        if not all([name, rule_type]):
            flash('Name and rule type are required.', 'error')
            return redirect(url_for('create_event_rule'))
        errors = []

        def parse_positive_int(field_name, label, default_value):
            raw_value = (request.form.get(field_name) or '').strip()
            if raw_value == '':
                return default_value
            try:
                parsed_value = int(raw_value)
                if parsed_value < 1:
                    errors.append(f'{label} must be at least 1.')
                    return None
                return parsed_value
            except ValueError:
                errors.append(f'{label} must be a whole number.')
                return None

        conditions = {}
        if rule_type == 'ioc_frequency':
            ioc_type = request.form.get('ioc_type')
            min_count = parse_positive_int('min_count', 'Minimum count', 1)
            time_window_hours = parse_positive_int('time_window_hours', 'Time window (hours)', 24)
            if not ioc_type:
                errors.append('IOC type is required for IOC Frequency rules.')
            if errors:
                for msg in errors:
                    flash(msg, 'danger')
                return redirect(url_for('create_event_rule'))
            conditions = {
                'ioc_type': ioc_type,
                'min_count': min_count,
                'time_window_hours': time_window_hours
            }
        elif rule_type == 'about_to_expire':
            days_before_expiry = parse_positive_int('days_before_expiry', 'Days before expiry', 7)
            if errors:
                for msg in errors:
                    flash(msg, 'danger')
                return redirect(url_for('create_event_rule'))
            conditions = {
                'days_before_expiry': days_before_expiry
            }
        elif rule_type == 'ioc_monitor':
            ioc_type = request.form.get('ioc_type')
            ioc_value = (request.form.get('ioc_value') or '').strip()
            if not ioc_type:
                errors.append('IOC type is required for IOC Monitor rules.')
            if not ioc_value:
                errors.append('IOC value is required for IOC Monitor rules.')
            if errors:
                for msg in errors:
                    flash(msg, 'danger')
                return redirect(url_for('create_event_rule'))
            conditions = {
                'ioc_type': ioc_type,
                'ioc_value': ioc_value
            }
        elif rule_type == 'incident_monitor':
            incident_id_str = request.form.get('incident_id', '').strip()
            if not incident_id_str:
                flash('Incident ID is required for Incident Monitor rule.', 'error')
                return redirect(url_for('create_event_rule'))
            try:
                conditions = {
                    'incident_id': int(incident_id_str)
                }
            except (ValueError, TypeError):
                flash('Invalid incident ID.', 'error')
                return redirect(url_for('create_event_rule'))
        else:
            flash('Invalid rule type.', 'error')
            return redirect(url_for('create_event_rule'))
        rule = EventRule(
            name=name,
            description=description,
            rule_type=rule_type,
            conditions=json.dumps(conditions),
            created_by=current_user.id
        )
        db.session.add(rule)
        db.session.commit()
        record_audit('create_event_rule', f'Created event rule "{name}" (ID: {rule.id})')
        flash('Event rule created successfully.', 'success')
        return redirect(url_for('event_rules'))
    categories = get_categories()
    return render_template('admin/create_event_rule.html', categories=categories)

@app.route('/admin/event_rules/<int:rule_id>/edit', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_event_rule(rule_id):
    rule = EventRule.query.get_or_404(rule_id)
    if request.method == 'POST':
        import json
        rule.name = request.form.get('name')
        rule.description = request.form.get('description')
        rule.is_active = 'is_active' in request.form
        rule_type = rule.rule_type
        errors = []

        def parse_positive_int(field_name, label, default_value):
            raw_value = (request.form.get(field_name) or '').strip()
            if raw_value == '':
                return default_value
            try:
                parsed_value = int(raw_value)
                if parsed_value < 1:
                    errors.append(f'{label} must be at least 1.')
                    return None
                return parsed_value
            except ValueError:
                errors.append(f'{label} must be a whole number.')
                return None

        conditions = {}
        if rule_type == 'ioc_frequency':
            ioc_type = request.form.get('ioc_type')
            min_count = parse_positive_int('min_count', 'Minimum count', 1)
            time_window_hours = parse_positive_int('time_window_hours', 'Time window (hours)', 24)
            if not ioc_type:
                errors.append('IOC type is required for IOC Frequency rules.')
            if errors:
                for msg in errors:
                    flash(msg, 'danger')
                return redirect(url_for('event_rules'))
            conditions = {
                'ioc_type': ioc_type,
                'min_count': min_count,
                'time_window_hours': time_window_hours
            }
        elif rule_type == 'about_to_expire':
            days_before_expiry = parse_positive_int('days_before_expiry', 'Days before expiry', 7)
            if errors:
                for msg in errors:
                    flash(msg, 'danger')
                return redirect(url_for('event_rules'))
            conditions = {
                'days_before_expiry': days_before_expiry
            }
        elif rule_type == 'ioc_monitor':
            ioc_type = request.form.get('ioc_type')
            ioc_value = (request.form.get('ioc_value') or '').strip()
            if not ioc_type:
                errors.append('IOC type is required for IOC Monitor rules.')
            if not ioc_value:
                errors.append('IOC value is required for IOC Monitor rules.')
            if errors:
                for msg in errors:
                    flash(msg, 'danger')
                return redirect(url_for('event_rules'))
            conditions = {
                'ioc_type': ioc_type,
                'ioc_value': ioc_value
            }
        elif rule_type == 'incident_monitor':
            incident_id_str = request.form.get('incident_id', '').strip()
            if not incident_id_str:
                flash('Incident ID is required for Incident Monitor rule.', 'error')
                return redirect(url_for('event_rules'))
            try:
                conditions = {
                    'incident_id': int(incident_id_str)
                }
            except (ValueError, TypeError):
                flash('Invalid incident ID.', 'error')
                return redirect(url_for('event_rules'))
        rule.conditions = json.dumps(conditions)
        db.session.commit()
        record_audit('edit_event_rule', f'Updated event rule "{rule.name}" (ID: {rule.id})')
        flash('Event rule updated successfully!', 'success')
        return redirect(url_for('event_rules'))
    import json
    conditions = json.loads(rule.conditions) if rule.conditions else {}
    return render_template('admin/edit_event_rule.html', rule=rule, conditions=conditions)

@app.route('/admin/event_rules/<int:rule_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_event_rule(rule_id):
    """Delete event rule - admin only"""
    rule = EventRule.query.get_or_404(rule_id)
    db.session.delete(rule)
    db.session.commit()
    record_audit('delete_event_rule', f'Deleted event rule "{rule.name}" (ID: {rule.id})')
    flash('Event rule deleted successfully!', 'success')
    return redirect(url_for('event_rules'))

@app.route('/events/<int:event_id>')
@login_required
def view_event(event_id):
    """View specific event details"""
    event = Event.query.get_or_404(event_id)
    
    # Check permissions
    if not current_user.has_permission('can_edit') and current_user.role.name not in ['Admin', 'Editor'] and event.status not in ['acknowledged', 'resolved']:
        flash('Access denied!', 'danger')
        return redirect(url_for('events'))
    
    return render_template('view_event.html', event=event, User=User, EventRule=EventRule)

@app.route('/events/<int:event_id>/acknowledge', methods=['POST'])
@login_required
def acknowledge_event(event_id):
    """Acknowledge an event - admins and editors only"""
    if not current_user.has_permission('can_edit') and current_user.role.name not in ['Admin', 'Editor']:
        flash('Access denied!', 'danger')
        return redirect(url_for('events'))
    
    event = Event.query.get_or_404(event_id)
    event.status = 'acknowledged'
    event.acknowledged_at = datetime.utcnow()
    event.acknowledged_by = current_user.id
    
    db.session.commit()
    flash('Event acknowledged successfully!', 'success')
    return redirect(url_for('view_event', event_id=event_id))

@app.route('/events/<int:event_id>/resolve', methods=['POST'])
@login_required
def resolve_event(event_id):
    """Resolve an event - admins and editors only"""
    if not current_user.has_permission('can_edit') and current_user.role.name not in ['Admin', 'Editor']:
        flash('Access denied!', 'danger')
        return redirect(url_for('events'))
    
    event = Event.query.get_or_404(event_id)
    event.status = 'resolved'
    event.resolved_at = datetime.utcnow()
    event.resolved_by = current_user.id
    
    db.session.commit()
    flash('Event resolved successfully!', 'success')
    return redirect(url_for('view_event', event_id=event_id))


# ----- API key utilities ----------------------------------------------------

def require_api_key(f):
    """Decorator to protect endpoints with an API key passed via header or query parameter."""
    @wraps(f)
    def decorated(*args, **kwargs):
        # support both header and query param for flexibility
        api_key_value = request.headers.get('X-API-Key') or request.args.get('api_key')
        if not api_key_value:
            return jsonify({'error': 'API key required'}), 401
        key_obj = APIKey.query.filter_by(key=api_key_value, is_active=True).first()
        if not key_obj:
            return jsonify({'error': 'Invalid API key'}), 403
        # store for downstream use
        from flask import g
        g.api_key = key_obj
        return f(*args, **kwargs)
    return decorated

# public endpoints for notes (sources)
@app.route('/api/notes', methods=['GET', 'POST'])
@require_api_key
def api_notes():
    """List or create sources via API.

    GET  - return a short listing of recent sources (max 100)
    POST - create a new source along with optional IOCs
    """
    from flask import g
    if request.method == 'GET':
        notes = Note.query.order_by(Note.created_at.desc()).limit(100).all()
        result = []
        for note in notes:
            result.append({
                'id': note.id,
                'title': note.title,
                'category': note.category,
                'created_at': note.created_at.isoformat(),
                'custom_identifier': note.custom_identifier
            })
        return jsonify(result)

    # POST creates a new source
    # parse JSON payload safely
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({'error': 'Invalid JSON payload'}), 400

    title = (data.get('title') or '').strip()
    content = (data.get('content') or '').strip()
    category = (data.get('category') or '').strip()
    keep = bool(data.get('keep', False))
    iocs = data.get('iocs', [])

    if not title or not category:
        return jsonify({'error': 'title and category are required'}), 400
    if len(title.split()) > 300:
        return jsonify({'error': 'title exceeds word limit (300)'}), 400
    if content and len(content.split()) > 10000:
        return jsonify({'error': 'content exceeds word limit (10000)'}), 400

    # determine owner of the note: prefer the admin who created the key
    owner_id = g.api_key.created_by
    if owner_id:
        owner = User.query.get(owner_id)
        if not owner:
            owner_id = None
    if not owner_id:
        sylla = User.query.filter_by(username='sylla').first()
        owner_id = sylla.id if sylla else None
    if not owner_id:
        # impossible, but avoid crashing
        return jsonify({'error': 'No valid owner could be determined for the new note'}), 500

    # perform DB work inside a try block so we can catch flush errors as well
    try:
        new_note = Note(
            title=title,
            content=content,
            category=category,
            user_id=owner_id,
            keep=keep
        )
        db.session.add(new_note)
        db.session.flush()  # may raise IntegrityError

        # process IOCs list
        if isinstance(iocs, list):
            for entry in iocs:
                if not isinstance(entry, dict):
                    continue
                ioc_type = entry.get('type')
                ioc_value = (entry.get('value') or '').strip()
                ioc_tags = (entry.get('tags') or '').strip()
                if ioc_value and IOC.is_valid_type(ioc_type):
                    db.session.add(IOC(
                        type=ioc_type,
                        value=ioc_value,
                        tags=ioc_tags,
                        note_id=new_note.id
                    ))
        db.session.commit()
        record_audit('api_create_source', f'API key {g.api_key.id} created source "{title}"')
        return jsonify({'message': 'Source created', 'note_id': new_note.id}), 201
    except IntegrityError:
        db.session.rollback()
        return jsonify({'error': 'Unique constraint failed (custom identifier?)'}), 400
    except Exception as e:
        db.session.rollback()
        # log the exception so admin can inspect server logs
        app.logger.exception('Error creating note via API')
        return jsonify({'error': 'internal error'}), 500

@app.route('/api/notes/<int:note_id>', methods=['GET', 'DELETE'])
@require_api_key
def api_note_detail(note_id):
    """Retrieve or delete a single source via API."""
    note = Note.query.get_or_404(note_id)
    if request.method == 'GET':
        return jsonify({
            'id': note.id,
            'title': note.title,
            'content': note.content,
            'category': note.category,
            'keep': note.keep,
            'created_at': note.created_at.isoformat(),
            'iocs': [ioc.to_dict() for ioc in note.iocs]
        })
    else:
        db.session.delete(note)
        db.session.commit()
        return jsonify({'message': 'Deleted'}), 200

@app.route('/api/events/<int:event_id>/resolve', methods=['POST'])
@login_required

def api_resolve_event(event_id):
    """API endpoint to resolve an event"""
    if not current_user.has_permission('can_edit') and current_user.role.name not in ['Admin', 'Editor']:
        return jsonify({'error': 'Access denied'}), 403

    event = Event.query.get_or_404(event_id)
    event.status = 'resolved'
    event.resolved_at = datetime.utcnow()
    event.resolved_by = current_user.id

    db.session.commit()
    return jsonify({'success': True, 'message': 'Event resolved'})

@app.route('/admin/categories')
@login_required
def manage_categories():
    """Manage categories - admin only"""
    if not current_user.has_permission('can_manage_users'):
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))
    
    categories = Category.query.order_by(Category.name).all()
    return render_template('admin/categories.html', categories=categories)

@app.route('/admin/categories/new', methods=['GET', 'POST'])
@login_required
def create_category():
    """Create new category - admin only"""
    if not current_user.has_permission('can_manage_users'):
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))
    # Categories are fixed in this application and cannot be created via UI.
    flash('Categories are fixed and cannot be created or changed.', 'info')
    return redirect(url_for('admin'))

@app.route('/admin/categories/<int:category_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_category(category_id):
    """Edit category - admin only"""
    if not current_user.has_permission('can_manage_users'):
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))
    # Categories are fixed and cannot be edited through the UI.
    flash('Categories are fixed and cannot be edited.', 'info')
    return redirect(url_for('admin'))

@app.route('/admin/categories/<int:category_id>/delete', methods=['POST'])
@login_required
def delete_category(category_id):
    """Delete category - admin only"""
    if not current_user.has_permission('can_manage_users'):
        flash('Access denied!', 'danger')
        return redirect(url_for('index'))
    # Categories are fixed and cannot be deleted.
    flash('Categories are fixed and cannot be deleted.', 'info')
    return redirect(url_for('admin'))

def get_categories():
    """Helper function to get all active categories"""
    return Category.query.filter_by(is_active=True).order_by(Category.name).all()

@app.route('/live-search')
@login_required
def live_search():
    query = request.args.get('query', '').strip()
    results = []
    
    if len(query) < 2:
        return jsonify(results)

    # Search notes by title or custom identifier
    notes_query = Note.query.filter(
        or_(
            Note.title.ilike(f'%{query}%'),
            Note.custom_identifier.ilike(f'%{query}%')
        )
    ).limit(5).all()

    for note in notes_query:
        results.append({
            'type': 'Source',
            'title': note.title,
            'url': url_for('view_note', note_id=note.id)
        })

    # Search IOCs by value
    ioc_limit = 10 - len(results)
    if ioc_limit > 0:
        iocs_query = IOC.query.filter(
            IOC.value.ilike(f'%{query}%')
        ).limit(ioc_limit).all()

        for ioc in iocs_query:
            # Prevent adding a note if it's already in results from the title search
            if not any(d['url'] == url_for('view_note', note_id=ioc.note_id) for d in results):
                results.append({
                    'type': 'IOC',
                    'title': f"{ioc.value}",
                    'context': f"in: {ioc.note.title}",
                    'url': url_for('view_note', note_id=ioc.note_id)
                })

    return jsonify(results)

def cleanup_expired_notes():
    """Delete notes that have exceeded their retention period"""
    try:
        retention_days = app.config['RETENTION_PERIOD_DAYS']
        if retention_days == 0:
            # Retention disabled, never delete notes
            return 0
        cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
        # Find notes that are not protected and have expired
        expired_notes = Note.query.filter(
            Note.keep == False,
            Note.created_at < cutoff_date
        ).all()
        deleted_count = 0
        for note in expired_notes:
            try:
                db.session.delete(note)
                deleted_count += 1
            except Exception as e:
                print(f"Error deleting note {note.id}: {e}")
                continue
        db.session.commit()
        return deleted_count
    except Exception as e:
        db.session.rollback()
        print(f"Error in cleanup_expired_notes: {e}")
        return 0

@app.route('/admin/cleanup-expired', methods=['POST'])
@login_required
@admin_required
def cleanup_expired():
    """Manually trigger cleanup of expired notes"""
    deleted_count = cleanup_expired_notes()
    flash(f'Successfully deleted {deleted_count} expired notes.', 'success')
    return redirect(url_for('admin_settings'))

def scheduled_cleanup():
    """Scheduled cleanup function that can be called periodically"""
    try:
        deleted_count = cleanup_expired_notes()
        if deleted_count > 0:
            print(f"Scheduled cleanup: Deleted {deleted_count} expired notes")
        return deleted_count
    except Exception as e:
        print(f"Error in scheduled cleanup: {e}")
        return 0

def start_cleanup_scheduler():
    """Start the cleanup scheduler in a background thread"""
    def run_cleanup_scheduler():
        interval_minutes = 60
        while True:
            try:
                with app.app_context():
                    enabled = get_config_bool('auto_cleanup_enabled', False)
                    interval_minutes = max(5, int(get_config_value('cleanup_interval_minutes', 60) or 60))
                    if enabled:
                        deleted_count = scheduled_cleanup()
                        if deleted_count > 0:
                            print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}] Auto-cleanup removed {deleted_count} expired notes")
            except Exception as e:
                print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}] Error in cleanup scheduler: {e}")
            time.sleep(interval_minutes * 60)

    cleanup_thread = threading.Thread(target=run_cleanup_scheduler, daemon=True)
    cleanup_thread.start()
    print("Cleanup scheduler started")

def start_event_rule_scheduler():
    """Start the event rule scheduler in a background thread"""
    def run_rule_scheduler():
        interval_minutes = 5
        while True:
            try:
                with app.app_context():
                    enabled = get_config_bool('event_rule_scheduler_enabled', False)
                    interval_minutes = max(1, int(get_config_value('event_rule_interval_minutes', 5) or 5))
                    if enabled:
                        created = run_event_rules_core()
                        if created:
                            print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}] Auto-rule run created {created} event(s)")
            except Exception as e:
                print(f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}] Error in rule scheduler: {e}")
            time.sleep(interval_minutes * 60)

    scheduler_thread = threading.Thread(target=run_rule_scheduler, daemon=True)
    scheduler_thread.start()
    print("Event rule scheduler started")

@app.route('/health')
@login_required
def health_check():
    """Health check endpoint for monitoring worker status"""
    try:
        # Test database connection
        db.session.execute(text('SELECT 1'))
        db.session.commit()
        
        # Check user table
        user_count = User.query.count()
        
        # Check session table (optional)
        try:
            session_count = SessionData.query.count()
        except Exception:
            session_count = "table_not_available"
        
        return jsonify({
            'status': 'healthy', 
            'database': 'connected',
            'session_count': session_count,
            'user_count': user_count,
            'worker_pid': os.getpid()
        }), 200
    except Exception as e:
        print(f"[ERROR] Health check failed: {e}")
        return jsonify({'status': 'unhealthy', 'error': str(e)}), 500

@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors"""
    print(f"[ERROR] Internal server error: {error}")
    db.session.rollback()
    return render_template('error.html', error="Internal server error"), 500

@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    return render_template('error.html', error="Page not found"), 404

def cleanup_expired_sessions():
    """Remove expired sessions from database"""
    try:
        expired_sessions = SessionData.query.filter(
            SessionData.expires_at < datetime.utcnow()
        ).all()
        
        for session in expired_sessions:
            db.session.delete(session)
        
        if expired_sessions:
            db.session.commit()
            print(f"[INFO] Cleaned up {len(expired_sessions)} expired sessions")
    except Exception as e:
        print(f"[WARNING] Error cleaning up expired sessions: {e}")

def ensure_session_table():
    """Ensure the session_data table exists"""
    try:
        inspector = inspect(db.engine)
        if 'session_data' not in inspector.get_table_names():
            print("[STARTUP] Creating session_data table manually...")
            # Create the table manually
            SessionData.__table__.create(db.engine, checkfirst=True)
            print("[STARTUP] session_data table created successfully")
            return True
        else:
            print("[STARTUP] session_data table already exists")
            return True
    except Exception as e:
        print(f"[ERROR] Failed to create session_data table: {e}")
        return False


def ensure_default_roles():
    """Create or align built-in roles with expected permissions."""
    inspector = inspect(db.engine)
    if 'user_role' not in inspector.get_table_names():
        return False
    role_definitions = {
        'Admin': {
            'description': 'Administrator with full access',
            'can_create': True,
            'can_edit': True,
            'can_delete': True,
            'can_manage_users': True
        },
        'Analyst': {
            'description': 'Create/edit/delete everywhere except admin areas',
            'can_create': True,
            'can_edit': True,
            'can_delete': True,
            'can_manage_users': False
        },
        'Reader': {
            'description': 'Read-only access, can change own password',
            'can_create': False,
            'can_edit': False,
            'can_delete': False,
            'can_manage_users': False
        }
    }

    existing_roles = {r.name: r for r in UserRole.query.all()}
    changed = False

    for role_name, attrs in role_definitions.items():
        role = existing_roles.get(role_name)
        if role:
            for attr, val in attrs.items():
                if getattr(role, attr) != val:
                    setattr(role, attr, val)
                    changed = True
        else:
            db.session.add(UserRole(name=role_name, **attrs))
            changed = True

    if changed:
        db.session.commit()

    # Migrate legacy 'User' role to 'Analyst' and remove the role entry
    legacy_user_role = existing_roles.get('User')
    analyst_role = existing_roles.get('Analyst') or UserRole.query.filter_by(name='Analyst').first()
    if legacy_user_role:
        if analyst_role:
            User.query.filter_by(role_id=legacy_user_role.id).update({User.role_id: analyst_role.id})
        db.session.delete(legacy_user_role)
        db.session.commit()
        changed = True

    return changed

startup_completed = False

def ensure_defaults_on_startup():
    global startup_completed
    if startup_completed:
        return
    startup_completed = True

    print(f"[STARTUP] Starting SyllaApp application (PID: {os.getpid()})")
    with app.app_context():
        print("[STARTUP] Creating database tables...")
        db.create_all()
        print("[STARTUP] Database tables created/verified")

        ensure_session_table()

        if ensure_default_roles():
            print("[STARTUP] Default roles ensured")

        if not AppConfig.query.filter_by(key='time_format').first():
            db.session.add(AppConfig(key='time_format', value='24h'))
            db.session.commit()
            print("[STARTUP] Default time format set to 24h")

        if not AppConfig.query.filter_by(key='date_format').first():
            db.session.add(AppConfig(key='date_format', value='ymd'))
            db.session.commit()
            print("[STARTUP] Default date format set to ymd")

        defaults = {
            'auto_cleanup_enabled': 'false',
            'cleanup_interval_minutes': '60',
            'event_rule_scheduler_enabled': 'false',
            'event_rule_interval_minutes': '5'
        }
        for cfg_key, cfg_val in defaults.items():
            if not AppConfig.query.filter_by(key=cfg_key).first():
                db.session.add(AppConfig(key=cfg_key, value=cfg_val))
        db.session.commit()

        if not User.query.filter_by(username='sylla').first():
            print("[STARTUP] Creating default admin user...")
            admin_role = UserRole.query.filter_by(name='Admin').first()
            # SECURITY: Generate random password instead of hardcoding
            import secrets
            initial_password = os.environ.get('INITIAL_ADMIN_PASSWORD') or secrets.token_urlsafe(16)
            admin_user = User(username='sylla', password=generate_password_hash(initial_password), role_id=admin_role.id)
            db.session.add(admin_user)
            db.session.commit()
            print("[STARTUP] Default admin user 'sylla' created")
            if not os.environ.get('INITIAL_ADMIN_PASSWORD'):
                print(f"[STARTUP] Initial password (save this): {initial_password}")
            print("[STARTUP] ⚠️  IMPORTANT: Change the default password after first login!")
        else:
            print("[STARTUP] Default admin user already exists")

        print("[STARTUP] Starting cleanup scheduler...")
        start_cleanup_scheduler()
        print("[STARTUP] Starting event rule scheduler...")
        start_event_rule_scheduler()

        deleted_count = scheduled_cleanup()
        if deleted_count > 0:
            print(f"Startup cleanup: Deleted {deleted_count} expired notes")

        print("[STARTUP] Cleaning up expired sessions...")
        try:
            cleanup_expired_sessions()
        except Exception as e:
            print(f"[WARNING] Could not cleanup expired sessions: {e}")

        print(f"[STARTUP] Application startup complete (PID: {os.getpid()})")


# Run initialization when module loads 
try:
    ensure_defaults_on_startup()
except Exception as e:
    print(f"[STARTUP] Deferred initialization to __main__: {e}")


if __name__ == '__main__':
    ensure_defaults_on_startup()

    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))

    ssl_context = None
    ssl_cert = os.environ.get('SSL_CERT_FILE')
    ssl_key = os.environ.get('SSL_KEY_FILE')

    if ssl_cert and ssl_key and os.path.exists(ssl_cert) and os.path.exists(ssl_key):
        ssl_context = (ssl_cert, ssl_key)
        print(f"SSL enabled with certificate: {ssl_cert}")
    elif ssl_cert or ssl_key:
        print("⚠️  SSL certificate files not found, running without SSL")

    print(f"Starting SyllaApp on {host}:{port}")
    print(f"Debug mode: {'ON' if debug_mode else 'OFF'}")
    print(f"Environment: {os.environ.get('FLASK_ENV', 'production')}")
    print(f"SSL: {'ENABLED' if ssl_context else 'DISABLED'}")

    app.run(debug=debug_mode, host=host, port=port, ssl_context=ssl_context)

# ==================== Incident RESPONSE Routes (Late implementation - Still looking for issues) ====================

@app.route('/incidents')
@login_required
def incidents_list():
    """List all active and recent incidents"""
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', 'active')
    
    query = Incident.query
    if status != 'all':
        query = query.filter_by(status=status)
    
    incidents = query.order_by(Incident.updated_at.desc()).paginate(page=page, per_page=20)
    return render_template('incidents_list.html', incidents=incidents, status=status)

@app.route('/incidents/create', methods=['GET', 'POST'])
@login_required
def create_incident():
    """Create a new incident response canvas"""
    if not current_user.has_permission('can_create'):
        flash('You do not have permission to create incidents.', 'danger')
        return redirect(url_for('incidents_list'))

    if request.method == 'POST':
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        category = request.form.get('category', '').strip()
        severity = request.form.get('severity', 'medium')
        
        if not title:
            flash('Incident title is required.', 'danger')
            return render_template('create_incident.html')
        
        incident = Incident(
            title=title,
            description=description,
            category=category,
            severity=severity,
            created_by=current_user.id
        )
        db.session.add(incident)
        db.session.commit()

        record_audit('create_incident', f'Created incident "{title}" (ID: {incident.id})')
        
        # Add creator as participant
        incident.participants.append(current_user)
        db.session.commit()
        
        flash(f'Incident "{title}" created. Invite others to collaborate!', 'success')
        return redirect(url_for('incident_canvas', incident_id=incident.id))
    
    return render_template('create_incident.html')

@app.route('/incidents/<int:incident_id>')
@login_required
def incident_canvas(incident_id):
    """Main incident response canvas"""
    incident = Incident.query.get_or_404(incident_id)
    
    # Add user as participant if not already
    if current_user not in incident.participants:
        incident.participants.append(current_user)
        db.session.commit()
    
    # Get related sources for each IOC
    sources_map = {}
    for ioc in incident.incident_iocs:
        matching_iocs = IOC.query.filter_by(type=ioc.type, value=ioc.value).all()
        sources = list(set([ioc_item.note.title for ioc_item in matching_iocs if ioc_item.note]))
        sources_map[ioc.id] = sources
    
    owner_name = incident.owner.username if incident.owner else 'Unknown'
    return render_template('incident_canvas.html', incident=incident, sources_map=sources_map, owner_name=owner_name)

@app.route('/api/incidents/<int:incident_id>/iocs', methods=['GET', 'POST'])
@login_required
def api_incident_iocs(incident_id):
    """API endpoint for adding/retrieving IOCs in an incident"""
    incident = Incident.query.get_or_404(incident_id)
    
    # Verify user is participant
    if current_user not in incident.participants:
        return jsonify({'error': 'Not a participant'}), 403
    
    if request.method == 'POST':
        if not has_incident_write_access(current_user):
            return jsonify({'error': 'Read-only role cannot add IOCs to incidents'}), 403
        data = request.get_json()
        ioc_value = data.get('value', '').strip()
        ioc_type = data.get('type', '').strip()
        analyst_note = data.get('analyst_note', '').strip()
        
        if not ioc_value or not ioc_type:
            return jsonify({'error': 'Value and type required'}), 400
        
        if not IOC.is_valid_type(ioc_type):
            return jsonify({'error': f'Invalid IOC type: {ioc_type}'}), 400
        
        # Check for duplicates within incident
        existing = IncidentIOC.query.filter_by(
            incident_id=incident_id,
            type=ioc_type,
            value=ioc_value
        ).first()
        
        if existing:
            return jsonify({'error': 'IOC already exists in this incident', 'ioc': existing.to_dict()}), 409
        
        incident_ioc = IncidentIOC(
            incident_id=incident_id,
            type=ioc_type,
            value=ioc_value,
            analyst_note=analyst_note,
            added_by=current_user.id
        )
        db.session.add(incident_ioc)
        db.session.commit()
        
        # Get related sources
        matching_iocs = IOC.query.filter_by(type=ioc_type, value=ioc_value).all()
        sources = list(set([ioc_item.note.title for ioc_item in matching_iocs if ioc_item.note]))
        
        return jsonify({
            'success': True,
            'ioc': incident_ioc.to_dict(),
            'sources': sources
        }), 201
    
    # GET: Return all IOCs in incident
    iocs = IncidentIOC.query.filter_by(incident_id=incident_id).order_by(IncidentIOC.created_at.desc()).all()
    
    return jsonify({
        'iocs': [ioc.to_dict() for ioc in iocs],
        'count': len(iocs)
    })

@app.route('/api/incidents/<int:incident_id>/iocs/<int:ioc_id>', methods=['PUT', 'DELETE'])
@login_required
def api_incident_ioc_detail(incident_id, ioc_id):
    """Update or delete a specific IOC in incident"""
    incident = Incident.query.get_or_404(incident_id)
    incident_ioc = IncidentIOC.query.get_or_404(ioc_id)
    
    if incident_ioc.incident_id != incident_id:
        return jsonify({'error': 'IOC not in this incident'}), 404
    
    # Verify user is participant
    if current_user not in incident.participants:
        return jsonify({'error': 'Not a participant'}), 403
    
    if request.method == 'PUT':
        if not has_incident_write_access(current_user):
            return jsonify({'error': 'Read-only role cannot modify incident IOCs'}), 403
        data = request.get_json()
        if 'analyst_note' in data:
            incident_ioc.analyst_note = data.get('analyst_note', '').strip()
            incident_ioc.updated_at = datetime.utcnow()
            db.session.commit()

        if 'type' in data:
            new_type = data.get('type', '').strip().lower()
            if new_type and IOC.is_valid_type(new_type):
                incident_ioc.type = new_type
                incident_ioc.updated_at = datetime.utcnow()
                db.session.commit()
            else:
                return jsonify({'error': f'Invalid IOC type: {new_type}'}), 400
        
        return jsonify({'success': True, 'ioc': incident_ioc.to_dict()})
    
    elif request.method == 'DELETE':
        if not has_incident_write_access(current_user):
            return jsonify({'error': 'Read-only role cannot modify incident IOCs'}), 403
        db.session.delete(incident_ioc)
        db.session.commit()
        return jsonify({'success': True})

@app.route('/api/incidents/<int:incident_id>/search')
@login_required
def api_incident_search(incident_id):
    """Search IOCs within an incident"""
    incident = Incident.query.get_or_404(incident_id)
    
    if current_user not in incident.participants:
        return jsonify({'error': 'Not a participant'}), 403
    
    query = request.args.get('q', '').strip().lower()
    if not query or len(query) < 2:
        return jsonify({'iocs': []})
    
    iocs = IncidentIOC.query.filter_by(incident_id=incident_id).all()
    results = [
        ioc.to_dict() for ioc in iocs
        if query in ioc.value.lower() or query in (ioc.analyst_note or '').lower()
    ]
    
    return jsonify({'iocs': results, 'count': len(results)})

@app.route('/api/incidents/<int:incident_id>/relationships')
@login_required
def api_incident_relationships(incident_id):
    """Get related IOCs from main database for all IOCs in incident"""
    incident = Incident.query.get_or_404(incident_id)
    
    if current_user not in incident.participants:
        return jsonify({'error': 'Not a participant'}), 403
    
    relationships = []
    seen_pairs = set()
    for incident_ioc in incident.incident_iocs:
        matching_iocs = IOC.query.filter_by(type=incident_ioc.type, value=incident_ioc.value).all()
        for ioc in matching_iocs:
            if not ioc.note:
                continue

            # When incident is completed, skip relationships pointing to sources created from this incident
            if incident.status == 'completed' and ioc.tags and f"incident:{incident.id}" in ioc.tags:
                continue

            pair_key = (incident_ioc.id, ioc.note.id)
            if pair_key in seen_pairs:
                continue
            seen_pairs.add(pair_key)

            relationships.append({
                'incident_ioc_id': incident_ioc.id,
                'ioc_type': incident_ioc.type,
                'ioc_value': incident_ioc.value,
                'source_title': ioc.note.title,
                'source_id': ioc.note.id,
                'source_url': url_for('view_note', note_id=ioc.note.id),
                'tags': ioc.tags,
                'created_at': ioc.note.created_at.isoformat(),
                'match_type': 'exact'
            })
    
    return jsonify({'relationships': relationships})

@app.route('/incidents/<int:incident_id>/complete', methods=['POST'])
@login_required
def complete_incident(incident_id):
    """Complete incident and optionally convert IOCs to main database as a note"""
    incident = Incident.query.get_or_404(incident_id)
    
    if incident.created_by != current_user.id:
        flash('Only incident creator can complete it.', 'danger')
        return redirect(url_for('incident_canvas', incident_id=incident_id))
    
    create_note = request.form.get('create_note') == 'on'
    
    if create_note and incident.incident_iocs:
        # Create a note containing all IOCs from incident
        note = Note(
            title=f"[Incident Response] {incident.title}",
            content=incident.description or "",
            category=incident.category or "General",
            user_id=current_user.id,
            keep=False  # Allow deletion of converted sources
        )
        db.session.add(note)
        db.session.flush()  # Get the note ID
        
        # Add all IOCs to the note
        for incident_ioc in incident.incident_iocs:
            ioc = IOC(
                type=incident_ioc.type,
                value=incident_ioc.value,
                tags=f"incident:{incident.id},severity:{incident.severity}",
                note_id=note.id
            )
            db.session.add(ioc)
            incident_ioc.converted_to_ioc_id = ioc.id
        
        db.session.commit()
        flash(f'Incident converted to note with {len(incident.incident_iocs)} IOCs.', 'success')
    
    # Mark incident as completed
    incident.status = 'completed'
    incident.completed_at = datetime.utcnow()
    db.session.commit()

    record_audit('complete_incident', f'Completed incident "{incident.title}" (ID: {incident.id})')
    
    flash('Incident marked as completed.', 'success')
    return redirect(url_for('incidents_list', status='completed'))

@app.route('/incidents/<int:incident_id>/close', methods=['POST'])
@login_required
def close_incident(incident_id):
    """Close/archive an incident"""
    incident = Incident.query.get_or_404(incident_id)
    
    if incident.created_by != current_user.id:
        return jsonify({'error': 'Only incident creator can close it'}), 403
    
    if incident.status == 'active':
        incident.status = 'archived'
        incident.completed_at = datetime.utcnow()
        db.session.commit()
        record_audit('close_incident', f'Archived incident "{incident.title}" (ID: {incident.id})')
        return jsonify({'success': True, 'message': 'Incident archived'})
    
    return jsonify({'error': 'Incident is already closed'}), 400

@app.route('/api/incidents/<int:incident_id>', methods=['DELETE'])
@login_required
def api_delete_incident(incident_id):
    """Delete an incident"""
    incident = Incident.query.get_or_404(incident_id)
    
    if incident.created_by != current_user.id:
        return jsonify({'error': 'Only incident creator can delete it'}), 403
    
    # Delete all related data (cascade will handle some, but be explicit)
    IncidentIOC.query.filter_by(incident_id=incident_id).delete()
    IncidentNote.query.filter_by(incident_id=incident_id).delete()
    IncidentLink.query.filter_by(incident_id=incident_id).delete()
    
    # Remove incident from participant associations
    incident.participants.clear()
    
    # Delete the incident
    db.session.delete(incident)
    db.session.commit()
    record_audit('delete_incident', f'Deleted incident "{incident.title}" (ID: {incident.id})')
    
    return jsonify({'success': True, 'message': 'Incident deleted'})

@app.route('/api/incidents/<int:incident_id>/notes', methods=['GET', 'POST'])
@login_required
def api_incident_notes(incident_id):
    """Get or create incident notes"""
    incident = Incident.query.get_or_404(incident_id)
    
    if current_user not in incident.participants:
        return jsonify({'error': 'Not a participant'}), 403
    
    if request.method == 'POST':
        if not has_incident_write_access(current_user):
            return jsonify({'error': 'Read-only role cannot add notes to incidents'}), 403
        data = request.get_json()
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        priority = data.get('priority', 'normal')
        
        if not title or not content:
            return jsonify({'error': 'Title and content required'}), 400
        
        note = IncidentNote(
            incident_id=incident_id,
            title=title,
            content=content,
            priority=priority,
            created_by=current_user.id
        )
        db.session.add(note)
        db.session.commit()
        
        return jsonify({'success': True, 'note': note.to_dict()}), 201
    
    # GET: Return all notes
    notes = IncidentNote.query.filter_by(incident_id=incident_id).order_by(IncidentNote.created_at.desc()).all()
    return jsonify({'notes': [n.to_dict() for n in notes], 'count': len(notes)})

@app.route('/api/incidents/<int:incident_id>/notes/<int:note_id>', methods=['DELETE', 'PUT'])
@login_required
def api_incident_note_detail(incident_id, note_id):
    """Update or delete a note"""
    incident = Incident.query.get_or_404(incident_id)
    note = IncidentNote.query.get_or_404(note_id)
    
    if note.incident_id != incident_id:
        return jsonify({'error': 'Note not in this incident'}), 404
    
    if current_user not in incident.participants:
        return jsonify({'error': 'Not a participant'}), 403
    
    if request.method == 'DELETE':
        if not has_incident_write_access(current_user):
            return jsonify({'error': 'Read-only role cannot modify incident notes'}), 403
        if note.created_by != current_user.id and current_user.id != incident.created_by:
            return jsonify({'error': 'Can only delete own notes'}), 403
        
        db.session.delete(note)
        db.session.commit()
        return jsonify({'success': True})
    
    elif request.method == 'PUT':
        if not has_incident_write_access(current_user):
            return jsonify({'error': 'Read-only role cannot modify incident notes'}), 403
        data = request.get_json()
        if 'title' in data:
            note.title = data.get('title', '').strip()
        if 'content' in data:
            note.content = data.get('content', '').strip()
        if 'priority' in data:
            note.priority = data.get('priority', 'normal')
        
        note.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True, 'note': note.to_dict()})

@app.route('/api/incidents/<int:incident_id>/links', methods=['GET', 'POST'])
@login_required
def api_incident_links(incident_id):
    """Get or add incident links"""
    incident = Incident.query.get_or_404(incident_id)
    
    if current_user not in incident.participants:
        return jsonify({'error': 'Not a participant'}), 403
    
    if request.method == 'POST':
        if not has_incident_write_access(current_user):
            return jsonify({'error': 'Read-only role cannot add links to incidents'}), 403
        data = request.get_json()
        title = data.get('title', '').strip()
        url = data.get('url', '').strip()
        link_type = data.get('link_type', 'reference')
        
        if not title or not url:
            return jsonify({'error': 'Title and URL required'}), 400
        
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        link = IncidentLink(
            incident_id=incident_id,
            title=title,
            url=url,
            link_type=link_type,
            created_by=current_user.id
        )
        db.session.add(link)
        db.session.commit()
        
        return jsonify({'success': True, 'link': link.to_dict()}), 201
    
    # GET: Return all links
    links = IncidentLink.query.filter_by(incident_id=incident_id).order_by(IncidentLink.created_at.desc()).all()
    return jsonify({'links': [l.to_dict() for l in links], 'count': len(links)})

@app.route('/api/incidents/<int:incident_id>/links/<int:link_id>', methods=['DELETE'])
@login_required
def api_incident_link_detail(incident_id, link_id):
    """Delete a link"""
    incident = Incident.query.get_or_404(incident_id)
    link = IncidentLink.query.get_or_404(link_id)
    
    if link.incident_id != incident_id:
        return jsonify({'error': 'Link not in this incident'}), 404
    
    if current_user not in incident.participants:
        return jsonify({'error': 'Not a participant'}), 403
    
    if not has_incident_write_access(current_user):
        return jsonify({'error': 'Read-only role cannot modify incident links'}), 403

    if link.created_by != current_user.id and current_user.id != incident.created_by:
        return jsonify({'error': 'Can only delete own links'}), 403
    
    db.session.delete(link)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/incidents/<int:incident_id>/invite')
@login_required
def incident_invite(incident_id):
    """Get invite code/link for incident"""
    incident = Incident.query.get_or_404(incident_id)
    
    if incident.created_by != current_user.id:
        return jsonify({'error': 'Only creator can invite'}), 403
    
    return jsonify({
        'incident_id': incident.id,
        'incident_title': incident.title,
        'invite_url': url_for('incident_canvas', incident_id=incident.id, _external=True),
        'current_participants': len(incident.participants)
    }) 