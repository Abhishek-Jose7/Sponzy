from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
from werkzeug.utils import secure_filename
from sqlalchemy import or_, case
from sqlalchemy.sql import func
from sqlalchemy.exc import SQLAlchemyError
import locale
from flask_socketio import SocketIO, emit, join_room
import json
import humanize 
from functools import wraps
from collections import defaultdict
import time
import logging
from logging.handlers import RotatingFileHandler
import re
from flask_wtf.csrf import CSRFProtect
from flask_mail import Mail, Message
from flask_caching import Cache
from flask_session import Session
from PIL import Image
import bleach
import markdown
from markupsafe import Markup
from config import Config
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, TextAreaField, FloatField, DateField, EmailField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Email, Length, NumberRange
from itsdangerous import URLSafeTimedSerializer
import pyotp
from flask_paginate import Pagination
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import uuid
import random

# Initialize URL safe serializer for tokens
ts = URLSafeTimedSerializer(os.environ.get('SECRET_KEY', 'your-secret-key'))

# Create Flask app with optimized configuration
app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
csrf = CSRFProtect(app)
socketio = SocketIO(app)
mail = Mail(app)
cache = Cache(app)

# Initialize rate limiter
limiter = Limiter(key_func=get_remote_address)
limiter.init_app(app)

# Set up session handling
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

# Configure logging
log_level = getattr(logging, app.config.get('LOG_LEVEL', 'INFO'))
log_format = app.config.get('LOG_FORMAT', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log_file = app.config.get('LOG_FILE', 'sponsify.log')
log_max_bytes = app.config.get('LOG_MAX_BYTES', 10 * 1024 * 1024)  # 10MB
log_backup_count = app.config.get('LOG_BACKUP_COUNT', 5)

handler = RotatingFileHandler(log_file, maxBytes=log_max_bytes, backupCount=log_backup_count)
handler.setFormatter(logging.Formatter(log_format))
app.logger.addHandler(handler)
app.logger.setLevel(log_level)

if app.config.get('LOG_TO_STDOUT'):
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter(log_format))
    app.logger.addHandler(stream_handler)

logger = app.logger

# Configure file uploads
UPLOAD_FOLDER = app.config.get('UPLOAD_FOLDER', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads'))
ALLOWED_EXTENSIONS = app.config.get('ALLOWED_EXTENSIONS', {'pdf', 'png', 'jpg', 'jpeg', 'gif'})
MAX_CONTENT_LENGTH = app.config.get('MAX_CONTENT_LENGTH', 5 * 1024 * 1024)  # 5MB max file size

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure the upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Request logging middleware
@app.before_request
def log_request_info():
    if not request.path.startswith('/static'):
        logger.debug(f'Request: {request.method} {request.path}')
        logger.debug(f'Headers: {request.headers}')
        if request.is_json:
            logger.debug(f'Body: {request.get_json()}')

# Initialize Mail
def send_email(to, subject, body):
    """Send an email using Flask-Mail."""
    try:
        msg = Message(
            subject,
            sender=app.config.get('MAIL_DEFAULT_SENDER', 'noreply@sponsify.com'),
            recipients=[to]
        )
        msg.body = body
        mail.send(msg)
    except Exception as e:
        logger.error(f"Error sending email: {e}")
        raise

def admin_required(f):
    """Decorator to require admin role for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You need to be an admin to access this page.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Load configuration based on environment
if os.environ.get('FLASK_ENV') == 'production':
    app.config.from_object('config.ProductionConfig')
elif os.environ.get('FLASK_ENV') == 'testing':
    app.config.from_object('config.TestingConfig')
else:
    app.config.from_object('config.DevelopmentConfig')

# Fallback configuration if config module is not available
app.config.setdefault('SECRET_KEY', os.environ.get('SECRET_KEY', 'your-secret-key'))
app.config.setdefault('SQLALCHEMY_DATABASE_URI', os.environ.get('DATABASE_URL', 'sqlite:///sponsify.db'))
app.config.setdefault('UPLOAD_FOLDER', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/uploads'))
app.config.setdefault('ALLOWED_EXTENSIONS', {'png', 'jpg', 'jpeg', 'gif'})
app.config.setdefault('SQLALCHEMY_TRACK_MODIFICATIONS', False)
app.config.setdefault('MAX_CONTENT_LENGTH', 16 * 1024 * 1024)  # 16MB max upload size
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['SECURITY_PASSWORD_SALT'] = os.environ.get('SECURITY_PASSWORD_SALT', 'your-salt-here')

# Set locale for number formatting
try:
    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
except:
    try:
        locale.setlocale(locale.LC_ALL, 'en_US')
    except:
        locale.setlocale(locale.LC_ALL, '')

# Enhanced number formatting filters
@app.template_filter('number_format')
def number_format(value, decimals=2, currency=None):
    try:
        num = float(value)
        if currency:
            return locale.currency(num, grouping=True, symbol=currency)
        return locale.format_string(f"%.{decimals}f", num, grouping=True)
    except (ValueError, TypeError):
        return "0.00"

@app.template_filter('percentage')
def percentage(value, decimals=1):
    try:
        num = float(value)
        return f"{num:.{decimals}%}"
    except (ValueError, TypeError):
        return "0.0%"

@app.template_filter('scientific')
def scientific(value, decimals=2):
    try:
        num = float(value)
        return f"{num:.{decimals}e}"
    except (ValueError, TypeError):
        return "0.00e+00"

@app.template_filter('compact')
def compact(value):
    try:
        num = float(value)
        if num >= 1_000_000_000:
            return f"{num/1_000_000_000:.1f}B"
        elif num >= 1_000_000:
            return f"{num/1_000_000:.1f}M"
        elif num >= 1_000:
            return f"{num/1_000:.1f}K"
        return f"{num:.0f}"
    except (ValueError, TypeError):
        return "0"

@app.template_filter('ordinal')
def ordinal(value):
    try:
        num = int(value)
        suffix = ['th', 'st', 'nd', 'rd']
        v = num % 100
        return f"{num}{suffix[0 if v > 3 else v]}"
    except (ValueError, TypeError):
        return "0th"

# Add date formatting filter
@app.template_filter('date')
def date_filter(value, format='%B %d, %Y'):
    """Format a date using the specified format."""
    if value is None:
        return ""
    try:
        if isinstance(value, str):
            # Try different date formats
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y']:
                try:
                    value = datetime.strptime(value, fmt)
                    break
                except ValueError:
                    continue
        
        # If it's still a string, it means we couldn't parse it
        if isinstance(value, str):
            return value
            
        return value.strftime(format)
    except Exception as e:
        logger.error(f"Error formatting date: {e}")
        return str(value)

@app.template_filter('timeago')
def timeago_filter(value):
    """Format a date as a time ago string (e.g., "3 hours ago")."""
    if value is None:
        return ""
    try:
        if isinstance(value, str):
            # Try different date formats
            for fmt in ['%Y-%m-%d %H:%M:%S', '%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y']:
                try:
                    value = datetime.strptime(value, fmt)
                    break
                except ValueError:
                    continue
        
        # If it's still a string, it means we couldn't parse it
        if isinstance(value, str):
            return value
            
        now = datetime.utcnow()
        delta = now - value
        
        if delta.days > 365:
            years = delta.days // 365
            return f"{years} year{'s' if years != 1 else ''} ago"
        elif delta.days > 30:
            months = delta.days // 30
            return f"{months} month{'s' if months != 1 else ''} ago"
        elif delta.days > 0:
            return f"{delta.days} day{'s' if delta.days != 1 else ''} ago"
        elif delta.seconds > 3600:
            hours = delta.seconds // 3600
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        elif delta.seconds > 60:
            minutes = delta.seconds // 60
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        else:
            return "just now"
    except Exception as e:
        logger.error(f"Error formatting timeago: {e}")
        return str(value)

def send_notification(user_id, title, message, type='system', link=None):
    """
    Create a notification for a user.
    
    Args:
        user_id (int): The ID of the user to notify
        title (str): The notification title
        message (str): The notification message
        type (str): The type of notification (system, message, sponsorship, event)
        link (str, optional): A link associated with the notification
    """
    try:
        notification = Notification(
            user_id=user_id,
            title=title,
            message=message,
            type=type,
            link=link,
            is_read=False
        )
        db.session.add(notification)
        db.session.commit()
        
        # Emit notification to user's room if they're connected via WebSocket
        room = f"user_{user_id}"
        socketio.emit('notification', {
            'id': notification.id,
            'title': notification.title,
            'message': notification.message,
            'type': notification.type,
            'link': notification.link,
            'created_at': notification.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }, room=room)
        
    except Exception as e:
        logger.error(f"Error sending notification: {e}")
        db.session.rollback()

# WebSocket events
@socketio.on('connect')
def handle_connect():
    logger.debug("Client connected")

@socketio.on('disconnect')
def handle_disconnect():
    logger.debug("Client disconnected")

@socketio.on('join_event')
def handle_join_event(data):
    try:
        event_id = data['event_id']
        join_room(f"event_{event_id}")
        logger.debug(f"User joined room for event {event_id}")
    except Exception as e:
        logger.error(f"Error in join_event: {e}")
        emit('error', {'message': 'Could not join event room', 'type': 'join_error'})

@socketio.on('funding_update')
def handle_funding_update(data):
    try:
        event_id = data['event_id']
        amount = data['amount']
        event = Event.query.get(event_id)
        if event:
            event.current_funding += float(amount)
            db.session.commit()
            emit('funding_updated', {
                'event_id': event_id,
                'current_funding': event.current_funding,
                'percent': (event.current_funding / event.funding_goal) * 100
            }, room=f"event_{event_id}")
    except Exception as e:
        logger.error(f"Error in funding_update: {e}")
        emit('error', {'message': 'Could not update funding', 'type': 'funding_error'})

# Database Models
class TeamMember(db.Model):
    """Model for organization team members."""
    __tablename__ = 'team_member'
    
    id = db.Column(db.Integer, primary_key=True)
    organization_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    bio = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    organization = db.relationship('User', backref='organization_team_members')

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    applicant_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    event = db.relationship('Event', backref='applications')

class SavedSponsorship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    event = db.relationship('Event', backref='saved_by')

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    
    # Add indexes for frequently queried fields
    __table_args__ = (
        db.Index('idx_user_email', 'email'),
        db.Index('idx_user_username', 'username'),
        db.Index('idx_user_role', 'role'),
        db.Index('idx_user_rating', 'rating'),
        db.Index('idx_user_created_at', 'created_at'),
        db.Index('idx_user_location', 'location'),
        db.Index('idx_user_industry', 'industry'),
        db.Index('idx_user_verification_status', 'verification_status'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False)  # 'seeker', 'sponsor', 'admin'
    seeker_type = db.Column(db.String(20))  # 'individual' or 'organization'
    location = db.Column(db.String(100))
    bio = db.Column(db.Text)
    profile_picture = db.Column(db.String(200))
    website = db.Column(db.String(200))
    social_links = db.Column(db.JSON)
    
    # Individual seeker fields
    first_name = db.Column(db.String(50))
    last_name = db.Column(db.String(50))
    skills = db.Column(db.JSON)  # List of skills
    achievements = db.Column(db.Text)
    resume_url = db.Column(db.String(200))
    portfolio_url = db.Column(db.String(200))
    
    # Organization seeker fields
    organization_name = db.Column(db.String(100))
    organization_type = db.Column(db.String(50))
    sector = db.Column(db.String(50))
    mission_statement = db.Column(db.Text)
    founding_date = db.Column(db.Date)
    team_members_info = db.Column(db.JSON)
    verification_documents = db.Column(db.JSON)
    verification_status = db.Column(db.String(20), default='pending')
    verification_notes = db.Column(db.Text)
    verification_submitted_at = db.Column(db.DateTime)
    verification_processed_at = db.Column(db.DateTime)
    verified_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    
    # Sponsor fields
    company_name = db.Column(db.String(100))
    industry = db.Column(db.String(50))
    sponsorship_budget = db.Column(db.Float)
    sponsorship_goals = db.Column(db.Text)
    preferred_categories = db.Column(db.JSON)
    target_audience = db.Column(db.JSON)
    sponsorship_history = db.Column(db.JSON)
    success_metrics = db.Column(db.JSON)
    active_sponsorships_count = db.Column(db.Integer, default=0)
    total_sponsored_amount = db.Column(db.Float, default=0.0)
    avg_sponsorship_amount = db.Column(db.Float, default=0.0)
    response_time = db.Column(db.Integer)  # in hours
    geographical_focus = db.Column(db.JSON)
    sponsorship_frequency = db.Column(db.String(20))
    min_sponsorship_amount = db.Column(db.Float)
    max_sponsorship_amount = db.Column(db.Float)
    preferred_duration = db.Column(db.String(20))
    impact_metrics = db.Column(db.JSON)
    sustainability_focus = db.Column(db.Boolean, default=False)
    diversity_focus = db.Column(db.Boolean, default=False)
    innovation_focus = db.Column(db.Boolean, default=False)
    accepts_remote = db.Column(db.Boolean, default=False)
    
    # Common fields
    rating = db.Column(db.Float, default=0.0)
    rating_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # New security fields
    email_verified = db.Column(db.Boolean, default=False)
    email_verification_sent_at = db.Column(db.DateTime)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    two_factor_secret = db.Column(db.String(32))
    account_locked = db.Column(db.Boolean, default=False)
    login_attempts = db.Column(db.Integer, default=0)
    last_login_attempt = db.Column(db.DateTime)
    password_changed_at = db.Column(db.DateTime)
    require_password_change = db.Column(db.Boolean, default=False)
    
    # Relationships
    events = db.relationship('Event', backref='organizer', lazy=True)
    ratings_given = db.relationship('Rating', foreign_keys='Rating.rater_id', backref='rater', lazy=True)
    ratings_received = db.relationship('Rating', foreign_keys='Rating.rated_id', backref='rated', lazy=True)
    applications = db.relationship('Application', backref='applicant', lazy=True)
    saved_sponsorships = db.relationship('SavedSponsorship', backref='user', lazy=True)
    verified_by = db.relationship('User', remote_side=[id])
    
    @property
    def is_organizer(self):
        return self.role == 'seeker'
    
    @property
    def is_sponsor(self):
        return self.role == 'sponsor'
    
    @property
    def is_individual_seeker(self):
        return self.role == 'seeker' and self.seeker_type == 'individual'
    
    @property
    def is_organization_seeker(self):
        return self.role == 'seeker' and self.seeker_type == 'organization'
    
    def get_active_sponsorships(self):
        return Sponsorship.query.filter_by(
            sponsor_id=self.id, 
            status='approved'
        ).order_by(Sponsorship.created_at.desc()).all()
    
    def get_pending_sponsorships(self):
        return Sponsorship.query.filter_by(
            sponsor_id=self.id, 
            status='pending'
        ).order_by(Sponsorship.created_at.desc()).all()
    
    def get_total_sponsored_amount(self):
        result = db.session.query(func.sum(Sponsorship.amount)).filter(
            Sponsorship.sponsor_id == self.id,
            Sponsorship.status == 'approved'
        ).scalar()
        return result or 0
    
    def can_sponsor_event(self, event):
        if event.organizer_id == self.id:
            return False
        if self.role != 'sponsor':
            return False
        return True

    # Security methods
    def lock_account(self):
        self.account_locked = True
        self.login_attempts = 0
        db.session.commit()
    
    def unlock_account(self):
        self.account_locked = False
        self.login_attempts = 0
        db.session.commit()
    
    def increment_login_attempts(self):
        self.login_attempts += 1
        self.last_login_attempt = datetime.utcnow()
        if self.login_attempts >= 5:
            self.lock_account()
        db.session.commit()
    
    def reset_login_attempts(self):
        self.login_attempts = 0
        db.session.commit()
    
    def generate_email_token(self):
        return ts.dumps(self.email, salt='email-verify-key')
    
    def verify_email_token(self, token, expiration=3600):
        try:
            email = ts.loads(token, salt='email-verify-key', max_age=expiration)
            if email == self.email:
                self.email_verified = True
                db.session.commit()
                return True
        except:
            return False
        return False
    
    def enable_two_factor(self):
        if not self.two_factor_secret:
            self.two_factor_secret = pyotp.random_base32()
        self.two_factor_enabled = True
        db.session.commit()
        return self.two_factor_secret
    
    def verify_two_factor(self, token):
        if not self.two_factor_enabled:
            return True
        totp = pyotp.TOTP(self.two_factor_secret)
        return totp.verify(token)
    
    def get_two_factor_uri(self):
        if self.two_factor_secret:
            totp = pyotp.TOTP(self.two_factor_secret)
            return totp.provisioning_uri(self.email, issuer_name='Sponsify')
        return None

    # New method to calculate sponsor match score
    @cache.memoize(timeout=300)
    def calculate_match_score(self, event):
        """Calculate a match score between a sponsor and an event."""
        score = 0
        
        # Category match (25 points max)
        if self.preferred_categories and event.category in self.preferred_categories:
            score += 25
        
        # Budget match (20 points max)
        if self.min_sponsorship_amount and self.max_sponsorship_amount:
            if self.min_sponsorship_amount <= event.funding_goal <= self.max_sponsorship_amount:
                score += 20
        
        # Location match (15 points max)
        if self.geographical_focus and event.location in self.geographical_focus:
            score += 15
        elif self.accepts_remote and event.remote_participation:
            score += 10
        
        # Focus areas (10 points max)
        focus_matches = []
        if self.sustainability_focus and event.sustainability_focus:
            focus_matches.append("sustainability")
        if self.diversity_focus and event.diversity_focus:
            focus_matches.append("diversity")
        if self.innovation_focus and event.innovation_focus:
            focus_matches.append("innovation")
        
        if focus_matches:
            points = min(len(focus_matches) * 5, 10)
            score += points
        
        # Success rate (10 points max)
        if self.success_metrics:
            success_rate = float(self.success_metrics.get('success_rate', 0))
            total_sponsorships = int(self.success_metrics.get('total_sponsorships', 0))
            if success_rate >= 0.8 and total_sponsorships >= 5:
                score += 10
            elif success_rate >= 0.6 and total_sponsorships >= 3:
                score += 5
        
        # Response time (5 points max)
        if self.response_time:
            if self.response_time < 24:
                score += 5
            elif self.response_time < 48:
                score += 3
        
        # Experience (5 points max)
        if self.active_sponsorships_count is not None:
            if self.active_sponsorships_count < 5:
                score += 5
            elif self.active_sponsorships_count < 10:
                score += 3
        
        # Rating (10 points max)
        if self.rating and self.rating_count and self.rating_count >= 3:
            rating_score = min(self.rating * 2, 10)
            score += rating_score
        
        return score

    def to_dict(self):
        """Convert user object to dictionary for JSON serialization."""
        data = {
            'id': self.id,
            'username': self.username,
            'role': self.role,
            'profile_picture': self.profile_picture,
            'location': self.location,
            'rating': self.rating,
            'rating_count': self.rating_count
        }
        
        if self.role == 'seeker':
            if self.seeker_type == 'organization':
                data.update({
                    'name': self.organization_name,
                    'type': 'organization',
                    'sector': self.sector,
                    'mission_statement': self.mission_statement
                })
            else:
                data.update({
                    'name': f"{self.first_name} {self.last_name}",
                    'type': 'individual',
                    'skills': self.skills
                })
        else:
            data.update({
                'name': self.company_name,
                'industry': self.industry,
                'focus_areas': {
                    'sustainability': self.sustainability_focus,
                    'diversity': self.diversity_focus,
                    'innovation': self.innovation_focus
                }
            })
        
        return data

    @property
    def is_admin(self):
        """Check if the user has admin role."""
        return self.role == 'admin'

class Event(db.Model):
    __tablename__ = 'event'
    
    # Add indexes for frequently queried fields
    __table_args__ = (
        db.Index('idx_event_status', 'status'),
        db.Index('idx_event_category', 'category'),
        db.Index('idx_event_date', 'date'),
        db.Index('idx_event_created_at', 'created_at'),
        db.Index('idx_event_organizer', 'organizer_id'),
        db.Index('idx_event_funding', 'current_funding', 'funding_goal'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, nullable=False)
    short_description = db.Column(db.String(255), default='')
    date = db.Column(db.DateTime, nullable=False)
    location = db.Column(db.String(120), nullable=False)
    funding_goal = db.Column(db.Float, nullable=False)
    current_funding = db.Column(db.Float, default=0.0)
    organizer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='active')  # active, completed, cancelled
    category = db.Column(db.String(50), default='Education')
    is_featured = db.Column(db.Boolean, default=False)
    is_verified = db.Column(db.Boolean, default=False)
    featured_image = db.Column(db.String(255), default='')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime, nullable=True)
    sustainability_focus = db.Column(db.Boolean, default=False)
    diversity_focus = db.Column(db.Boolean, default=False)
    innovation_focus = db.Column(db.Boolean, default=False)
    remote_participation = db.Column(db.Boolean, default=False)
    sponsorships = db.relationship('Sponsorship', backref='event', lazy=True)

    def to_dict(self):
        """Convert event object to dictionary for JSON serialization."""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'short_description': self.short_description,
            'date': self.date.isoformat(),
            'location': self.location,
            'funding_goal': self.funding_goal,
            'current_funding': self.current_funding,
            'category': self.category,
            'featured_image': self.featured_image,
            'organizer': self.organizer.to_dict(),
            'status': self.status,
            'created_at': self.created_at.isoformat(),
            'focus_areas': {
                'sustainability': self.sustainability_focus,
                'diversity': self.diversity_focus,
                'innovation': self.innovation_focus,
                'remote': self.remote_participation
            }
        }

class Sponsorship(db.Model):
    __tablename__ = 'sponsorship'
    
    # Add indexes for frequently queried fields
    __table_args__ = (
        db.Index('idx_sponsorship_status', 'status'),
        db.Index('idx_sponsorship_created_at', 'created_at'),
        db.Index('idx_sponsorship_sponsor', 'sponsor_id'),
        db.Index('idx_sponsorship_event', 'event_id'),
        db.Index('idx_sponsorship_amount', 'amount'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey('event.id'), nullable=False)
    sponsor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, approved, rejected
    message = db.Column(db.Text)
    is_anonymous = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    sponsor = db.relationship('User', backref='sponsorships')
    
    def approve(self):
        if self.status != 'pending':
            raise ValueError("Only pending sponsorships can be approved")
        
        self.status = 'approved'
        
        # Update event's current funding
        self.event.current_funding += self.amount
        db.session.commit()
        
    def reject(self):
        if self.status != 'pending':
            raise ValueError("Only pending sponsorships can be rejected")
        
        self.status = 'rejected'
        db.session.commit()
        
    def cancel(self):
        # Only pending or approved sponsorships can be cancelled
        if self.status not in ['pending', 'approved']:
            raise ValueError("This sponsorship cannot be cancelled")
        
        # If the sponsorship was approved, reduce the event's funding
        if self.status == 'approved':
            self.event.current_funding -= self.amount
        
        self.status = 'cancelled'
        db.session.commit()

class Rating(db.Model):
    __tablename__ = 'rating'
    
    # Add composite index for user ratings
    __table_args__ = (
        db.Index('idx_rating_users', 'rater_id', 'rated_id'),
        db.Index('idx_rating_created', 'created_at'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    rater_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rated_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)  # 1-5 stars
    comment = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class ChatMessage(db.Model):
    __tablename__ = 'chat_message'
    
    # Add indexes for chat queries
    __table_args__ = (
        db.Index('idx_chat_users', 'sender_id', 'recipient_id'),
        db.Index('idx_chat_created', 'created_at'),
        db.Index('idx_chat_read', 'read'),
    )
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    
    # Relationships
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    recipient = db.relationship('User', foreign_keys=[recipient_id], backref='received_messages')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    type = db.Column(db.String(50), nullable=False)
    link = db.Column(db.String(255))
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='notifications')

class BlogPost(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(120), nullable=False)
    slug = db.Column(db.String(120), nullable=False, unique=True)
    content = db.Column(db.Text, nullable=False)
    excerpt = db.Column(db.String(255))
    featured_image = db.Column(db.String(255))
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    author = db.relationship('User', backref='blog_posts')

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    text = db.Column(db.Text, nullable=False)
    rating = db.Column(db.Integer)
    category = db.Column(db.String(50))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User', backref='feedback')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    """Home page route with different views based on user status."""
    if not current_user.is_authenticated:
        # For new users - show landing page
        return render_template('landing.html')
    elif current_user.role == 'seeker':
        # For seekers - show available sponsors
        page = request.args.get('page', 1, type=int)
        per_page = 12
        
        # Get filter parameters
        industries = request.args.getlist('industry')
        budget = request.args.get('budget')
        location = request.args.get('location')
        rating = request.args.get('rating', type=int)
        query = request.args.get('q', '')
        
        # Build query for sponsors
        sponsors_query = User.query.filter_by(role='sponsor')
        
        if industries:
            sponsors_query = sponsors_query.filter(User.industry.in_(industries))
        if location:
            sponsors_query = sponsors_query.filter(User.location.ilike(f'%{location}%'))
        if query:
            sponsors_query = sponsors_query.filter(
                db.or_(
                    User.company_name.ilike(f'%{query}%'),
                    User.sponsorship_goals.ilike(f'%{query}%')
                )
            )
        
        # Apply budget filter
        if budget:
            if budget == '0-5000':
                sponsors_query = sponsors_query.filter(User.sponsorship_budget <= 5000)
            elif budget == '5000-10000':
                sponsors_query = sponsors_query.filter(
                    User.sponsorship_budget > 5000,
                    User.sponsorship_budget <= 10000
                )
            elif budget == '10000-50000':
                sponsors_query = sponsors_query.filter(
                    User.sponsorship_budget > 10000,
                    User.sponsorship_budget <= 50000
                )
            elif budget == '50000+':
                sponsors_query = sponsors_query.filter(User.sponsorship_budget > 50000)
        
        # Apply rating filter
        if rating:
            sponsors_query = sponsors_query.filter(User.rating >= rating)
        
        # Get paginated results
        pagination = sponsors_query.paginate(page=page, per_page=per_page, error_out=False)
        sponsors = pagination.items
        
        return render_template('seeker_home.html', sponsors=sponsors, pagination=pagination)
    else:
        # For sponsors - show relevant events
        page = request.args.get('page', 1, type=int)
        per_page = 10
        
        # Get filter parameters
        categories = request.args.getlist('category')
        status = request.args.getlist('status')
        date_range = request.args.get('date_range')
        query = request.args.get('q', '')
        
        # Build query for events
        events_query = Event.query.filter(
            Event.status == 'active',
            Event.organizer_id != current_user.id
        )
        
        if categories:
            events_query = events_query.filter(Event.category.in_(categories))
        if status:
            if 'open' in status:
                events_query = events_query.filter(Event.current_funding < Event.funding_goal)
            if 'funded' in status:
                events_query = events_query.filter(Event.current_funding >= Event.funding_goal)
        if query:
            events_query = events_query.filter(
                db.or_(
                    Event.title.ilike(f'%{query}%'),
                    Event.description.ilike(f'%{query}%')
                )
            )
        
        # Apply date range filter
        if date_range:
            now = datetime.utcnow()
            if date_range == 'week':
                events_query = events_query.filter(Event.date <= now + timedelta(days=7))
            elif date_range == 'month':
                events_query = events_query.filter(Event.date <= now + timedelta(days=30))
            elif date_range == 'quarter':
                events_query = events_query.filter(Event.date <= now + timedelta(days=90))
            elif date_range == 'year':
                events_query = events_query.filter(Event.date <= now + timedelta(days=365))
        
        # Get paginated results
        pagination = events_query.order_by(Event.date.desc()).paginate(page=page, per_page=per_page, error_out=False)
        events = pagination.items
        
        return render_template('sponsor_home.html', events=events, pagination=pagination)

@app.route('/events')
def events():
    """Events listing page."""
    # Get event categories for dropdown
    categories = get_event_categories()
    # Create category objects with id and name
    categories = [{"id": cat, "name": cat} for cat in categories]
    
    # For locations dropdown, get all unique locations
    locations = db.session.query(Event.location).distinct().all()
    locations = [loc[0] for loc in locations if loc[0]]
    
    # Get all events with pagination
    page = request.args.get('page', 1, type=int)
    per_page = 12
    
    # Base query
    events_query = Event.query.filter_by(status='active')
    
    # Apply filters
    if request.args.get('q'):
        search_term = f"%{request.args.get('q')}%"
        events_query = events_query.filter(
            db.or_(
                Event.title.ilike(search_term),
                Event.description.ilike(search_term)
            )
        )
    
    if request.args.get('category'):
        events_query = events_query.filter(Event.category == request.args.get('category'))
    
    if request.args.get('location'):
        events_query = events_query.filter(Event.location == request.args.get('location'))
    
    if request.args.get('date'):
        today = datetime.utcnow().date()
        if request.args.get('date') == 'upcoming':
            events_query = events_query.filter(Event.date >= today)
        elif request.args.get('date') == 'this_month':
            end_of_month = (today.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
            events_query = events_query.filter(Event.date >= today, Event.date <= end_of_month)
        elif request.args.get('date') == 'next_month':
            start_of_next_month = (today.replace(day=28) + timedelta(days=4)).replace(day=1)
            end_of_next_month = (start_of_next_month.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
            events_query = events_query.filter(Event.date >= start_of_next_month, Event.date <= end_of_next_month)
    
    # Get paginated results
    pagination = events_query.order_by(Event.date.desc()).paginate(page=page, per_page=per_page, error_out=False)
    events = pagination.items
    
    return render_template('events.html', events=events, categories=categories, 
                          locations=locations, pagination=pagination)

@app.route('/categories')
def categories():
    """Categories listing page."""
    return render_template('categories.html')

@app.route('/how-it-works')
def how_it_works():
    """How it works page."""
    return render_template('how_it_works.html')

@app.route('/search')
def search():
    """Search results page."""
    return render_template('search.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = bool(request.form.get('remember'))
        
        # Log login attempt
        logger.info(f"Login attempt for email: {email}")
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            logger.info(f"User found: {user.username}, role: {user.role}, seeker_type: {user.seeker_type}")
            
            if user.account_locked:
                logger.warning(f"Login attempt for locked account: {email}")
                flash('Your account is locked. Please contact support.', 'error')
                return redirect(url_for('login'))
            
            if check_password_hash(user.password_hash, password):
                login_user(user, remember=remember)
                logger.info(f"User logged in successfully: {user.username}")
                
                # Reset login attempts on successful login
                user.reset_login_attempts()
                db.session.commit()
                
                # Redirect based on user role
                if user.role == 'seeker':
                    if user.seeker_type == 'individual':
                        return redirect(url_for('individual_dashboard'))
                    else:  # organization
                        return redirect(url_for('organization_dashboard'))
                elif user.role == 'sponsor':
                    return redirect(url_for('sponsor_dashboard'))
                
                return redirect(url_for('dashboard'))
            else:
                # Increment login attempts
                user.increment_login_attempts()
                db.session.commit()
                logger.warning(f"Invalid password for user: {email}")
                flash('Invalid email or password', 'error')
        else:
            logger.warning(f"Login attempt with non-existent email: {email}")
            flash('Invalid email or password', 'error')
    
    return render_template('login.html')

@app.route('/choose-role')
def choose_role():
    """Role selection page."""
    return render_template('choose_role.html')

class SignupForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=80)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    role = SelectField('Role', choices=[('seeker', 'Seeker'), ('sponsor', 'Sponsor')], validators=[DataRequired()])
    
    # Seeker type field (only for seekers)
    seeker_type = SelectField('Seeker Type', choices=[('individual', 'Individual'), ('organization', 'Organization/Institution')])
    
    # Common fields for both seeker types
    location = StringField('Location')
    bio = TextAreaField('Bio')
    website = StringField('Website')
    
    # Individual seeker fields
    first_name = StringField('First Name')
    last_name = StringField('Last Name')
    skills = StringField('Skills (comma separated)')
    achievements = TextAreaField('Achievements')
    resume_url = StringField('Resume URL')
    portfolio_url = StringField('Portfolio URL')
    
    # Organization seeker fields
    organization_name = StringField('Organization Name')
    organization_type = SelectField('Organization Type', choices=[
        ('educational', 'Educational Institution'),
        ('non_profit', 'Non-Profit Organization'),
        ('research', 'Research Institution'),
        ('community', 'Community Organization'),
        ('other', 'Other')
    ])
    sector = StringField('Sector')
    mission_statement = TextAreaField('Mission Statement')
    founding_date = DateField('Founding Date')
    
    # Sponsor fields
    company_name = StringField('Company Name')
    industry = StringField('Industry')
    sponsorship_budget = FloatField('Sponsorship Budget')
    sponsorship_goals = TextAreaField('Sponsorship Goals')

    def validate(self, extra_validators=None):
        """Validate the form."""
        if not super().validate():
            return False
            
        if self.role.data == 'seeker':
            if self.seeker_type.data == 'individual':
                if not self.first_name.data or not self.last_name.data:
                    self.first_name.errors.append('Required for individual seekers')
                    return False
            elif self.seeker_type.data == 'organization':
                if not self.organization_name.data or not self.organization_type.data:
                    self.organization_name.errors.append('Required for organization seekers')
                    return False
        elif self.role.data == 'sponsor':
            if not self.company_name.data or not self.industry.data:
                self.company_name.errors.append('Required for sponsors')
                return False
                
        return True

class CreateEventForm(FlaskForm):
    title = StringField('Event Title', validators=[DataRequired(), Length(min=3, max=120)])
    description = TextAreaField('Event Description', validators=[DataRequired()])
    short_description = StringField('Short Description', validators=[Length(max=255)])
    date = DateField('Event Date', validators=[DataRequired()])
    time = StringField('Event Time', validators=[DataRequired()])
    location = StringField('Location', validators=[DataRequired()])
    funding_goal = FloatField('Funding Goal', validators=[DataRequired(), NumberRange(min=0)])
    category = SelectField('Category', choices=[
        ('Education', 'Education'),
        ('Technology', 'Technology'),
        ('Science', 'Science'),
        ('Arts', 'Arts'),
        ('Sports', 'Sports'),
        ('Culture', 'Culture'),
        ('Environment', 'Environment'),
        ('Health', 'Health'),
        ('Innovation', 'Innovation'),
        ('Research', 'Research'),
        ('Community', 'Community'),
        ('Professional Development', 'Professional Development'),
        ('Hackathon', 'Hackathon'),
        ('Startup Event', 'Startup Event'),
        ('College Festival', 'College Festival'),
        ('Tech Conference', 'Tech Conference'),
        ('Workshop', 'Workshop'),
        ('Career Fair', 'Career Fair'),
        ('Networking Event', 'Networking Event'),
        ('Case Competition', 'Case Competition')
    ], validators=[DataRequired()])
    
    # Additional fields for event focus
    sustainability_focus = BooleanField('Sustainability Focus')
    diversity_focus = BooleanField('Diversity Focus')
    innovation_focus = BooleanField('Innovation Focus')
    remote_participation = BooleanField('Remote Participation Available')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Handle user signup with proper error handling."""
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    form = SignupForm()
    
    if form.validate_on_submit():
        try:
            # Create a new user
            user = User(
                username=form.username.data,
                email=form.email.data,
                password_hash=generate_password_hash(form.password.data),
                role=form.role.data,
                seeker_type=form.seeker_type.data if form.role.data == 'seeker' else None
            )
            
            # Add role-specific fields
            if form.role.data == 'seeker':
                if form.seeker_type.data == 'individual':
                    user.first_name = form.first_name.data
                    user.last_name = form.last_name.data
                    user.skills = form.skills.data.split(',') if form.skills.data else []
                    user.achievements = form.achievements.data
                    user.resume_url = form.resume_url.data
                    user.portfolio_url = form.portfolio_url.data
                else:  # organization
                    user.organization_name = form.organization_name.data
                    user.organization_type = form.organization_type.data
                    user.sector = form.sector.data
                    user.mission_statement = form.mission_statement.data
                    user.founding_date = form.founding_date.data
            else:  # sponsor
                user.company_name = form.company_name.data
                user.industry = form.industry.data
                user.sponsorship_budget = form.sponsorship_budget.data
                user.sponsorship_goals = form.sponsorship_goals.data
            
            # Add common fields
            user.location = form.location.data
            user.bio = form.bio.data
            user.website = form.website.data
            
            db.session.add(user)
            db.session.commit()
            
            # Send verification email
            send_verification_email(user)
            
            flash('Account created successfully! Please check your email to verify your account.', 'success')
            return redirect(url_for('login'))
            
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error during signup: {str(e)}")
            flash('An error occurred while creating your account. Please try again.', 'error')
        except Exception as e:
            logger.error(f"Unexpected error during signup: {str(e)}")
            flash('An unexpected error occurred. Please try again later.', 'error')
    
    return render_template('signup.html', form=form)

@app.route('/seeker/dashboard')
@login_required
def seeker_dashboard():
    """Dashboard for event seekers."""
    if current_user.role != 'seeker':
        return redirect(url_for('dashboard'))
    
    # Get user's events
    events = Event.query.filter_by(organizer_id=current_user.id).order_by(Event.created_at.desc()).all()
    
    # Get active sponsorships
    active_sponsorships = Sponsorship.query.join(Event).filter(
        Event.organizer_id == current_user.id,
        Sponsorship.status == 'approved'
    ).all()
    
    # Get pending sponsorships
    pending_sponsorships = Sponsorship.query.join(Event).filter(
        Event.organizer_id == current_user.id,
        Sponsorship.status == 'pending'
    ).all()
    
    return render_template('seeker_dashboard.html',
                         events=events,
                         active_sponsorships=active_sponsorships,
                         pending_sponsorships=pending_sponsorships)

@app.route('/individual/dashboard')
@login_required
def individual_dashboard():
    if current_user.role != 'seeker' or current_user.seeker_type != 'individual':
        flash('Access denied. This dashboard is for individual seekers only.', 'error')
        return redirect(url_for('dashboard'))

    # Get individual's events
    events = Event.query.filter_by(organizer_id=current_user.id).order_by(Event.created_at.desc()).all()

    # Get active and pending sponsorships
    active_sponsorships = Sponsorship.query.join(Event).filter(
        Event.organizer_id == current_user.id,
        Sponsorship.status == 'approved'
    ).order_by(Sponsorship.created_at.desc()).all()

    pending_sponsorships = Sponsorship.query.join(Event).filter(
        Event.organizer_id == current_user.id,
        Sponsorship.status == 'pending'
    ).order_by(Sponsorship.created_at.desc()).all()

    # Find similar individuals
    similar_individuals = []
    try:
        similar_users = User.query.filter(
            User.id != current_user.id,
            User.role == 'seeker',
            User.seeker_type == 'individual'
        ).limit(5).all()

        for user in similar_users:
            user_events = Event.query.filter_by(organizer_id=user.id).all()
            total_funding = sum(event.current_funding for event in user_events)
            similar_individuals.append({
                'user': user,
                'event_count': len(user_events),
                'total_funding': total_funding
            })
    except Exception as e:
        app.logger.error(f"Error fetching similar individuals: {str(e)}")

    return render_template('individual_dashboard.html',
                         events=events,
                         active_sponsorships=active_sponsorships,
                         pending_sponsorships=pending_sponsorships,
                         similar_individuals=similar_individuals)

@app.route('/organization/dashboard')
@login_required
def organization_dashboard():
    if current_user.role != 'seeker' or current_user.seeker_type != 'organization':
        flash('Access denied. This dashboard is for organization seekers only.', 'error')
        return redirect(url_for('dashboard'))

    # Get organization's events
    events = Event.query.filter_by(organizer_id=current_user.id).order_by(Event.created_at.desc()).all()

    # Get active and pending sponsorships
    active_sponsorships = Sponsorship.query.join(Event).filter(
        Event.organizer_id == current_user.id,
        Sponsorship.status == 'approved'
    ).order_by(Sponsorship.created_at.desc()).all()

    pending_sponsorships = Sponsorship.query.join(Event).filter(
        Event.organizer_id == current_user.id,
        Sponsorship.status == 'pending'
    ).order_by(Sponsorship.created_at.desc()).all()

    # Get team size (if implemented)
    team_size = TeamMember.query.filter_by(organization_id=current_user.id).count() if hasattr(current_user, 'organization_team_members') else 0

    # Get verification status
    verification_status = current_user.verification_status if hasattr(current_user, 'verification_status') else False

    # Find similar organizations
    similar_organizations = []
    try:
        similar_orgs = User.query.filter(
            User.id != current_user.id,
            User.role == 'seeker',
            User.seeker_type == 'organization',
            User.organization_type == current_user.organization_type
        ).limit(5).all()

        for org in similar_orgs:
            org_events = Event.query.filter_by(organizer_id=org.id).all()
            total_funding = sum(event.current_funding for event in org_events)
            similar_organizations.append({
                'user': org,
                'event_count': len(org_events),
                'total_funding': total_funding
            })
    except Exception as e:
        app.logger.error(f"Error fetching similar organizations: {str(e)}")

    return render_template('organization_dashboard.html',
                         events=events,
                         active_sponsorships=active_sponsorships,
                         pending_sponsorships=pending_sponsorships,
                         team_size=team_size,
                         verification_status=verification_status,
                         similar_organizations=similar_organizations)

@app.route('/sponsor/dashboard')
@login_required
def sponsor_dashboard():
    """Dashboard for sponsors."""
    if current_user.role != 'sponsor':
        return redirect(url_for('dashboard'))
    
    # Get active sponsorships
    active_sponsorships = Sponsorship.query.filter_by(
        sponsor_id=current_user.id,
        status='approved'
    ).order_by(Sponsorship.created_at.desc()).all()
    
    # Get pending sponsorships
    pending_sponsorships = Sponsorship.query.filter_by(
        sponsor_id=current_user.id,
        status='pending'
    ).order_by(Sponsorship.created_at.desc()).all()
    
    # Get total sponsored amount
    total_sponsored = db.session.query(func.sum(Sponsorship.amount)).filter(
        Sponsorship.sponsor_id == current_user.id,
        Sponsorship.status == 'approved'
    ).scalar() or 0.0
    
    # Get recommended events based on industry and budget
    recommended_events = Event.query.filter(
        Event.status == 'active',
        Event.organizer_id != current_user.id
    ).order_by(Event.created_at.desc()).limit(5).all()
    
    # Get unread messages count
    unread_messages = ChatMessage.query.filter_by(
        recipient_id=current_user.id,
        read=False
    ).count()
    
    # Get recent activities (last 5 notifications)
    recent_activities = Notification.query.filter_by(
        user_id=current_user.id
    ).order_by(Notification.created_at.desc()).limit(5).all()
    
    # Calculate total students supported (through approved sponsorships)
    total_students = len(set(
        sponsorship.event.organizer_id 
        for sponsorship in active_sponsorships
    ))
    
    return render_template('sponsor_dashboard.html',
                         active_sponsorships=len(active_sponsorships),
                         active_sponsorships_list=active_sponsorships,
                         pending_sponsorships=len(pending_sponsorships),
                         pending_requests=len(pending_sponsorships),
                         pending_requests_list=pending_sponsorships,
                         total_sponsored=total_sponsored,
                         recommended_events=recommended_events,
                         unread_messages=unread_messages,
                         recent_activities=recent_activities,
                         total_students=total_students)

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'seeker':
        if current_user.seeker_type == 'individual':
            return redirect(url_for('individual_dashboard'))
        elif current_user.seeker_type == 'organization':
            return redirect(url_for('organization_dashboard'))
    elif current_user.role == 'sponsor':
        return redirect(url_for('sponsor_dashboard'))
    
    # If no specific dashboard matches (shouldn't happen), show an error
    flash('Unable to determine the appropriate dashboard for your account type.', 'error')
    return redirect(url_for('index'))

@app.route('/about')
def about():
    """About page."""
    return render_template('about.html')

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired(), Length(min=2, max=100)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    subject = StringField('Subject', validators=[DataRequired(), Length(min=2, max=100)])
    message = TextAreaField('Message', validators=[DataRequired(), Length(min=10)])
    submit = SubmitField('Send Message')

@app.route('/contact', methods=['GET', 'POST'])
def contact():
    """Contact page."""
    form = ContactForm()
    
    if form.validate_on_submit():
        # Process contact form submission
        try:
            flash('Your message has been sent! We will get back to you soon.', 'success')
            # Here you would typically send an email or save to database
            return redirect(url_for('contact'))
        except Exception as e:
            flash('An error occurred while sending your message. Please try again.', 'error')
    
    return render_template('contact.html', form=form)

@app.route('/success-stories')
def success_stories():
    """Success stories page."""
    return render_template('success_stories.html')

@app.route('/blog')
def blog():
    """Blog page."""
    return render_template('blog.html')

@app.route('/faq')
def faq():
    """FAQ page."""
    return render_template('faq.html')

@app.route('/help')
def help_center():
    return render_template('help.html')

@app.route('/feedback')
def feedback():
    """Feedback page."""
    return render_template('feedback.html')

@app.route('/terms')
def terms():
    """Terms of service page."""
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    """Privacy policy page."""
    return render_template('privacy.html')

@app.route('/cookies')
def cookies():
    """Cookie policy page."""
    return render_template('cookies.html')

@app.route('/guidelines')
def guidelines():
    """Community guidelines page."""
    return render_template('guidelines.html')

@app.route('/resources')
def resources():
    """Sponsorship resources page."""
    return render_template('resources.html')

@app.route('/organizer-tips')
def organizer_tips():
    """Organizer tips page."""
    return render_template('organizer_tips.html')

@app.route('/sponsor-tips')
def sponsor_tips():
    """Sponsor tips page."""
    return render_template('sponsor_tips.html')

@app.route('/create-event', methods=['GET', 'POST'])
@login_required
def create_event():
    """Handle event creation."""
    form = CreateEventForm()
    
    if form.validate_on_submit():
        try:
            # Combine date and time
            date_str = form.date.data.strftime('%Y-%m-%d')
            time_str = form.time.data
            event_datetime = datetime.strptime(f"{date_str} {time_str}", '%Y-%m-%d %H:%M')
            
            # Create the event
            event = Event(
                title=form.title.data,
                description=form.description.data,
                short_description=form.short_description.data,
                date=event_datetime,
                location=form.location.data,
                funding_goal=form.funding_goal.data,
                organizer_id=current_user.id,
                category=form.category.data,
                sustainability_focus=form.sustainability_focus.data,
                diversity_focus=form.diversity_focus.data,
                innovation_focus=form.innovation_focus.data,
                remote_participation=form.remote_participation.data
            )
            
            # Handle image upload
            if 'featured_image' in request.files:
                file = request.files['featured_image']
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    # Use timestamp to ensure uniqueness
                    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
                    new_filename = f"{timestamp}_{filename}"
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
                    
                    # Resize image if needed
                    img_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                    with Image.open(img_path) as img:
                        if img.width > 1200 or img.height > 800:
                            img.thumbnail((1200, 800))
                            img.save(img_path)
                    
                    event.featured_image = new_filename
            
            db.session.add(event)
            db.session.commit()
            
            # Notify matching sponsors
            notify_matching_sponsors(event)
            
            flash('Event created successfully!', 'success')
            return redirect(url_for('event_details', event_id=event.id))
            
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error during event creation: {str(e)}")
            flash('An error occurred while creating the event. Please try again.', 'error')
        except Exception as e:
            logger.error(f"Unexpected error during event creation: {str(e)}")
            flash('An unexpected error occurred. Please try again later.', 'error')
    
    return render_template('create_event.html', form=form)

@app.route('/event/<int:event_id>')
def event_details(event_id):
    event = Event.query.get_or_404(event_id)
    return render_template('event_details.html', event=event)

@app.route('/sponsor/<int:event_id>', methods=['POST'])
@login_required
def sponsor_event(event_id):
    amount = float(request.form.get('amount'))
    sponsorship = Sponsorship(
        event_id=event_id,
        sponsor_id=current_user.id,
        amount=amount
    )
    db.session.add(sponsorship)
    db.session.commit()
    return redirect(url_for('event_details', event_id=event_id))

@app.route('/rate/<int:user_id>', methods=['POST'])
@login_required
def rate_user(user_id):
    rating_value = int(request.form.get('rating'))
    comment = request.form.get('comment')
    
    existing_rating = Rating.query.filter_by(
        rater_id=current_user.id,
        rated_id=user_id
    ).first()

    if existing_rating:
        existing_rating.rating = rating_value
        existing_rating.comment = comment
    else:
        rating = Rating(
            rater_id=current_user.id,
            rated_id=user_id,
            rating=rating_value,
            comment=comment
        )
        db.session.add(rating)

    # Update user's average rating
    rated_user = User.query.get(user_id)
    ratings = Rating.query.filter_by(rated_id=user_id).all()
    rated_user.rating = sum(r.rating for r in ratings) / len(ratings)
    rated_user.rating_count = len(ratings)

    db.session.commit()
    return jsonify({'success': True})

@app.route('/profile/<username>')
@login_required
def profile(username):
    user = User.query.filter_by(username=username).first_or_404()
    
    # Get user's events based on role
    if user.role == 'seeker':
        events = Event.query.filter_by(organizer_id=user.id).all()
        sponsored_events = []
    else:
        events = []
        sponsored_events = Event.query.join(Sponsorship).filter(Sponsorship.sponsor_id == user.id).all()
    
    return render_template('profile.html', 
                         user=user, 
                         events=events, 
                         sponsored_events=sponsored_events)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/notifications')
@login_required
def notifications():
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    notifications = Notification.query.filter_by(user_id=current_user.id)\
        .order_by(Notification.created_at.desc())\
        .paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('notifications.html', notifications=notifications)

@app.route('/notification/<int:notification_id>/delete', methods=['POST'])
@login_required
def delete_notification(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id != current_user.id:
        abort(403)
    
    try:
        db.session.delete(notification)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting notification: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/notifications/clear', methods=['POST'])
@login_required
def clear_all_notifications():
    try:
        Notification.query.filter_by(user_id=current_user.id).delete()
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error clearing notifications: {e}")
        return jsonify({'success': False, 'error': str(e)})

@app.route('/notifications/mark-all-read', methods=['POST'])
@login_required
def mark_all_notifications_read():
    try:
        Notification.query.filter_by(user_id=current_user.id).update({'is_read': True})
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error marking notifications as read: {e}")
        return jsonify({'success': False, 'error': str(e)})

@socketio.on('mark_all_read')
@login_required
def handle_mark_all_read():
    try:
        Notification.query.filter_by(user_id=current_user.id).update({'is_read': True})
        db.session.commit()
        emit('notifications_marked_read', room=f"user_{current_user.id}")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error marking notifications as read via WebSocket: {e}")
        emit('error', {'message': 'Failed to mark notifications as read'})

@app.route('/settings')
@login_required
def settings():
    return render_template('settings.html')

@app.route('/settings/update', methods=['POST'])
@login_required
def update_settings():
    if 'avatar' in request.files:
        file = request.files['avatar']
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            current_user.avatar = filename
    
    current_user.name = request.form.get('name', current_user.name)
    current_user.bio = request.form.get('bio', current_user.bio)
    current_user.email = request.form.get('email', current_user.email)
    
    if request.form.get('new_password'):
        if check_password_hash(current_user.password_hash, request.form.get('current_password', '')):
            current_user.password_hash = generate_password_hash(request.form.get('new_password'))
        else:
            flash('Current password is incorrect', 'error')
            return redirect(url_for('settings'))
    
    db.session.commit()
    flash('Settings updated successfully', 'success')
    return redirect(url_for('settings'))

@app.route('/mark_notification_read/<int:notification_id>')
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    if notification.user_id == current_user.id:
        notification.is_read = True
        db.session.commit()
    return redirect(url_for('notifications'))


@app.route('/my-events')
@login_required
def my_events():
    events = Event.query.filter_by(organizer_id=current_user.id).order_by(Event.created_at.desc()).all()
    return render_template('my_events.html', events=events)

@app.route('/my-sponsorships')
@login_required
def my_sponsorships():
    active_sponsorships = current_user.get_active_sponsorships()
    pending_sponsorships = current_user.get_pending_sponsorships()
    total_sponsored = current_user.get_total_sponsored_amount()
    
    return render_template(
        'my_sponsorships.html',
        active_sponsorships=active_sponsorships,
        pending_sponsorships=pending_sponsorships,
        total_sponsored=total_sponsored
    )

@app.route('/sponsorship/<int:sponsorship_id>')
@login_required
def sponsorship_details(sponsorship_id):
    sponsorship = Sponsorship.query.get_or_404(sponsorship_id)
    if current_user.id != sponsorship.sponsor_id and current_user.id != sponsorship.event.organizer_id:
        abort(403)
    return render_template('sponsorship_details.html', sponsorship=sponsorship)

@app.route('/sponsorship/<int:sponsorship_id>/approve', methods=['POST'])
@login_required
def approve_sponsorship(sponsorship_id):
    sponsorship = Sponsorship.query.get_or_404(sponsorship_id)
    if current_user.id != sponsorship.event.organizer_id:
        abort(403)
    
    try:
        sponsorship.approve()
        flash('Sponsorship has been approved successfully.', 'success')
        
        # Send notification to sponsor
        send_notification(
            user_id=sponsorship.sponsor_id,
            title='Sponsorship Approved',
            message=f'Your sponsorship for {sponsorship.event.title} has been approved!',
            type='sponsorship',
            link=url_for('sponsorship_details', sponsorship_id=sponsorship.id)
        )
        
    except Exception as e:
        db.session.rollback()
        flash('Error approving sponsorship. Please try again.', 'error')
    
    return redirect(url_for('sponsorship_details', sponsorship_id=sponsorship_id))

@app.route('/sponsorship/<int:sponsorship_id>/reject', methods=['POST'])
@login_required
def reject_sponsorship(sponsorship_id):
    sponsorship = Sponsorship.query.get_or_404(sponsorship_id)
    if current_user.id != sponsorship.event.organizer_id:
        abort(403)
    
    try:
        sponsorship.reject()
        flash('Sponsorship has been rejected.', 'info')
        
        # Send notification to sponsor
        send_notification(
            user_id=sponsorship.sponsor_id,
            title='Sponsorship Rejected',
            message=f'Your sponsorship for {sponsorship.event.title} has been rejected.',
            type='sponsorship',
            link=url_for('sponsorship_details', sponsorship_id=sponsorship.id)
        )
        
    except Exception as e:
        db.session.rollback()
        flash('Error rejecting sponsorship. Please try again.', 'error')
    
    return redirect(url_for('sponsorship_details', sponsorship_id=sponsorship_id))

@app.route('/sponsorship/<int:sponsorship_id>/cancel', methods=['POST'])
@login_required
def cancel_sponsorship(sponsorship_id):
    sponsorship = Sponsorship.query.get_or_404(sponsorship_id)
    if current_user.id != sponsorship.sponsor_id:
        abort(403)
    
    try:
        sponsorship.cancel()
        flash('Sponsorship has been cancelled.', 'info')
        
        # Send notification to organizer
        send_notification(
            user_id=sponsorship.event.organizer_id,
            title='Sponsorship Cancelled',
            message=f'A sponsorship for {sponsorship.event.title} has been cancelled by {current_user.username}.',
            type='sponsorship',
            link=url_for('sponsorship_details', sponsorship_id=sponsorship.id)
        )
        
    except Exception as e:
        db.session.rollback()
        flash('Error cancelling sponsorship. Please try again.', 'error')
    
    return redirect(url_for('sponsorship_details', sponsorship_id=sponsorship_id))

@app.route('/event/<int:event_id>/sponsor', methods=['GET', 'POST'])
@login_required
def create_sponsorship(event_id):
    event = Event.query.get_or_404(event_id)
    
    if not current_user.can_sponsor_event(event):
        flash('You cannot sponsor this event.', 'error')
        return redirect(url_for('event_details', event_id=event_id))
    
    if request.method == 'POST':
        amount = float(request.form.get('amount', 0))
        message = request.form.get('message', '')
        is_anonymous = bool(request.form.get('is_anonymous', False))
        
        if amount <= 0:
            flash('Please enter a valid sponsorship amount.', 'error')
            return redirect(url_for('create_sponsorship', event_id=event_id))
        
        try:
            sponsorship = Sponsorship(
                event_id=event_id,
                sponsor_id=current_user.id,
                amount=amount,
                message=message,
                is_anonymous=is_anonymous
            )
            db.session.add(sponsorship)
            
            # Send notification for organizer
            send_notification(
                user_id=event.organizer_id,
                title='New Sponsorship Request',
                message=f'You have received a new sponsorship request for {event.title}',
                type='sponsorship',
                link=url_for('sponsorship_details', sponsorship_id=sponsorship.id)
            )
            
            db.session.commit()
            flash('Your sponsorship request has been submitted successfully.', 'success')
            return redirect(url_for('sponsorship_details', sponsorship_id=sponsorship.id))
            
        except Exception as e:
            db.session.rollback()
            flash('Error creating sponsorship. Please try again.', 'error')
    
    return render_template('sponsor_form.html', event=event)

def get_unread_notifications_count():
    """Get the number of unread notifications for the current user."""
    if not current_user.is_authenticated:
        return 0
    
    try:
        return Notification.query.filter_by(
            user_id=current_user.id,
            is_read=False
        ).count()
    except Exception as e:
        logger.error(f"Error getting unread notifications count: {str(e)}")
        return 0

def get_notification_icon(notification_type):
    """Get the appropriate icon for a notification type."""
    icon_map = {
        'sponsorship': 'hand-holding-usd',
        'message': 'envelope',
        'event': 'calendar-alt',
        'default': 'bell'
    }
    return icon_map.get(notification_type, icon_map['default'])

def get_notifications():
    """Get current user's notifications."""
    if not current_user.is_authenticated:
        return []
    
    try:
        # Get the user's notifications
        notifications = Notification.query.filter_by(user_id=current_user.id)\
            .order_by(Notification.created_at.desc())\
            .limit(5)\
            .all()
            
        # If no notifications exist yet, return some default ones for UI display
        if not notifications:
            return [
                {
                    'id': 1,
                    'message': 'Welcome to Sponsify!',
                    'link': '#',
                    'icon': 'bell',
                    'is_read': False,
                    'created_at': datetime.utcnow() - timedelta(minutes=5)
                }
            ]
            
        return notifications
        
    except Exception as e:
        print(f"Error getting notifications: {e}")
        return []

@app.context_processor
def inject_globals():
    """Function to inject global variables to all templates."""
    return {
        'app_name': 'Sponzy',
        'current_year': datetime.utcnow().year,
        'get_unread_notifications_count': get_unread_notifications_count,
        'get_notification_icon': get_notification_icon,
        'get_notifications': get_notifications,
    }

@app.context_processor
def utility_processor():
    """Inject utility functions into all templates."""
    return {}  # No longer need to return anything since get_notifications is now at module level

@app.route('/event/<int:event_id>/live')
def event_live(event_id):
    event = Event.query.get_or_404(event_id)
    
    # Get funding history for the chart
    funding_history = {
        'labels': [],
        'data': []
    }
    
    # Get daily funding totals
    daily_funding = db.session.query(
        func.date(Sponsorship.created_at).label('date'),
        func.sum(Sponsorship.amount).label('total')
    ).filter(
        Sponsorship.event_id == event_id,
        Sponsorship.status == 'approved'
    ).group_by(
        func.date(Sponsorship.created_at)
    ).order_by(
        func.date(Sponsorship.created_at)
    ).all()
    
    # If no funding history, add current date with zero
    if not daily_funding:
        funding_history['labels'].append(datetime.utcnow().strftime('%Y-%m-%d'))
        funding_history['data'].append(0)
    else:
        for day in daily_funding:
            funding_history['labels'].append(day.date.strftime('%Y-%m-%d'))
            funding_history['data'].append(float(day.total))
    
    return render_template('event_live.html', 
                         event=event,
                         funding_history=funding_history,
                         now=datetime.utcnow())

# Enhanced error handling for WebSocket events
@socketio.on_error()
def error_handler(e):
    emit('error', {'message': str(e)})

# Add rate limiting for WebSocket events
rate_limits = defaultdict(list)

def rate_limit(limit=5, window=60):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            now = time.time()
            user_id = current_user.id if current_user.is_authenticated else request.sid
            
            # Clean old timestamps
            rate_limits[user_id] = [ts for ts in rate_limits[user_id] if now - ts < window]
            
            if len(rate_limits[user_id]) >= limit:
                emit('error', {'message': 'Rate limit exceeded. Please wait before sending more messages.'})
                return
            
            rate_limits[user_id].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator

# WebSocket events for chat
@socketio.on('send_message')
@rate_limit(limit=5, window=60)
def handle_message(data):
    if not current_user.is_authenticated:
        return
    
    try:
        event_id = data.get('event_id')
        message = data.get('message')
        
        if not message or not event_id:
            return
        
        # Create chat message
        chat_message = ChatMessage(
            event_id=event_id,
            sender_id=current_user.id,
            recipient_id=data.get('recipient_id'),
            content=message
        )
        db.session.add(chat_message)
        db.session.commit()
        
        # Emit message to event room
        emit('new_message', {
            'id': chat_message.id,
            'sender_id': current_user.id,
            'username': current_user.username,
            'message': message,
            'created_at': chat_message.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }, room=f'event_{event_id}')
        
    except Exception as e:
        db.session.rollback()
        emit('error', {'message': 'Failed to send message'})

@socketio.on('typing')
def handle_typing(data):
    if not current_user.is_authenticated:
        return
    
    event_id = data.get('event_id')
    if event_id:
        emit('user_typing', {
            'user_id': current_user.id,
            'username': current_user.username
        }, room=f'event_{event_id}')

@app.route('/event/<int:event_id>/chat')
@login_required
def event_chat(event_id):
    try:
        event = Event.query.get_or_404(event_id)
        messages = ChatMessage.query.filter_by(event_id=event_id)\
            .order_by(ChatMessage.created_at.desc())\
            .limit(50)\
            .all()
        return render_template('event_chat.html', event=event, messages=messages)
    except Exception as e:
        flash('Error loading chat. Please try again.', 'error')
        return redirect(url_for('event_details', event_id=event_id))

@app.errorhandler(404)
def not_found_error(error):
    logger.info(f"404 error: {request.path}")
    return render_template('errors/404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    logger.error(f"500 error: {str(error)}")
    return render_template('errors/500.html'), 500

@app.errorhandler(403)
def forbidden_error(error):
    logger.warning(f"403 error: {request.path}")
    return render_template('errors/403.html'), 403

@app.errorhandler(413)
def request_entity_too_large(error):
    logger.warning(f"413 error: File upload too large")
    flash('The file you are trying to upload is too large.', 'error')
    return render_template('errors/413.html'), 413

@app.errorhandler(429)
def too_many_requests(error):
    logger.warning(f"429 error: Rate limit exceeded for {request.remote_addr}")
    return render_template('errors/429.html'), 429

@socketio.on_error_default
def default_error_handler(e):
    emit('error', {
        'message': 'An error occurred. Please try again.',
        'type': 'general_error'
    })

@socketio.on('clear_chat')
@login_required
def handle_clear_chat(data):
    try:
        event_id = data.get('event_id')
        if not event_id:
            raise ValueError('Event ID is required')
        event = Event.query.get_or_404(event_id)
        if current_user.id != event.organizer_id:
            raise PermissionError('Only event organizers can clear chat')
        ChatMessage.query.filter_by(event_id=event_id).delete()
        db.session.commit()
        emit('chat_cleared', {'event_id': event_id}, room=f'event_{event_id}')
    except ValueError as e:
        emit('error', {'message': str(e), 'type': 'validation_error'})
    except PermissionError as e:
        emit('error', {'message': str(e), 'type': 'permission_error'})
    except Exception as e:
        db.session.rollback()
        emit('error', {'message': 'Failed to clear chat', 'type': 'server_error'})

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # In a real application, we would generate a token and send a reset email
            # For now, we'll just show a success message
            flash('If an account exists with this email, password reset instructions have been sent.', 'success')
            return redirect(url_for('login'))
        else:
            # Don't reveal that the user doesn't exist for security reasons
            flash('If an account exists with this email, password reset instructions have been sent.', 'success')
            return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

# Initialize rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

def sanitize_input(value):
    """Sanitize user input to prevent XSS and injection attacks."""
    if isinstance(value, str):
        return bleach.clean(value, strip=True)
    elif isinstance(value, list):
        return [sanitize_input(item) for item in value]
    return value

class DatabaseError(Exception):
    """Custom exception for database errors."""
    pass

def handle_db_error(func):
    """Decorator to handle database errors."""
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except SQLAlchemyError as e:
            db.session.rollback()
            logger.error(f"Database error in {func.__name__}: {str(e)}")
            raise DatabaseError(f"Database operation failed: {str(e)}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Unexpected error in {func.__name__}: {str(e)}")
            raise
    return wrapper

@app.route('/sponsor-search')
@login_required
@limiter.limit("30 per minute")
@handle_db_error
def sponsor_search():
    """Search for sponsors with enhanced filtering capabilities."""
    if current_user.role != 'seeker':
        flash('Only seekers can access the sponsor search page.', 'error')
        return redirect(url_for('dashboard'))
    
    page = request.args.get('page', 1, type=int)
    query = request.args.get('query', '')
    industry = request.args.get('industry', '')
    min_budget = request.args.get('min_budget', 0, type=float)
    max_budget = request.args.get('max_budget', 0, type=float)
    focus_area = request.args.get('focus_area', '')
    location = request.args.get('location', '')
    sort_by = request.args.get('sort_by', 'match_score')
    
    # Base query for sponsors
    sponsors_query = User.query.filter_by(role='sponsor', verification_status='approved')
    
    # Apply filters
    if query:
        sponsors_query = sponsors_query.filter(
            db.or_(
                User.username.ilike(f'%{query}%'),
                User.company_name.ilike(f'%{query}%'),
                User.bio.ilike(f'%{query}%'),
                User.sponsorship_goals.ilike(f'%{query}%')
            )
        )
    
    if industry:
        sponsors_query = sponsors_query.filter(User.industry == industry)
    
    if min_budget > 0:
        sponsors_query = sponsors_query.filter(User.sponsorship_budget >= min_budget)
    
    if max_budget > 0:
        sponsors_query = sponsors_query.filter(User.sponsorship_budget <= max_budget)
    
    if focus_area == 'sustainability':
        sponsors_query = sponsors_query.filter(User.sustainability_focus == True)
    elif focus_area == 'diversity':
        sponsors_query = sponsors_query.filter(User.diversity_focus == True)
    elif focus_area == 'innovation':
        sponsors_query = sponsors_query.filter(User.innovation_focus == True)
    
    if location:
        sponsors_query = sponsors_query.filter(User.location.ilike(f'%{location}%'))
    
    # Get the user's most recent event for match scoring
    recent_event = None
    if current_user.role == 'seeker':
        recent_event = Event.query.filter_by(organizer_id=current_user.id).order_by(Event.created_at.desc()).first()
    
    # Sorting
    if sort_by == 'rating':
        sponsors_query = sponsors_query.order_by(User.rating.desc())
    elif sort_by == 'budget_high':
        sponsors_query = sponsors_query.order_by(User.sponsorship_budget.desc())
    elif sort_by == 'budget_low':
        sponsors_query = sponsors_query.order_by(User.sponsorship_budget.asc())
    elif sort_by == 'recent':
        sponsors_query = sponsors_query.order_by(User.created_at.desc())
    
    # Execute query with pagination
    sponsors_page = sponsors_query.paginate(page=page, per_page=12, error_out=False)
    sponsors = sponsors_page.items
    
    # Calculate match scores for each sponsor (if user is a seeker)
    if current_user.role == 'seeker':
        for sponsor in sponsors:
            if recent_event:
                sponsor.match_score = sponsor.calculate_match_score(recent_event)
                sponsor.match_reasons = get_detailed_match_reasons(sponsor, recent_event)
            else:
                # If user has no events, calculate basic match score based on preferences
                sponsor.match_score = calculate_enhanced_match_score(sponsor, None)
                sponsor.match_reasons = get_detailed_match_reasons(sponsor, None)
    
    # Get filter options
    filter_options = {
        'industries': db.session.query(User.industry).filter(
            User.role == 'sponsor',
            User.industry.isnot(None)
        ).distinct().all(),
        'locations': db.session.query(User.location).filter(
            User.role == 'sponsor',
            User.location.isnot(None)
        ).distinct().all()
    }
    
    # Clean up filter options
    filter_options['industries'] = [i[0] for i in filter_options['industries'] if i[0]]
    filter_options['locations'] = [l[0] for l in filter_options['locations'] if l[0]]
    
    # Organize sponsors by industry for categorical display
    sponsors_by_industry = {}
    if not query and not industry and not focus_area and not location:
        # Only categorize when no specific filters are applied
        all_sponsors = User.query.filter_by(role='sponsor', verification_status='approved').all()
        
        for sponsor in all_sponsors:
            if sponsor.industry:
                if sponsor.industry not in sponsors_by_industry:
                    sponsors_by_industry[sponsor.industry] = []
                sponsors_by_industry[sponsor.industry].append(sponsor)
    
    return render_template(
        'sponsor_search.html',
        sponsors=sponsors,
        sponsors_by_industry=sponsors_by_industry,
        pagination=sponsors_page,
        filter_options=filter_options,
        query=query,
        industry=industry,
        min_budget=min_budget,
        max_budget=max_budget,
        focus_area=focus_area,
        location=location,
        sort_by=sort_by
    )

@app.route('/seeker-search')
@login_required
@limiter.limit("30 per minute")
@handle_db_error
def seeker_search():
    """
    Search for educational institutions and individual educators
    Supports search by name, organization, bio text and filtering by type, sector, location
    Also provides categorical display when no filters are active
    """
    page = request.args.get('page', 1, type=int)
    query = request.args.get('query', '')
    seeker_type = request.args.get('seeker_type', '')
    sector = request.args.get('sector', '')
    location = request.args.get('location', '')
    sort_by = request.args.get('sort_by', 'rating')
    
    # Base query to get all users with seeker role
    seekers_query = User.query.filter_by(role='seeker')
    
    # Apply search filters if provided
    if query:
        seekers_query = seekers_query.filter(
            db.or_(
                User.username.ilike(f'%{query}%'),
                User.organization_name.ilike(f'%{query}%'),
                User.bio.ilike(f'%{query}%'),
                User.first_name.ilike(f'%{query}%'),
                User.last_name.ilike(f'%{query}%')
            )
        )
    
    # Apply type filter
    if seeker_type:
        if seeker_type == 'individual':
            seekers_query = seekers_query.filter(
                db.or_(
                    User.organization_name == None,
                    User.organization_name == ''
                )
            )
        elif seeker_type == 'organization':
            seekers_query = seekers_query.filter(
                db.and_(
                    User.organization_name != None,
                    User.organization_name != ''
                )
            )
    
    # Apply sector filter
    if sector:
        seekers_query = seekers_query.filter(User.sector == sector)
    
    # Apply location filter
    if location:
        seekers_query = seekers_query.filter(User.location == location)
    
    # Apply sorting
    if sort_by == 'rating':
        seekers_query = seekers_query.order_by(User.rating.desc())
    elif sort_by == 'recent':
        seekers_query = seekers_query.order_by(User.created_at.desc())
    
    # Get data for filter dropdowns
    sector_query = db.session.query(User.sector).filter(
        User.sector.isnot(None), 
        User.sector != '',
        User.role == 'seeker'
    ).distinct().all()
    
    location_query = db.session.query(User.location).filter(
        User.location.isnot(None), 
        User.location != '',
        User.role == 'seeker'
    ).distinct().all()
    
    filter_options = {
        'seeker_types': ['individual', 'organization'],
        'sectors': [s[0] for s in sector_query],
        'locations': [l[0] for l in location_query]
    }
    
    # If no filters are active, group seekers by type for categorical display
    if not any([query, seeker_type, sector, location]):
        all_seekers = seekers_query.all()
        seekers_by_type = {
            'organization': [],
            'individual': []
        }
        
        for seeker in all_seekers:
            if seeker.organization_name:
                seekers_by_type['organization'].append(seeker)
            else:
                seekers_by_type['individual'].append(seeker)
        
        # Sort each category
        for category in seekers_by_type:
            if sort_by == 'rating':
                seekers_by_type[category] = sorted(
                    seekers_by_type[category], 
                    key=lambda x: x.rating if x.rating else 0, 
                    reverse=True
                )[:12]  # Limit to 12 per category for the landing view
            else:
                seekers_by_type[category] = sorted(
                    seekers_by_type[category], 
                    key=lambda x: x.created_at, 
                    reverse=True
                )[:12]
        
        return render_template(
            'seeker_search.html',
            seekers_by_type=seekers_by_type,
            filter_options=filter_options,
            query=query,
            seeker_type=seeker_type,
            sector=sector,
            location=location,
            sort_by=sort_by
        )
    
    # For filtered views, paginate the results
    pagination = seekers_query.paginate(page=page, per_page=12, error_out=False)
    seekers = pagination.items
    
    return render_template(
        'seeker_search.html',
        seekers=seekers,
        pagination=pagination,
        filter_options=filter_options,
        query=query,
        seeker_type=seeker_type,
        sector=sector,
        location=location,
        sort_by=sort_by
    )

def get_default_filter_options():
    """Get default filter options when there's an error."""
    return {
        'industries': [],
        'categories': get_event_categories(),
        'durations': ['short-term', 'long-term', 'one-time', 'flexible'],
        'frequencies': ['monthly', 'quarterly', 'yearly', 'custom'],
        'focus_areas': ['sustainability', 'diversity', 'innovation', 'education', 'research'],
        'sort_options': [
            {'value': 'match', 'label': 'Best Match'},
            {'value': 'rating', 'label': 'Highest Rated'},
            {'value': 'success_rate', 'label': 'Most Successful'}
        ]
    }

@cache.memoize(timeout=300)
def calculate_enhanced_match_score(sponsor, event):
    """Calculate an enhanced match score between a sponsor and an event."""
    score = 0
    reasons = []
    
    # Category match (25 points max)
    if event.category in sponsor.preferred_categories:
        score += 25
        reasons.append(f"Perfect category match: {event.category}")
    else:
        # Check for related categories
        related_categories = get_related_categories(event.category)
        if any(cat in sponsor.preferred_categories for cat in related_categories):
            score += 15
            reasons.append("Related category match")
    
    # Budget match (20 points max)
    if sponsor.min_sponsorship_amount <= event.funding_goal <= sponsor.max_sponsorship_amount:
        score += 20
        reasons.append("Budget requirements match perfectly")
    else:
        # Allow for 20% flexibility in budget
        flexibility = 0.2
        min_with_flex = sponsor.min_sponsorship_amount * (1 - flexibility)
        max_with_flex = sponsor.max_sponsorship_amount * (1 + flexibility)
        if min_with_flex <= event.funding_goal <= max_with_flex:
            score += 10
            reasons.append("Budget requirements match with flexibility")
    
    # Location match (15 points max)
    if event.location in sponsor.geographical_focus:
        score += 15
        reasons.append(f"Location match: {event.location}")
    elif sponsor.accepts_remote and event.remote_participation:
        score += 10
        reasons.append("Remote participation possible")
    
    # Focus areas (10 points max)
    focus_matches = []
    if event.sustainability_focus and sponsor.sustainability_focus:
        focus_matches.append("sustainability")
    if event.diversity_focus and sponsor.diversity_focus:
        focus_matches.append("diversity")
    if event.innovation_focus and sponsor.innovation_focus:
        focus_matches.append("innovation")
    
    if focus_matches:
        points = min(len(focus_matches) * 5, 10)
        score += points
        reasons.append(f"Matching focus areas: {', '.join(focus_matches)}")
    
    # Success rate (10 points max)
    if sponsor.success_metrics:
        success_rate = float(sponsor.success_metrics.get('success_rate', 0))
        total_sponsorships = int(sponsor.success_metrics.get('total_sponsorships', 0))
        if success_rate >= 0.8 and total_sponsorships >= 5:
            score += 10
            reasons.append(f"High success rate: {success_rate:.0%} with {total_sponsorships} sponsorships")
        elif success_rate >= 0.6 and total_sponsorships >= 3:
            score += 5
            reasons.append(f"Good success rate: {success_rate:.0%}")
    
    # Response time (5 points max)
    if sponsor.response_time:
        if sponsor.response_time < 24:
            score += 5
            reasons.append("Quick response time (<24 hours)")
        elif sponsor.response_time < 48:
            score += 3
            reasons.append("Good response time (<48 hours)")
    
    # Experience (5 points max)
    if sponsor.active_sponsorships_count < 5:
        score += 5
        reasons.append("Available capacity for new sponsorships")
    elif sponsor.active_sponsorships_count < 10:
        score += 3
        reasons.append("Moderate capacity for new sponsorships")
    
    # Rating (10 points max)
    if sponsor.rating_count >= 3:  # Minimum reviews threshold
        rating_score = min(sponsor.rating * 2, 10)
        score += rating_score
        reasons.append(f"Strong rating: {sponsor.rating:.1f}/5 ({sponsor.rating_count} reviews)")
    
    return {
        'score': score,
        'reasons': reasons
    }

@cache.memoize(timeout=300)
def get_detailed_match_reasons(sponsor, event):
    """Generate detailed explanations for the match score with caching."""
    reasons = []
    
    # Category match
    if event.category in sponsor.preferred_categories:
        reasons.append(f"Perfect category match: {event.category}")
    else:
        related_categories = get_related_categories(event.category)
        for cat in related_categories:
            if cat in sponsor.preferred_categories:
                reasons.append(f"Related category match: {cat}")
                break
    
    # Budget match
    if sponsor.min_sponsorship_amount <= event.funding_goal <= sponsor.max_sponsorship_amount:
        reasons.append("Budget requirements align perfectly")
    else:
        flexibility = 0.2
        min_with_flex = sponsor.min_sponsorship_amount * (1 - flexibility)
        max_with_flex = sponsor.max_sponsorship_amount * (1 + flexibility)
        if min_with_flex <= event.funding_goal <= max_with_flex:
            reasons.append("Budget requirements align with flexibility")
    
    # Location match
    if event.location == sponsor.location:
        reasons.append(f"Same location: {event.location}")
    elif event.location in sponsor.geographical_focus:
        reasons.append(f"Within sponsor's focus area: {event.location}")
    elif sponsor.accepts_remote and event.remote_participation:
        reasons.append("Compatible with remote sponsorship")
    
    # Focus areas
    focus_matches = []
    if event.sustainability_focus and sponsor.sustainability_focus:
        focus_matches.append("sustainability")
    if event.diversity_focus and sponsor.diversity_focus:
        focus_matches.append("diversity")
    if event.innovation_focus and sponsor.innovation_focus:
        focus_matches.append("innovation")
    if focus_matches:
        reasons.append(f"Aligned focus areas: {', '.join(focus_matches)}")
    
    # Success metrics
    if 'success_rate' in sponsor.success_metrics:
        success_rate = float(sponsor.success_metrics['success_rate'])
        total_sponsorships = int(sponsor.success_metrics.get('total_sponsorships', 0))
        if success_rate >= 0.8 and total_sponsorships >= 10:
            reasons.append(f"Proven track record: {success_rate*100:.0f}% success rate across {total_sponsorships} sponsorships")
        elif success_rate >= 0.8:
            reasons.append(f"High success rate: {success_rate*100:.0f}%")
        elif total_sponsorships >= 10:
            reasons.append(f"Experienced sponsor: {total_sponsorships} past sponsorships")
    
    # Response time
    if sponsor.response_time:
        if sponsor.response_time <= 24:
            reasons.append("Very responsive: Replies within 24 hours")
        elif sponsor.response_time <= 48:
            reasons.append("Responsive: Replies within 48 hours")
    
    # Rating and reviews
    if sponsor.rating_count >= 3:
        reasons.append(f"Well-rated: {sponsor.rating:.1f}/5 from {sponsor.rating_count} reviews")
    
    # Additional expertise
    if sponsor.expertise_areas:
        relevant_expertise = [area for area in sponsor.expertise_areas if area.lower() in event.description.lower()]
        if relevant_expertise:
            reasons.append(f"Relevant expertise in: {', '.join(relevant_expertise)}")
    
    return reasons

@cache.memoize(timeout=3600)  # Cache for 1 hour
def get_related_categories(category):
    """Return a list of categories related to the given category with caching."""
    related_categories = {
        'Education': ['Workshop', 'Seminar', 'Training', 'Conference'],
        'Technology': ['Hackathon', 'Innovation', 'Digital', 'Software'],
        'Science': ['Research', 'Innovation', 'Laboratory', 'Academic'],
        'Arts': ['Cultural', 'Creative', 'Performance', 'Exhibition'],
        'Sports': ['Athletics', 'Competition', 'Fitness', 'Tournament'],
        'Business': ['Entrepreneurship', 'Networking', 'Professional', 'Career'],
        'Community': ['Social', 'Charity', 'Nonprofit', 'Outreach'],
        'Research': ['Academic', 'Science', 'Innovation', 'Laboratory'],
        'Innovation': ['Technology', 'Entrepreneurship', 'Research', 'Digital'],
        'Workshop': ['Education', 'Training', 'Seminar', 'Professional'],
        'Conference': ['Education', 'Professional', 'Networking', 'Seminar'],
        'Hackathon': ['Technology', 'Innovation', 'Competition', 'Digital'],
        'Cultural': ['Arts', 'Community', 'Social', 'Creative'],
        'Competition': ['Sports', 'Innovation', 'Technology', 'Academic']
    }
    return related_categories.get(category, [])

def get_event_categories():
    """Return list of available event categories."""
    return [
        'Education',
        'Technology',
        'Science',
        'Arts',
        'Sports',
        'Culture',
        'Environment',
        'Health',
        'Innovation',
        'Research',
        'Community',
        'Professional Development'
    ]

@app.route('/event-feed')
@login_required
def event_feed():
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    # Get filter parameters
    categories = request.args.getlist('category')
    status = request.args.getlist('status')
    date_range = request.args.get('date_range')
    query = request.args.get('q', '')
    
    # Build query
    events_query = Event.query
    
    if categories:
        events_query = events_query.filter(Event.category.in_(categories))
    if status:
        if 'open' in status:
            events_query = events_query.filter(Event.current_funding < Event.funding_goal)
        if 'funded' in status:
            events_query = events_query.filter(Event.current_funding >= Event.funding_goal)
    if query:
        events_query = events_query.filter(
            db.or_(
                Event.title.ilike(f'%{query}%'),
                Event.description.ilike(f'%{query}%')
            )
        )
    
    # Apply date range filter
    if date_range:
        now = datetime.utcnow()
        if date_range == 'week':
            events_query = events_query.filter(Event.date <= now + timedelta(days=7))
        elif date_range == 'month':
            events_query = events_query.filter(Event.date <= now + timedelta(days=30))
        elif date_range == 'quarter':
            events_query = events_query.filter(Event.date <= now + timedelta(days=90))
        elif date_range == 'year':
            events_query = events_query.filter(Event.date <= now + timedelta(days=365))
    
    # Get paginated results
    pagination = events_query.order_by(Event.date.desc()).paginate(page=page, per_page=per_page, error_out=False)
    events = pagination.items
    
    return render_template('event_feed.html', events=events, pagination=pagination)

@app.route('/chat')
@login_required
def chat():
    user_id = request.args.get('user_id', type=int)
    current_chat_user = None
    messages = []
    
    # Get all conversations
    chats = []
    # Get messages with other users
    messages_query = ChatMessage.query.filter(
        (ChatMessage.sender_id == current_user.id) | 
        (ChatMessage.recipient_id == current_user.id)
    ).order_by(ChatMessage.created_at.desc())
    
    # Group messages by conversation partner
    conversations = {}
    for msg in messages_query:
        other_user_id = msg.recipient_id if msg.sender_id == current_user.id else msg.sender_id
        if other_user_id not in conversations:
            conversations[other_user_id] = {
                'last_message': msg,
                'unread_count': 0
            }
        if not msg.read and msg.recipient_id == current_user.id:
            conversations[other_user_id]['unread_count'] += 1
    
    # Convert to list for template
    for user_id, data in conversations.items():
        user = User.query.get(user_id)
        if user:
            chats.append((user, data['unread_count']))
    
    # Sort by last message time
    chats.sort(key=lambda x: x[0].messages[-1].created_at if x[0].messages else datetime.min, reverse=True)
    
    # If a specific user is selected, get their messages
    if user_id:
        current_chat_user = User.query.get_or_404(user_id)
        messages = ChatMessage.query.filter(
            ((ChatMessage.sender_id == current_user.id) & (ChatMessage.recipient_id == user_id)) |
            ((ChatMessage.sender_id == user_id) & (ChatMessage.recipient_id == current_user.id))
        ).order_by(ChatMessage.created_at.asc()).all()
        
        # Mark messages as read
        for message in messages:
            if not message.read and message.recipient_id == current_user.id:
                message.read = True
        db.session.commit()
    
    return render_template('chat.html', 
                         chats=chats,
                         current_chat_user=current_chat_user,
                         messages=messages)

@socketio.on('join_chat')
def handle_join_chat(data):
    if not current_user.is_authenticated:
        return
    
    user_id = data.get('user_id')
    if user_id:
        room = f"chat_{current_user.id}_{user_id}"
        join_room(room)
        emit('status', {'msg': f'Joined chat room: {room}'}, room=room)

@socketio.on('send_message')
def handle_send_message(data):
    if not current_user.is_authenticated:
        return
    
    recipient_id = data.get('recipient_id')
    content = data.get('content')
    
    if not recipient_id or not content:
        return
    
    try:
        # Create message
        message = ChatMessage(
            sender_id=current_user.id,
            recipient_id=recipient_id,
            content=content
        )
        db.session.add(message)
        
        # Create notification
        notification = Notification(
            user_id=recipient_id,
            title='New Message',
            content=f'New message from {current_user.username}',
            type='message',
            link=url_for('chat', user_id=current_user.id)
        )
        db.session.add(notification)
        
        db.session.commit()
        
        # Emit message to chat room
        room = f"chat_{current_user.id}_{recipient_id}"
        emit('new_message', {
            'id': message.id,
            'sender_id': message.sender_id,
            'recipient_id': message.recipient_id,
            'content': message.content,
            'created_at': message.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }, room=room)
        
        # Emit notification to recipient's room
        recipient_room = f"user_{recipient_id}"
        emit('notification', {
            'id': notification.id,
            'title': notification.title,
            'content': notification.content,
            'type': notification.type,
            'link': notification.link,
            'created_at': notification.created_at.strftime('%Y-%m-%d %H:%M:%S')
        }, room=recipient_room)
        
    except Exception as e:
        db.session.rollback()
        emit('error', {'msg': str(e)})

@socketio.on('typing')
def handle_typing(data):
    if not current_user.is_authenticated:
        return
    
    recipient_id = data.get('recipient_id')
    if recipient_id:
        room = f"chat_{current_user.id}_{recipient_id}"
        emit('user_typing', {
            'user_id': current_user.id,
            'username': current_user.username
        }, room=room)

def init_db():
    """Initialize the database."""
    with app.app_context():
        try:
            # Drop all tables first
            db.drop_all()
            # Create all tables
            db.create_all()
            logger.info("Database tables created successfully")
            # Seed the data
            seed_data()
            logger.info("Database seeded successfully")
        except Exception as e:
            logger.error(f"Database error during initialization: {str(e)}")
            db.session.rollback()
            raise

def seed_data():
    """Seed the database with initial data."""
    try:
        # Create admin user
        admin = User(
            username='admin',
            email='admin@example.com',
            password_hash=generate_password_hash('admin123'),
            role='admin',
            email_verified=True,
            verification_status='approved'
        )
        db.session.add(admin)
        
        # Create John (Individual Seeker)
        john = User(
            username='john',
            email='john@example.com',
            password_hash=generate_password_hash('password123'),
            role='seeker',
            seeker_type='individual',
            first_name='John',
            last_name='Doe',
            location='San Francisco, CA',
            bio='Passionate individual seeking opportunities to make a difference.',
            skills=['Python', 'JavaScript', 'Project Management'],
            achievements='Led multiple successful community projects',
            resume_url='https://example.com/john-resume.pdf',
            portfolio_url='https://example.com/john-portfolio',
            email_verified=True,
            verification_status='approved'
        )
        db.session.add(john)
        
        # Create GDSC (Organization Seeker)
        gdsc = User(
            username='gdsc_club',
            email='gdsc@example.com',
            password_hash=generate_password_hash('password123'),
            role='seeker',
            seeker_type='organization',
            organization_name='Google Developer Student Clubs',
            organization_type='educational',
            sector='Technology',
            location='San Francisco, CA',
            bio='Google Developer Student Clubs (GDSC) are community groups for college and university students interested in Google developer technologies.',
            mission_statement='Empowering students to build solutions for local problems using Google technologies',
            founding_date=datetime(2020, 1, 1).date(),
            team_members_info=[
                {'name': 'Aaron Deniz', 'role': 'Lead', 'email': 'aaron.deniz@example.com'},
                {'name': 'Abhishek', 'role': 'Core Team Member', 'email': 'abhishek@example.com'}
            ],
            social_links={
                'website': 'https://gdsc.community.dev',
                'linkedin': 'https://linkedin.com/company/gdsc',
                'github': 'https://github.com/gdsc'
            },
            email_verified=True,
            verification_status='approved'
        )
        db.session.add(gdsc)

        # Create Microsoft Student Club (Organization Seeker)
        msc = User(
            username='msc_club',
            email='msc@example.com',
            password_hash=generate_password_hash('password123'),
            role='seeker',
            seeker_type='organization',
            organization_name='Microsoft Student Club',
            organization_type='educational',
            sector='Technology',
            location='Seattle, WA',
            bio='Microsoft Student Club is a community of students passionate about Microsoft technologies and cloud computing.',
            mission_statement='Fostering innovation and learning through Microsoft technologies',
            founding_date=datetime(2021, 1, 1).date(),
            team_members_info=[
                {'name': 'Sarah Chen', 'role': 'President', 'email': 'sarah.chen@example.com'},
                {'name': 'Mike Ross', 'role': 'Technical Lead', 'email': 'mike.ross@example.com'}
            ],
            social_links={
                'website': 'https://msc.community.dev',
                'linkedin': 'https://linkedin.com/company/msc',
                'github': 'https://github.com/msc'
            },
            email_verified=True,
            verification_status='approved'
        )
        db.session.add(msc)

        # Create AWS Student Club (Organization Seeker)
        awssc = User(
            username='aws_club',
            email='awssc@example.com',
            password_hash=generate_password_hash('password123'),
            role='seeker',
            seeker_type='organization',
            organization_name='AWS Student Club',
            organization_type='educational',
            sector='Technology',
            location='New York, NY',
            bio='AWS Student Club helps students learn about cloud computing and Amazon Web Services.',
            mission_statement='Building the next generation of cloud architects',
            founding_date=datetime(2022, 1, 1).date(),
            team_members_info=[
                {'name': 'Alex Kumar', 'role': 'Club Lead', 'email': 'alex.kumar@example.com'},
                {'name': 'Emma Wilson', 'role': 'Events Coordinator', 'email': 'emma.wilson@example.com'}
            ],
            social_links={
                'website': 'https://awssc.community.dev',
                'linkedin': 'https://linkedin.com/company/awssc',
                'github': 'https://github.com/awssc'
            },
            email_verified=True,
            verification_status='approved'
        )
        db.session.add(awssc)
        
        # Create Suzie Bakes (Sponsor)
        suzie = User(
            username='suzie_bakes',
            email='suzie@example.com',
            password_hash=generate_password_hash('password123'),
            role='sponsor',
            company_name='Suzie Bakes',
            industry='Food & Beverage',
            location='San Francisco, CA',
            sponsorship_budget=10000.0,
            sponsorship_goals='Support local community events and promote sustainable baking practices',
            preferred_categories=['Community', 'Education', 'Arts'],
            target_audience=['Students', 'Young Professionals', 'Food Enthusiasts'],
            geographical_focus=['San Francisco Bay Area'],
            sponsorship_frequency='monthly',
            min_sponsorship_amount=500.0,
            max_sponsorship_amount=2000.0,
            preferred_duration='short-term',
            sustainability_focus=True,
            diversity_focus=True,
            innovation_focus=True,
            email_verified=True,
            verification_status='approved'
        )
        db.session.add(suzie)

        # Create TechGrowth Ventures (Sponsor)
        techgrowth = User(
            username='techgrowth',
            email='techgrowth@example.com',
            password_hash=generate_password_hash('password123'),
            role='sponsor',
            company_name='TechGrowth Ventures',
            industry='Technology',
            location='San Francisco, CA',
            sponsorship_budget=50000.0,
            sponsorship_goals='Supporting innovative tech education and startup initiatives',
            preferred_categories=['Technology', 'Education', 'Startup Event'],
            target_audience=['Students', 'Developers', 'Entrepreneurs'],
            geographical_focus=['San Francisco Bay Area', 'Seattle', 'New York'],
            sponsorship_frequency='quarterly',
            min_sponsorship_amount=2000.0,
            max_sponsorship_amount=10000.0,
            preferred_duration='long-term',
            sustainability_focus=True,
            diversity_focus=True,
            innovation_focus=True,
            email_verified=True,
            verification_status='approved'
        )
        db.session.add(techgrowth)

        # Create EduFund Foundation (Sponsor)
        edufund = User(
            username='edufund',
            email='edufund@example.com',
            password_hash=generate_password_hash('password123'),
            role='sponsor',
            company_name='EduFund Foundation',
            industry='Education',
            location='New York, NY',
            sponsorship_budget=100000.0,
            sponsorship_goals='Promoting educational initiatives and student development programs',
            preferred_categories=['Education', 'Technology', 'Research'],
            target_audience=['Students', 'Educational Institutions', 'Researchers'],
            geographical_focus=['New York', 'Boston', 'Chicago'],
            sponsorship_frequency='yearly',
            min_sponsorship_amount=5000.0,
            max_sponsorship_amount=25000.0,
            preferred_duration='long-term',
            sustainability_focus=True,
            diversity_focus=True,
            innovation_focus=True,
            email_verified=True,
            verification_status='approved'
        )
        db.session.add(edufund)
        
        # Commit users first to get their IDs
        db.session.commit()
        
        # Create sample events
        events = [
            Event(
                title='Unplug - Startup Event',
                description='Join us for an exciting startup event where innovative ideas come to life. Connect with industry leaders, pitch your ideas, and find potential investors.',
                short_description='A startup event for aspiring entrepreneurs',
                date=datetime(2024, 6, 15, 9, 0),
                location='San Francisco, CA',
                funding_goal=5000.0,
                current_funding=0.0,
                organizer_id=gdsc.id,  # Use GDSC's ID as the organizer
                status='active',
                category='Startup Event',
                is_featured=True,
                is_verified=True,
                sustainability_focus=True,
                diversity_focus=True,
                innovation_focus=True,
                remote_participation=True
            ),
            Event(
                title='Cloud Computing Workshop',
                description='Learn about cloud computing fundamentals and hands-on experience with AWS services.',
                short_description='AWS cloud computing workshop for beginners',
                date=datetime(2024, 7, 1, 10, 0),
                location='New York, NY',
                funding_goal=3000.0,
                current_funding=0.0,
                organizer_id=awssc.id,
                status='active',
                category='Workshop',
                is_featured=True,
                is_verified=True,
                sustainability_focus=False,
                diversity_focus=True,
                innovation_focus=True,
                remote_participation=True
            ),
            Event(
                title='Microsoft Azure Hackathon',
                description='24-hour hackathon focused on building innovative solutions using Microsoft Azure.',
                short_description='Azure cloud hackathon event',
                date=datetime(2024, 8, 1, 9, 0),
                location='Seattle, WA',
                funding_goal=8000.0,
                current_funding=0.0,
                organizer_id=msc.id,
                status='active',
                category='Hackathon',
                is_featured=True,
                is_verified=True,
                sustainability_focus=True,
                diversity_focus=True,
                innovation_focus=True,
                remote_participation=False
            )
        ]
        
        for event in events:
            db.session.add(event)
        
        db.session.commit()
        logger.info("Database seeded successfully")
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error seeding database: {str(e)}")
        raise

def send_verification_email(user):
    """Send a verification email to the user."""
    token = user.generate_email_token()
    verify_url = url_for('verify_email', token=token, _external=True)
    
    msg = Message('Verify your email address',
                 sender=app.config.get('MAIL_DEFAULT_SENDER', 'noreply@sponsify.com'),
                 recipients=[user.email])
    
    msg.body = f'''Please verify your email address by clicking the following link:
{verify_url}

If you did not create an account, please ignore this email.

Best regards,
The Sponsify Team
'''
    mail.send(msg)
    user.email_verification_sent_at = datetime.utcnow()
    db.session.commit()

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        user = User.query.filter_by(email=ts.loads(token, salt='email-verify-key')).first_or_404()
    except:
        flash('The verification link is invalid or has expired.', 'error')
        return redirect(url_for('login'))
    
    if user.verify_email_token(token):
        flash('Your email has been verified. You can now log in.', 'success')
        return redirect(url_for('login'))
    
    flash('The verification link is invalid or has expired.', 'error')
    return redirect(url_for('login'))

@app.route('/resend-verification')
@login_required
def resend_verification():
    if current_user.email_verified:
        flash('Your email is already verified.', 'info')
        return redirect(url_for('dashboard'))
    
    # Check if we should allow resending (prevent spam)
    if current_user.email_verification_sent_at:
        time_since_last = datetime.utcnow() - current_user.email_verification_sent_at
        if time_since_last < timedelta(minutes=5):
            flash('Please wait 5 minutes before requesting another verification email.', 'error')
            return redirect(url_for('dashboard'))
    
    send_verification_email(current_user)
    flash('A new verification email has been sent.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/organization/verify', methods=['GET', 'POST'])
@login_required
def verify_organization():
    if not current_user.is_organization_seeker:
        flash('Only organization accounts can be verified.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            documents = []
            # Handle document uploads
            for key in ['registration', 'tax_doc', 'proof_address']:
                if key in request.files:
                    file = request.files[key]
                    if file and allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
                        new_filename = f"{current_user.id}_{key}_{timestamp}_{filename}"
                        file.save(os.path.join(app.config['UPLOAD_FOLDER'], new_filename))
                        documents.append({
                            'type': key,
                            'filename': new_filename,
                            'original_name': filename,
                            'uploaded_at': datetime.utcnow().isoformat()
                        })
            
            current_user.verification_documents = documents
            current_user.verification_status = 'pending'
            current_user.verification_submitted_at = datetime.utcnow()
            current_user.verification_notes = request.form.get('notes', '')
            
            db.session.commit()
            
            # Notify admins
            admins = User.query.filter_by(role='admin').all()
            for admin in admins:
                send_notification(
                    user_id=admin.id,
                    title='New Organization Verification Request',
                    message=f'Organization {current_user.organization_name} has submitted verification documents.',
                    type='verification',
                    link=url_for('admin.review_verification', user_id=current_user.id)
                )
            
            flash('Your verification documents have been submitted successfully.', 'success')
            return redirect(url_for('organization_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error during organization verification: {e}")
            flash('An error occurred while submitting verification documents.', 'error')
    
    return render_template('organization/verify.html')

@app.route('/admin/verify/<int:user_id>', methods=['POST'])
@login_required
def process_verification(user_id):
    if not current_user.role == 'admin':
        abort(403)
    
    organization = User.query.get_or_404(user_id)
    action = request.form.get('action')
    notes = request.form.get('notes', '')
    
    if action not in ['approve', 'reject']:
        flash('Invalid action.', 'error')
        return redirect(url_for('admin.review_verification', user_id=user_id))
    
    try:
        organization.verification_status = 'approved' if action == 'approve' else 'rejected'
        organization.verification_notes = notes
        organization.verification_processed_at = datetime.utcnow()
        organization.verified_by_id = current_user.id
        
        db.session.commit()
        
        # Send notification to organization
        send_notification(
            user_id=organization.id,
            title='Verification Status Updated',
            message=f'Your organization verification has been {organization.verification_status}.',
            type='verification',
            link=url_for('organization_dashboard')
        )
        
        flash(f'Organization verification has been {organization.verification_status}.', 'success')
        return redirect(url_for('admin.verification_requests'))
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error processing verification: {e}")
        flash('An error occurred while processing verification.', 'error')
        return redirect(url_for('admin.review_verification', user_id=user_id))

@app.route('/admin/verifications')
@login_required
@admin_required
def verification_list():
    page = request.args.get('page', 1, type=int)
    status = request.args.get('status', 'all')
    sort = request.args.get('sort', 'date_desc')
    
    # Base query for organization seekers
    query = User.query.filter_by(role='organization_seeker')
    
    # Apply status filter
    if status != 'all':
        query = query.filter_by(verification_status=status)
    
    # Apply sorting
    if sort == 'date_desc':
        query = query.order_by(User.verification_submitted_at.desc())
    elif sort == 'date_asc':
        query = query.order_by(User.verification_submitted_at.asc())
    elif sort == 'name_asc':
        query = query.order_by(User.name.asc())
    elif sort == 'name_desc':
        query = query.order_by(User.name.desc())
    
    # Paginate results
    pagination = query.paginate(page=page, per_page=10, error_out=False)
    verifications = pagination.items
    
    return render_template('admin/verification_list.html',
                         verifications=verifications,
                         pagination=pagination,
                         status=status,
                         sort=sort)

@app.route('/admin/verify/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_verify_organization(user_id):
    organization = User.query.get_or_404(user_id)
    
    if organization.role != 'organization_seeker':
        flash('Invalid user type for verification.', 'error')
        return redirect(url_for('verification_list'))
    
    if request.method == 'POST':
        status = request.form.get('status')
        notes = request.form.get('notes')
        
        if status not in ['approved', 'rejected']:
            flash('Invalid verification status.', 'error')
            return redirect(url_for('admin_verify_organization', user_id=user_id))
        
        if status == 'rejected' and not notes:
            flash('Please provide notes explaining the rejection.', 'error')
            return redirect(url_for('admin_verify_organization', user_id=user_id))
        
        organization.verification_status = status
        organization.verification_notes = notes
        organization.verification_processed_at = datetime.utcnow()
        organization.verified_by_id = current_user.id
        db.session.commit()
        
        # Send email notification
        subject = f'Organization Verification {status.title()}'
        if status == 'approved':
            body = f'Congratulations! Your organization has been verified on Sponsify.'
        else:
            body = f'Your organization verification was not approved. Reason: {notes}'
        
        send_email(organization.email, subject, body)
        
        flash(f'Organization verification {status}.', 'success')
        return redirect(url_for('verification_list'))
    
    return render_template('admin/verify_organization.html', organization=organization)

@app.route('/download/<int:user_id>/<doc_type>')
@login_required
@admin_required
def download_verification_doc(user_id, doc_type):
    if doc_type not in ['registration', 'tax_doc', 'proof_address']:
        abort(404)
    
    organization = User.query.get_or_404(user_id)
    if organization.role != 'organization_seeker':
        abort(404)
    
    try:
        docs = json.loads(organization.verification_documents)
        if doc_type not in docs:
            abort(404)
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], f'verification/{user_id}/{docs[doc_type]}')
        return send_file(file_path, as_attachment=True)
    except:
        abort(404)

@app.route('/admin/statistics')
@login_required
def user_statistics():
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('index'))
        
    total_users = User.query.count()
    total_seekers = User.query.filter_by(role='seeker').count()
    total_sponsors = User.query.filter_by(role='sponsor').count()
    total_events = Event.query.count()
    
    # Get recent signups (last 7 days)
    week_ago = datetime.utcnow() - timedelta(days=7)
    recent_signups = User.query.filter(User.created_at >= week_ago).count()
    
    # Get active events (not ended)
    active_events = Event.query.filter(Event.event_datetime >= datetime.utcnow()).count()
    
    return render_template('admin/statistics.html',
                         total_users=total_users,
                         total_seekers=total_seekers,
                         total_sponsors=total_sponsors,
                         total_events=total_events,
                         recent_signups=recent_signups,
                         active_events=active_events)

def get_similar_users(user, limit=5, randomize=False):
    """Get similar users based on role and preferences."""
    query = User.query.filter(User.id != user.id)
    
    if user.role == 'seeker':
        # Match other seekers based on category and sector
        if user.seeker_type == 'organization':
            query = query.filter(
                User.role == 'seeker',
                User.seeker_type == 'organization',
                User.sector == user.sector
            )
        else:
            # Match based on skills and interests
            query = query.filter(
                User.role == 'seeker',
                User.seeker_type == 'individual'
            )
            # Instead of using overlap, we'll fetch users and filter in Python
            all_matching_users = query.all()
            filtered_users = []
            
            if user.skills:
                for potential_match in all_matching_users:
                    # Check if any skills match
                    if potential_match.skills and any(skill in user.skills for skill in potential_match.skills):
                        filtered_users.append(potential_match)
                
                # Sort and limit results
                if randomize:
                    random.shuffle(filtered_users)
                else:
                    filtered_users.sort(key=lambda x: x.rating if x.rating else 0, reverse=True)
                
                return filtered_users[:limit]
    else:
        # Match sponsors based on industry and focus areas
        query = query.filter(
            User.role == 'sponsor',
            User.industry == user.industry
        )
        
        # Handle preferred_categories filtering in Python instead of using overlap
        all_matching_sponsors = query.all()
        filtered_sponsors = []
        
        if user.preferred_categories:
            for potential_match in all_matching_sponsors:
                # Check if any categories match
                if potential_match.preferred_categories and any(cat in user.preferred_categories for cat in potential_match.preferred_categories):
                    filtered_sponsors.append(potential_match)
            
            # Sort and limit results
            if randomize:
                random.shuffle(filtered_sponsors)
            else:
                filtered_sponsors.sort(key=lambda x: x.rating if x.rating else 0, reverse=True)
            
            return filtered_sponsors[:limit]
    
    # If we didn't return filtered results above, apply sorting and limits to the query
    if randomize:
        query = query.order_by(func.random())
    else:
        query = query.order_by(User.rating.desc())
    
    return query.limit(limit).all()

def get_recommended_events(user, limit=10, randomize=False):
    """Get recommended events based on user preferences."""
    query = Event.query.filter(Event.status == 'active')
    
    if user.role == 'sponsor':
        if user.preferred_categories:
            query = query.filter(Event.category.in_(user.preferred_categories))
        if user.geographical_focus:
            query = query.filter(Event.location.in_(user.geographical_focus))
        if user.min_sponsorship_amount:
            query = query.filter(Event.funding_goal >= user.min_sponsorship_amount)
        if user.max_sponsorship_amount:
            query = query.filter(Event.funding_goal <= user.max_sponsorship_amount)
        
        # Consider focus areas
        if user.sustainability_focus:
            query = query.filter(Event.sustainability_focus == True)
        if user.diversity_focus:
            query = query.filter(Event.diversity_focus == True)
        if user.innovation_focus:
            query = query.filter(Event.innovation_focus == True)
    else:
        # For seekers, recommend events in similar categories
        user_events = Event.query.filter_by(organizer_id=user.id).all()
        if user_events:
            user_categories = {event.category for event in user_events}
            query = query.filter(Event.category.in_(user_categories))
    
    if randomize:
        query = query.order_by(func.random())
    else:
        # Order by relevance and funding progress
        query = query.order_by(
            Event.is_featured.desc(),
            (Event.current_funding / Event.funding_goal).desc()
        )
    
    return query.limit(limit).all()

def get_detailed_match_reasons(sponsor, event):
    """Get detailed reasons for event-sponsor match score."""
    reasons = []
    
    # Check category match
    if event.category in (sponsor.preferred_categories or []):
        reasons.append(f"Matches your preferred category: {event.category}")
    
    # Check location match
    if event.location in (sponsor.geographical_focus or []):
        reasons.append(f"Event location ({event.location}) matches your geographical focus")
    
    # Check budget match
    if sponsor.min_sponsorship_amount <= event.funding_goal <= sponsor.max_sponsorship_amount:
        reasons.append("Funding goal matches your budget range")
    
    # Check focus areas
    if sponsor.sustainability_focus and event.sustainability_focus:
        reasons.append("Matches your sustainability focus")
    if sponsor.diversity_focus and event.diversity_focus:
        reasons.append("Matches your diversity focus")
    if sponsor.innovation_focus and event.innovation_focus:
        reasons.append("Matches your innovation focus")
    
    # Check organizer rating
    if event.organizer.rating >= 4.0:
        reasons.append(f"Highly rated organizer ({event.organizer.rating:.1f}/5.0)")
    
    return reasons

@app.route('/discover')
@login_required
def discover():
    """Enhanced discover page with real-time updates and filtering."""
    # Get initial data
    similar_users = get_similar_users(current_user)
    recommended_events = get_recommended_events(current_user)
    
    # Get all unique categories and locations for filters
    categories = Event.query.with_entities(Event.category).distinct().all()
    categories = sorted([cat[0] for cat in categories if cat[0]])
    
    locations = Event.query.with_entities(Event.location).distinct().all()
    locations = sorted([loc[0] for loc in locations if loc[0]])
    
    # Get user preferences for WebSocket
    user_preferences = {
        'preferred_categories': current_user.preferred_categories or [],
        'geographical_focus': current_user.geographical_focus or [],
        'sustainability_focus': current_user.sustainability_focus or False,
        'diversity_focus': current_user.diversity_focus or False,
        'innovation_focus': current_user.innovation_focus or False
    } if current_user.role == 'sponsor' else {}
    
    # Calculate event scores for sponsors
    event_scores = {}
    if current_user.role == 'sponsor':
        for event in recommended_events:
            try:
                score = current_user.calculate_match_score(event)
                reasons = get_detailed_match_reasons(current_user, event)
                event_scores[event.id] = {
                    'score': score,
                    'reasons': reasons
                }
            except Exception as e:
                print(f"Error calculating match score for event {event.id}: {str(e)}")
                event_scores[event.id] = {
                    'score': 0,
                    'reasons': ['Unable to calculate match score']
                }
    
    # Get filter options
    filter_options = get_default_filter_options()
    
    return render_template('discover.html',
                         similar_users=similar_users,
                         recommended_events=recommended_events,
                         categories=categories,
                         locations=locations,
                         event_scores=event_scores,
                         user_preferences=user_preferences,
                         filter_options=filter_options)

@socketio.on('join_discover_room')
def handle_join_discover():
    """Handle user joining the discover room for real-time updates."""
    room = f'discover_{current_user.id}'
    join_room(room)
    # Also join role-specific room for broader updates
    join_room(f'discover_{current_user.role}')

@socketio.on('refresh_similar_users')
def handle_refresh_similar_users():
    """Handle request to refresh similar users."""
    similar_users = get_similar_users(current_user, randomize=True)
    emit('similar_users_update', {
        'users': [user.to_dict() for user in similar_users]
    })

@socketio.on('refresh_recommended_events')
def handle_refresh_recommended_events():
    """Handle request to refresh recommended events."""
    events = get_recommended_events(current_user, randomize=True)
    event_data = []
    for event in events:
        data = event.to_dict()
        if current_user.role == 'sponsor':
            score = current_user.calculate_match_score(event)
            reasons = get_detailed_match_reasons(current_user, event)
            data['match'] = {
                'score': score,
                'reasons': reasons
            }
        event_data.append(data)
    
    emit('recommended_events_update', {
        'events': event_data
    })

@socketio.on('apply_filters')
def handle_apply_filters(data):
    """Handle filter application for events and users."""
    # Base query for events
    query = Event.query
    
    # Apply category filter
    if data.get('category'):
        query = query.filter(Event.category == data['category'])
    
    # Apply location filter
    if data.get('location'):
        query = query.filter(Event.location == data['location'])
    
    # Apply tag filters
    if data.get('tags'):
        for tag in data['tags']:
            if tag == 'sustainability':
                query = query.filter(Event.sustainability_focus == True)
            elif tag == 'diversity':
                query = query.filter(Event.diversity_focus == True)
            elif tag == 'innovation':
                query = query.filter(Event.innovation_focus == True)
            elif tag == 'remote':
                query = query.filter(Event.remote_participation == True)
    
    # Apply search filter
    if data.get('search'):
        search = f"%{data['search']}%"
        query = query.filter(or_(
            Event.title.ilike(search),
            Event.description.ilike(search),
            Event.short_description.ilike(search)
        ))
    
    # Apply sorting
    sort = data.get('sort', 'match')
    if sort == 'date':
        query = query.order_by(Event.date.desc())
    elif sort == 'funding':
        query = query.order_by((Event.current_funding / Event.funding_goal).desc())
    
    # Get filtered events
    events = query.limit(10).all()
    
    # Prepare event data with match scores for sponsors
    event_data = []
    for event in events:
        data = event.to_dict()
        if current_user.role == 'sponsor':
            score = current_user.calculate_match_score(event)
            reasons = get_detailed_match_reasons(current_user, event)
            data['match'] = {
                'score': score,
                'reasons': reasons
            }
        event_data.append(data)
    
    # Emit filtered results
    emit('recommended_events_update', {
        'events': event_data
    })

def notify_matching_sponsors(event):
    """Notify sponsors about new events matching their preferences."""
    matching_sponsors = User.query.filter(
        User.role == 'sponsor',
        User.preferred_categories.contains(event.category)
    ).all()
    
    for sponsor in matching_sponsors:
        score = sponsor.calculate_match_score(event)
        if score >= 70:  # Only notify for high matches
            room = f'discover_{sponsor.id}'
            socketio.emit('new_event_notification', {
                'event': event.to_dict(),
                'match_score': score
            }, room=room)

# Real-time chat functionality
@socketio.on('private_message')
def handle_private_message(data):
    """Handle private messages between users."""
    try:
        recipient_id = data.get('recipient_id')
        message = data.get('message')
        if not recipient_id or not message:
            return
        
        # Create new chat message
        new_message = ChatMessage(
            sender_id=current_user.id,
            recipient_id=recipient_id,
            content=message
        )
        db.session.add(new_message)
        db.session.commit()
        
        # Emit to both sender and recipient
        message_data = {
            'id': new_message.id,
            'sender_id': current_user.id,
            'sender_name': current_user.username,
            'content': message,
            'timestamp': new_message.created_at.isoformat()
        }
        emit('new_private_message', message_data, room=f'user_{recipient_id}')
        emit('new_private_message', message_data, room=f'user_{current_user.id}')
        
        # Send notification to recipient
        send_notification(
            recipient_id,
            f"New message from {current_user.username}",
            message[:50] + '...' if len(message) > 50 else message,
            'message',
            url_for('chat', recipient_id=current_user.id)
        )
    except Exception as e:
        logger.error(f"Error handling private message: {e}")
        emit('error', {'message': 'Failed to send message'})

# Live funding progress updates
@socketio.on('funding_update')
def handle_funding_update(data):
    """Handle real-time funding updates."""
    try:
        event_id = data.get('event_id')
        amount = data.get('amount')
        event = Event.query.get(event_id)
        
        if event:
            event.current_funding += amount
            db.session.commit()
            
            # Calculate progress percentage
            progress = (event.current_funding / event.funding_goal) * 100
            
            # Emit update to all users viewing the event
            emit('funding_progress', {
                'event_id': event_id,
                'current_funding': event.current_funding,
                'progress': progress
            }, room=f'event_{event_id}')
            
            # Send notification to event organizer
            if progress >= 100 and event.current_funding >= event.funding_goal:
                send_notification(
                    event.organizer_id,
                    "Funding Goal Reached!",
                    f"Your event '{event.title}' has reached its funding goal!",
                    'funding',
                    url_for('event_details', event_id=event_id)
                )
    except Exception as e:
        logger.error(f"Error handling funding update: {e}")
        emit('error', {'message': 'Failed to update funding'})

# Event countdown timer updates
@socketio.on('join_event_room')
def handle_join_event_room(data):
    """Join event-specific room for real-time updates."""
    event_id = data.get('event_id')
    if event_id:
        join_room(f'event_{event_id}')
        
        # Send initial countdown data
        event = Event.query.get(event_id)
        if event:
            time_left = event.date - datetime.utcnow()
            emit('countdown_update', {
                'event_id': event_id,
                'days': time_left.days,
                'hours': time_left.seconds // 3600,
                'minutes': (time_left.seconds % 3600) // 60,
                'seconds': time_left.seconds % 60
            })

# Live activity feed
def broadcast_activity(activity_type, data):
    """Broadcast activity to relevant users."""
    try:
        activity_data = {
            'type': activity_type,
            'data': data,
            'timestamp': datetime.utcnow().isoformat()
        }
        emit('new_activity', activity_data, broadcast=True)
    except Exception as e:
        logger.error(f"Error broadcasting activity: {e}")

# Real-time notifications for user interactions
@socketio.on('user_interaction')
def handle_user_interaction(data):
    """Handle various user interactions."""
    try:
        interaction_type = data.get('type')
        target_id = data.get('target_id')
        
        if interaction_type == 'follow':
            # Handle follow interaction
            send_notification(
                target_id,
                f"{current_user.username} started following you",
                "You have a new follower!",
                'social',
                url_for('profile', username=current_user.username)
            )
        elif interaction_type == 'like':
            # Handle like interaction
            send_notification(
                target_id,
                f"{current_user.username} liked your event",
                "Your event received a like!",
                'social',
                url_for('event_details', event_id=data.get('event_id'))
            )
        
        # Broadcast activity
        broadcast_activity(interaction_type, {
            'user_id': current_user.id,
            'username': current_user.username,
            'target_id': target_id,
            'event_id': data.get('event_id')
        })
    except Exception as e:
        logger.error(f"Error handling user interaction: {e}")
        emit('error', {'message': 'Failed to process interaction'})

# Periodic countdown updates
def update_event_countdowns():
    """Update countdown timers for all active events."""
    try:
        active_events = Event.query.filter(
            Event.date > datetime.utcnow(),
            Event.status == 'active'
        ).all()
        
        for event in active_events:
            time_left = event.date - datetime.utcnow()
            socketio.emit('countdown_update', {
                'event_id': event.id,
                'days': time_left.days,
                'hours': time_left.seconds // 3600,
                'minutes': (time_left.seconds % 3600) // 60,
                'seconds': time_left.seconds % 60
            }, room=f'event_{event.id}')
    except Exception as e:
        logger.error(f"Error updating event countdowns: {e}")

# Schedule periodic countdown updates
@socketio.on('connect')
def handle_connect():
    """Handle WebSocket connection."""
    if current_user.is_authenticated:
        join_room(f'user_{current_user.id}')
        # Send a welcome notification on first login
        if not current_user.last_seen:
            emit('notification', {
                'title': 'Welcome!',
                'message': 'Welcome to Sponsify!',
                'type': 'info'
            })
    current_user.last_seen = datetime.utcnow()
    db.session.commit()

def allowed_file(filename):
    """Check if the file extension is allowed."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.errorhandler(SQLAlchemyError)
def handle_database_error(error):
    db.session.rollback()
    logger.error(f"Database error: {str(error)}")
    return render_template('errors/500.html'), 500

@app.route('/find-seekers')
def find_seekers():
    """
    Search for educational institutions and individual educators
    Supports search by name, organization, bio text and filtering by type, sector, location
    Also provides categorical display when no filters are active
    """
    page = request.args.get('page', 1, type=int)
    query = request.args.get('query', '')
    seeker_type = request.args.get('seeker_type', '')
    sector = request.args.get('sector', '')
    location = request.args.get('location', '')
    sort_by = request.args.get('sort_by', 'rating')
    
    # Base query to get all users with seeker role
    seekers_query = User.query.filter_by(role='seeker')
    
    # Apply search filters if provided
    if query:
        seekers_query = seekers_query.filter(
            db.or_(
                User.username.ilike(f'%{query}%'),
                User.organization_name.ilike(f'%{query}%'),
                User.bio.ilike(f'%{query}%'),
                User.first_name.ilike(f'%{query}%'),
                User.last_name.ilike(f'%{query}%')
            )
        )
    
    # Apply type filter
    if seeker_type:
        if seeker_type == 'individual':
            seekers_query = seekers_query.filter(
                db.or_(
                    User.organization_name == None,
                    User.organization_name == ''
                )
            )
        elif seeker_type == 'organization':
            seekers_query = seekers_query.filter(
                db.and_(
                    User.organization_name != None,
                    User.organization_name != ''
                )
            )
    
    # Apply sector filter
    if sector:
        seekers_query = seekers_query.filter(User.sector == sector)
    
    # Apply location filter
    if location:
        seekers_query = seekers_query.filter(User.location == location)
    
    # Apply sorting
    if sort_by == 'rating':
        seekers_query = seekers_query.order_by(User.rating.desc())
    elif sort_by == 'recent':
        seekers_query = seekers_query.order_by(User.created_at.desc())
    
    # Get data for filter dropdowns
    sector_query = db.session.query(User.sector).filter(
        User.sector.isnot(None), 
        User.sector != '',
        User.role == 'seeker'
    ).distinct().all()
    
    location_query = db.session.query(User.location).filter(
        User.location.isnot(None), 
        User.location != '',
        User.role == 'seeker'
    ).distinct().all()
    
    filter_options = {
        'seeker_types': ['individual', 'organization'],
        'sectors': [s[0] for s in sector_query],
        'locations': [l[0] for l in location_query]
    }
    
    # If no filters are active, group seekers by type for categorical display
    if not any([query, seeker_type, sector, location]):
        all_seekers = seekers_query.all()
        seekers_by_type = {
            'organization': [],
            'individual': []
        }
        
        for seeker in all_seekers:
            if seeker.organization_name:
                seekers_by_type['organization'].append(seeker)
            else:
                seekers_by_type['individual'].append(seeker)
        
        # Sort each category
        for category in seekers_by_type:
            if sort_by == 'rating':
                seekers_by_type[category] = sorted(
                    seekers_by_type[category], 
                    key=lambda x: x.rating if x.rating else 0, 
                    reverse=True
                )[:12]  # Limit to 12 per category for the landing view
            else:
                seekers_by_type[category] = sorted(
                    seekers_by_type[category], 
                    key=lambda x: x.created_at, 
                    reverse=True
                )[:12]
        
        return render_template(
            'seeker_search.html',
            seekers_by_type=seekers_by_type,
            filter_options=filter_options,
            query=query,
            seeker_type=seeker_type,
            sector=sector,
            location=location,
            sort_by=sort_by
        )
    
    # For filtered views, paginate the results
    pagination = seekers_query.paginate(page=page, per_page=12, error_out=False)
    seekers = pagination.items
    
    return render_template(
        'seeker_search.html',
        seekers=seekers,
        pagination=pagination,
        filter_options=filter_options,
        query=query,
        seeker_type=seeker_type,
        sector=sector,
        location=location,
        sort_by=sort_by
    )

def reset_db():
    """Drop all tables and recreate them."""
    with app.app_context():
        try:
            db.drop_all()
            logger.info("Database tables dropped successfully")
            db.create_all()
            logger.info("Database tables recreated successfully")
            seed_data()
            logger.info("Database seeded successfully")
        except SQLAlchemyError as e:
            logger.error(f"Database error during reset: {str(e)}")
            db.session.rollback()
            raise
        except Exception as e:
            logger.error(f"Unexpected error during database reset: {str(e)}")
            raise

def init_db():
    """Initialize the database with proper error handling."""
    with app.app_context():
        try:
            # Create all tables
            db.create_all()
            logger.info("Database tables created successfully")
            
            # Check if database is already seeded
            if User.query.first() is None:
                seed_data()
            else:
                logger.info("Database already contains data, skipping seed")
        except SQLAlchemyError as e:
            logger.error(f"Database error during initialization: {str(e)}")
            db.session.rollback()
            # If there's a schema error, try to reset the database
            if "no such column" in str(e):
                logger.info("Detected schema change, attempting to reset database")
                reset_db()
            else:
                raise
        except Exception as e:
            logger.error(f"Unexpected error during database initialization: {str(e)}")
            raise

@app.route('/admin/reset-database', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_reset_database():
    """Admin route to reset the database."""
    if request.method == 'POST':
        try:
            reset_db()
            flash('Database has been reset successfully.', 'success')
        except Exception as e:
            flash(f'Error resetting database: {str(e)}', 'error')
        
        return redirect(url_for('admin_dashboard'))
        
    return render_template('admin/reset_database.html')

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    """Admin dashboard view."""
    # Get basic stats
    user_count = User.query.count()
    event_count = Event.query.count()
    sponsorship_count = Sponsorship.query.count()
    
    # Get pending verifications
    pending_verifications = User.query.filter_by(
        verification_status='pending',
        role='seeker',
        seeker_type='organization'
    ).count()
    
    # Get all users with pagination
    page = request.args.get('page', 1, type=int)
    per_page = 10
    users = User.query.order_by(User.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    # Group users by role
    users_by_role = {
        'seekers': User.query.filter_by(role='seeker').all(),
        'sponsors': User.query.filter_by(role='sponsor').all(),
        'admins': User.query.filter_by(role='admin').all()
    }
    
    stats = {
        'user_count': user_count,
        'event_count': event_count,
        'sponsorship_count': sponsorship_count,
        'pending_verifications': pending_verifications
    }
    
    return render_template('admin/dashboard.html', 
                         stats=stats, 
                         users=users,
                         users_by_role=users_by_role)

@app.route('/subscription-plans')
def subscription_plans():
    """Display subscription plans page."""
    plans = [
        {
            'name': 'Free',
            'price': 0,
            'features': [
                'Basic search functionality',
                'Create up to 3 events',
                'Basic analytics',
                'Community support'
            ],
            'highlighted': False
        },
        {
            'name': 'Standard',
            'price': 29.99,
            'features': [
                'Advanced search filters',
                'Create unlimited events',
                'Featured event listings',
                'Priority support',
                'Detailed analytics',
                'Email notifications'
            ],
            'highlighted': True
        },
        {
            'name': 'Premium',
            'price': 99.99,
            'features': [
                'All Standard features',
                'Custom branding',
                'Advanced analytics and reports',
                'Dedicated account manager',
                'API access',
                'Verified sponsor badge',
                'Priority placement in search results'
            ],
            'highlighted': False
        }
    ]
    return render_template('subscription_plans.html', plans=plans)

def create_admin_user():
    """Create an admin user if it doesn't exist."""
    with app.app_context():
        admin_email = "admin@sponzy.com"
        admin_username = "admin"

        try:
            # Check if admin exists by email or username
            admin = User.query.filter(
                or_(User.email == admin_email, User.username == admin_username)
            ).first()

            if not admin:
                # Generate a more secure password
                default_password = "password123"  # Ideally, this should be environment-configurable
                hashed_password = generate_password_hash(default_password)

                admin = User(
                    username=admin_username,
                    email=admin_email,
                    password_hash=hashed_password,
                    role="admin",
                    first_name="Admin",
                    last_name="User"
                )
                db.session.add(admin)
                db.session.commit()
                logging.info(f"Admin user created with email: {admin_email} and password: {default_password}")
            else:
                # Ensure existing user has admin role
                if admin.role != "admin":
                    admin.role = "admin"
                    db.session.commit()
                    logging.info(f"Existing user {admin.username} updated to admin role")
                logging.info(f"Admin user already exists: {admin.username} ({admin.email})")

            return admin

        except Exception as e:
            db.session.rollback()
            logging.error(f"Error creating/updating admin user: {e}")
            return None

@app.route('/send-sponsorship-request/<int:sponsor_id>', methods=['POST'])
@login_required
def send_sponsorship_request(sponsor_id):
    """Send a sponsorship request to a sponsor."""
    try:
        if current_user.role != 'seeker':
            if request.is_json:
                return jsonify({'success': False, 'error': 'Only seekers can send sponsorship requests.'}), 403
            flash('Only seekers can send sponsorship requests.', 'error')
            return redirect(url_for('dashboard'))
        
        sponsor = User.query.get_or_404(sponsor_id)
        if sponsor.role != 'sponsor':
            if request.is_json:
                return jsonify({'success': False, 'error': 'Invalid sponsor selected.'}), 400
            flash('Invalid sponsor selected.', 'error')
            return redirect(url_for('dashboard'))
        
        # Get the seeker's most recent event
        event = Event.query.filter_by(organizer_id=current_user.id).order_by(Event.created_at.desc()).first()
        if not event:
            if request.is_json:
                return jsonify({'success': False, 'error': 'You need to create an event before sending sponsorship requests.'}), 400
            flash('You need to create an event before sending sponsorship requests.', 'error')
            return redirect(url_for('create_event'))
        
        # Check if a request already exists
        existing_request = Sponsorship.query.filter_by(
            event_id=event.id,
            sponsor_id=sponsor_id,
            status='pending'
        ).first()
        
        if existing_request:
            if request.is_json:
                return jsonify({'success': False, 'error': 'You have already sent a sponsorship request to this sponsor.'}), 400
            flash('You have already sent a sponsorship request to this sponsor.', 'warning')
            return redirect(url_for('sponsor_search'))
        
        # Create new sponsorship request
        sponsorship = Sponsorship(
            event_id=event.id,
            sponsor_id=sponsor_id,
            amount=event.funding_goal * 0.1,  # Default to 10% of funding goal
            status='pending',
            message=f"Sponsorship request for {event.title}"
        )
        
        db.session.add(sponsorship)
        db.session.commit()
        
        # Send notification to sponsor
        send_notification(
            user_id=sponsor_id,
            title='New Sponsorship Request',
            message=f'{current_user.username} has requested sponsorship for their event "{event.title}"',
            type='sponsorship',
            link=url_for('sponsorship_details', sponsorship_id=sponsorship.id)
        )
        
        if request.is_json:
            return jsonify({'success': True})
        flash('Sponsorship request sent successfully!', 'success')
        return redirect(url_for('sponsor_search'))
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error sending sponsorship request: {str(e)}")
        if request.is_json:
            return jsonify({'success': False, 'error': str(e)}), 500
        flash('Error sending sponsorship request. Please try again.', 'error')
        return redirect(url_for('sponsor_search'))

# Add this to the startup sequence
if __name__ == '__main__':
    try:
        # Initialize database on startup
        init_db()
        # Create admin user
        create_admin_user()
        logger.info("Database initialization completed")
        
        # Run the application
        socketio.run(app, debug=True) 
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        raise

@app.cli.command("reset-sponsorships")
def reset_sponsorships():
    """Reset all sponsorship data while preserving events."""
    try:
        # Delete all sponsorship requests
        SponsorshipRequest.query.delete()
        
        # Delete all active sponsorships
        Sponsorship.query.delete()
        
        # Delete all sponsorship-related notifications
        Notification.query.filter(
            Notification.type.in_(['sponsorship_request', 'sponsorship_approved', 'sponsorship_rejected'])
        ).delete()
        
        # Reset event funding to 0
        Event.query.update({Event.current_funding: 0})
        
        db.session.commit()
        print("Successfully reset all sponsorship data while preserving events.")
    except Exception as e:
        db.session.rollback()
        print(f"Error resetting sponsorship data: {str(e)}")

@app.route('/admin/clear-requests', methods=['GET', 'POST'])
@login_required
@admin_required
def clear_requests():
    if request.method == 'POST':
        confirmation = request.form.get('confirmation')
        
        if confirmation != 'CLEAR':
            flash('Invalid confirmation. Please type "CLEAR" to confirm.', 'error')
            return redirect(url_for('clear_requests'))
        
        try:
            # Delete all pending sponsorship requests
            deleted_count = Sponsorship.query.filter_by(status='pending').delete()
            db.session.commit()
            
            flash(f'Successfully cleared {deleted_count} pending sponsorship requests.', 'success')
            return redirect(url_for('admin_dashboard'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error clearing sponsorship requests: {e}")
            flash('An error occurred while clearing sponsorship requests.', 'error')
            return redirect(url_for('clear_requests'))
    
    return render_template('admin/clear_requests.html')