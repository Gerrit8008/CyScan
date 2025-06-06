#!/usr/bin/env python3
"""
Authentication Routes
Handles user registration, login, logout, email verification
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import secrets
import string
import re

from models import db, User, SubscriptionHistory
from subscription_constants import SUBSCRIPTION_LEVELS

auth_bp = Blueprint('auth', __name__)

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_valid_password(password):
    """Password must be at least 8 characters with uppercase, lowercase, and number"""
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    return True

@auth_bp.route('/login')
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin.dashboard'))
        else:
            return redirect(url_for('client.dashboard'))
    
    user_type = request.args.get('type', 'client')
    return render_template('auth/login.html', user_type=user_type)

@auth_bp.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    remember = bool(request.form.get('remember'))
    user_type = request.form.get('user_type', 'client')
    
    if not email or not password:
        flash('Email and password are required.', 'error')
        return redirect(url_for('auth.login', type=user_type))
    
    user = User.query.filter_by(email=email).first()
    
    if not user or not user.check_password(password):
        flash('Invalid email or password.', 'error')
        return redirect(url_for('auth.login', type=user_type))
    
    if not user.is_active:
        flash('Your account has been deactivated. Please contact support.', 'error')
        return redirect(url_for('auth.login', type=user_type))
    
    if not user.email_verified:
        flash('Please verify your email address before logging in.', 'warning')
        return redirect(url_for('auth.resend_verification', email=email))
    
    # Check user type matches
    if user_type == 'admin' and user.role != 'admin':
        flash('Admin access required.', 'error')
        return redirect(url_for('auth.login', type='client'))
    
    if user_type == 'client' and user.role == 'admin':
        return redirect(url_for('auth.login', type='admin'))
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    login_user(user, remember=remember)
    
    # Redirect based on role
    next_page = request.args.get('next')
    if next_page:
        return redirect(next_page)
    elif user.role == 'admin':
        return redirect(url_for('admin.dashboard'))
    else:
        return redirect(url_for('client.dashboard'))

@auth_bp.route('/register')
def register():
    if current_user.is_authenticated:
        return redirect(url_for('client.dashboard'))
    return render_template('auth/register.html', subscription_levels=SUBSCRIPTION_LEVELS)

@auth_bp.route('/register', methods=['POST'])
def register_post():
    email = request.form.get('email', '').strip().lower()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    company_name = request.form.get('company_name', '').strip()
    phone = request.form.get('phone', '').strip()
    subscription_tier = request.form.get('subscription_tier', 'basic')
    
    # Validation
    errors = []
    
    if not email:
        errors.append('Email is required.')
    elif not is_valid_email(email):
        errors.append('Please enter a valid email address.')
    elif User.query.filter_by(email=email).first():
        errors.append('Email already registered.')
    
    if not username:
        errors.append('Username is required.')
    elif len(username) < 3:
        errors.append('Username must be at least 3 characters.')
    elif User.query.filter_by(username=username).first():
        errors.append('Username already taken.')
    
    if not password:
        errors.append('Password is required.')
    elif not is_valid_password(password):
        errors.append('Password must be at least 8 characters with uppercase, lowercase, and number.')
    elif password != confirm_password:
        errors.append('Passwords do not match.')
    
    if not company_name:
        errors.append('Company name is required.')
    
    if subscription_tier not in SUBSCRIPTION_LEVELS:
        subscription_tier = 'basic'
    
    if errors:
        for error in errors:
            flash(error, 'error')
        return render_template('auth/register.html', 
                             email=email, username=username, company_name=company_name, 
                             phone=phone, subscription_tier=subscription_tier,
                             subscription_levels=SUBSCRIPTION_LEVELS)
    
    # Create user
    user = User(
        email=email,
        username=username,
        company_name=company_name,
        phone=phone,
        subscription_tier=subscription_tier,
        role='client'
    )
    user.set_password(password)
    user.generate_api_key()
    
    # Generate email verification token
    user.email_verification_token = secrets.token_urlsafe(32)
    
    db.session.add(user)
    db.session.commit()
    
    # Record subscription history
    if subscription_tier != 'basic':
        history = SubscriptionHistory(
            user_id=user.id,
            old_tier=None,
            new_tier=subscription_tier,
            action='register'
        )
        db.session.add(history)
        db.session.commit()
    
    # Send verification email (implement later)
    flash('Registration successful! Please check your email to verify your account.', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@auth_bp.route('/verify/<token>')
def verify_email(token):
    user = User.query.filter_by(email_verification_token=token).first()
    if not user:
        flash('Invalid or expired verification link.', 'error')
        return redirect(url_for('auth.login'))
    
    user.email_verified = True
    user.email_verification_token = None
    db.session.commit()
    
    flash('Email verified successfully! You can now log in.', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/resend-verification')
def resend_verification():
    email = request.args.get('email')
    return render_template('auth/resend_verification.html', email=email)

@auth_bp.route('/resend-verification', methods=['POST'])
def resend_verification_post():
    email = request.form.get('email', '').strip().lower()
    
    if not email:
        flash('Email is required.', 'error')
        return render_template('auth/resend_verification.html')
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('No account found with that email address.', 'error')
        return render_template('auth/resend_verification.html', email=email)
    
    if user.email_verified:
        flash('Your email is already verified.', 'info')
        return redirect(url_for('auth.login'))
    
    # Generate new verification token
    user.email_verification_token = secrets.token_urlsafe(32)
    db.session.commit()
    
    # Send verification email (implement later)
    flash('Verification email sent! Please check your inbox.', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/forgot-password')
def forgot_password():
    return render_template('auth/forgot_password.html')

@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password_post():
    email = request.form.get('email', '').strip().lower()
    
    if not email:
        flash('Email is required.', 'error')
        return render_template('auth/forgot_password.html')
    
    user = User.query.filter_by(email=email).first()
    if user:
        # Generate password reset token
        reset_token = secrets.token_urlsafe(32)
        # Store token in session or database with expiry
        session[f'reset_token_{reset_token}'] = {
            'user_id': user.id,
            'expires': (datetime.utcnow() + timedelta(hours=1)).timestamp()
        }
        
        # Send reset email (implement later)
        flash('Password reset instructions sent to your email.', 'success')
    else:
        # Don't reveal if email exists or not
        flash('Password reset instructions sent to your email.', 'success')
    
    return redirect(url_for('auth.login'))

@auth_bp.route('/reset-password/<token>')
def reset_password(token):
    # Check if token exists and is valid
    reset_data = session.get(f'reset_token_{token}')
    if not reset_data:
        flash('Invalid or expired reset link.', 'error')
        return redirect(url_for('auth.forgot_password'))
    
    if datetime.utcnow().timestamp() > reset_data['expires']:
        session.pop(f'reset_token_{token}', None)
        flash('Reset link has expired.', 'error')
        return redirect(url_for('auth.forgot_password'))
    
    return render_template('auth/reset_password.html', token=token)

@auth_bp.route('/reset-password/<token>', methods=['POST'])
def reset_password_post(token):
    reset_data = session.get(f'reset_token_{token}')
    if not reset_data:
        flash('Invalid or expired reset link.', 'error')
        return redirect(url_for('auth.forgot_password'))
    
    if datetime.utcnow().timestamp() > reset_data['expires']:
        session.pop(f'reset_token_{token}', None)
        flash('Reset link has expired.', 'error')
        return redirect(url_for('auth.forgot_password'))
    
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not password:
        flash('Password is required.', 'error')
        return render_template('auth/reset_password.html', token=token)
    
    if not is_valid_password(password):
        flash('Password must be at least 8 characters with uppercase, lowercase, and number.', 'error')
        return render_template('auth/reset_password.html', token=token)
    
    if password != confirm_password:
        flash('Passwords do not match.', 'error')
        return render_template('auth/reset_password.html', token=token)
    
    # Update password
    user = User.query.get(reset_data['user_id'])
    if user:
        user.set_password(password)
        db.session.commit()
        
        # Remove reset token
        session.pop(f'reset_token_{token}', None)
        
        flash('Password updated successfully! You can now log in.', 'success')
        return redirect(url_for('auth.login'))
    
    flash('User not found.', 'error')
    return redirect(url_for('auth.forgot_password'))

@auth_bp.route('/profile')
@login_required
def profile():
    return render_template('auth/profile.html')

@auth_bp.route('/profile', methods=['POST'])
@login_required
def profile_post():
    username = request.form.get('username', '').strip()
    company_name = request.form.get('company_name', '').strip()
    phone = request.form.get('phone', '').strip()
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    errors = []
    
    # Update basic info
    if username and username != current_user.username:
        if len(username) < 3:
            errors.append('Username must be at least 3 characters.')
        elif User.query.filter_by(username=username).filter(User.id != current_user.id).first():
            errors.append('Username already taken.')
        else:
            current_user.username = username
    
    if company_name:
        current_user.company_name = company_name
    
    if phone:
        current_user.phone = phone
    
    # Update password if provided
    if new_password:
        if not current_password:
            errors.append('Current password is required to change password.')
        elif not current_user.check_password(current_password):
            errors.append('Current password is incorrect.')
        elif not is_valid_password(new_password):
            errors.append('New password must be at least 8 characters with uppercase, lowercase, and number.')
        elif new_password != confirm_password:
            errors.append('New passwords do not match.')
        else:
            current_user.set_password(new_password)
    
    if errors:
        for error in errors:
            flash(error, 'error')
        return render_template('auth/profile.html')
    
    current_user.updated_at = datetime.utcnow()
    db.session.commit()
    
    flash('Profile updated successfully!', 'success')
    return redirect(url_for('auth.profile'))