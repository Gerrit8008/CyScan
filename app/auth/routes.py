"""
Authentication Routes
"""

from flask import render_template, request, redirect, url_for, flash, session, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from app.auth import auth_bp
from models import db, User, SubscriptionHistory
from subscription_constants import SUBSCRIPTION_LEVELS
from datetime import datetime
import logging
import re
import secrets

logger = logging.getLogger(__name__)

@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin.dashboard'))
        return redirect(url_for('client.dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        remember = bool(request.form.get('remember'))
        
        if not email or not password:
            flash('Please enter both email and password.', 'error')
            return render_template('auth/login.html')
        
        user = User.query.filter_by(email=email).first()
        
        if user and user.check_password(password):
            if not user.is_active:
                flash('Your account has been deactivated. Please contact support.', 'error')
                return render_template('auth/login.html')
            
            login_user(user, remember=remember)
            
            # Update last login
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            logger.info(f'User {user.email} logged in successfully')
            
            # Redirect to appropriate dashboard
            next_page = request.args.get('next')
            if next_page:
                return redirect(next_page)
            elif user.role == 'admin':
                return redirect(url_for('admin.dashboard'))
            else:
                return redirect(url_for('client.dashboard'))
        else:
            flash('Invalid email or password.', 'error')
            logger.warning(f'Failed login attempt for email: {email}')
    
    return render_template('auth/login.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if current_user.is_authenticated:
        return redirect(url_for('client.dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        company_name = request.form.get('company_name', '').strip()
        phone = request.form.get('phone', '').strip()
        subscription_tier = request.form.get('subscription_tier', 'basic')
        
        # Validation
        errors = []
        
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters long.')
        
        if not email or not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
            errors.append('Please enter a valid email address.')
        
        if not password or len(password) < 6:
            errors.append('Password must be at least 6 characters long.')
        
        if password != confirm_password:
            errors.append('Passwords do not match.')
        
        if subscription_tier not in SUBSCRIPTION_LEVELS:
            errors.append('Invalid subscription tier selected.')
        
        if errors:
            for error in errors:
                flash(error, 'error')
            return render_template('auth/register.html', 
                                 subscription_levels=SUBSCRIPTION_LEVELS)
        
        # Check if user already exists
        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('An account with this email already exists.', 'error')
            return render_template('auth/register.html',
                                 subscription_levels=SUBSCRIPTION_LEVELS)
        
        # Check username uniqueness
        existing_username = User.query.filter_by(username=username).first()
        if existing_username:
            flash('Username already taken.', 'error')
            return render_template('auth/register.html',
                                 subscription_levels=SUBSCRIPTION_LEVELS)
        
        try:
            # Create user
            user = User(
                username=username,
                email=email,
                company_name=company_name,
                phone=phone,
                role='client',
                subscription_tier=subscription_tier,
                email_verified=False
            )
            user.set_password(password)
            user.generate_api_key()
            
            db.session.add(user)
            db.session.commit()
            
            # Create subscription history record
            sub_history = SubscriptionHistory(
                user_id=user.id,
                old_tier=None,
                new_tier=subscription_tier,
                action='signup'
            )
            db.session.add(sub_history)
            db.session.commit()
            
            logger.info(f'New user registered: {email} (ID: {user.id})')
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f'Registration failed for {email}: {e}')
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('auth/register.html', 
                         subscription_levels=SUBSCRIPTION_LEVELS)

@auth_bp.route('/logout')
@login_required
def logout():
    """User logout"""
    logger.info(f'User {current_user.email} logged out')
    logout_user()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

@auth_bp.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    """User profile management"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        company_name = request.form.get('company_name', '').strip()
        phone = request.form.get('phone', '').strip()
        
        # Check username uniqueness if changed
        if username != current_user.username:
            existing_user = User.query.filter_by(username=username).first()
            if existing_user:
                flash('Username already taken.', 'error')
                return render_template('auth/profile.html')
        
        try:
            current_user.username = username
            current_user.company_name = company_name
            current_user.phone = phone
            current_user.updated_at = datetime.utcnow()
            
            db.session.commit()
            flash('Profile updated successfully!', 'success')
            
        except Exception as e:
            db.session.rollback()
            logger.error(f'Profile update failed for user {current_user.id}: {e}')
            flash('Profile update failed. Please try again.', 'error')
    
    return render_template('auth/profile.html')

@auth_bp.route('/change-password', methods=['POST'])
@login_required
def change_password():
    """Change user password"""
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not current_user.check_password(current_password):
        flash('Current password is incorrect.', 'error')
        return redirect(url_for('auth.profile'))
    
    if len(new_password) < 6:
        flash('New password must be at least 6 characters long.', 'error')
        return redirect(url_for('auth.profile'))
    
    if new_password != confirm_password:
        flash('New passwords do not match.', 'error')
        return redirect(url_for('auth.profile'))
    
    try:
        current_user.set_password(new_password)
        current_user.updated_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f'Password changed for user {current_user.email}')
        flash('Password changed successfully!', 'success')
        
    except Exception as e:
        db.session.rollback()
        logger.error(f'Password change failed for user {current_user.id}: {e}')
        flash('Password change failed. Please try again.', 'error')
    
    return redirect(url_for('auth.profile'))

@auth_bp.route('/upgrade', methods=['GET', 'POST'])
@login_required
def upgrade():
    """Upgrade subscription"""
    if request.method == 'POST':
        new_tier = request.form.get('subscription_tier')
        
        if new_tier not in SUBSCRIPTION_LEVELS:
            flash('Invalid subscription tier.', 'error')
            return redirect(url_for('auth.upgrade'))
        
        subscription_info = SUBSCRIPTION_LEVELS[new_tier]
        
        # For basic (free) plan, upgrade immediately
        if new_tier == 'basic' or subscription_info['price'] == 0:
            try:
                old_tier = current_user.subscription_tier
                current_user.subscription_tier = new_tier
                current_user.reset_monthly_usage()
                current_user.updated_at = datetime.utcnow()
                
                # Create subscription history record
                sub_history = SubscriptionHistory(
                    user_id=current_user.id,
                    old_tier=old_tier,
                    new_tier=new_tier,
                    action='upgrade' if new_tier != 'basic' else 'downgrade'
                )
                
                db.session.add(sub_history)
                db.session.commit()
                
                flash(f'Successfully changed to {subscription_info["name"]} plan!', 'success')
                return redirect(url_for('client.dashboard'))
                
            except Exception as e:
                db.session.rollback()
                logger.error(f'Subscription change failed for user {current_user.id}: {e}')
                flash('Subscription change failed. Please try again.', 'error')
        else:
            # For paid plans, redirect to payment
            # In production, integrate with Stripe/PayPal
            flash('Payment integration coming soon. Contact support for paid plans.', 'warning')
    
    return render_template('auth/upgrade.html', 
                         subscription_levels=SUBSCRIPTION_LEVELS,
                         current_tier=current_user.subscription_tier)

@auth_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Password reset request"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        
        if not email:
            flash('Please enter your email address.', 'error')
            return render_template('auth/forgot_password.html')
        
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Generate reset token
            reset_token = secrets.token_urlsafe(32)
            user.email_verification_token = reset_token
            db.session.commit()
            
            # In production, send email with reset link
            # For now, just show success message
            flash('Password reset instructions have been sent to your email.', 'info')
            logger.info(f'Password reset requested for {email}')
        else:
            # Don't reveal if email exists or not
            flash('Password reset instructions have been sent to your email.', 'info')
            logger.warning(f'Password reset requested for non-existent email: {email}')
        
        return redirect(url_for('auth.login'))
    
    return render_template('auth/forgot_password.html')

@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Password reset with token"""
    user = User.query.filter_by(email_verification_token=token).first()
    
    if not user:
        flash('Invalid or expired reset token.', 'error')
        return redirect(url_for('auth.forgot_password'))
    
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.', 'error')
            return render_template('auth/reset_password.html', token=token)
        
        if password != confirm_password:
            flash('Passwords do not match.', 'error')
            return render_template('auth/reset_password.html', token=token)
        
        try:
            user.set_password(password)
            user.email_verification_token = None
            user.updated_at = datetime.utcnow()
            db.session.commit()
            
            flash('Password reset successfully! Please log in.', 'success')
            logger.info(f'Password reset completed for {user.email}')
            return redirect(url_for('auth.login'))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f'Password reset failed for user {user.id}: {e}')
            flash('Password reset failed. Please try again.', 'error')
    
    return render_template('auth/reset_password.html', token=token)