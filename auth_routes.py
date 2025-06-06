from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash
from datetime import datetime
import secrets
import re

from models import db, User, SubscriptionHistory
from flask_mail import Message, current_app as app

auth_bp = Blueprint('auth', __name__)

def validate_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def validate_password(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    return True, "Password is valid"

@auth_bp.route('/login')
def login():
    if current_user.is_authenticated:
        if current_user.role == 'admin':
            return redirect(url_for('admin.dashboard'))
        return redirect(url_for('client.dashboard'))
    return render_template('auth/login.html')

@auth_bp.route('/login', methods=['POST'])
def login_post():
    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')
    remember = bool(request.form.get('remember'))
    
    if not email or not password:
        flash('Please provide both email and password.', 'error')
        return redirect(url_for('auth.login'))
    
    user = User.query.filter_by(email=email).first()
    
    if not user or not user.check_password(password):
        flash('Invalid email or password.', 'error')
        return redirect(url_for('auth.login'))
    
    if not user.is_active:
        flash('Your account has been deactivated. Please contact support.', 'error')
        return redirect(url_for('auth.login'))
    
    if not user.email_verified:
        flash('Please verify your email address before logging in.', 'warning')
        return redirect(url_for('auth.resend_verification', email=email))
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    login_user(user, remember=remember)
    
    next_page = request.args.get('next')
    if next_page:
        return redirect(next_page)
    
    if user.role == 'admin':
        return redirect(url_for('admin.dashboard'))
    return redirect(url_for('client.dashboard'))

@auth_bp.route('/register')
def register():
    if current_user.is_authenticated:
        return redirect(url_for('client.dashboard'))
    return render_template('auth/register.html')

@auth_bp.route('/register', methods=['POST'])
def register_post():
    # Get form data
    email = request.form.get('email', '').strip().lower()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    company_name = request.form.get('company_name', '').strip()
    phone = request.form.get('phone', '').strip()
    terms = request.form.get('terms')
    
    # Validation
    errors = []
    
    if not email or not validate_email(email):
        errors.append('Please provide a valid email address.')
    
    if not username or len(username) < 3:
        errors.append('Username must be at least 3 characters long.')
    
    if not password:
        errors.append('Password is required.')
    else:
        valid, msg = validate_password(password)
        if not valid:
            errors.append(msg)
    
    if password != confirm_password:
        errors.append('Passwords do not match.')
    
    if not company_name:
        errors.append('Company name is required.')
    
    if not terms:
        errors.append('You must accept the terms and conditions.')
    
    # Check if user exists
    if User.query.filter_by(email=email).first():
        errors.append('Email address already registered.')
    
    if User.query.filter_by(username=username).first():
        errors.append('Username already taken.')
    
    if errors:
        for error in errors:
            flash(error, 'error')
        return redirect(url_for('auth.register'))
    
    # Create new user
    user = User(
        email=email,
        username=username,
        company_name=company_name,
        phone=phone,
        role='client',
        subscription_tier='basic',
        subscription_status='active'
    )
    user.set_password(password)
    user.generate_api_key()
    user.email_verification_token = secrets.token_urlsafe(32)
    
    db.session.add(user)
    
    # Add subscription history
    sub_history = SubscriptionHistory(
        user_id=user.id,
        new_tier='basic',
        action='signup',
        amount=0
    )
    db.session.add(sub_history)
    
    db.session.commit()
    
    # Send verification email
    try:
        from flask_mail import Message, Mail
        mail = Mail(app)
        
        msg = Message(
            subject='Verify your CybrScan account',
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[email]
        )
        
        verification_url = url_for('auth.verify_email', 
                                 token=user.email_verification_token, 
                                 _external=True)
        
        msg.body = f'''Welcome to CybrScan!

Please verify your email address by clicking the link below:

{verification_url}

If you did not create this account, please ignore this email.

Best regards,
The CybrScan Team'''
        
        mail.send(msg)
        flash('Registration successful! Please check your email to verify your account.', 'success')
    except Exception as e:
        app.logger.error(f'Failed to send verification email: {e}')
        flash('Registration successful! However, we could not send the verification email. Please contact support.', 'warning')
    
    return redirect(url_for('auth.login'))

@auth_bp.route('/verify/<token>')
def verify_email(token):
    user = User.query.filter_by(email_verification_token=token).first()
    
    if not user:
        flash('Invalid verification link.', 'error')
        return redirect(url_for('auth.login'))
    
    if user.email_verified:
        flash('Email already verified.', 'info')
        return redirect(url_for('auth.login'))
    
    user.email_verified = True
    user.email_verification_token = None
    db.session.commit()
    
    flash('Email verified successfully! You can now log in.', 'success')
    return redirect(url_for('auth.login'))

@auth_bp.route('/resend-verification/<email>')
def resend_verification(email):
    user = User.query.filter_by(email=email).first()
    
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('auth.register'))
    
    if user.email_verified:
        flash('Email already verified.', 'info')
        return redirect(url_for('auth.login'))
    
    # Generate new token
    user.email_verification_token = secrets.token_urlsafe(32)
    db.session.commit()
    
    # Send verification email
    try:
        from flask_mail import Message, Mail
        mail = Mail(app)
        
        msg = Message(
            subject='Verify your CybrScan account',
            sender=app.config['MAIL_DEFAULT_SENDER'],
            recipients=[email]
        )
        
        verification_url = url_for('auth.verify_email', 
                                 token=user.email_verification_token, 
                                 _external=True)
        
        msg.body = f'''Welcome to CybrScan!

Please verify your email address by clicking the link below:

{verification_url}

If you did not create this account, please ignore this email.

Best regards,
The CybrScan Team'''
        
        mail.send(msg)
        flash('Verification email sent! Please check your inbox.', 'success')
    except Exception as e:
        app.logger.error(f'Failed to send verification email: {e}')
        flash('Failed to send verification email. Please contact support.', 'error')
    
    return redirect(url_for('auth.login'))

@auth_bp.route('/forgot-password')
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('client.dashboard'))
    return render_template('auth/reset-password-request.html')

@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password_post():
    email = request.form.get('email', '').strip().lower()
    
    if not email:
        flash('Please provide your email address.', 'error')
        return redirect(url_for('auth.forgot_password'))
    
    user = User.query.filter_by(email=email).first()
    
    if user:
        # Generate reset token
        reset_token = secrets.token_urlsafe(32)
        session[f'reset_token_{reset_token}'] = {
            'user_id': user.id,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Send reset email
        try:
            from flask_mail import Message, Mail
            mail = Mail(app)
            
            msg = Message(
                subject='Reset your CybrScan password',
                sender=app.config['MAIL_DEFAULT_SENDER'],
                recipients=[email]
            )
            
            reset_url = url_for('auth.reset_password', 
                              token=reset_token, 
                              _external=True)
            
            msg.body = f'''You requested a password reset for your CybrScan account.

Click the link below to reset your password:

{reset_url}

This link will expire in 1 hour.

If you did not request this reset, please ignore this email.

Best regards,
The CybrScan Team'''
            
            mail.send(msg)
        except Exception as e:
            app.logger.error(f'Failed to send reset email: {e}')
    
    # Always show success message to prevent user enumeration
    flash('If an account exists with that email, you will receive password reset instructions.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/reset-password/<token>')
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('client.dashboard'))
    
    # Check if token is valid
    reset_data = session.get(f'reset_token_{token}')
    if not reset_data:
        flash('Invalid or expired reset link.', 'error')
        return redirect(url_for('auth.forgot_password'))
    
    return render_template('auth/reset-password-confirm.html', token=token)

@auth_bp.route('/reset-password/<token>', methods=['POST'])
def reset_password_post(token):
    reset_data = session.get(f'reset_token_{token}')
    if not reset_data:
        flash('Invalid or expired reset link.', 'error')
        return redirect(url_for('auth.forgot_password'))
    
    password = request.form.get('password', '')
    confirm_password = request.form.get('confirm_password', '')
    
    if not password:
        flash('Password is required.', 'error')
        return redirect(url_for('auth.reset_password', token=token))
    
    valid, msg = validate_password(password)
    if not valid:
        flash(msg, 'error')
        return redirect(url_for('auth.reset_password', token=token))
    
    if password != confirm_password:
        flash('Passwords do not match.', 'error')
        return redirect(url_for('auth.reset_password', token=token))
    
    # Update password
    user = User.query.get(reset_data['user_id'])
    if user:
        user.set_password(password)
        db.session.commit()
        
        # Remove token from session
        session.pop(f'reset_token_{token}', None)
        
        flash('Password reset successful! You can now log in with your new password.', 'success')
        return redirect(url_for('auth.login'))
    
    flash('User not found.', 'error')
    return redirect(url_for('auth.forgot_password'))

@auth_bp.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))