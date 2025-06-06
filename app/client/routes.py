"""
Client Routes
"""

from flask import render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import login_required, current_user
from functools import wraps
from app.client import client_bp
from models import db, User, Scanner, Scan, ScannerCustomization, SubscriptionHistory
from subscription_constants import SUBSCRIPTION_LEVELS, get_subscription_features, get_client_subscription_level
from color_extractor import extract_website_colors
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import logging
import os
import secrets
import json

logger = logging.getLogger(__name__)

def client_required(f):
    """Decorator to require client role or admin"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            flash('Please log in to access this page.', 'error')
            return redirect(url_for('auth.login'))
        if current_user.role not in ['client', 'admin']:
            flash('Access denied.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@client_bp.route('/dashboard')
@login_required
@client_required
def dashboard():
    """Client dashboard"""
    try:
        # Get user's scanners
        user_scanners = Scanner.query.filter_by(user_id=current_user.id, is_active=True).all()
        
        # Get recent scans
        recent_scans = Scan.query.filter_by(user_id=current_user.id)\
                                .order_by(Scan.created_at.desc()).limit(10).all()
        
        # Calculate monthly usage
        start_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        monthly_scans = Scan.query.filter(
            Scan.user_id == current_user.id,
            Scan.created_at >= start_of_month
        ).count()
        
        # Get subscription info
        subscription_level = get_client_subscription_level({'subscription_level': current_user.subscription_tier})
        subscription_features = get_subscription_features(subscription_level)
        
        # Calculate usage percentage
        max_scans = subscription_features['features']['scans_per_month']
        if max_scans == -1:  # Unlimited
            usage_percentage = 0
        else:
            usage_percentage = min(100, (monthly_scans / max_scans) * 100) if max_scans > 0 else 0
        
        # Scanner usage
        max_scanners = subscription_features['features']['scanners']
        scanner_usage = len(user_scanners)
        if max_scanners == -1:  # Unlimited
            scanner_usage_percentage = 0
        else:
            scanner_usage_percentage = min(100, (scanner_usage / max_scanners) * 100) if max_scanners > 0 else 0
        
        return render_template('client/client-dashboard.html',
                             user_scanners=user_scanners,
                             recent_scans=recent_scans,
                             monthly_scans=monthly_scans,
                             max_scans=max_scans,
                             usage_percentage=usage_percentage,
                             scanner_usage=scanner_usage,
                             max_scanners=max_scanners,
                             scanner_usage_percentage=scanner_usage_percentage,
                             subscription_level=subscription_level,
                             subscription_features=subscription_features,
                             subscription_levels=SUBSCRIPTION_LEVELS)
                             
    except Exception as e:
        logger.error(f"Dashboard error for user {current_user.id}: {e}")
        flash("Error loading dashboard. Please try again.", "error")
        return render_template('client/client-dashboard.html',
                             user_scanners=[],
                             recent_scans=[],
                             monthly_scans=0,
                             max_scans=0,
                             usage_percentage=0,
                             scanner_usage=0,
                             max_scanners=0,
                             scanner_usage_percentage=0,
                             subscription_level='basic',
                             subscription_features=SUBSCRIPTION_LEVELS['basic'],
                             subscription_levels=SUBSCRIPTION_LEVELS)

@client_bp.route('/scanners')
@login_required
@client_required
def scanners():
    """List user's scanners"""
    user_scanners = Scanner.query.filter_by(user_id=current_user.id).order_by(Scanner.created_at.desc()).all()
    
    # Get subscription limits
    subscription_level = get_client_subscription_level({'subscription_level': current_user.subscription_tier})
    subscription_features = get_subscription_features(subscription_level)
    max_scanners = subscription_features['features']['scanners']
    
    can_create_more = (max_scanners == -1) or (len(user_scanners) < max_scanners)
    
    return render_template('client/scanners.html',
                         scanners=user_scanners,
                         can_create_more=can_create_more,
                         max_scanners=max_scanners,
                         subscription_level=subscription_level)

@client_bp.route('/scanners/create', methods=['GET', 'POST'])
@login_required
@client_required
def create_scanner():
    """Create a new scanner"""
    # Check subscription limits
    subscription_level = get_client_subscription_level({'subscription_level': current_user.subscription_tier})
    subscription_features = get_subscription_features(subscription_level)
    max_scanners = subscription_features['features']['scanners']
    
    current_scanners = Scanner.query.filter_by(user_id=current_user.id).count()
    
    if max_scanners != -1 and current_scanners >= max_scanners:
        flash(f'You have reached your scanner limit ({max_scanners}). Please upgrade your subscription.', 'warning')
        return redirect(url_for('client.upgrade'))
    
    if request.method == 'POST':
        try:
            # Get form data
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            title = request.form.get('title', 'Security Scanner')
            subtitle = request.form.get('subtitle', '')
            footer_text = request.form.get('footer_text', '')
            
            # Colors
            primary_color = request.form.get('primary_color', '#2563eb')
            secondary_color = request.form.get('secondary_color', '#1e40af')
            accent_color = request.form.get('accent_color', '#3b82f6')
            background_color = request.form.get('background_color', '#ffffff')
            text_color = request.form.get('text_color', '#1f2937')
            button_color = request.form.get('button_color', '#2563eb')
            button_text_color = request.form.get('button_text_color', '#ffffff')
            
            # Features
            enable_ssl_scan = bool(request.form.get('enable_ssl_scan'))
            enable_port_scan = bool(request.form.get('enable_port_scan'))
            enable_dns_scan = bool(request.form.get('enable_dns_scan'))
            enable_header_scan = bool(request.form.get('enable_header_scan'))
            enable_vulnerability_scan = bool(request.form.get('enable_vulnerability_scan'))
            
            # Settings
            custom_domain = request.form.get('custom_domain', '').strip()
            webhook_url = request.form.get('webhook_url', '').strip()
            notification_email = request.form.get('notification_email', '').strip()
            scan_timeout = request.form.get('scan_timeout', 30, type=int)
            auto_detect_colors = bool(request.form.get('auto_detect_colors'))
            
            if not name:
                flash('Scanner name is required.', 'error')
                return render_template('client/scanner-create.html')
            
            # Create scanner
            scanner = Scanner(
                user_id=current_user.id,
                name=name,
                description=description,
                title=title,
                subtitle=subtitle,
                footer_text=footer_text,
                primary_color=primary_color,
                secondary_color=secondary_color,
                accent_color=accent_color,
                background_color=background_color,
                text_color=text_color,
                button_color=button_color,
                button_text_color=button_text_color,
                enable_ssl_scan=enable_ssl_scan,
                enable_port_scan=enable_port_scan,
                enable_dns_scan=enable_dns_scan,
                enable_header_scan=enable_header_scan,
                enable_vulnerability_scan=enable_vulnerability_scan,
                custom_domain=custom_domain,
                webhook_url=webhook_url,
                notification_email=notification_email,
                scan_timeout=scan_timeout,
                auto_detect_colors=auto_detect_colors
            )
            scanner.generate_api_key()
            
            # Handle logo upload
            if 'logo' in request.files and request.files['logo'].filename:
                logo_file = request.files['logo']
                if logo_file and allowed_file(logo_file.filename):
                    filename = secure_filename(logo_file.filename)
                    # Add timestamp to avoid conflicts
                    filename = f"{int(datetime.utcnow().timestamp())}_{filename}"
                    logo_path = os.path.join('uploads', 'logos', filename)
                    
                    # Create directory if it doesn't exist
                    os.makedirs(os.path.dirname(os.path.join('static', logo_path)), exist_ok=True)
                    
                    logo_file.save(os.path.join('static', logo_path))
                    scanner.logo_url = f'/static/{logo_path}'
            
            # Handle favicon upload
            if 'favicon' in request.files and request.files['favicon'].filename:
                favicon_file = request.files['favicon']
                if favicon_file and allowed_file(favicon_file.filename):
                    filename = secure_filename(favicon_file.filename)
                    filename = f"{int(datetime.utcnow().timestamp())}_{filename}"
                    favicon_path = os.path.join('uploads', 'favicons', filename)
                    
                    os.makedirs(os.path.dirname(os.path.join('static', favicon_path)), exist_ok=True)
                    
                    favicon_file.save(os.path.join('static', favicon_path))
                    scanner.favicon_url = f'/static/{favicon_path}'
            
            db.session.add(scanner)
            current_user.scanners_used += 1
            db.session.commit()
            
            flash('Scanner created successfully!', 'success')
            return redirect(url_for('client.scanner_detail', scanner_id=scanner.id))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Scanner creation error for user {current_user.id}: {e}")
            flash('Failed to create scanner. Please try again.', 'error')
    
    return render_template('client/scanner-create.html',
                         subscription_features=subscription_features)

@client_bp.route('/scanners/<int:scanner_id>')
@login_required
@client_required
def scanner_detail(scanner_id):
    """Scanner detail view"""
    scanner = Scanner.query.filter_by(id=scanner_id, user_id=current_user.id).first_or_404()
    
    # Get recent scans for this scanner
    recent_scans = Scan.query.filter_by(scanner_id=scanner.id)\
                            .order_by(Scan.created_at.desc()).limit(20).all()
    
    # Calculate statistics
    total_scans = Scan.query.filter_by(scanner_id=scanner.id).count()
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    monthly_scans = Scan.query.filter(
        Scan.scanner_id == scanner.id,
        Scan.created_at >= thirty_days_ago
    ).count()
    
    # Average risk score
    avg_risk = db.session.query(db.func.avg(Scan.risk_score))\
                        .filter(Scan.scanner_id == scanner.id, Scan.status == 'completed')\
                        .scalar() or 0
    
    return render_template('client/scanner-view.html',
                         scanner=scanner,
                         recent_scans=recent_scans,
                         total_scans=total_scans,
                         monthly_scans=monthly_scans,
                         avg_risk=round(avg_risk, 1))

@client_bp.route('/scanners/<int:scanner_id>/edit', methods=['GET', 'POST'])
@login_required
@client_required
def edit_scanner(scanner_id):
    """Edit scanner"""
    scanner = Scanner.query.filter_by(id=scanner_id, user_id=current_user.id).first_or_404()
    
    if request.method == 'POST':
        try:
            # Update basic info
            scanner.name = request.form.get('name', scanner.name)
            scanner.description = request.form.get('description', scanner.description)
            scanner.title = request.form.get('title', scanner.title)
            scanner.subtitle = request.form.get('subtitle', scanner.subtitle)
            scanner.footer_text = request.form.get('footer_text', scanner.footer_text)
            
            # Update colors
            scanner.primary_color = request.form.get('primary_color', scanner.primary_color)
            scanner.secondary_color = request.form.get('secondary_color', scanner.secondary_color)
            scanner.accent_color = request.form.get('accent_color', scanner.accent_color)
            scanner.background_color = request.form.get('background_color', scanner.background_color)
            scanner.text_color = request.form.get('text_color', scanner.text_color)
            scanner.button_color = request.form.get('button_color', scanner.button_color)
            scanner.button_text_color = request.form.get('button_text_color', scanner.button_text_color)
            
            # Update features
            scanner.enable_ssl_scan = bool(request.form.get('enable_ssl_scan'))
            scanner.enable_port_scan = bool(request.form.get('enable_port_scan'))
            scanner.enable_dns_scan = bool(request.form.get('enable_dns_scan'))
            scanner.enable_header_scan = bool(request.form.get('enable_header_scan'))
            scanner.enable_vulnerability_scan = bool(request.form.get('enable_vulnerability_scan'))
            
            # Update settings
            scanner.custom_domain = request.form.get('custom_domain', scanner.custom_domain)
            scanner.webhook_url = request.form.get('webhook_url', scanner.webhook_url)
            scanner.notification_email = request.form.get('notification_email', scanner.notification_email)
            scanner.scan_timeout = request.form.get('scan_timeout', scanner.scan_timeout, type=int)
            scanner.auto_detect_colors = bool(request.form.get('auto_detect_colors'))
            
            # Handle file uploads
            if 'logo' in request.files and request.files['logo'].filename:
                logo_file = request.files['logo']
                if logo_file and allowed_file(logo_file.filename):
                    filename = secure_filename(logo_file.filename)
                    filename = f"{int(datetime.utcnow().timestamp())}_{filename}"
                    logo_path = os.path.join('uploads', 'logos', filename)
                    
                    os.makedirs(os.path.dirname(os.path.join('static', logo_path)), exist_ok=True)
                    logo_file.save(os.path.join('static', logo_path))
                    scanner.logo_url = f'/static/{logo_path}'
            
            if 'favicon' in request.files and request.files['favicon'].filename:
                favicon_file = request.files['favicon']
                if favicon_file and allowed_file(favicon_file.filename):
                    filename = secure_filename(favicon_file.filename)
                    filename = f"{int(datetime.utcnow().timestamp())}_{filename}"
                    favicon_path = os.path.join('uploads', 'favicons', filename)
                    
                    os.makedirs(os.path.dirname(os.path.join('static', favicon_path)), exist_ok=True)
                    favicon_file.save(os.path.join('static', favicon_path))
                    scanner.favicon_url = f'/static/{favicon_path}'
            
            scanner.updated_at = datetime.utcnow()
            db.session.commit()
            
            flash('Scanner updated successfully!', 'success')
            return redirect(url_for('client.scanner_detail', scanner_id=scanner.id))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Scanner update error: {e}")
            flash('Failed to update scanner. Please try again.', 'error')
    
    return render_template('client/scanner-edit.html', scanner=scanner)

@client_bp.route('/scanners/<int:scanner_id>/preview')
@login_required
@client_required
def scanner_preview(scanner_id):
    """Preview scanner appearance"""
    scanner = Scanner.query.filter_by(id=scanner_id, user_id=current_user.id).first_or_404()
    return render_template('client/scanner_preview.html', scanner=scanner)

@client_bp.route('/scanners/<int:scanner_id>/deploy')
@login_required
@client_required
def deploy_scanner(scanner_id):
    """Deploy scanner (show embed code)"""
    scanner = Scanner.query.filter_by(id=scanner_id, user_id=current_user.id).first_or_404()
    
    # Generate deployment URL
    base_url = request.url_root.rstrip('/')
    deployment_url = f"{base_url}/scan/{scanner.api_key}"
    embed_code = f'<iframe src="{deployment_url}" width="100%" height="600" frameborder="0"></iframe>'
    
    return render_template('client/scanner_deployed.html',
                         scanner=scanner,
                         deployment_url=deployment_url,
                         embed_code=embed_code)

@client_bp.route('/scans')
@login_required
@client_required
def scans():
    """List user's scans"""
    page = request.args.get('page', 1, type=int)
    scanner_filter = request.args.get('scanner', '', type=int)
    status_filter = request.args.get('status', '')
    
    query = Scan.query.filter_by(user_id=current_user.id)
    
    if scanner_filter:
        query = query.filter_by(scanner_id=scanner_filter)
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    scans_pagination = query.order_by(Scan.created_at.desc())\
                           .paginate(page=page, per_page=20, error_out=False)
    
    # Get user's scanners for filter dropdown
    user_scanners = Scanner.query.filter_by(user_id=current_user.id).all()
    
    return render_template('client/scan-reports.html',
                         scans=scans_pagination.items,
                         pagination=scans_pagination,
                         user_scanners=user_scanners,
                         scanner_filter=scanner_filter,
                         status_filter=status_filter)

@client_bp.route('/scans/<int:scan_id>')
@login_required
@client_required
def scan_detail(scan_id):
    """Scan detail view"""
    scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first_or_404()
    return render_template('client/report-view.html', scan=scan)

@client_bp.route('/upgrade')
@login_required
@client_required
def upgrade():
    """Subscription upgrade page"""
    current_tier = current_user.subscription_tier
    
    return render_template('client/upgrade-subscription.html',
                         current_tier=current_tier,
                         subscription_levels=SUBSCRIPTION_LEVELS)

@client_bp.route('/upgrade/<tier>', methods=['POST'])
@login_required
@client_required
def process_upgrade(tier):
    """Process subscription upgrade"""
    if tier not in SUBSCRIPTION_LEVELS:
        flash('Invalid subscription tier.', 'error')
        return redirect(url_for('client.upgrade'))
    
    subscription_info = SUBSCRIPTION_LEVELS[tier]
    
    # For basic (free) plan, upgrade immediately
    if tier == 'basic' or subscription_info.get('price', 0) == 0:
        try:
            old_tier = current_user.subscription_tier
            current_user.subscription_tier = tier
            current_user.reset_monthly_usage()
            current_user.updated_at = datetime.utcnow()
            
            # Create subscription history record
            sub_history = SubscriptionHistory(
                user_id=current_user.id,
                old_tier=old_tier,
                new_tier=tier,
                action='upgrade' if tier != 'basic' else 'downgrade'
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
        flash('Payment processing is not yet implemented. Contact support for paid plans.', 'warning')
    
    return redirect(url_for('client.upgrade'))

@client_bp.route('/settings')
@login_required
@client_required
def settings():
    """Client settings"""
    return render_template('client/settings.html')

# Helper functions
def allowed_file(filename):
    """Check if file extension is allowed"""
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg', 'ico'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# API endpoints
@client_bp.route('/api/dashboard-stats')
@login_required
@client_required
def api_dashboard_stats():
    """API endpoint for dashboard statistics"""
    try:
        # Monthly usage
        start_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        monthly_scans = Scan.query.filter(
            Scan.user_id == current_user.id,
            Scan.created_at >= start_of_month
        ).count()
        
        # Recent activity
        recent_scans = Scan.query.filter_by(user_id=current_user.id)\
                                .order_by(Scan.created_at.desc()).limit(5).all()
        
        scan_data = []
        for scan in recent_scans:
            scan_data.append({
                'id': scan.id,
                'domain': scan.domain,
                'status': scan.status,
                'risk_score': scan.risk_score,
                'created_at': scan.created_at.isoformat() if scan.created_at else None
            })
        
        return jsonify({
            'monthly_scans': monthly_scans,
            'recent_scans': scan_data
        })
        
    except Exception as e:
        logger.error(f"API dashboard stats error: {e}")
        return jsonify({'error': 'Failed to load stats'}), 500

@client_bp.route('/api/extract-colors', methods=['POST'])
@login_required
@client_required
def api_extract_colors():
    """API endpoint to extract colors from a website"""
    try:
        data = request.get_json()
        website_url = data.get('url')
        
        if not website_url:
            return jsonify({'error': 'Website URL is required'}), 400
        
        # Check subscription limits for advanced features
        subscription_level = get_client_subscription_level({'subscription_level': current_user.subscription_level})
        features = get_subscription_features(subscription_level)
        
        if not features['features'].get('custom_css', False) and subscription_level == 'basic':
            return jsonify({'error': 'Color extraction requires a paid subscription'}), 403
        
        # Extract colors from the website
        color_analysis = extract_website_colors(website_url)
        
        if color_analysis['success']:
            return jsonify({
                'success': True,
                'palette': color_analysis['suggested_palette'],
                'recommendations': color_analysis['recommendations'],
                'extracted_data': {
                    'logo_url': color_analysis['extracted_colors']['logo_colors'].get('logo_url'),
                    'favicon_url': color_analysis['extracted_colors']['logo_colors'].get('favicon_url'),
                    'total_colors_found': len(color_analysis['extracted_colors']['css_colors']) + 
                                        len(color_analysis['extracted_colors']['inline_colors'])
                }
            })
        else:
            return jsonify({
                'success': False,
                'error': color_analysis.get('error', 'Failed to extract colors'),
                'palette': color_analysis['suggested_palette']  # Fallback palette
            }), 400
        
    except Exception as e:
        logger.error(f"Color extraction error: {e}")
        return jsonify({'error': 'Failed to extract colors'}), 500