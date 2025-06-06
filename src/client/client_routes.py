#!/usr/bin/env python3
"""
Client Routes
Handles client dashboard, scanner management, subscription management
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
import os
import json
import secrets
import string
from io import BytesIO
import csv

from models import db, User, Scanner, Scan, ScannerCustomization, SubscriptionHistory
from subscription_constants import SUBSCRIPTION_LEVELS, get_subscription_features, get_client_scanner_limit, get_client_scan_limit

client_bp = Blueprint('client', __name__)

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'ico'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@client_bp.route('/dashboard')
@login_required
def dashboard():
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    # Get user's scanners
    scanners = Scanner.query.filter_by(user_id=current_user.id).order_by(Scanner.created_at.desc()).all()
    
    # Get recent scans
    recent_scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).limit(10).all()
    
    # Calculate statistics
    total_scans = Scan.query.filter_by(user_id=current_user.id).count()
    completed_scans = Scan.query.filter_by(user_id=current_user.id, status='completed').count()
    failed_scans = Scan.query.filter_by(user_id=current_user.id, status='failed').count()
    
    # This month's scans
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    month_scans = Scan.query.filter_by(user_id=current_user.id).filter(Scan.created_at >= month_start).count()
    
    # Average risk score
    avg_risk_score = db.session.query(db.func.avg(Scan.risk_score)).filter_by(user_id=current_user.id, status='completed').scalar()
    avg_risk_score = round(avg_risk_score or 0, 1)
    
    # Get subscription info
    subscription_features = get_subscription_features(current_user.subscription_tier)
    scanner_limit = get_client_scanner_limit({'subscription_level': current_user.subscription_tier})
    scan_limit = get_client_scan_limit({'subscription_level': current_user.subscription_tier})
    
    stats = {
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'failed_scans': failed_scans,
        'month_scans': month_scans,
        'avg_risk_score': avg_risk_score,
        'scanners_count': len(scanners),
        'scanners_limit': scanner_limit,
        'scans_limit': scan_limit,
        'scans_this_month': current_user.scans_this_month
    }
    
    return render_template('client/client-dashboard.html', 
                         scanners=scanners, 
                         recent_scans=recent_scans,
                         stats=stats,
                         subscription_features=subscription_features)

@client_bp.route('/scanners')
@login_required
def scanners():
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    scanners = Scanner.query.filter_by(user_id=current_user.id).order_by(Scanner.created_at.desc()).all()
    scanner_limit = get_client_scanner_limit({'subscription_level': current_user.subscription_tier})
    
    return render_template('client/scanners.html', 
                         scanners=scanners, 
                         scanner_limit=scanner_limit)

@client_bp.route('/scanners/create')
@login_required
def create_scanner():
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    # Check scanner limits
    if not current_user.can_create_scanner():
        flash('Scanner limit reached. Please upgrade your subscription.', 'warning')
        return redirect(url_for('client.upgrade_subscription'))
    
    return render_template('client/scanner-create.html')

@client_bp.route('/scanners/create', methods=['POST'])
@login_required
def create_scanner_post():
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    # Check scanner limits
    if not current_user.can_create_scanner():
        flash('Scanner limit reached. Please upgrade your subscription.', 'warning')
        return redirect(url_for('client.upgrade_subscription'))
    
    name = request.form.get('name', '').strip()
    description = request.form.get('description', '').strip()
    
    if not name:
        flash('Scanner name is required.', 'error')
        return render_template('client/scanner-create.html', name=name, description=description)
    
    # Create scanner
    scanner = Scanner(
        user_id=current_user.id,
        name=name,
        description=description
    )
    scanner.generate_api_key()
    
    db.session.add(scanner)
    current_user.scanners_used += 1
    db.session.commit()
    
    flash('Scanner created successfully!', 'success')
    return redirect(url_for('client.edit_scanner', scanner_id=scanner.id))

@client_bp.route('/scanners/<int:scanner_id>')
@login_required
def view_scanner(scanner_id):
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    scanner = Scanner.query.filter_by(id=scanner_id, user_id=current_user.id).first()
    if not scanner:
        flash('Scanner not found.', 'error')
        return redirect(url_for('client.scanners'))
    
    # Get scanner scans
    scans = Scan.query.filter_by(scanner_id=scanner.id).order_by(Scan.created_at.desc()).limit(50).all()
    
    return render_template('client/scanner-view.html', scanner=scanner, scans=scans)

@client_bp.route('/scanners/<int:scanner_id>/edit')
@login_required
def edit_scanner(scanner_id):
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    scanner = Scanner.query.filter_by(id=scanner_id, user_id=current_user.id).first()
    if not scanner:
        flash('Scanner not found.', 'error')
        return redirect(url_for('client.scanners'))
    
    return render_template('client/scanner-edit.html', scanner=scanner)

@client_bp.route('/scanners/<int:scanner_id>/edit', methods=['POST'])
@login_required
def edit_scanner_post(scanner_id):
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    scanner = Scanner.query.filter_by(id=scanner_id, user_id=current_user.id).first()
    if not scanner:
        flash('Scanner not found.', 'error')
        return redirect(url_for('client.scanners'))
    
    # Basic settings
    scanner.name = request.form.get('name', '').strip()
    scanner.description = request.form.get('description', '').strip()
    scanner.notification_email = request.form.get('notification_email', '').strip()
    scanner.scan_timeout = int(request.form.get('scan_timeout', 30))
    
    # Branding
    scanner.title = request.form.get('title', 'Security Scanner').strip()
    scanner.subtitle = request.form.get('subtitle', '').strip()
    scanner.footer_text = request.form.get('footer_text', '').strip()
    
    # Colors
    scanner.primary_color = request.form.get('primary_color', '#2563eb')
    scanner.secondary_color = request.form.get('secondary_color', '#1e40af')
    scanner.accent_color = request.form.get('accent_color', '#3b82f6')
    scanner.background_color = request.form.get('background_color', '#ffffff')
    scanner.text_color = request.form.get('text_color', '#1f2937')
    scanner.button_color = request.form.get('button_color', '#2563eb')
    scanner.button_text_color = request.form.get('button_text_color', '#ffffff')
    
    # Features
    scanner.enable_ssl_scan = bool(request.form.get('enable_ssl_scan'))
    scanner.enable_port_scan = bool(request.form.get('enable_port_scan'))
    scanner.enable_dns_scan = bool(request.form.get('enable_dns_scan'))
    scanner.enable_header_scan = bool(request.form.get('enable_header_scan'))
    scanner.enable_vulnerability_scan = bool(request.form.get('enable_vulnerability_scan'))
    
    # Auto color detection
    scanner.auto_detect_colors = bool(request.form.get('auto_detect_colors'))
    
    # Handle file uploads
    if 'logo' in request.files:
        file = request.files['logo']
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(f"logo_{scanner.id}_{secrets.token_hex(8)}.{file.filename.rsplit('.', 1)[1].lower()}")
            file_path = os.path.join('uploads', filename)
            file.save(file_path)
            scanner.logo_url = f'/uploads/{filename}'
    
    if 'favicon' in request.files:
        file = request.files['favicon']
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(f"favicon_{scanner.id}_{secrets.token_hex(8)}.{file.filename.rsplit('.', 1)[1].lower()}")
            file_path = os.path.join('uploads', filename)
            file.save(file_path)
            scanner.favicon_url = f'/uploads/{filename}'
    
    scanner.updated_at = datetime.utcnow()
    db.session.commit()
    
    flash('Scanner updated successfully!', 'success')
    return redirect(url_for('client.edit_scanner', scanner_id=scanner.id))

@client_bp.route('/scanners/<int:scanner_id>/customize')
@login_required
def customize_scanner(scanner_id):
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    scanner = Scanner.query.filter_by(id=scanner_id, user_id=current_user.id).first()
    if not scanner:
        flash('Scanner not found.', 'error')
        return redirect(url_for('client.scanners'))
    
    return render_template('client/customize_scanner.html', scanner=scanner)

@client_bp.route('/scanners/<int:scanner_id>/preview')
@login_required
def preview_scanner(scanner_id):
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    scanner = Scanner.query.filter_by(id=scanner_id, user_id=current_user.id).first()
    if not scanner:
        flash('Scanner not found.', 'error')
        return redirect(url_for('client.scanners'))
    
    return render_template('client/scanner_preview.html', scanner=scanner)

@client_bp.route('/scanners/<int:scanner_id>/deploy')
@login_required
def deploy_scanner(scanner_id):
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    scanner = Scanner.query.filter_by(id=scanner_id, user_id=current_user.id).first()
    if not scanner:
        flash('Scanner not found.', 'error')
        return redirect(url_for('client.scanners'))
    
    # Generate deployment files
    base_url = request.url_root.rstrip('/')
    scanner_url = f"{base_url}/scan/{scanner.api_key}"
    embed_code = f'<iframe src="{scanner_url}" width="100%" height="600" frameborder="0"></iframe>'
    
    return render_template('client/scanner_deployed.html', 
                         scanner=scanner, 
                         scanner_url=scanner_url,
                         embed_code=embed_code)

@client_bp.route('/scanners/<int:scanner_id>/delete', methods=['POST'])
@login_required
def delete_scanner(scanner_id):
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    scanner = Scanner.query.filter_by(id=scanner_id, user_id=current_user.id).first()
    if not scanner:
        flash('Scanner not found.', 'error')
        return redirect(url_for('client.scanners'))
    
    # Delete all related scans and customizations
    Scan.query.filter_by(scanner_id=scanner.id).delete()
    ScannerCustomization.query.filter_by(scanner_id=scanner.id).delete()
    
    db.session.delete(scanner)
    current_user.scanners_used = max(0, current_user.scanners_used - 1)
    db.session.commit()
    
    flash('Scanner deleted successfully!', 'success')
    return redirect(url_for('client.scanners'))

@client_bp.route('/reports')
@login_required
def reports():
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    # Get filters
    scanner_id = request.args.get('scanner_id', type=int)
    status = request.args.get('status')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    
    # Build query
    query = Scan.query.filter_by(user_id=current_user.id)
    
    if scanner_id:
        query = query.filter_by(scanner_id=scanner_id)
    
    if status:
        query = query.filter_by(status=status)
    
    if date_from:
        try:
            date_from = datetime.strptime(date_from, '%Y-%m-%d')
            query = query.filter(Scan.created_at >= date_from)
        except ValueError:
            pass
    
    if date_to:
        try:
            date_to = datetime.strptime(date_to, '%Y-%m-%d') + timedelta(days=1)
            query = query.filter(Scan.created_at < date_to)
        except ValueError:
            pass
    
    scans = query.order_by(Scan.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    # Get user's scanners for filter
    scanners = Scanner.query.filter_by(user_id=current_user.id).all()
    
    return render_template('client/reports.html', 
                         scans=scans, 
                         scanners=scanners,
                         current_filters={
                             'scanner_id': scanner_id,
                             'status': status,
                             'date_from': request.args.get('date_from', ''),
                             'date_to': request.args.get('date_to', '')
                         })

@client_bp.route('/reports/<scan_id>')
@login_required
def view_report(scan_id):
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    scan = Scan.query.filter_by(scan_id=scan_id, user_id=current_user.id).first()
    if not scan:
        flash('Report not found.', 'error')
        return redirect(url_for('client.reports'))
    
    return render_template('client/report-view.html', scan=scan)

@client_bp.route('/reports/export')
@login_required
def export_reports():
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    # Get all scans for the user
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).all()
    
    # Create CSV
    output = BytesIO()
    output.write('\ufeff'.encode('utf-8'))  # BOM for Excel compatibility
    
    writer = csv.writer(output.getvalue().decode('utf-8'))
    writer.writerow([
        'Scan ID', 'Domain', 'Scanner', 'Status', 'Risk Score', 
        'Vulnerabilities', 'Contact Name', 'Contact Email', 
        'Contact Company', 'Created At', 'Completed At'
    ])
    
    for scan in scans:
        writer.writerow([
            scan.scan_id,
            scan.domain,
            scan.scanner.name if scan.scanner else '',
            scan.status,
            scan.risk_score or 0,
            scan.vulnerabilities_found or 0,
            scan.contact_name or '',
            scan.contact_email or '',
            scan.contact_company or '',
            scan.created_at.strftime('%Y-%m-%d %H:%M:%S') if scan.created_at else '',
            scan.completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan.completed_at else ''
        ])
    
    output.seek(0)
    
    return send_file(
        BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'cybrscan_reports_{datetime.utcnow().strftime("%Y%m%d")}.csv'
    )

@client_bp.route('/subscription')
@login_required
def subscription():
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    current_features = get_subscription_features(current_user.subscription_tier)
    
    # Get subscription history
    history = SubscriptionHistory.query.filter_by(user_id=current_user.id).order_by(SubscriptionHistory.created_at.desc()).limit(10).all()
    
    return render_template('client/subscription.html', 
                         current_features=current_features,
                         subscription_levels=SUBSCRIPTION_LEVELS,
                         history=history)

@client_bp.route('/upgrade-subscription')
@login_required
def upgrade_subscription():
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    return render_template('client/upgrade-subscription.html', 
                         subscription_levels=SUBSCRIPTION_LEVELS,
                         current_tier=current_user.subscription_tier)

@client_bp.route('/upgrade-subscription', methods=['POST'])
@login_required
def upgrade_subscription_post():
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    new_tier = request.form.get('tier')
    
    if new_tier not in SUBSCRIPTION_LEVELS:
        flash('Invalid subscription tier.', 'error')
        return redirect(url_for('client.upgrade_subscription'))
    
    if new_tier == current_user.subscription_tier:
        flash('You are already on this subscription tier.', 'info')
        return redirect(url_for('client.subscription'))
    
    # For now, just update the tier (implement Stripe payment later)
    old_tier = current_user.subscription_tier
    current_user.subscription_tier = new_tier
    current_user.updated_at = datetime.utcnow()
    
    # Record history
    history = SubscriptionHistory(
        user_id=current_user.id,
        old_tier=old_tier,
        new_tier=new_tier,
        action='upgrade' if SUBSCRIPTION_LEVELS[new_tier]['price'] > SUBSCRIPTION_LEVELS[old_tier]['price'] else 'downgrade',
        amount=SUBSCRIPTION_LEVELS[new_tier]['price']
    )
    
    db.session.add(history)
    db.session.commit()
    
    flash(f'Successfully upgraded to {SUBSCRIPTION_LEVELS[new_tier]["name"]}!', 'success')
    return redirect(url_for('client.subscription'))

@client_bp.route('/settings')
@login_required
def settings():
    if current_user.role != 'client':
        flash('Client access required.', 'error')
        return redirect(url_for('admin.dashboard'))
    
    return render_template('client/settings.html')

@client_bp.route('/api/detect-colors', methods=['POST'])
@login_required
def detect_colors():
    """API endpoint to detect colors from a website"""
    if current_user.role != 'client':
        return jsonify({'error': 'Unauthorized'}), 403
    
    domain = request.json.get('domain', '').strip()
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    try:
        # This would use a web scraping library to extract colors
        # For now, return mock data
        colors = {
            'primary_color': '#2563eb',
            'secondary_color': '#1e40af',
            'accent_color': '#3b82f6',
            'background_color': '#ffffff',
            'text_color': '#1f2937'
        }
        
        return jsonify(colors)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500