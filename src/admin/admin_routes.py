#!/usr/bin/env python3
"""
Admin Routes
Handles admin dashboard, user management, system settings
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, send_file
from flask_login import login_required, current_user
from datetime import datetime, timedelta
from sqlalchemy import func, desc
import csv
from io import BytesIO

from models import db, User, Scanner, Scan, SubscriptionHistory, AdminSettings
from subscription_constants import SUBSCRIPTION_LEVELS

admin_bp = Blueprint('admin', __name__)

def admin_required(f):
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    # Get key statistics
    total_users = User.query.filter_by(role='client').count()
    active_users = User.query.filter_by(role='client', is_active=True).count()
    total_scanners = Scanner.query.count()
    active_scanners = Scanner.query.filter_by(is_active=True).count()
    total_scans = Scan.query.count()
    
    # Recent activity
    recent_users = User.query.filter_by(role='client').order_by(desc(User.created_at)).limit(5).all()
    recent_scans = Scan.query.order_by(desc(Scan.created_at)).limit(10).all()
    
    # Monthly stats
    month_start = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    month_users = User.query.filter_by(role='client').filter(User.created_at >= month_start).count()
    month_scans = Scan.query.filter(Scan.created_at >= month_start).count()
    
    # Revenue stats (subscription tiers)
    revenue_stats = []
    for tier_key, tier_data in SUBSCRIPTION_LEVELS.items():
        user_count = User.query.filter_by(subscription_tier=tier_key, role='client').count()
        monthly_revenue = user_count * tier_data['price']
        revenue_stats.append({
            'tier': tier_data['name'],
            'users': user_count,
            'price': tier_data['price'],
            'revenue': monthly_revenue
        })
    
    total_monthly_revenue = sum(stat['revenue'] for stat in revenue_stats)
    
    # System health
    failed_scans_today = Scan.query.filter(
        Scan.status == 'failed',
        Scan.created_at >= datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
    ).count()
    
    stats = {
        'total_users': total_users,
        'active_users': active_users,
        'total_scanners': total_scanners,
        'active_scanners': active_scanners,
        'total_scans': total_scans,
        'month_users': month_users,
        'month_scans': month_scans,
        'total_monthly_revenue': total_monthly_revenue,
        'failed_scans_today': failed_scans_today
    }
    
    return render_template('admin/admin-dashboard.html',
                         stats=stats,
                         revenue_stats=revenue_stats,
                         recent_users=recent_users,
                         recent_scans=recent_scans)

@admin_bp.route('/users')
@login_required
@admin_required
def users():
    page = request.args.get('page', 1, type=int)
    per_page = 25
    
    # Get filters
    search = request.args.get('search', '').strip()
    tier = request.args.get('tier', '')
    status = request.args.get('status', '')
    
    # Build query
    query = User.query.filter_by(role='client')
    
    if search:
        query = query.filter(
            db.or_(
                User.email.contains(search),
                User.username.contains(search),
                User.company_name.contains(search)
            )
        )
    
    if tier:
        query = query.filter_by(subscription_tier=tier)
    
    if status == 'active':
        query = query.filter_by(is_active=True)
    elif status == 'inactive':
        query = query.filter_by(is_active=False)
    elif status == 'verified':
        query = query.filter_by(email_verified=True)
    elif status == 'unverified':
        query = query.filter_by(email_verified=False)
    
    users = query.order_by(desc(User.created_at)).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('admin/user-management.html',
                         users=users,
                         subscription_levels=SUBSCRIPTION_LEVELS,
                         current_filters={
                             'search': search,
                             'tier': tier,
                             'status': status
                         })

@admin_bp.route('/users/<int:user_id>')
@login_required
@admin_required
def view_user(user_id):
    user = User.query.filter_by(id=user_id, role='client').first()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin.users'))
    
    # Get user's scanners and scans
    scanners = Scanner.query.filter_by(user_id=user.id).all()
    recent_scans = Scan.query.filter_by(user_id=user.id).order_by(desc(Scan.created_at)).limit(20).all()
    
    # Get subscription history
    history = SubscriptionHistory.query.filter_by(user_id=user.id).order_by(desc(SubscriptionHistory.created_at)).all()
    
    # Calculate user stats
    total_scans = Scan.query.filter_by(user_id=user.id).count()
    completed_scans = Scan.query.filter_by(user_id=user.id, status='completed').count()
    avg_risk_score = db.session.query(func.avg(Scan.risk_score)).filter_by(user_id=user.id, status='completed').scalar()
    
    user_stats = {
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'avg_risk_score': round(avg_risk_score or 0, 1),
        'scanners_count': len(scanners)
    }
    
    return render_template('admin/client-view.html',
                         user=user,
                         scanners=scanners,
                         recent_scans=recent_scans,
                         history=history,
                         user_stats=user_stats,
                         subscription_levels=SUBSCRIPTION_LEVELS)

@admin_bp.route('/users/<int:user_id>/edit', methods=['POST'])
@login_required
@admin_required
def edit_user(user_id):
    user = User.query.filter_by(id=user_id, role='client').first()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin.users'))
    
    action = request.form.get('action')
    
    if action == 'update_subscription':
        new_tier = request.form.get('subscription_tier')
        if new_tier in SUBSCRIPTION_LEVELS and new_tier != user.subscription_tier:
            old_tier = user.subscription_tier
            user.subscription_tier = new_tier
            
            # Record history
            history = SubscriptionHistory(
                user_id=user.id,
                old_tier=old_tier,
                new_tier=new_tier,
                action='admin_change'
            )
            db.session.add(history)
            
            flash(f'Subscription updated to {SUBSCRIPTION_LEVELS[new_tier]["name"]}.', 'success')
        else:
            flash('Invalid subscription tier.', 'error')
    
    elif action == 'toggle_status':
        user.is_active = not user.is_active
        status = 'activated' if user.is_active else 'deactivated'
        flash(f'User {status} successfully.', 'success')
    
    elif action == 'verify_email':
        user.email_verified = True
        user.email_verification_token = None
        flash('Email verified successfully.', 'success')
    
    elif action == 'reset_usage':
        user.reset_monthly_usage()
        flash('Monthly usage reset successfully.', 'success')
    
    user.updated_at = datetime.utcnow()
    db.session.commit()
    
    return redirect(url_for('admin.view_user', user_id=user_id))

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = User.query.filter_by(id=user_id, role='client').first()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('admin.users'))
    
    # Delete all user data
    Scan.query.filter_by(user_id=user.id).delete()
    Scanner.query.filter_by(user_id=user.id).delete()
    SubscriptionHistory.query.filter_by(user_id=user.id).delete()
    
    db.session.delete(user)
    db.session.commit()
    
    flash('User and all associated data deleted successfully.', 'success')
    return redirect(url_for('admin.users'))

@admin_bp.route('/scanners')
@login_required
@admin_required
def scanners():
    page = request.args.get('page', 1, type=int)
    per_page = 25
    
    # Get filters
    search = request.args.get('search', '').strip()
    user_id = request.args.get('user_id', type=int)
    status = request.args.get('status', '')
    
    # Build query
    query = Scanner.query.join(User)
    
    if search:
        query = query.filter(
            db.or_(
                Scanner.name.contains(search),
                Scanner.description.contains(search),
                User.email.contains(search),
                User.company_name.contains(search)
            )
        )
    
    if user_id:
        query = query.filter_by(user_id=user_id)
    
    if status == 'active':
        query = query.filter(Scanner.is_active == True)
    elif status == 'inactive':
        query = query.filter(Scanner.is_active == False)
    
    scanners = query.order_by(desc(Scanner.created_at)).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('admin/scanner-management.html',
                         scanners=scanners,
                         current_filters={
                             'search': search,
                             'user_id': user_id,
                             'status': status
                         })

@admin_bp.route('/scanners/<int:scanner_id>')
@login_required
@admin_required
def view_scanner(scanner_id):
    scanner = Scanner.query.get_or_404(scanner_id)
    
    # Get scanner scans
    scans = Scan.query.filter_by(scanner_id=scanner.id).order_by(desc(Scan.created_at)).limit(50).all()
    
    # Calculate scanner stats
    total_scans = Scan.query.filter_by(scanner_id=scanner.id).count()
    completed_scans = Scan.query.filter_by(scanner_id=scanner.id, status='completed').count()
    avg_risk_score = db.session.query(func.avg(Scan.risk_score)).filter_by(scanner_id=scanner.id, status='completed').scalar()
    
    scanner_stats = {
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'avg_risk_score': round(avg_risk_score or 0, 1)
    }
    
    return render_template('admin/scanner-view.html',
                         scanner=scanner,
                         scans=scans,
                         scanner_stats=scanner_stats)

@admin_bp.route('/scanners/<int:scanner_id>/toggle', methods=['POST'])
@login_required
@admin_required
def toggle_scanner(scanner_id):
    scanner = Scanner.query.get_or_404(scanner_id)
    scanner.is_active = not scanner.is_active
    scanner.updated_at = datetime.utcnow()
    db.session.commit()
    
    status = 'activated' if scanner.is_active else 'deactivated'
    flash(f'Scanner {status} successfully.', 'success')
    return redirect(url_for('admin.view_scanner', scanner_id=scanner_id))

@admin_bp.route('/scans')
@login_required
@admin_required
def scans():
    page = request.args.get('page', 1, type=int)
    per_page = 50
    
    # Get filters
    search = request.args.get('search', '').strip()
    status = request.args.get('status', '')
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    
    # Build query
    query = Scan.query.join(Scanner).join(User)
    
    if search:
        query = query.filter(
            db.or_(
                Scan.domain.contains(search),
                Scan.contact_email.contains(search),
                Scan.contact_company.contains(search),
                User.email.contains(search)
            )
        )
    
    if status:
        query = query.filter(Scan.status == status)
    
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
    
    scans = query.order_by(desc(Scan.created_at)).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return render_template('admin/scan-reports.html',
                         scans=scans,
                         current_filters={
                             'search': search,
                             'status': status,
                             'date_from': request.args.get('date_from', ''),
                             'date_to': request.args.get('date_to', '')
                         })

@admin_bp.route('/scans/<scan_id>')
@login_required
@admin_required
def view_scan(scan_id):
    scan = Scan.query.filter_by(scan_id=scan_id).first_or_404()
    return render_template('admin/scan-view.html', scan=scan)

@admin_bp.route('/reports')
@login_required
@admin_required
def reports():
    # Date range for reports
    end_date = datetime.utcnow()
    start_date = end_date - timedelta(days=30)
    
    # User growth
    user_growth = []
    for i in range(30):
        date = start_date + timedelta(days=i)
        count = User.query.filter_by(role='client').filter(User.created_at <= date).count()
        user_growth.append({
            'date': date.strftime('%Y-%m-%d'),
            'count': count
        })
    
    # Scan activity
    scan_activity = []
    for i in range(30):
        date = start_date + timedelta(days=i)
        next_date = date + timedelta(days=1)
        count = Scan.query.filter(
            Scan.created_at >= date,
            Scan.created_at < next_date
        ).count()
        scan_activity.append({
            'date': date.strftime('%Y-%m-%d'),
            'count': count
        })
    
    # Revenue breakdown
    revenue_breakdown = []
    for tier_key, tier_data in SUBSCRIPTION_LEVELS.items():
        user_count = User.query.filter_by(subscription_tier=tier_key, role='client').count()
        revenue_breakdown.append({
            'tier': tier_data['name'],
            'users': user_count,
            'revenue': user_count * tier_data['price']
        })
    
    # Top scanners by usage
    top_scanners = db.session.query(
        Scanner.name,
        Scanner.total_scans,
        User.company_name
    ).join(User).order_by(desc(Scanner.total_scans)).limit(10).all()
    
    return render_template('admin/reports-dashboard.html',
                         user_growth=user_growth,
                         scan_activity=scan_activity,
                         revenue_breakdown=revenue_breakdown,
                         top_scanners=top_scanners)

@admin_bp.route('/settings')
@login_required
@admin_required
def settings():
    # Get all admin settings
    settings = {}
    all_settings = AdminSettings.query.all()
    for setting in all_settings:
        settings[setting.key] = setting.value
    
    return render_template('admin/settings-dashboard.html', settings=settings)

@admin_bp.route('/settings', methods=['POST'])
@login_required
@admin_required
def settings_post():
    # Update settings
    settings_to_update = [
        'site_name', 'support_email', 'smtp_server', 'smtp_port',
        'smtp_username', 'smtp_use_tls', 'max_scan_timeout',
        'rate_limit_per_minute', 'maintenance_mode'
    ]
    
    for key in settings_to_update:
        value = request.form.get(key, '').strip()
        if value or key in ['smtp_use_tls', 'maintenance_mode']:
            AdminSettings.set(key, value)
    
    flash('Settings updated successfully!', 'success')
    return redirect(url_for('admin.settings'))

@admin_bp.route('/export/users')
@login_required
@admin_required
def export_users():
    users = User.query.filter_by(role='client').order_by(User.created_at.desc()).all()
    
    output = BytesIO()
    output.write('\ufeff'.encode('utf-8'))  # BOM for Excel compatibility
    
    writer = csv.writer(output.getvalue().decode('utf-8'))
    writer.writerow([
        'ID', 'Email', 'Username', 'Company', 'Phone', 'Subscription',
        'Status', 'Email Verified', 'Scanners', 'Total Scans',
        'Scans This Month', 'Created At', 'Last Login'
    ])
    
    for user in users:
        writer.writerow([
            user.id,
            user.email,
            user.username,
            user.company_name or '',
            user.phone or '',
            user.subscription_tier,
            'Active' if user.is_active else 'Inactive',
            'Yes' if user.email_verified else 'No',
            user.scanners_used,
            user.scans.count(),
            user.scans_this_month,
            user.created_at.strftime('%Y-%m-%d %H:%M:%S') if user.created_at else '',
            user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else ''
        ])
    
    output.seek(0)
    
    return send_file(
        BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'cybrscan_users_{datetime.utcnow().strftime("%Y%m%d")}.csv'
    )

@admin_bp.route('/export/scans')
@login_required
@admin_required
def export_scans():
    scans = Scan.query.join(Scanner).join(User).order_by(desc(Scan.created_at)).all()
    
    output = BytesIO()
    output.write('\ufeff'.encode('utf-8'))  # BOM for Excel compatibility
    
    writer = csv.writer(output.getvalue().decode('utf-8'))
    writer.writerow([
        'Scan ID', 'Domain', 'Scanner', 'User Email', 'Company',
        'Status', 'Risk Score', 'Vulnerabilities', 'Contact Name',
        'Contact Email', 'Contact Company', 'IP Address',
        'Created At', 'Completed At'
    ])
    
    for scan in scans:
        writer.writerow([
            scan.scan_id,
            scan.domain,
            scan.scanner.name if scan.scanner else '',
            scan.user.email if scan.user else '',
            scan.user.company_name if scan.user else '',
            scan.status,
            scan.risk_score or 0,
            scan.vulnerabilities_found or 0,
            scan.contact_name or '',
            scan.contact_email or '',
            scan.contact_company or '',
            scan.ip_address or '',
            scan.created_at.strftime('%Y-%m-%d %H:%M:%S') if scan.created_at else '',
            scan.completed_at.strftime('%Y-%m-%d %H:%M:%S') if scan.completed_at else ''
        ])
    
    output.seek(0)
    
    return send_file(
        BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'cybrscan_scans_{datetime.utcnow().strftime("%Y%m%d")}.csv'
    )