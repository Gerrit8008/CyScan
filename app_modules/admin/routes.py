"""
Admin Routes
"""

from flask import render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_required, current_user
from functools import wraps
from app_modules.admin import admin_bp
from models import db, User, Scanner, Scan, SubscriptionHistory, AdminSettings, BillingTransaction, Lead
from subscription_constants import SUBSCRIPTION_LEVELS, calculate_msp_revenue_potential
from datetime import datetime, timedelta
import logging
import json
from sqlalchemy import func, extract

logger = logging.getLogger(__name__)

def admin_required(f):
    """Decorator to require admin role"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('auth.login'))
        return f(*args, **kwargs)
    return decorated_function

@admin_bp.route('/dashboard')
@login_required
@admin_required
def dashboard():
    """Comprehensive admin dashboard with analytics"""
    try:
        # Basic statistics
        total_users = User.query.filter_by(role='client').count()
        total_scanners = Scanner.query.count()
        total_scans = Scan.query.count()
        total_leads = Lead.query.count()
        
        # Revenue statistics
        total_revenue = db.session.query(func.sum(BillingTransaction.amount))\
            .filter(BillingTransaction.status == 'completed',
                   BillingTransaction.transaction_type == 'subscription').scalar() or 0
        
        monthly_revenue = db.session.query(func.sum(BillingTransaction.amount))\
            .filter(BillingTransaction.status == 'completed',
                   BillingTransaction.transaction_type == 'subscription',
                   BillingTransaction.created_at >= datetime.utcnow().replace(day=1)).scalar() or 0
        
        # Subscription breakdown with revenue
        subscription_stats = {}
        subscription_revenue = {}
        for level, details in SUBSCRIPTION_LEVELS.items():
            count = User.query.filter_by(subscription_level=level, role='client').count()
            subscription_stats[level] = count
            subscription_revenue[level] = count * details['price']
        
        # Growth metrics (30 days)
        thirty_days_ago = datetime.utcnow() - timedelta(days=30)
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        
        new_users_30d = User.query.filter(User.created_at >= thirty_days_ago, User.role == 'client').count()
        new_users_7d = User.query.filter(User.created_at >= seven_days_ago, User.role == 'client').count()
        monthly_scans = Scan.query.filter(Scan.created_at >= thirty_days_ago).count()
        weekly_scans = Scan.query.filter(Scan.created_at >= seven_days_ago).count()
        
        # Top performing scanners
        top_scanners = db.session.query(
            Scanner, func.count(Scan.id).label('scan_count')
        ).join(Scan).group_by(Scanner.id)\
         .order_by(func.count(Scan.id).desc()).limit(5).all()
        
        # Recent activity
        recent_users = User.query.filter_by(role='client').order_by(User.created_at.desc()).limit(5).all()
        recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
        recent_transactions = BillingTransaction.query.order_by(BillingTransaction.created_at.desc()).limit(5).all()
        
        # Lead generation metrics
        leads_this_month = Lead.query.filter(Lead.created_at >= datetime.utcnow().replace(day=1)).count()
        conversion_rate = 0
        if total_leads > 0:
            converted_leads = Lead.query.filter_by(converted_to_client=True).count()
            conversion_rate = (converted_leads / total_leads) * 100
        
        # Scanner usage by subscription level
        scanner_usage = {}
        for level in SUBSCRIPTION_LEVELS.keys():
            users_at_level = User.query.filter_by(subscription_level=level, role='client').all()
            total_scanners_at_level = sum(user.scanners.count() for user in users_at_level)
            scanner_usage[level] = total_scanners_at_level
        
        # Weekly scan trends (last 12 weeks)
        weekly_trends = []
        for i in range(12):
            week_start = datetime.utcnow() - timedelta(weeks=i+1)
            week_end = datetime.utcnow() - timedelta(weeks=i)
            week_scans = Scan.query.filter(
                Scan.created_at >= week_start,
                Scan.created_at < week_end
            ).count()
            weekly_trends.append({
                'week': week_start.strftime('%Y-%m-%d'),
                'scans': week_scans
            })
        weekly_trends.reverse()
        
        # Risk analysis
        high_risk_scans = Scan.query.filter(Scan.risk_score < 60).count()
        medium_risk_scans = Scan.query.filter(Scan.risk_score >= 60, Scan.risk_score < 80).count()
        low_risk_scans = Scan.query.filter(Scan.risk_score >= 80).count()
        
        # MSP Performance metrics
        msp_metrics = calculate_msp_revenue_potential('professional', 50)  # Example calculation
        
        return render_template('admin/admin-dashboard.html',
                             # Basic stats
                             total_users=total_users,
                             total_scanners=total_scanners,
                             total_scans=total_scans,
                             total_leads=total_leads,
                             
                             # Revenue
                             total_revenue=total_revenue,
                             monthly_revenue=monthly_revenue,
                             subscription_stats=subscription_stats,
                             subscription_revenue=subscription_revenue,
                             
                             # Growth
                             new_users_30d=new_users_30d,
                             new_users_7d=new_users_7d,
                             monthly_scans=monthly_scans,
                             weekly_scans=weekly_scans,
                             
                             # Performance
                             top_scanners=top_scanners,
                             scanner_usage=scanner_usage,
                             
                             # Recent activity
                             recent_users=recent_users,
                             recent_scans=recent_scans,
                             recent_transactions=recent_transactions,
                             
                             # Analytics
                             leads_this_month=leads_this_month,
                             conversion_rate=conversion_rate,
                             weekly_trends=weekly_trends,
                             
                             # Risk analysis
                             high_risk_scans=high_risk_scans,
                             medium_risk_scans=medium_risk_scans,
                             low_risk_scans=low_risk_scans,
                             
                             # MSP metrics
                             msp_metrics=msp_metrics,
                             
                             subscription_levels=SUBSCRIPTION_LEVELS)
        
    except Exception as e:
        logger.error(f"Admin dashboard error: {e}")
        # Fallback to basic dashboard
        total_users = User.query.filter_by(role='client').count()
        total_scanners = Scanner.query.count()
        total_scans = Scan.query.count()
        
        return render_template('admin/admin-dashboard.html',
                             total_users=total_users,
                             total_scanners=total_scanners,
                             total_scans=total_scans,
                             error_message="Some analytics data unavailable",
                             subscription_levels=SUBSCRIPTION_LEVELS)

@admin_bp.route('/users')
@login_required
@admin_required
def users():
    """User management"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    tier_filter = request.args.get('tier', '')
    
    query = User.query.filter_by(role='client')
    
    if search:
        query = query.filter(
            (User.email.contains(search)) |
            (User.username.contains(search)) |
            (User.company_name.contains(search))
        )
    
    if tier_filter and tier_filter in SUBSCRIPTION_LEVELS:
        query = query.filter_by(subscription_tier=tier_filter)
    
    users_pagination = query.order_by(User.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    return render_template('admin/users.html',
                         users=users_pagination.items,
                         pagination=users_pagination,
                         subscription_levels=SUBSCRIPTION_LEVELS,
                         current_search=search,
                         current_tier=tier_filter)

@admin_bp.route('/users/<int:user_id>')
@login_required
@admin_required
def user_detail(user_id):
    """User detail view"""
    user = User.query.get_or_404(user_id)
    
    if user.role != 'client':
        flash('User not found.', 'error')
        return redirect(url_for('admin.users'))
    
    # Get user's scanners and scans
    scanners = Scanner.query.filter_by(user_id=user.id).all()
    recent_scans = Scan.query.filter_by(user_id=user.id).order_by(Scan.created_at.desc()).limit(10).all()
    subscription_history = SubscriptionHistory.query.filter_by(user_id=user.id).order_by(SubscriptionHistory.created_at.desc()).all()
    
    # Monthly usage
    start_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    monthly_scans = Scan.query.filter(
        Scan.user_id == user.id,
        Scan.created_at >= start_of_month
    ).count()
    
    return render_template('admin/user_detail.html',
                         user=user,
                         scanners=scanners,
                         recent_scans=recent_scans,
                         subscription_history=subscription_history,
                         monthly_scans=monthly_scans,
                         subscription_levels=SUBSCRIPTION_LEVELS)

@admin_bp.route('/users/<int:user_id>/update', methods=['POST'])
@login_required
@admin_required
def update_user(user_id):
    """Update user details"""
    user = User.query.get_or_404(user_id)
    
    if user.role != 'client':
        flash('User not found.', 'error')
        return redirect(url_for('admin.users'))
    
    action = request.form.get('action')
    
    try:
        if action == 'update_subscription':
            new_tier = request.form.get('subscription_tier')
            if new_tier in SUBSCRIPTION_LEVELS:
                old_tier = user.subscription_tier
                user.subscription_tier = new_tier
                user.reset_monthly_usage()
                
                # Create history record
                sub_history = SubscriptionHistory(
                    user_id=user.id,
                    old_tier=old_tier,
                    new_tier=new_tier,
                    action='admin_change'
                )
                db.session.add(sub_history)
                
                flash(f'Subscription updated to {SUBSCRIPTION_LEVELS[new_tier]["name"]}.', 'success')
            else:
                flash('Invalid subscription tier.', 'error')
        
        elif action == 'toggle_status':
            user.is_active = not user.is_active
            status = 'activated' if user.is_active else 'deactivated'
            flash(f'User {status} successfully.', 'success')
        
        elif action == 'reset_usage':
            user.reset_monthly_usage()
            flash('Monthly usage reset successfully.', 'success')
        
        elif action == 'update_profile':
            user.username = request.form.get('username', user.username)
            user.company_name = request.form.get('company_name', user.company_name)
            user.phone = request.form.get('phone', user.phone)
            flash('Profile updated successfully.', 'success')
        
        user.updated_at = datetime.utcnow()
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to update user {user_id}: {e}')
        flash('Update failed. Please try again.', 'error')
    
    return redirect(url_for('admin.user_detail', user_id=user_id))

@admin_bp.route('/scanners')
@login_required
@admin_required
def scanners():
    """Scanner management"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    
    query = Scanner.query.join(User)
    
    if search:
        query = query.filter(
            (Scanner.name.contains(search)) |
            (User.email.contains(search)) |
            (User.company_name.contains(search))
        )
    
    scanners_pagination = query.order_by(Scanner.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    return render_template('admin/scanners.html',
                         scanners=scanners_pagination.items,
                         pagination=scanners_pagination,
                         current_search=search)

@admin_bp.route('/scanners/<int:scanner_id>')
@login_required
@admin_required
def scanner_detail(scanner_id):
    """Scanner detail view"""
    scanner = Scanner.query.get_or_404(scanner_id)
    
    # Get recent scans for this scanner
    recent_scans = Scan.query.filter_by(scanner_id=scanner.id).order_by(Scan.created_at.desc()).limit(20).all()
    
    # Scanner statistics
    total_scans = Scan.query.filter_by(scanner_id=scanner.id).count()
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    monthly_scans = Scan.query.filter(
        Scan.scanner_id == scanner.id,
        Scan.created_at >= thirty_days_ago
    ).count()
    
    return render_template('admin/scanner_detail.html',
                         scanner=scanner,
                         recent_scans=recent_scans,
                         total_scans=total_scans,
                         monthly_scans=monthly_scans)

@admin_bp.route('/scanners/<int:scanner_id>/update', methods=['POST'])
@login_required
@admin_required
def update_scanner(scanner_id):
    """Update scanner settings"""
    scanner = Scanner.query.get_or_404(scanner_id)
    
    action = request.form.get('action')
    
    try:
        if action == 'toggle_status':
            scanner.is_active = not scanner.is_active
            status = 'activated' if scanner.is_active else 'deactivated'
            flash(f'Scanner {status} successfully.', 'success')
        
        elif action == 'update_name':
            scanner.name = request.form.get('name', scanner.name)
            scanner.description = request.form.get('description', scanner.description)
            flash('Scanner details updated successfully.', 'success')
        
        scanner.updated_at = datetime.utcnow()
        db.session.commit()
        
    except Exception as e:
        db.session.rollback()
        logger.error(f'Failed to update scanner {scanner_id}: {e}')
        flash('Update failed. Please try again.', 'error')
    
    return redirect(url_for('admin.scanner_detail', scanner_id=scanner_id))

@admin_bp.route('/scans')
@login_required
@admin_required
def scans():
    """Scan management"""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    
    query = Scan.query.join(User).join(Scanner)
    
    if search:
        query = query.filter(
            (Scan.domain.contains(search)) |
            (User.email.contains(search)) |
            (Scanner.name.contains(search))
        )
    
    if status_filter:
        query = query.filter_by(status=status_filter)
    
    scans_pagination = query.order_by(Scan.created_at.desc()).paginate(
        page=page, per_page=50, error_out=False
    )
    
    return render_template('admin/scans.html',
                         scans=scans_pagination.items,
                         pagination=scans_pagination,
                         current_search=search,
                         current_status=status_filter)

@admin_bp.route('/scans/<int:scan_id>')
@login_required
@admin_required
def scan_detail(scan_id):
    """Scan detail view"""
    scan = Scan.query.get_or_404(scan_id)
    
    return render_template('admin/scan_detail.html', scan=scan)

@admin_bp.route('/settings')
@login_required
@admin_required
def settings():
    """Admin settings"""
    settings = {}
    
    # Get all admin settings
    admin_settings = AdminSettings.query.all()
    for setting in admin_settings:
        settings[setting.key] = setting.value
    
    return render_template('admin/settings.html', settings=settings)

@admin_bp.route('/settings/update', methods=['POST'])
@login_required
@admin_required
def update_settings():
    """Update admin settings"""
    try:
        for key, value in request.form.items():
            if key.startswith('setting_'):
                setting_key = key[8:]  # Remove 'setting_' prefix
                AdminSettings.set(setting_key, value)
        
        flash('Settings updated successfully.', 'success')
        
    except Exception as e:
        logger.error(f'Failed to update settings: {e}')
        flash('Settings update failed. Please try again.', 'error')
    
    return redirect(url_for('admin.settings'))

@admin_bp.route('/reports')
@login_required
@admin_required
def reports():
    """Admin reports and analytics"""
    # Date range
    days = request.args.get('days', 30, type=int)
    start_date = datetime.utcnow() - timedelta(days=days)
    
    # User growth
    new_users = User.query.filter(
        User.role == 'client',
        User.created_at >= start_date
    ).count()
    
    # Scan activity
    total_scans = Scan.query.filter(Scan.created_at >= start_date).count()
    avg_daily_scans = total_scans / days if days > 0 else 0
    
    # Top domains scanned
    top_domains = db.session.query(
        Scan.domain,
        db.func.count(Scan.id).label('count')
    ).filter(
        Scan.created_at >= start_date
    ).group_by(Scan.domain).order_by(
        db.func.count(Scan.id).desc()
    ).limit(10).all()
    
    # Risk score distribution
    risk_stats = db.session.query(
        db.func.avg(Scan.risk_score).label('avg_risk'),
        db.func.min(Scan.risk_score).label('min_risk'),
        db.func.max(Scan.risk_score).label('max_risk')
    ).filter(
        Scan.created_at >= start_date,
        Scan.status == 'completed'
    ).first()
    
    return render_template('admin/reports.html',
                         days=days,
                         new_users=new_users,
                         total_scans=total_scans,
                         avg_daily_scans=round(avg_daily_scans, 1),
                         top_domains=top_domains,
                         risk_stats=risk_stats)

# API endpoints for admin dashboard
@admin_bp.route('/api/stats')
@login_required
@admin_required
def api_stats():
    """API endpoint for dashboard statistics"""
    total_users = User.query.filter_by(role='client').count()
    total_scanners = Scanner.query.count()
    total_scans = Scan.query.count()
    
    # Monthly growth
    thirty_days_ago = datetime.utcnow() - timedelta(days=30)
    monthly_users = User.query.filter(
        User.role == 'client',
        User.created_at >= thirty_days_ago
    ).count()
    monthly_scans = Scan.query.filter(Scan.created_at >= thirty_days_ago).count()
    
    return jsonify({
        'total_users': total_users,
        'total_scanners': total_scanners,
        'total_scans': total_scans,
        'monthly_users': monthly_users,
        'monthly_scans': monthly_scans
    })

@admin_bp.route('/api/scan-activity')
@login_required
@admin_required
def api_scan_activity():
    """API endpoint for scan activity chart"""
    days = request.args.get('days', 7, type=int)
    
    scan_data = []
    for i in range(days):
        date = datetime.utcnow() - timedelta(days=i)
        start = date.replace(hour=0, minute=0, second=0, microsecond=0)
        end = start + timedelta(days=1)
        
        count = Scan.query.filter(
            Scan.created_at >= start,
            Scan.created_at < end
        ).count()
        
        scan_data.append({
            'date': start.strftime('%Y-%m-%d'),
            'count': count
        })
    
    return jsonify(list(reversed(scan_data)))

# Lead Management Routes
@admin_bp.route('/leads')
@login_required
@admin_required
def leads():
    """Lead management dashboard"""
    page = request.args.get('page', 1, type=int)
    status_filter = request.args.get('status', '')
    search = request.args.get('search', '')
    
    query = Lead.query
    
    if status_filter:
        query = query.filter_by(lead_status=status_filter)
    
    if search:
        query = query.filter(
            (Lead.name.contains(search)) |
            (Lead.email.contains(search)) |
            (Lead.company.contains(search)) |
            (Lead.website.contains(search))
        )
    
    leads_pagination = query.order_by(Lead.created_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    # Lead statistics
    total_leads = Lead.query.count()
    converted_leads = Lead.query.filter_by(converted_to_client=True).count()
    this_month_leads = Lead.query.filter(
        Lead.created_at >= datetime.utcnow().replace(day=1)
    ).count()
    
    conversion_rate = (converted_leads / total_leads * 100) if total_leads > 0 else 0
    
    return render_template('admin/leads.html',
                         leads=leads_pagination.items,
                         pagination=leads_pagination,
                         total_leads=total_leads,
                         converted_leads=converted_leads,
                         this_month_leads=this_month_leads,
                         conversion_rate=conversion_rate,
                         current_search=search,
                         current_status=status_filter)

@admin_bp.route('/leads/<int:lead_id>')
@login_required
@admin_required
def lead_detail(lead_id):
    """Lead detail view"""
    lead = Lead.query.get_or_404(lead_id)
    
    # Get associated scan data
    scan_history = Scan.query.filter_by(contact_email=lead.email)\
                            .order_by(Scan.created_at.desc()).all()
    
    # Get MSP owner information
    msp_owner = User.query.get(lead.user_id)
    scanner = Scanner.query.get(lead.scanner_id)
    
    return render_template('admin/lead_detail.html',
                         lead=lead,
                         scan_history=scan_history,
                         msp_owner=msp_owner,
                         scanner=scanner)

# Analytics Routes
@admin_bp.route('/analytics')
@login_required
@admin_required
def analytics():
    """Advanced analytics dashboard"""
    # Revenue analytics
    monthly_revenue_data = []
    for i in range(12):
        month_start = datetime.utcnow().replace(day=1) - timedelta(days=30*i)
        month_end = month_start + timedelta(days=30)
        
        revenue = db.session.query(func.sum(BillingTransaction.amount))\
            .filter(BillingTransaction.status == 'completed',
                   BillingTransaction.created_at >= month_start,
                   BillingTransaction.created_at < month_end).scalar() or 0
        
        monthly_revenue_data.append({
            'month': month_start.strftime('%Y-%m'),
            'revenue': float(revenue)
        })
    
    monthly_revenue_data.reverse()
    
    # User growth
    user_growth_data = []
    for i in range(12):
        month_start = datetime.utcnow().replace(day=1) - timedelta(days=30*i)
        month_end = month_start + timedelta(days=30)
        
        new_users = User.query.filter(
            User.role == 'client',
            User.created_at >= month_start,
            User.created_at < month_end
        ).count()
        
        user_growth_data.append({
            'month': month_start.strftime('%Y-%m'),
            'users': new_users
        })
    
    user_growth_data.reverse()
    
    # Scanner performance
    scanner_performance = db.session.query(
        Scanner.name,
        Scanner.id,
        func.count(Scan.id).label('total_scans'),
        func.count(Lead.id).label('leads_generated'),
        func.avg(Scan.risk_score).label('avg_risk_score')
    ).outerjoin(Scan).outerjoin(Lead)\
     .group_by(Scanner.id).order_by(func.count(Scan.id).desc()).limit(10).all()
    
    # Subscription distribution
    subscription_distribution = []
    for level, details in SUBSCRIPTION_LEVELS.items():
        count = User.query.filter_by(subscription_level=level, role='client').count()
        subscription_distribution.append({
            'level': details['name'],
            'count': count,
            'revenue': count * details['price']
        })
    
    return render_template('admin/analytics.html',
                         monthly_revenue_data=monthly_revenue_data,
                         user_growth_data=user_growth_data,
                         scanner_performance=scanner_performance,
                         subscription_distribution=subscription_distribution)

# Revenue Management
@admin_bp.route('/revenue')
@login_required
@admin_required
def revenue():
    """Revenue management dashboard"""
    # Recent transactions
    recent_transactions = BillingTransaction.query\
        .order_by(BillingTransaction.created_at.desc()).limit(20).all()
    
    # Revenue by subscription level
    revenue_by_level = {}
    for level, details in SUBSCRIPTION_LEVELS.items():
        users_count = User.query.filter_by(subscription_level=level, role='client').count()
        revenue_by_level[level] = {
            'users': users_count,
            'monthly_revenue': users_count * details['price'],
            'annual_revenue': users_count * details['price'] * 12
        }
    
    # Failed payments
    failed_payments = BillingTransaction.query\
        .filter_by(status='failed').order_by(BillingTransaction.created_at.desc()).limit(10).all()
    
    # Commission calculations
    total_commission_owed = db.session.query(func.sum(BillingTransaction.amount))\
        .filter(BillingTransaction.transaction_type == 'commission',
               BillingTransaction.status == 'pending').scalar() or 0
    
    return render_template('admin/revenue.html',
                         recent_transactions=recent_transactions,
                         revenue_by_level=revenue_by_level,
                         failed_payments=failed_payments,
                         total_commission_owed=total_commission_owed,
                         subscription_levels=SUBSCRIPTION_LEVELS)

# System Settings
@admin_bp.route('/system-settings')
@login_required
@admin_required
def system_settings():
    """System settings management"""
    # Get current settings
    settings = {
        'smtp_configured': bool(AdminSettings.get('smtp_server')),
        'stripe_configured': bool(AdminSettings.get('stripe_publishable_key')),
        'maintenance_mode': AdminSettings.get('maintenance_mode', 'false').lower() == 'true',
        'max_scans_per_day': AdminSettings.get('max_scans_per_day', '1000'),
        'default_subscription': AdminSettings.get('default_subscription', 'basic'),
    }
    
    # System health checks
    health_checks = {
        'database': True,  # We can query if we're here
        'email_service': bool(AdminSettings.get('smtp_server')),
        'payment_service': bool(AdminSettings.get('stripe_secret_key')),
        'disk_space': True,  # Placeholder
    }
    
    return render_template('admin/system_settings.html',
                         settings=settings,
                         health_checks=health_checks,
                         subscription_levels=SUBSCRIPTION_LEVELS)

@admin_bp.route('/system-settings/update', methods=['POST'])
@login_required
@admin_required
def update_system_settings():
    """Update system settings"""
    try:
        # Update settings from form
        maintenance_mode = 'true' if request.form.get('maintenance_mode') else 'false'
        AdminSettings.set('maintenance_mode', maintenance_mode)
        
        max_scans = request.form.get('max_scans_per_day', '1000')
        AdminSettings.set('max_scans_per_day', max_scans)
        
        default_subscription = request.form.get('default_subscription', 'basic')
        AdminSettings.set('default_subscription', default_subscription)
        
        flash('System settings updated successfully', 'success')
        
    except Exception as e:
        logger.error(f"Error updating system settings: {e}")
        flash('Error updating system settings', 'error')
    
    return redirect(url_for('admin.system_settings'))