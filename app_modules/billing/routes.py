#!/usr/bin/env python3
"""
Billing Routes for CybrScan
Handles subscription upgrades, payments, and billing management
"""

import os
import json
import logging
from flask import render_template, request, jsonify, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from . import billing_bp
from models import db, User, BillingTransaction
from payment_handler import PaymentHandler
from subscription_constants import SUBSCRIPTION_LEVELS, get_subscription_features

logger = logging.getLogger(__name__)

# Initialize payment handler
payment_handler = PaymentHandler()

@billing_bp.route('/upgrade')
@login_required
def upgrade():
    """Show subscription upgrade options"""
    current_features = get_subscription_features(current_user.subscription_level)
    return render_template('billing/upgrade.html', 
                         subscription_levels=SUBSCRIPTION_LEVELS,
                         current_subscription=current_user.subscription_level,
                         current_features=current_features)

@billing_bp.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    """Create Stripe checkout session for subscription upgrade"""
    try:
        data = request.get_json()
        subscription_level = data.get('subscription_level')
        
        if not subscription_level or subscription_level not in SUBSCRIPTION_LEVELS:
            return jsonify({'error': 'Invalid subscription level'}), 400
        
        # Don't allow downgrade to basic (should be handled separately)
        if subscription_level == 'basic':
            return jsonify({'error': 'Cannot upgrade to basic plan'}), 400
        
        # Create success and cancel URLs
        success_url = url_for('billing.payment_success', _external=True)
        cancel_url = url_for('billing.upgrade', _external=True)
        
        # Create checkout session
        session = payment_handler.create_checkout_session(
            user_id=current_user.id,
            subscription_level=subscription_level,
            success_url=success_url,
            cancel_url=cancel_url
        )
        
        return jsonify({'checkout_url': session.url})
        
    except Exception as e:
        logger.error(f"Error creating checkout session: {e}")
        return jsonify({'error': 'Failed to create checkout session'}), 500

@billing_bp.route('/payment-success')
@login_required  
def payment_success():
    """Handle successful payment redirect"""
    try:
        session_id = request.args.get('session_id')
        if not session_id:
            flash('Invalid payment session', 'error')
            return redirect(url_for('client.dashboard'))
        
        # Handle the successful payment
        success = payment_handler.handle_successful_payment(session_id)
        
        if success:
            flash('Subscription upgraded successfully!', 'success')
            return render_template('billing/payment_success.html')
        else:
            flash('Payment verification failed', 'error')
            return redirect(url_for('billing.upgrade'))
            
    except Exception as e:
        logger.error(f"Error handling payment success: {e}")
        flash('Error processing payment', 'error')
        return redirect(url_for('billing.upgrade'))

@billing_bp.route('/manage-subscription')
@login_required
def manage_subscription():
    """Redirect to Stripe customer portal for subscription management"""
    try:
        if not current_user.stripe_customer_id:
            flash('No active subscription found', 'error')
            return redirect(url_for('billing.upgrade'))
        
        return_url = url_for('client.dashboard', _external=True)
        session = payment_handler.create_portal_session(
            customer_id=current_user.stripe_customer_id,
            return_url=return_url
        )
        
        return redirect(session.url)
        
    except Exception as e:
        logger.error(f"Error creating portal session: {e}")
        flash('Error accessing subscription management', 'error')
        return redirect(url_for('client.dashboard'))

@billing_bp.route('/cancel-subscription', methods=['POST'])
@login_required
def cancel_subscription():
    """Cancel user's subscription"""
    try:
        success = payment_handler.cancel_subscription(current_user.id)
        
        if success:
            flash('Subscription cancelled successfully', 'success')
        else:
            flash('Error cancelling subscription', 'error')
            
        return redirect(url_for('client.dashboard'))
        
    except Exception as e:
        logger.error(f"Error cancelling subscription: {e}")
        flash('Error cancelling subscription', 'error')
        return redirect(url_for('client.dashboard'))

@billing_bp.route('/billing-history')
@login_required
def billing_history():
    """Show user's billing history"""
    transactions = BillingTransaction.query.filter_by(
        user_id=current_user.id
    ).order_by(BillingTransaction.created_at.desc()).all()
    
    return render_template('billing/billing_history.html', transactions=transactions)

@billing_bp.route('/webhook', methods=['POST'])
def stripe_webhook():
    """Handle Stripe webhook events"""
    try:
        payload = request.data
        sig_header = request.headers.get('stripe-signature')
        
        success = payment_handler.handle_webhook(payload, sig_header)
        
        if success:
            return '', 200
        else:
            return '', 400
            
    except Exception as e:
        logger.error(f"Webhook error: {e}")
        return '', 400

@billing_bp.route('/api/subscription-status')
@login_required
def api_subscription_status():
    """API endpoint to get current subscription status"""
    try:
        status = payment_handler.get_subscription_status(current_user.id)
        
        return jsonify({
            'subscription_level': current_user.subscription_level,
            'subscription_status': current_user.subscription_status,
            'next_billing_date': current_user.next_billing_date.isoformat() if current_user.next_billing_date else None,
            'stripe_status': status.status if status else None
        })
        
    except Exception as e:
        logger.error(f"Error getting subscription status: {e}")
        return jsonify({'error': 'Failed to get subscription status'}), 500

@billing_bp.route('/api/revenue-calculator', methods=['POST'])
@login_required
def revenue_calculator():
    """Calculate potential MSP revenue based on subscription level"""
    try:
        data = request.get_json()
        clients_per_month = data.get('clients_per_month', 10)
        subscription_level = data.get('subscription_level', current_user.subscription_level)
        
        from subscription_constants import calculate_msp_revenue_potential
        
        revenue_data = calculate_msp_revenue_potential(subscription_level, clients_per_month)
        return jsonify(revenue_data)
        
    except Exception as e:
        logger.error(f"Error calculating revenue: {e}")
        return jsonify({'error': 'Failed to calculate revenue'}), 500

@billing_bp.route('/msp-dashboard')
@login_required
def msp_dashboard():
    """MSP revenue and analytics dashboard"""
    # Get user's commission history
    commission_transactions = BillingTransaction.query.filter_by(
        user_id=current_user.id,
        transaction_type='commission'
    ).order_by(BillingTransaction.created_at.desc()).limit(10).all()
    
    # Calculate total commission earned
    total_commission = sum(t.amount for t in commission_transactions if t.status == 'completed')
    
    # Get subscription features
    features = get_subscription_features(current_user.subscription_level)
    
    return render_template('billing/msp_dashboard.html',
                         commission_transactions=commission_transactions,
                         total_commission=total_commission,
                         subscription_features=features,
                         current_subscription=current_user.subscription_level)