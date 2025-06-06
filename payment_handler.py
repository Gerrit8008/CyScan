#!/usr/bin/env python3
"""
Payment Handler for CybrScan
Handles Stripe integration for subscription management and billing
"""

import stripe
import os
import logging
from datetime import datetime, timedelta
from flask import current_app
from models import db, User, BillingTransaction

logger = logging.getLogger(__name__)

class PaymentHandler:
    def __init__(self):
        # Initialize Stripe with API keys
        stripe.api_key = os.environ.get('STRIPE_SECRET_KEY')
        self.publishable_key = os.environ.get('STRIPE_PUBLISHABLE_KEY')
        self.webhook_secret = os.environ.get('STRIPE_WEBHOOK_SECRET')
        
        # Price IDs for each subscription level (set these in Stripe dashboard)
        self.price_ids = {
            'starter': os.environ.get('STRIPE_STARTER_PRICE_ID', 'price_starter'),
            'professional': os.environ.get('STRIPE_PROFESSIONAL_PRICE_ID', 'price_professional'), 
            'enterprise': os.environ.get('STRIPE_ENTERPRISE_PRICE_ID', 'price_enterprise')
        }
    
    def create_checkout_session(self, user_id, subscription_level, success_url, cancel_url):
        """Create a Stripe checkout session for subscription upgrade"""
        try:
            user = User.query.get(user_id)
            if not user:
                raise ValueError("User not found")
            
            # Get the price ID for the subscription level
            price_id = self.price_ids.get(subscription_level)
            if not price_id:
                raise ValueError(f"Invalid subscription level: {subscription_level}")
            
            # Create checkout session
            session = stripe.checkout.Session.create(
                payment_method_types=['card'],
                line_items=[{
                    'price': price_id,
                    'quantity': 1,
                }],
                mode='subscription',
                success_url=success_url + '?session_id={CHECKOUT_SESSION_ID}',
                cancel_url=cancel_url,
                customer_email=user.email,
                metadata={
                    'user_id': user_id,
                    'subscription_level': subscription_level
                },
                allow_promotion_codes=True,
                billing_address_collection='required',
                customer_creation='always'
            )
            
            logger.info(f"Created checkout session for user {user_id}: {session.id}")
            return session
            
        except Exception as e:
            logger.error(f"Error creating checkout session: {e}")
            raise
    
    def handle_successful_payment(self, session_id):
        """Handle successful payment and upgrade user subscription"""
        try:
            # Retrieve the checkout session
            session = stripe.checkout.Session.retrieve(session_id)
            
            if session.payment_status == 'paid':
                user_id = session.metadata.get('user_id')
                subscription_level = session.metadata.get('subscription_level')
                
                # Update user subscription
                user = User.query.get(user_id)
                if user:
                    user.subscription_level = subscription_level
                    user.stripe_customer_id = session.customer
                    user.subscription_status = 'active'
                    user.subscription_start_date = datetime.utcnow()
                    
                    # Calculate next billing date
                    user.next_billing_date = datetime.utcnow() + timedelta(days=30)
                    
                    db.session.commit()
                    
                    # Record billing transaction
                    self.record_transaction(
                        user_id=user_id,
                        amount=session.amount_total / 100,  # Convert from cents
                        currency=session.currency,
                        subscription_level=subscription_level,
                        stripe_session_id=session_id,
                        status='completed'
                    )
                    
                    logger.info(f"Successfully upgraded user {user_id} to {subscription_level}")
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error handling successful payment: {e}")
            raise
    
    def create_portal_session(self, customer_id, return_url):
        """Create a Stripe customer portal session for managing subscriptions"""
        try:
            session = stripe.billing_portal.Session.create(
                customer=customer_id,
                return_url=return_url,
            )
            return session
            
        except Exception as e:
            logger.error(f"Error creating portal session: {e}")
            raise
    
    def cancel_subscription(self, user_id):
        """Cancel a user's subscription"""
        try:
            user = User.query.get(user_id)
            if not user or not user.stripe_customer_id:
                raise ValueError("User or customer not found")
            
            # Get customer's subscriptions
            subscriptions = stripe.Subscription.list(
                customer=user.stripe_customer_id,
                status='active'
            )
            
            # Cancel all active subscriptions
            for subscription in subscriptions.data:
                stripe.Subscription.delete(subscription.id)
            
            # Update user status
            user.subscription_status = 'cancelled'
            user.subscription_level = 'basic'  # Downgrade to basic
            db.session.commit()
            
            logger.info(f"Cancelled subscription for user {user_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error cancelling subscription: {e}")
            raise
    
    def record_transaction(self, user_id, amount, currency, subscription_level, 
                          stripe_session_id=None, status='pending'):
        """Record a billing transaction in the database"""
        try:
            transaction = BillingTransaction(
                user_id=user_id,
                amount=amount,
                currency=currency,
                subscription_level=subscription_level,
                stripe_session_id=stripe_session_id,
                status=status,
                created_at=datetime.utcnow()
            )
            
            db.session.add(transaction)
            db.session.commit()
            
            logger.info(f"Recorded transaction for user {user_id}: {amount} {currency}")
            return transaction
            
        except Exception as e:
            logger.error(f"Error recording transaction: {e}")
            raise
    
    def handle_webhook(self, payload, sig_header):
        """Handle Stripe webhook events"""
        try:
            event = stripe.Webhook.construct_event(
                payload, sig_header, self.webhook_secret
            )
            
            # Handle different event types
            if event['type'] == 'checkout.session.completed':
                session = event['data']['object']
                self.handle_successful_payment(session['id'])
            
            elif event['type'] == 'invoice.payment_succeeded':
                invoice = event['data']['object']
                self.handle_recurring_payment(invoice)
            
            elif event['type'] == 'invoice.payment_failed':
                invoice = event['data']['object']
                self.handle_failed_payment(invoice)
            
            elif event['type'] == 'customer.subscription.deleted':
                subscription = event['data']['object']
                self.handle_subscription_cancelled(subscription)
            
            logger.info(f"Handled webhook event: {event['type']}")
            return True
            
        except Exception as e:
            logger.error(f"Error handling webhook: {e}")
            raise
    
    def handle_recurring_payment(self, invoice):
        """Handle recurring subscription payments"""
        try:
            customer_id = invoice['customer']
            
            # Find user by Stripe customer ID
            user = User.query.filter_by(stripe_customer_id=customer_id).first()
            if user:
                # Update next billing date
                user.next_billing_date = datetime.utcnow() + timedelta(days=30)
                
                # Record transaction
                self.record_transaction(
                    user_id=user.id,
                    amount=invoice['amount_paid'] / 100,
                    currency=invoice['currency'],
                    subscription_level=user.subscription_level,
                    status='completed'
                )
                
                db.session.commit()
                logger.info(f"Processed recurring payment for user {user.id}")
            
        except Exception as e:
            logger.error(f"Error handling recurring payment: {e}")
            raise
    
    def handle_failed_payment(self, invoice):
        """Handle failed payment attempts"""
        try:
            customer_id = invoice['customer']
            
            # Find user by Stripe customer ID
            user = User.query.filter_by(stripe_customer_id=customer_id).first()
            if user:
                # Mark subscription as past due
                user.subscription_status = 'past_due'
                
                # Record failed transaction
                self.record_transaction(
                    user_id=user.id,
                    amount=invoice['amount_due'] / 100,
                    currency=invoice['currency'],
                    subscription_level=user.subscription_level,
                    status='failed'
                )
                
                db.session.commit()
                logger.warning(f"Payment failed for user {user.id}")
            
        except Exception as e:
            logger.error(f"Error handling failed payment: {e}")
            raise
    
    def handle_subscription_cancelled(self, subscription):
        """Handle subscription cancellation"""
        try:
            customer_id = subscription['customer']
            
            # Find user by Stripe customer ID
            user = User.query.filter_by(stripe_customer_id=customer_id).first()
            if user:
                user.subscription_status = 'cancelled'
                user.subscription_level = 'basic'
                db.session.commit()
                
                logger.info(f"Subscription cancelled for user {user.id}")
            
        except Exception as e:
            logger.error(f"Error handling subscription cancellation: {e}")
            raise
    
    def get_subscription_status(self, user_id):
        """Get the current subscription status for a user"""
        try:
            user = User.query.get(user_id)
            if not user or not user.stripe_customer_id:
                return None
            
            # Get customer's subscriptions from Stripe
            subscriptions = stripe.Subscription.list(
                customer=user.stripe_customer_id,
                limit=1
            )
            
            if subscriptions.data:
                return subscriptions.data[0]
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting subscription status: {e}")
            return None
    
    def calculate_msp_commission(self, user, revenue_amount):
        """Calculate commission for MSP based on subscription level"""
        commission_rates = {
            'starter': 0.10,      # 10% commission
            'professional': 0.15,  # 15% commission
            'enterprise': 0.20     # 20% commission
        }
        
        rate = commission_rates.get(user.subscription_level, 0)
        commission = revenue_amount * rate
        
        # Record commission
        commission_record = BillingTransaction(
            user_id=user.id,
            amount=commission,
            currency='USD',
            subscription_level=user.subscription_level,
            transaction_type='commission',
            status='pending',
            created_at=datetime.utcnow()
        )
        
        db.session.add(commission_record)
        db.session.commit()
        
        return commission