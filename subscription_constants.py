#!/usr/bin/env python3
"""
Subscription Constants for CybrScan MSP Platform

This file defines the subscription levels and their features.
Designed specifically for MSPs to offer white-label security services.
"""

# Legacy plan mapping for backward compatibility
LEGACY_PLAN_MAPPING = {
    'business': 'professional',
    'pro': 'professional'
}

# Subscription level definitions with comprehensive MSP features
SUBSCRIPTION_LEVELS = {
    'basic': {
        'name': 'Basic',
        'price': 0.00,  # Free forever - no credit card required
        'period': 'forever',
        'description': 'Perfect for trying out our platform',
        'features': {
            'scanners': 1,
            'scans_per_month': 10,
            'white_label': False,
            'branding': 'Basic branding',
            'reports': 'Email reports',
            'support': 'Community support',
            'api_access': False,
            'client_portal': False,
            'lead_capture': True,
            'custom_domain': False,
            'priority_scanning': False,
            'advanced_analytics': False
        }
    },
    'starter': {
        'name': 'Starter',
        'price': 59.00,
        'period': 'month',
        'description': 'Perfect for small MSPs getting started',
        'features': {
            'scanners': 1,
            'scans_per_month': 50,
            'white_label': True,
            'branding': 'White-label branding',
            'reports': 'Professional reporting',
            'support': 'Email support',
            'api_access': False,
            'client_portal': True,
            'lead_capture': True,
            'custom_domain': False,
            'priority_scanning': False,
            'advanced_analytics': True,
            'integrations': 'Basic integrations',
            'email_templates': True
        }
    },
    'professional': {
        'name': 'Professional',
        'price': 99.00,
        'period': 'month',
        'description': 'Ideal for growing MSPs',
        'popular': True,
        'features': {
            'scanners': 3,
            'scans_per_month': 500,
            'white_label': True,
            'branding': 'Advanced white-labeling',
            'reports': 'Advanced reporting',
            'support': 'Priority phone support',
            'api_access': True,
            'client_portal': True,
            'lead_capture': True,
            'custom_domain': True,
            'priority_scanning': True,
            'advanced_analytics': True,
            'integrations': 'Custom integrations',
            'scheduled_scanning': True,
            'email_templates': True,
            'custom_css': True,
            'multi_client': True
        }
    },
    'enterprise': {
        'name': 'Enterprise',
        'price': 149.00,
        'period': 'month',
        'description': 'For large MSPs and enterprises',
        'features': {
            'scanners': 10,
            'scans_per_month': 1000,
            'white_label': True,
            'branding': 'Complete white-labeling',
            'reports': 'Executive reporting',
            'support': '24/7 dedicated support',
            'api_access': True,
            'client_portal': True,
            'lead_capture': True,
            'custom_domain': True,
            'priority_scanning': True,
            'advanced_analytics': True,
            'integrations': 'Custom development',
            'scheduled_scanning': True,
            'email_templates': True,
            'custom_css': True,
            'multi_client': True,
            'sla': True,
            'training': True,
            'multi_tenant': True,
            'dedicated_support': True,
            'custom_features': True
        }
    }
}

def get_subscription_features(level):
    """Get the features for a subscription level"""
    if level not in SUBSCRIPTION_LEVELS:
        level = 'basic'  # Default to basic if level not found
    return SUBSCRIPTION_LEVELS[level]

def get_subscription_limit(level, limit_type):
    """Get a specific limit for a subscription level"""
    if level not in SUBSCRIPTION_LEVELS:
        level = 'basic'  # Default to basic if level not found
    
    features = SUBSCRIPTION_LEVELS[level]['features']
    if limit_type == 'scanners':
        return features.get('scanners', 1)
    elif limit_type == 'scans':
        return features.get('scans_per_month', 10)
    else:
        return None

def get_subscription_price(level):
    """Get the price for a subscription level"""
    if level not in SUBSCRIPTION_LEVELS:
        level = 'basic'  # Default to basic if level not found
    return SUBSCRIPTION_LEVELS[level]['price']

def get_client_subscription_level(client):
    """Get normalized subscription level for a client"""
    if not client:
        return 'basic'  # Default to basic
    
    # Handle both dictionary and object-like access
    if hasattr(client, 'subscription_level'):
        subscription_level = client.subscription_level
    elif isinstance(client, dict):
        subscription_level = client.get('subscription_level', 'basic')
    else:
        subscription_level = 'basic'
    
    subscription_level = subscription_level.lower() if subscription_level else 'basic'
    
    # Handle legacy plan names
    if subscription_level in LEGACY_PLAN_MAPPING:
        subscription_level = LEGACY_PLAN_MAPPING[subscription_level]
    
    # Ensure subscription_level exists in SUBSCRIPTION_LEVELS
    if subscription_level not in SUBSCRIPTION_LEVELS:
        subscription_level = 'basic'
    
    return subscription_level

def get_client_scanner_limit(client):
    """Get scanner limit based on client's subscription level"""
    subscription_level = get_client_subscription_level(client)
    return SUBSCRIPTION_LEVELS[subscription_level]['features']['scanners']

def get_client_scan_limit(client):
    """Get scan limit based on client's subscription level"""
    subscription_level = get_client_subscription_level(client)
    return SUBSCRIPTION_LEVELS[subscription_level]['features']['scans_per_month']

def has_feature(client, feature_name):
    """Check if a client has access to a specific feature"""
    subscription_level = get_client_subscription_level(client)
    features = SUBSCRIPTION_LEVELS[subscription_level]['features']
    return features.get(feature_name, False)

def get_feature_value(client, feature_name, default=None):
    """Get the value of a specific feature for a client"""
    subscription_level = get_client_subscription_level(client)
    features = SUBSCRIPTION_LEVELS[subscription_level]['features']
    return features.get(feature_name, default)

def can_create_scanner(client, current_scanner_count=0):
    """Check if client can create another scanner"""
    scanner_limit = get_client_scanner_limit(client)
    return current_scanner_count < scanner_limit

def can_perform_scan(client, current_monthly_scans=0):
    """Check if client can perform another scan this month"""
    scan_limit = get_client_scan_limit(client)
    return current_monthly_scans < scan_limit

def get_upgrade_suggestions(current_level):
    """Get suggestions for upgrading from current level"""
    levels = list(SUBSCRIPTION_LEVELS.keys())
    if current_level not in levels:
        return []
    
    current_index = levels.index(current_level)
    return levels[current_index + 1:] if current_index < len(levels) - 1 else []

def calculate_msp_revenue_potential(subscription_level, clients_per_month=10):
    """Calculate potential MSP revenue based on subscription and client base"""
    if subscription_level not in SUBSCRIPTION_LEVELS:
        return {'error': 'Invalid subscription level'}
    
    monthly_cost = SUBSCRIPTION_LEVELS[subscription_level]['price']
    
    # Estimated revenue per client based on security service pricing
    revenue_per_client = {
        'basic': 25,      # Basic security assessment
        'starter': 75,    # Monthly security service
        'professional': 150,  # Comprehensive security service
        'enterprise': 300     # Enterprise security suite
    }
    
    monthly_revenue = clients_per_month * revenue_per_client.get(subscription_level, 0)
    net_profit = monthly_revenue - monthly_cost
    annual_profit = net_profit * 12
    roi_percentage = (net_profit / monthly_cost * 100) if monthly_cost > 0 else float('inf')
    
    return {
        'subscription_level': subscription_level,
        'monthly_cost': monthly_cost,
        'clients_served': clients_per_month,
        'monthly_revenue': monthly_revenue,
        'monthly_profit': net_profit,
        'annual_profit': annual_profit,
        'roi_percentage': roi_percentage
    }