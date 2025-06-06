# CybrScan Routing Analysis Report

## Executive Summary

This report analyzes all HTML template files in the CybrScan application to identify broken links and routing issues. The current `run.py` file only implements 5 basic routes, while the templates reference over 100 different routes. This creates a significant gap between the frontend expectations and backend implementation.

## Current Routes in run.py

The following routes are currently implemented:
1. `/` - Index page
2. `/health` - Health check endpoint
3. `/pricing` - Pricing page
4. `/auth/register` - Registration page
5. `/auth/login` - Login page

## Analysis Results

### 1. Working Links (Currently Functional)

These links/routes work with the current run.py:
- `url_for('index')` → `/`
- `url_for('pricing')` → `/pricing`
- `url_for('register')` → `/auth/register`
- `url_for('login')` → `/auth/login`
- Direct href links to: `/`, `/pricing`, `/auth/register`, `/auth/login`

### 2. Broken Links (Missing Routes)

#### Authentication Routes (url_for calls)
- `url_for('logout')` - Referenced in base.html and multiple templates
- `url_for('auth.logout')` - Referenced in admin and client templates
- `url_for('auth.reset_password_request')` - Password reset functionality
- `url_for('auth.admin_create_user')` - Admin user creation

#### Dashboard Routes (url_for calls)
- `url_for('admin_dashboard')` - Admin dashboard access
- `url_for('client_dashboard')` - Client dashboard access
- `url_for('manage_scanners')` - Scanner management

#### Admin Routes (Direct hrefs)
- `/admin/dashboard` - Admin main dashboard
- `/admin/clients` - Client management
- `/admin/reports` - Reports dashboard
- `/admin/scanners` - Scanner management
- `/admin/settings` - Settings management
- `/admin/subscriptions` - Subscription management
- `/admin/scanners/{id}/edit` - Scanner editing
- `/admin/scanners/{id}/stats` - Scanner statistics
- `/admin/scanners/{id}/view` - Scanner viewing

#### Client Routes (Direct hrefs)
- `/client/dashboard` - Client main dashboard
- `/client/reports` - Client reports
- `/client/scanners` - Client scanner list
- `/client/settings` - Client settings
- `/client/statistics` - Client statistics
- `/client/upgrade` - Upgrade subscription
- `/client/activity` - Activity log
- `/client/billing` - Billing information
- `/client/recommendations` - Security recommendations
- `/client/scanners/{id}/edit` - Edit scanner
- `/client/scanners/{id}/stats` - Scanner statistics
- `/client/scanners/{id}/view` - View scanner
- `/client/scanners/{id}/reports` - Scanner reports
- `/client/scanner_create` - Create new scanner
- `/client/billing/manage` - Manage billing
- `/client/billing/upgrade` - Upgrade plan
- `/client/billing/downgrade` - Downgrade plan

#### Billing Routes (url_for calls)
- `url_for('billing.manage_subscription')`
- `url_for('billing.upgrade')`
- `url_for('billing.revenue_calculator')`
- `url_for('billing.create_checkout_session')`

#### API Routes (Form actions and hrefs)
- `/api/scan` - Scanner API endpoint
- `/api/run_scan` - Run scan endpoint
- `/api/scanner/{scanner_id}` - Scanner API access
- `/client/scanners/{id}/regenerate-api-key` - API key regeneration

#### Scanner Routes
- `/scan` - Demo scanner
- `/scanner/{scanner_id}/embed` - Embedded scanner
- `/customize` - Scanner customization
- `/preview/{id}` - Scanner preview
- `/results` - Scan results

#### Static/Support Routes
- `/auth/logout` - Logout functionality
- `/contact` - Contact page
- `/docs` - Documentation
- `/help` - Help center
- `/about` - About page
- `/privacy` - Privacy policy
- `/terms` - Terms of service
- `/auth/reset-password-request` - Password reset
- `/auth/reset-password-confirm` - Password reset confirmation

### 3. Additional Routes Needed for Full Functionality

Based on the template analysis, here are the routes that need to be added to run.py:

#### Authentication Module
```python
# Auth routes
@app.route('/auth/logout')
@app.route('/auth/reset-password-request', methods=['GET', 'POST'])
@app.route('/auth/reset-password-confirm/<token>', methods=['GET', 'POST'])
@app.route('/auth/admin/users')
@app.route('/auth/admin/create-user', methods=['GET', 'POST'])
```

#### Admin Module
```python
# Admin routes
@app.route('/admin/dashboard')
@app.route('/admin/clients')
@app.route('/admin/reports')
@app.route('/admin/scanners')
@app.route('/admin/settings')
@app.route('/admin/subscriptions')
@app.route('/admin/scanners/<int:scanner_id>/edit', methods=['GET', 'POST'])
@app.route('/admin/scanners/<int:scanner_id>/stats')
@app.route('/admin/scanners/<int:scanner_id>/view')
```

#### Client Module
```python
# Client routes
@app.route('/client/dashboard')
@app.route('/client/reports')
@app.route('/client/scanners')
@app.route('/client/settings', methods=['GET', 'POST'])
@app.route('/client/statistics')
@app.route('/client/upgrade')
@app.route('/client/activity')
@app.route('/client/billing')
@app.route('/client/recommendations')
@app.route('/client/scanners/create', methods=['GET', 'POST'])
@app.route('/client/scanners/<int:scanner_id>/edit', methods=['GET', 'POST'])
@app.route('/client/scanners/<int:scanner_id>/stats')
@app.route('/client/scanners/<int:scanner_id>/view')
@app.route('/client/scanners/<int:scanner_id>/reports')
@app.route('/client/scanners/<int:scanner_id>/regenerate-api-key', methods=['POST'])
@app.route('/client/billing/manage')
@app.route('/client/billing/upgrade')
@app.route('/client/billing/downgrade')
@app.route('/client/process-payment', methods=['POST'])
@app.route('/client/process-upgrade', methods=['POST'])
@app.route('/client/process-downgrade', methods=['POST'])
```

#### Billing Module
```python
# Billing routes
@app.route('/billing/manage-subscription')
@app.route('/billing/upgrade')
@app.route('/billing/revenue-calculator')
@app.route('/billing/create-checkout-session', methods=['POST'])
```

#### Scanner/API Module
```python
# Scanner and API routes
@app.route('/scan')
@app.route('/scanner/<scanner_id>/embed')
@app.route('/customize', methods=['GET', 'POST'])
@app.route('/preview/<int:scanner_id>')
@app.route('/results')
@app.route('/api/scan', methods=['POST'])
@app.route('/api/run_scan', methods=['POST'])
@app.route('/api/scanner/<scanner_id>')
```

#### Static Pages
```python
# Static pages
@app.route('/contact')
@app.route('/docs')
@app.route('/help')
@app.route('/about')
@app.route('/privacy')
@app.route('/terms')
```

## Key Issues Identified

1. **Authentication System**: No logout functionality or password reset mechanism
2. **Role-Based Access**: Templates check for `session.user_role` but no authentication system exists
3. **Database Integration**: Many routes expect database operations (scanner CRUD, user management)
4. **API Endpoints**: Scanner functionality requires API endpoints that don't exist
5. **Static Files**: References to CSS and favicon files that may not be properly served
6. **Form Processing**: Multiple forms submit to endpoints that don't exist

## Recommendations

1. **Implement Authentication System**: Add Flask-Login or similar for user management
2. **Create Blueprint Structure**: Organize routes into blueprints (auth, admin, client, billing, api)
3. **Add Database Models**: Implement SQLAlchemy models for users, scanners, subscriptions
4. **Implement API Layer**: Create RESTful API endpoints for scanner operations
5. **Add Error Handling**: Implement 404 and error pages
6. **Create Middleware**: Add authentication and authorization middleware
7. **Implement CSRF Protection**: Add Flask-WTF for form security

## Priority Implementation Order

1. **Phase 1 - Core Authentication**
   - Login/logout functionality
   - User session management
   - Basic role checking

2. **Phase 2 - Dashboard Structure**
   - Client dashboard
   - Admin dashboard
   - Basic navigation

3. **Phase 3 - Scanner Functionality**
   - Scanner creation/editing
   - Scanner API endpoints
   - Basic scanning functionality

4. **Phase 4 - Billing/Subscription**
   - Subscription management
   - Payment processing
   - Plan upgrades/downgrades

5. **Phase 5 - Additional Features**
   - Reports and statistics
   - User management
   - Settings and customization

## Conclusion

The CybrScan application has a comprehensive frontend structure but lacks the backend implementation to support it. The current run.py file needs significant expansion to support all the functionality referenced in the templates. A complete rewrite using Flask blueprints and proper application structure is recommended to support the full feature set.