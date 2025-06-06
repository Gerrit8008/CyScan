"""
Scanner Routes - Handle public scanner access and scanning functionality
"""

from flask import render_template, request, redirect, url_for, flash, jsonify, abort
from app.scanner import scanner_bp
from models import db, Scanner, Scan, ScannerCustomization, User
from scanner import SecurityScanner
from subscription_constants import get_subscription_features, get_client_subscription_level
from datetime import datetime, timedelta
import logging
import json
import re
import secrets
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

@scanner_bp.route('/scan/<api_key>')
def scanner_page(api_key):
    """Public scanner page"""
    # Find scanner by API key
    scanner = Scanner.query.filter_by(api_key=api_key, is_active=True).first()
    
    if not scanner:
        abort(404)
    
    # Get scanner owner
    owner = User.query.get(scanner.user_id)
    if not owner or not owner.is_active:
        abort(404)
    
    # Check if scanner should auto-detect colors from a website
    if scanner.auto_detect_colors and request.args.get('detect_from'):
        target_url = request.args.get('detect_from')
        if is_valid_url(target_url):
            try:
                colors = extract_colors_from_website(target_url)
                if colors:
                    # Store detected colors for this domain
                    customization = ScannerCustomization.query.filter_by(
                        scanner_id=scanner.id,
                        domain=extract_domain(target_url)
                    ).first()
                    
                    if not customization:
                        customization = ScannerCustomization(
                            scanner_id=scanner.id,
                            domain=extract_domain(target_url),
                            detected_primary_color=colors.get('primary'),
                            detected_secondary_color=colors.get('secondary'),
                            detected_accent_color=colors.get('accent'),
                            detected_logo_url=colors.get('logo')
                        )
                        db.session.add(customization)
                    else:
                        customization.detected_primary_color = colors.get('primary')
                        customization.detected_secondary_color = colors.get('secondary')
                        customization.detected_accent_color = colors.get('accent')
                        customization.detected_logo_url = colors.get('logo')
                    
                    try:
                        db.session.commit()
                    except Exception as e:
                        logger.error(f"Error saving color customization: {e}")
                        db.session.rollback()
            except Exception as e:
                logger.error(f"Error detecting colors from {target_url}: {e}")
    
    # Get customization for the current domain if available
    current_domain = request.args.get('domain') or request.referrer
    customization = None
    
    if current_domain:
        domain = extract_domain(current_domain)
        customization = ScannerCustomization.query.filter_by(
            scanner_id=scanner.id,
            domain=domain
        ).first()
    
    # Apply customization or use scanner defaults
    display_colors = {
        'primary_color': customization.detected_primary_color if customization and customization.detected_primary_color else scanner.primary_color,
        'secondary_color': customization.detected_secondary_color if customization and customization.detected_secondary_color else scanner.secondary_color,
        'accent_color': customization.detected_accent_color if customization and customization.detected_accent_color else scanner.accent_color,
        'background_color': scanner.background_color,
        'text_color': scanner.text_color,
        'button_color': scanner.button_color,
        'button_text_color': scanner.button_text_color
    }
    
    display_logo = customization.detected_logo_url if customization and customization.detected_logo_url else scanner.logo_url
    
    return render_template('scanner/scan.html',
                         scanner=scanner,
                         colors=display_colors,
                         logo_url=display_logo,
                         customization=customization)

@scanner_bp.route('/scan/<api_key>/submit', methods=['POST'])
def submit_scan(api_key):
    """Submit a new scan"""
    # Find scanner by API key
    scanner = Scanner.query.filter_by(api_key=api_key, is_active=True).first()
    
    if not scanner:
        return jsonify({'error': 'Scanner not found'}), 404
    
    # Get scanner owner
    owner = User.query.get(scanner.user_id)
    if not owner or not owner.is_active:
        return jsonify({'error': 'Scanner owner not found'}), 404
    
    # Check subscription limits
    subscription_level = get_client_subscription_level({'subscription_level': owner.subscription_tier})
    features = get_subscription_features(subscription_level)
    
    # Count monthly scans
    start_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    monthly_scans = Scan.query.filter(
        Scan.user_id == owner.id,
        Scan.created_at >= start_of_month
    ).count()
    
    max_scans = features['features']['scans_per_month']
    if max_scans != -1 and monthly_scans >= max_scans:
        return jsonify({'error': 'Monthly scan limit exceeded'}), 429
    
    try:
        # Get form data
        domain = request.form.get('domain', '').strip()
        contact_name = request.form.get('contact_name', '').strip()
        contact_email = request.form.get('contact_email', '').strip()
        contact_phone = request.form.get('contact_phone', '').strip()
        contact_company = request.form.get('contact_company', '').strip()
        
        # Validate domain
        if not domain:
            return jsonify({'error': 'Domain is required'}), 400
        
        # Clean and validate domain
        domain = clean_domain(domain)
        if not is_valid_domain(domain):
            return jsonify({'error': 'Invalid domain format'}), 400
        
        # Generate unique scan ID
        scan_id = secrets.token_urlsafe(16)
        
        # Create scan record
        scan = Scan(
            scanner_id=scanner.id,
            user_id=owner.id,
            domain=domain,
            scan_id=scan_id,
            contact_name=contact_name,
            contact_email=contact_email,
            contact_phone=contact_phone,
            contact_company=contact_company,
            status='pending',
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            referer=request.headers.get('Referer', '')
        )
        
        db.session.add(scan)
        
        # Update counters
        scanner.increment_scan_count()
        owner.increment_scan_count()
        
        db.session.commit()
        
        # Start background scan (in a real implementation, this would be queued)
        try:
            perform_scan(scan.id)
        except Exception as e:
            logger.error(f"Error starting scan {scan.id}: {e}")
            scan.status = 'failed'
            scan.error_message = str(e)
            db.session.commit()
        
        return jsonify({
            'status': 'success',
            'scan_id': scan.scan_id,
            'message': 'Scan submitted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error submitting scan: {e}")
        return jsonify({'error': 'Failed to submit scan'}), 500

@scanner_bp.route('/scan/<api_key>/results/<scan_id>')
def scan_results(api_key, scan_id):
    """Display scan results"""
    # Find scanner by API key
    scanner = Scanner.query.filter_by(api_key=api_key, is_active=True).first()
    
    if not scanner:
        abort(404)
    
    # Find scan
    scan = Scan.query.filter_by(scan_id=scan_id, scanner_id=scanner.id).first()
    
    if not scan:
        abort(404)
    
    # Get customization for the scanned domain
    customization = ScannerCustomization.query.filter_by(
        scanner_id=scanner.id,
        domain=scan.domain
    ).first()
    
    # Apply customization or use scanner defaults
    display_colors = {
        'primary_color': customization.detected_primary_color if customization and customization.detected_primary_color else scanner.primary_color,
        'secondary_color': customization.detected_secondary_color if customization and customization.detected_secondary_color else scanner.secondary_color,
        'accent_color': customization.detected_accent_color if customization and customization.detected_accent_color else scanner.accent_color,
        'background_color': scanner.background_color,
        'text_color': scanner.text_color,
        'button_color': scanner.button_color,
        'button_text_color': scanner.button_text_color
    }
    
    display_logo = customization.detected_logo_url if customization and customization.detected_logo_url else scanner.logo_url
    
    return render_template('scanner/results.html',
                         scanner=scanner,
                         scan=scan,
                         colors=display_colors,
                         logo_url=display_logo)

@scanner_bp.route('/scan/<api_key>/status/<scan_id>')
def scan_status(api_key, scan_id):
    """Get scan status (AJAX endpoint)"""
    # Find scanner by API key
    scanner = Scanner.query.filter_by(api_key=api_key, is_active=True).first()
    
    if not scanner:
        return jsonify({'error': 'Scanner not found'}), 404
    
    # Find scan
    scan = Scan.query.filter_by(scan_id=scan_id, scanner_id=scanner.id).first()
    
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    response_data = {
        'status': scan.status,
        'progress': get_scan_progress(scan.status),
        'domain': scan.domain
    }
    
    if scan.status == 'completed':
        response_data.update({
            'risk_score': scan.risk_score,
            'vulnerabilities_found': scan.vulnerabilities_found,
            'results_url': url_for('scanner.scan_results', api_key=api_key, scan_id=scan_id)
        })
    elif scan.status == 'failed':
        response_data['error_message'] = scan.error_message
    
    return jsonify(response_data)

# Helper functions
def is_valid_url(url):
    """Check if URL is valid"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def is_valid_domain(domain):
    """Check if domain is valid"""
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return pattern.match(domain) is not None

def clean_domain(domain):
    """Clean and normalize domain"""
    # Remove protocol if present
    domain = re.sub(r'^https?://', '', domain)
    # Remove www. if present
    domain = re.sub(r'^www\.', '', domain)
    # Remove trailing slash and path
    domain = domain.split('/')[0]
    # Remove port if present
    domain = domain.split(':')[0]
    return domain.lower()

def extract_domain(url):
    """Extract domain from URL"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        # Remove www. if present
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    except:
        return None

def extract_colors_from_website(url):
    """Extract colors from a website"""
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        # Set headers to mimic a real browser
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        # Fetch the webpage
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        # Parse HTML
        soup = BeautifulSoup(response.content, 'html.parser')
        
        colors = {}
        
        # Look for CSS variables or common color patterns
        # Check inline styles and stylesheets
        styles = soup.find_all('style')
        for style in styles:
            style_content = style.get_text()
            
            # Extract color values using regex
            color_patterns = [
                r'(?:color|background-color|border-color):\s*(#[0-9a-fA-F]{6})',
                r'(?:color|background-color|border-color):\s*(#[0-9a-fA-F]{3})',
                r'(?:color|background-color|border-color):\s*rgb\(([^)]+)\)',
                r'--primary-color:\s*(#[0-9a-fA-F]{6})',
                r'--secondary-color:\s*(#[0-9a-fA-F]{6})',
                r'--accent-color:\s*(#[0-9a-fA-F]{6})'
            ]
            
            for pattern in color_patterns:
                matches = re.findall(pattern, style_content, re.IGNORECASE)
                if matches:
                    if 'primary' not in colors and matches:
                        colors['primary'] = matches[0] if matches[0].startswith('#') else f'#{matches[0]}'
                        break
        
        # Look for logo in common places
        logo_selectors = [
            'img[alt*=\"logo\" i]',
            'img[src*=\"logo\" i]',
            'img[class*=\"logo\" i]',
            '.logo img',
            '#logo img',
            'header img:first-of-type'
        ]
        
        for selector in logo_selectors:
            logo_img = soup.select_one(selector)
            if logo_img and logo_img.get('src'):
                src = logo_img.get('src')
                if src.startswith('//'):
                    src = 'https:' + src
                elif src.startswith('/'):
                    parsed_url = urlparse(url)
                    src = f"{parsed_url.scheme}://{parsed_url.netloc}{src}"
                elif not src.startswith(('http://', 'https://')):
                    parsed_url = urlparse(url)
                    src = f"{parsed_url.scheme}://{parsed_url.netloc}/{src}"
                
                colors['logo'] = src
                break
        
        # If no primary color found, try to extract from meta theme-color
        if 'primary' not in colors:
            theme_color = soup.find('meta', attrs={'name': 'theme-color'})
            if theme_color and theme_color.get('content'):
                colors['primary'] = theme_color.get('content')
        
        # Generate secondary and accent colors based on primary
        if 'primary' in colors:
            primary = colors['primary']
            if primary.startswith('#') and len(primary) == 7:
                # Generate variations
                colors['secondary'] = adjust_color_brightness(primary, -20)
                colors['accent'] = adjust_color_brightness(primary, 10)
        
        return colors
        
    except Exception as e:
        logger.error(f"Error extracting colors from {url}: {e}")
        return None

def adjust_color_brightness(hex_color, percent):
    """Adjust the brightness of a hex color"""
    try:
        # Remove # if present
        hex_color = hex_color.lstrip('#')
        
        # Convert to RGB
        r = int(hex_color[0:2], 16)
        g = int(hex_color[2:4], 16)
        b = int(hex_color[4:6], 16)
        
        # Adjust brightness
        r = max(0, min(255, r + int(255 * percent / 100)))
        g = max(0, min(255, g + int(255 * percent / 100)))
        b = max(0, min(255, b + int(255 * percent / 100)))
        
        # Convert back to hex
        return f"#{r:02x}{g:02x}{b:02x}"
        
    except:
        return hex_color

def get_scan_progress(status):
    """Get scan progress percentage based on status"""
    progress_map = {
        'pending': 10,
        'scanning': 50,
        'processing': 80,
        'completed': 100,
        'failed': 100
    }
    return progress_map.get(status, 0)

def perform_scan(scan_id):
    """Perform the actual security scan"""
    scan = Scan.query.get(scan_id)
    if not scan:
        return
    
    try:
        scan.status = 'scanning'
        db.session.commit()
        
        # Initialize security scanner
        security_scanner = SecurityScanner()
        
        # Get scanner settings
        scanner = Scanner.query.get(scan.scanner_id)
        scan_types = []
        
        if scanner.enable_ssl_scan:
            scan_types.append('ssl')
        if scanner.enable_port_scan:
            scan_types.append('ports')
        if scanner.enable_dns_scan:
            scan_types.append('dns')
        if scanner.enable_header_scan:
            scan_types.append('headers')
        if scanner.enable_vulnerability_scan:
            scan_types.append('vulnerabilities')
        
        # If no specific scans enabled, use default
        if not scan_types:
            scan_types = ['ssl', 'ports', 'dns', 'headers', 'vulnerabilities']
        
        # Perform comprehensive scan
        scan_results = security_scanner.scan_domain(scan.domain, scan_types)
        
        scan.status = 'processing'
        db.session.commit()
        
        # Store results in new format
        scan.results = json.dumps(scan_results)
        scan.risk_score = scan_results.get('risk_score', 0)
        scan.vulnerabilities_found = len(scan_results.get('vulnerabilities', []))
        
        # Store individual results for backward compatibility
        scan.ssl_results = scan_results.get('results', {}).get('ssl', {})
        scan.port_results = scan_results.get('results', {}).get('ports', {})
        scan.dns_results = scan_results.get('results', {}).get('dns', {})
        scan.header_results = scan_results.get('results', {}).get('headers', {})
        scan.vulnerability_results = scan_results.get('results', {}).get('vulnerabilities', {})
        
        scan.status = 'completed'
        scan.completed_at = datetime.utcnow()
        scan.scan_duration = (scan.completed_at - scan.created_at).total_seconds()
        
        db.session.commit()
        
        # Send email report if contact email provided
        if scan.contact_email and scan.contact_email.strip():
            try:
                send_scan_email_report(scan)
            except Exception as e:
                logger.error(f"Failed to send email report for scan {scan_id}: {e}")
        
        logger.info(f"Scan {scan_id} completed successfully")
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        scan.status = 'failed'
        scan.error_message = str(e)
        db.session.commit()

def send_scan_email_report(scan):
    """Send email report for completed scan"""
    from email_handler import email_handler
    
    # Get scanner and owner info
    scanner = Scanner.query.get(scan.scanner_id)
    owner = User.query.get(scanner.user_id)
    
    if not scanner or not owner:
        return False
    
    # Parse scan results
    scan_results = json.loads(scan.results) if scan.results else {}
    
    # Prepare lead data
    lead_data = {
        'name': scan.contact_name or 'Unknown',
        'email': scan.contact_email,
        'company': scan.contact_company or 'Unknown',
        'phone': scan.contact_phone or ''
    }
    
    # Generate HTML report
    html_report = generate_html_report(scan_results, scan)
    
    # Get scanner branding
    company_name = scanner.company_name or owner.company_name or "CybrScan"
    logo_path = get_logo_path(scanner.logo_url) if scanner.logo_url else None
    brand_color = scanner.primary_color or '#02054c'
    
    # Custom email subject and intro
    email_subject = scanner.email_subject or f"Your Security Assessment Results - {company_name}"
    email_intro = scanner.email_intro or f"Thank you for using {company_name}'s security assessment service. Please find your comprehensive security report below."
    
    # Send branded email
    return email_handler.send_branded_email_report(
        lead_data=lead_data,
        scan_results=scan_results,
        html_report=html_report,
        company_name=company_name,
        logo_path=logo_path,
        brand_color=brand_color,
        email_subject=email_subject,
        email_intro=email_intro
    )

def generate_html_report(scan_results, scan):
    """Generate HTML report from scan results"""
    try:
        # Use template to generate report
        from flask import render_template_string
        
        template = """
        <div class="scan-report">
            <h2>Security Assessment Results for {{ scan.domain }}</h2>
            
            <div class="risk-score">
                <h3>Overall Risk Score: {{ scan_results.risk_score }}/100</h3>
                <div class="risk-level {{ 'high-risk' if scan_results.risk_score < 60 else 'medium-risk' if scan_results.risk_score < 80 else 'low-risk' }}">
                    Risk Level: {{ 'High' if scan_results.risk_score < 60 else 'Medium' if scan_results.risk_score < 80 else 'Low' }}
                </div>
            </div>
            
            {% if scan_results.vulnerabilities %}
            <div class="vulnerabilities">
                <h3>Security Issues Found ({{ scan_results.vulnerabilities|length }})</h3>
                <ul>
                {% for vuln in scan_results.vulnerabilities %}
                    <li class="vuln-{{ vuln.severity }}">
                        <strong>{{ vuln.type|title }}:</strong> {{ vuln.description }}
                        <span class="severity">({{ vuln.severity|title }} Risk)</span>
                    </li>
                {% endfor %}
                </ul>
            </div>
            {% endif %}
            
            <div class="scan-details">
                <h3>Scan Details</h3>
                <p><strong>Domain:</strong> {{ scan.domain }}</p>
                <p><strong>Scan Date:</strong> {{ scan.created_at.strftime('%Y-%m-%d %H:%M:%S') }}</p>
                <p><strong>Scan Duration:</strong> {{ scan.scan_duration or 'N/A' }} seconds</p>
                <p><strong>Scan Types:</strong> {{ scan_results.scan_types|join(', ')|title }}</p>
            </div>
            
            {% if scan_results.results %}
            <div class="detailed-results">
                <h3>Detailed Results</h3>
                {% for scan_type, results in scan_results.results.items() %}
                    <div class="result-section">
                        <h4>{{ scan_type|title }} Analysis</h4>
                        {% if results.get('status') == 'completed' %}
                            <div class="result-content">
                                {{ results | safe }}
                            </div>
                        {% else %}
                            <p class="error">{{ scan_type|title }} scan failed: {{ results.get('error', 'Unknown error') }}</p>
                        {% endif %}
                    </div>
                {% endfor %}
            </div>
            {% endif %}
            
            <div class="recommendations">
                <h3>Recommendations</h3>
                <p>Based on the security assessment, we recommend addressing the identified issues to improve your security posture. 
                Contact your cybersecurity provider for assistance implementing these recommendations.</p>
            </div>
        </div>
        
        <style>
            .scan-report { font-family: Arial, sans-serif; }
            .risk-score { background: #f8f9fa; padding: 15px; border-radius: 5px; margin: 15px 0; }
            .high-risk { color: #dc3545; font-weight: bold; }
            .medium-risk { color: #fd7e14; font-weight: bold; }
            .low-risk { color: #28a745; font-weight: bold; }
            .vulnerabilities ul { list-style-type: none; padding: 0; }
            .vulnerabilities li { padding: 8px; margin: 5px 0; border-radius: 3px; }
            .vuln-critical { background: #f8d7da; border-left: 4px solid #dc3545; }
            .vuln-high { background: #f8d7da; border-left: 4px solid #dc3545; }
            .vuln-medium { background: #fff3cd; border-left: 4px solid #fd7e14; }
            .vuln-low { background: #d4edda; border-left: 4px solid #28a745; }
            .severity { font-size: 0.9em; opacity: 0.8; }
            .result-section { margin: 15px 0; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }
            .error { color: #dc3545; font-style: italic; }
        </style>
        """
        
        return render_template_string(template, scan_results=scan_results, scan=scan)
        
    except Exception as e:
        logger.error(f"Error generating HTML report: {e}")
        return f"<p>Scan completed for {scan.domain}. Risk Score: {scan_results.get('risk_score', 'N/A')}/100</p>"

def get_logo_path(logo_url):
    """Get local path for logo file"""
    if not logo_url:
        return None
    
    # If it's a local upload, convert to absolute path
    if logo_url.startswith('/uploads/'):
        return f"/home/gerrit/CybrScan{logo_url}"
    
    # For external URLs, we can't use them as file paths
    return None

# API endpoints for embedded scanners
@scanner_bp.route('/api/scanner/<api_key>/config')
def get_scanner_config(api_key):
    """Get scanner configuration for embedded use"""
    scanner = Scanner.query.filter_by(api_key=api_key, is_active=True).first()
    
    if not scanner:
        return jsonify({'error': 'Scanner not found'}), 404
    
    # Get owner subscription info
    owner = User.query.get(scanner.user_id)
    subscription_level = get_client_subscription_level({'subscription_level': owner.subscription_tier})
    features = get_subscription_features(subscription_level)
    
    config = {
        'scanner_id': scanner.id,
        'name': scanner.name,
        'title': scanner.title,
        'subtitle': scanner.subtitle,
        'footer_text': scanner.footer_text,
        'colors': {
            'primary': scanner.primary_color,
            'secondary': scanner.secondary_color,
            'accent': scanner.accent_color,
            'background': scanner.background_color,
            'text': scanner.text_color,
            'button': scanner.button_color,
            'button_text': scanner.button_text_color
        },
        'logo_url': scanner.logo_url,
        'favicon_url': scanner.favicon_url,
        'features': {
            'ssl_scan': scanner.enable_ssl_scan,
            'port_scan': scanner.enable_port_scan,
            'dns_scan': scanner.enable_dns_scan,
            'header_scan': scanner.enable_header_scan,
            'vulnerability_scan': scanner.enable_vulnerability_scan
        },
        'auto_detect_colors': scanner.auto_detect_colors,
        'subscription_features': features['features']
    }
    
    return jsonify(config)

@scanner_bp.route('/api/scanner/<api_key>/embed-script.js')
def get_embed_script(api_key):
    """Get JavaScript embed script for scanner"""
    scanner = Scanner.query.filter_by(api_key=api_key, is_active=True).first()
    
    if not scanner:
        return "console.error('Scanner not found');", 404, {'Content-Type': 'application/javascript'}
    
    # Generate embed script
    script = f"""
(function() {{
    const SCANNER_API_KEY = '{api_key}';
    const SCANNER_BASE_URL = window.location.protocol + '//' + window.location.host;
    
    // Create scanner widget
    function createScannerWidget(containerId, options = {{}}) {{
        const container = document.getElementById(containerId);
        if (!container) {{
            console.error('Scanner container not found: ' + containerId);
            return;
        }}
        
        // Fetch scanner configuration
        fetch(`${{SCANNER_BASE_URL}}/api/scanner/${{SCANNER_API_KEY}}/config`)
            .then(response => response.json())
            .then(config => {{
                container.innerHTML = generateScannerHTML(config, options);
                attachScannerEvents(container, config);
            }})
            .catch(error => {{
                console.error('Error loading scanner:', error);
                container.innerHTML = '<p>Error loading security scanner</p>';
            }});
    }}
    
    // Generate scanner HTML
    function generateScannerHTML(config, options) {{
        const colors = config.colors;
        const style = `
            <style>
                .cybr-scanner {{
                    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
                    background: ${{colors.background}};
                    color: ${{colors.text}};
                    padding: 30px;
                    border-radius: 12px;
                    box-shadow: 0 8px 32px rgba(0,0,0,0.1);
                    max-width: 600px;
                    margin: 0 auto;
                }}
                .cybr-scanner h2 {{
                    color: ${{colors.primary}};
                    margin-bottom: 10px;
                    font-size: 24px;
                    font-weight: 600;
                }}
                .cybr-scanner p {{
                    color: ${{colors.text}};
                    margin-bottom: 20px;
                    opacity: 0.8;
                }}
                .cybr-scanner .form-group {{
                    margin-bottom: 20px;
                }}
                .cybr-scanner label {{
                    display: block;
                    margin-bottom: 5px;
                    font-weight: 500;
                    color: ${{colors.text}};
                }}
                .cybr-scanner input {{
                    width: 100%;
                    padding: 12px;
                    border: 2px solid #e1e5e9;
                    border-radius: 6px;
                    font-size: 16px;
                    transition: border-color 0.3s;
                }}
                .cybr-scanner input:focus {{
                    outline: none;
                    border-color: ${{colors.primary}};
                }}
                .cybr-scanner .scan-button {{
                    background: ${{colors.button}};
                    color: ${{colors.button_text}};
                    border: none;
                    padding: 12px 30px;
                    border-radius: 6px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: all 0.3s;
                }}
                .cybr-scanner .scan-button:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 4px 16px rgba(0,0,0,0.2);
                }}
                .cybr-scanner .scan-button:disabled {{
                    opacity: 0.6;
                    cursor: not-allowed;
                    transform: none;
                }}
                .cybr-scanner .progress-bar {{
                    width: 100%;
                    height: 6px;
                    background: #e1e5e9;
                    border-radius: 3px;
                    overflow: hidden;
                    margin: 20px 0;
                    display: none;
                }}
                .cybr-scanner .progress-fill {{
                    height: 100%;
                    background: ${{colors.primary}};
                    transition: width 0.3s;
                    width: 0%;
                }}
                .cybr-scanner .results {{
                    margin-top: 20px;
                    padding: 20px;
                    background: #f8f9fa;
                    border-radius: 8px;
                    display: none;
                }}
                .cybr-scanner .logo {{
                    max-width: 150px;
                    margin-bottom: 20px;
                }}
                .cybr-scanner .footer {{
                    margin-top: 20px;
                    text-align: center;
                    font-size: 12px;
                    opacity: 0.6;
                }}
            </style>
        `;
        
        const html = `
            ${{style}}
            <div class="cybr-scanner">
                ${{config.logo_url ? `<img src="${{config.logo_url}}" alt="Logo" class="logo">` : ''}}
                <h2>${{config.title || 'Security Scanner'}}</h2>
                <p>${{config.subtitle || 'Check your website security in seconds'}}</p>
                
                <form id="scanner-form">
                    <div class="form-group">
                        <label for="domain">Website URL or Domain:</label>
                        <input type="text" id="domain" name="domain" placeholder="example.com" required>
                    </div>
                    
                    <div class="form-group">
                        <label for="contact_name">Your Name:</label>
                        <input type="text" id="contact_name" name="contact_name" placeholder="John Doe">
                    </div>
                    
                    <div class="form-group">
                        <label for="contact_email">Email Address:</label>
                        <input type="email" id="contact_email" name="contact_email" placeholder="john@example.com">
                    </div>
                    
                    <div class="form-group">
                        <label for="contact_company">Company:</label>
                        <input type="text" id="contact_company" name="contact_company" placeholder="Your Company">
                    </div>
                    
                    <button type="submit" class="scan-button" id="scan-btn">
                        🔒 Start Security Scan
                    </button>
                </form>
                
                <div class="progress-bar" id="progress-bar">
                    <div class="progress-fill" id="progress-fill"></div>
                </div>
                
                <div class="results" id="scan-results"></div>
                
                ${{config.footer_text ? `<div class="footer">${{config.footer_text}}</div>` : ''}}
            </div>
        `;
        
        return html;
    }}
    
    // Attach event handlers
    function attachScannerEvents(container, config) {{
        const form = container.querySelector('#scanner-form');
        const button = container.querySelector('#scan-btn');
        const progressBar = container.querySelector('#progress-bar');
        const progressFill = container.querySelector('#progress-fill');
        const results = container.querySelector('#scan-results');
        
        form.addEventListener('submit', async (e) => {{
            e.preventDefault();
            
            const formData = new FormData(form);
            button.disabled = true;
            button.textContent = 'Scanning...';
            progressBar.style.display = 'block';
            
            try {{
                // Submit scan
                const response = await fetch(`${{SCANNER_BASE_URL}}/scan/${{SCANNER_API_KEY}}/submit`, {{
                    method: 'POST',
                    body: formData
                }});
                
                const data = await response.json();
                if (data.status === 'success') {{
                    // Poll for results
                    pollScanResults(data.scan_id, progressFill, results, button);
                }} else {{
                    throw new Error(data.error || 'Scan submission failed');
                }}
            }} catch (error) {{
                console.error('Scan error:', error);
                button.disabled = false;
                button.textContent = '🔒 Start Security Scan';
                progressBar.style.display = 'none';
                results.innerHTML = `<p style="color: #dc3545;">Error: ${{error.message}}</p>`;
                results.style.display = 'block';
            }}
        }});
    }}
    
    // Poll for scan results
    function pollScanResults(scanId, progressFill, results, button) {{
        const pollInterval = setInterval(async () => {{
            try {{
                const response = await fetch(`${{SCANNER_BASE_URL}}/scan/${{SCANNER_API_KEY}}/status/${{scanId}}`);
                const data = await response.json();
                
                // Update progress
                progressFill.style.width = data.progress + '%';
                
                if (data.status === 'completed') {{
                    clearInterval(pollInterval);
                    
                    // Display results
                    results.innerHTML = `
                        <h3>Security Scan Complete!</h3>
                        <p><strong>Risk Score:</strong> ${{data.risk_score}}/100</p>
                        <p><strong>Vulnerabilities Found:</strong> ${{data.vulnerabilities_found}}</p>
                        <a href="${{data.results_url}}" target="_blank" style="color: ${{config.colors.primary}};">
                            View Detailed Report →
                        </a>
                    `;
                    results.style.display = 'block';
                    
                    button.disabled = false;
                    button.textContent = '🔒 Start Security Scan';
                    progressFill.style.width = '100%';
                    
                }} else if (data.status === 'failed') {{
                    clearInterval(pollInterval);
                    
                    results.innerHTML = `<p style="color: #dc3545;">Scan failed: ${{data.error_message || 'Unknown error'}}</p>`;
                    results.style.display = 'block';
                    
                    button.disabled = false;
                    button.textContent = '🔒 Start Security Scan';
                    progressFill.style.width = '0%';
                }}
            }} catch (error) {{
                console.error('Error polling scan results:', error);
                clearInterval(pollInterval);
                
                button.disabled = false;
                button.textContent = '🔒 Start Security Scan';
                progressFill.style.width = '0%';
            }}
        }}, 2000);
    }}
    
    // Expose to global scope
    window.CybrScan = {{
        createWidget: createScannerWidget
    }};
}})();
"""
    
    return script, 200, {'Content-Type': 'application/javascript'}

@scanner_bp.route('/api/scanner/<api_key>/iframe')
def get_iframe_embed(api_key):
    """Get iframe embed code for scanner"""
    scanner = Scanner.query.filter_by(api_key=api_key, is_active=True).first()
    
    if not scanner:
        return jsonify({'error': 'Scanner not found'}), 404
    
    from flask import request
    base_url = request.url_root.rstrip('/')
    
    iframe_code = f'''<iframe 
    src="{base_url}/scan/{api_key}" 
    width="100%" 
    height="600" 
    frameborder="0" 
    style="border: none; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.1);">
</iframe>'''
    
    return jsonify({
        'iframe_code': iframe_code,
        'direct_url': f"{base_url}/scan/{api_key}",
        'api_key': api_key
    })

@scanner_bp.route('/api/scanner/<api_key>/widget-code')
def get_widget_code(api_key):
    """Get JavaScript widget embed code"""
    scanner = Scanner.query.filter_by(api_key=api_key, is_active=True).first()
    
    if not scanner:
        return jsonify({'error': 'Scanner not found'}), 404
    
    from flask import request
    base_url = request.url_root.rstrip('/')
    
    widget_code = f'''<!-- CybrScan Security Scanner Widget -->
<div id="cybr-scanner-widget"></div>
<script src="{base_url}/api/scanner/{api_key}/embed-script.js"></script>
<script>
    // Initialize the scanner widget
    CybrScan.createWidget('cybr-scanner-widget');
</script>'''
    
    return jsonify({
        'widget_code': widget_code,
        'script_url': f"{base_url}/api/scanner/{api_key}/embed-script.js",
        'container_id': 'cybr-scanner-widget'
    })

@scanner_bp.route('/api/scanner/<api_key>/stats')
def get_scanner_stats(api_key):
    """Get scanner usage statistics"""
    scanner = Scanner.query.filter_by(api_key=api_key, is_active=True).first()
    
    if not scanner:
        return jsonify({'error': 'Scanner not found'}), 404
    
    # Get owner for permission check
    owner = User.query.get(scanner.user_id)
    if not owner or not owner.is_active:
        return jsonify({'error': 'Scanner owner not found'}), 404
    
    # Get scan statistics
    total_scans = Scan.query.filter_by(scanner_id=scanner.id).count()
    completed_scans = Scan.query.filter_by(scanner_id=scanner.id, status='completed').count()
    failed_scans = Scan.query.filter_by(scanner_id=scanner.id, status='failed').count()
    
    # Get monthly scans
    start_of_month = datetime.utcnow().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    monthly_scans = Scan.query.filter(
        Scan.scanner_id == scanner.id,
        Scan.created_at >= start_of_month
    ).count()
    
    # Get recent scans
    recent_scans = Scan.query.filter_by(scanner_id=scanner.id)\
        .order_by(Scan.created_at.desc())\
        .limit(5).all()
    
    recent_scan_data = []
    for scan in recent_scans:
        recent_scan_data.append({
            'domain': scan.domain,
            'status': scan.status,
            'risk_score': scan.risk_score,
            'created_at': scan.created_at.isoformat(),
            'completed_at': scan.completed_at.isoformat() if scan.completed_at else None
        })
    
    return jsonify({
        'scanner_id': scanner.id,
        'total_scans': total_scans,
        'completed_scans': completed_scans,
        'failed_scans': failed_scans,
        'monthly_scans': monthly_scans,
        'success_rate': round((completed_scans / total_scans * 100), 2) if total_scans > 0 else 0,
        'recent_scans': recent_scan_data
    })

@scanner_bp.route('/api/scanner/<api_key>/customize', methods=['POST'])
def customize_scanner_api(api_key):
    """API endpoint to customize scanner appearance"""
    scanner = Scanner.query.filter_by(api_key=api_key, is_active=True).first()
    
    if not scanner:
        return jsonify({'error': 'Scanner not found'}), 404
    
    # This would typically require authentication/authorization
    # For now, we'll allow customization via API key
    
    try:
        data = request.get_json()
        
        # Update scanner customization
        if 'colors' in data:
            colors = data['colors']
            if 'primary' in colors:
                scanner.primary_color = colors['primary']
            if 'secondary' in colors:
                scanner.secondary_color = colors['secondary']
            if 'accent' in colors:
                scanner.accent_color = colors['accent']
            if 'background' in colors:
                scanner.background_color = colors['background']
            if 'text' in colors:
                scanner.text_color = colors['text']
            if 'button' in colors:
                scanner.button_color = colors['button']
            if 'button_text' in colors:
                scanner.button_text_color = colors['button_text']
        
        if 'branding' in data:
            branding = data['branding']
            if 'title' in branding:
                scanner.title = branding['title']
            if 'subtitle' in branding:
                scanner.subtitle = branding['subtitle']
            if 'footer_text' in branding:
                scanner.footer_text = branding['footer_text']
            if 'logo_url' in branding:
                scanner.logo_url = branding['logo_url']
        
        db.session.commit()
        
        return jsonify({'status': 'success', 'message': 'Scanner customization updated'})
        
    except Exception as e:
        logger.error(f"Error customizing scanner via API: {e}")
        return jsonify({'error': 'Failed to update customization'}), 500