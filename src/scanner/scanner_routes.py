#!/usr/bin/env python3
"""
Scanner Routes
Handles scanner-specific functionality, API endpoints, color detection
"""

from flask import Blueprint, render_template, request, jsonify
import requests
import socket
import ssl
import dns.resolver
from urllib.parse import urlparse
import re
from datetime import datetime
import secrets

from models import db, Scanner, Scan, ScannerCustomization

scanner_bp = Blueprint('scanner', __name__)

class ColorExtractor:
    """Extract colors from website CSS"""
    
    @staticmethod
    def extract_colors_from_url(url):
        """Extract primary colors from a website"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            html = response.text.lower()
            
            # Extract colors from inline styles and CSS
            colors = []
            
            # Find color patterns in CSS
            color_patterns = [
                r'color:\s*([#][0-9a-f]{6})',
                r'background-color:\s*([#][0-9a-f]{6})',
                r'border-color:\s*([#][0-9a-f]{6})',
                r'([#][0-9a-f]{6})',  # Any hex color
            ]
            
            for pattern in color_patterns:
                matches = re.findall(pattern, html)
                colors.extend(matches)
            
            # Remove duplicates and common colors
            unique_colors = list(set(colors))
            filtered_colors = [c for c in unique_colors if c not in ['#ffffff', '#000000', '#fff', '#000']]
            
            # Try to get CSS files
            css_urls = re.findall(r'<link[^>]*href=["\']([^"\']*\.css[^"\']*)["\']', html)
            for css_url in css_urls[:3]:  # Limit to first 3 CSS files
                try:
                    if css_url.startswith('//'):
                        css_url = 'https:' + css_url
                    elif css_url.startswith('/'):
                        parsed = urlparse(url)
                        css_url = f"{parsed.scheme}://{parsed.netloc}{css_url}"
                    elif not css_url.startswith('http'):
                        parsed = urlparse(url)
                        css_url = f"{parsed.scheme}://{parsed.netloc}/{css_url}"
                    
                    css_response = requests.get(css_url, headers=headers, timeout=5)
                    css_content = css_response.text.lower()
                    
                    for pattern in color_patterns:
                        matches = re.findall(pattern, css_content)
                        filtered_colors.extend([c for c in matches if c not in ['#ffffff', '#000000', '#fff', '#000']])
                        
                except Exception:
                    continue
            
            # Remove duplicates again
            filtered_colors = list(set(filtered_colors))
            
            # Determine primary colors
            if len(filtered_colors) >= 1:
                primary_color = filtered_colors[0]
            else:
                primary_color = '#2563eb'
            
            if len(filtered_colors) >= 2:
                secondary_color = filtered_colors[1]
            else:
                secondary_color = '#1e40af'
            
            if len(filtered_colors) >= 3:
                accent_color = filtered_colors[2]
            else:
                accent_color = '#3b82f6'
            
            return {
                'primary_color': primary_color,
                'secondary_color': secondary_color,
                'accent_color': accent_color,
                'background_color': '#ffffff',
                'text_color': '#1f2937',
                'all_colors': filtered_colors[:10]  # Return top 10 colors found
            }
            
        except Exception as e:
            # Return default colors if extraction fails
            return {
                'primary_color': '#2563eb',
                'secondary_color': '#1e40af',
                'accent_color': '#3b82f6',
                'background_color': '#ffffff',
                'text_color': '#1f2937',
                'all_colors': [],
                'error': str(e)
            }

@scanner_bp.route('/api/extract-colors', methods=['POST'])
def extract_colors():
    """API endpoint to extract colors from a website"""
    data = request.get_json()
    domain = data.get('domain', '').strip()
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    try:
        extractor = ColorExtractor()
        colors = extractor.extract_colors_from_url(domain)
        return jsonify(colors)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@scanner_bp.route('/api/scanner/<scanner_key>/config')
def get_scanner_config(scanner_key):
    """Get scanner configuration for embedding"""
    scanner = Scanner.query.filter_by(api_key=scanner_key, is_active=True).first()
    if not scanner:
        return jsonify({'error': 'Scanner not found'}), 404
    
    # Check if owner's subscription is active
    if scanner.owner.subscription_status != 'active':
        return jsonify({'error': 'Scanner is inactive'}), 403
    
    config = {
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
        'timeout': scanner.scan_timeout
    }
    
    return jsonify(config)

@scanner_bp.route('/api/scanner/<scanner_key>/scan', methods=['POST'])
def api_scan(scanner_key):
    """API endpoint for performing scans"""
    scanner = Scanner.query.filter_by(api_key=scanner_key, is_active=True).first()
    if not scanner:
        return jsonify({'error': 'Scanner not found'}), 404
    
    # Check if owner's subscription is active
    if scanner.owner.subscription_status != 'active':
        return jsonify({'error': 'Scanner is inactive'}), 403
    
    # Check scan limits
    if not scanner.owner.can_perform_scan():
        return jsonify({'error': 'Scan limit exceeded'}), 403
    
    data = request.get_json()
    domain = data.get('domain', '').strip()
    contact_info = data.get('contact', {})
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    # Validate domain format
    domain_pattern = re.compile(
        r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    )
    if not domain_pattern.match(domain):
        return jsonify({'error': 'Invalid domain format'}), 400
    
    # Create scan record
    scan = Scan(
        scanner_id=scanner.id,
        user_id=scanner.user_id,
        domain=domain,
        scan_id=secrets.token_urlsafe(16),
        contact_name=contact_info.get('name'),
        contact_email=contact_info.get('email'),
        contact_phone=contact_info.get('phone'),
        contact_company=contact_info.get('company'),
        ip_address=request.remote_addr,
        user_agent=request.headers.get('User-Agent'),
        referer=request.headers.get('Referer')
    )
    
    db.session.add(scan)
    db.session.commit()
    
    # Return scan ID immediately for async processing
    return jsonify({
        'scan_id': scan.scan_id,
        'status': 'pending',
        'message': 'Scan initiated successfully'
    })

@scanner_bp.route('/api/scan/<scan_id>/status')
def get_scan_status(scan_id):
    """Get scan status and results"""
    scan = Scan.query.filter_by(scan_id=scan_id).first()
    if not scan:
        return jsonify({'error': 'Scan not found'}), 404
    
    response = {
        'scan_id': scan.scan_id,
        'status': scan.status,
        'domain': scan.domain,
        'created_at': scan.created_at.isoformat(),
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None
    }
    
    if scan.status == 'completed':
        response.update({
            'risk_score': scan.risk_score,
            'vulnerabilities_found': scan.vulnerabilities_found,
            'results': {
                'ssl': scan.ssl_results,
                'ports': scan.port_results,
                'dns': scan.dns_results,
                'headers': scan.header_results,
                'vulnerabilities': scan.vulnerability_results
            }
        })
    elif scan.status == 'failed':
        response['error_message'] = scan.error_message
    
    return jsonify(response)

@scanner_bp.route('/embed/<scanner_key>')
def embed_scanner(scanner_key):
    """Embeddable scanner widget"""
    scanner = Scanner.query.filter_by(api_key=scanner_key, is_active=True).first()
    if not scanner:
        return render_template('error.html', message='Scanner not found'), 404
    
    # Check if owner's subscription is active
    if scanner.owner.subscription_status != 'active':
        return render_template('error.html', message='Scanner is inactive'), 403
    
    return render_template('scanner/embed.html', scanner=scanner)

@scanner_bp.route('/widget/<scanner_key>')
def scanner_widget(scanner_key):
    """Standalone scanner widget page"""
    scanner = Scanner.query.filter_by(api_key=scanner_key, is_active=True).first()
    if not scanner:
        return render_template('error.html', message='Scanner not found'), 404
    
    # Check if owner's subscription is active
    if scanner.owner.subscription_status != 'active':
        return render_template('error.html', message='Scanner is inactive'), 403
    
    return render_template('scanner/widget.html', scanner=scanner)

@scanner_bp.route('/api/scanner/<scanner_key>/leads')
def get_scanner_leads(scanner_key):
    """Get leads captured by scanner (for scanner owner only)"""
    scanner = Scanner.query.filter_by(api_key=scanner_key).first()
    if not scanner:
        return jsonify({'error': 'Scanner not found'}), 404
    
    # This would need authentication to verify the requesting user owns the scanner
    # For now, return basic lead data
    
    leads = Scan.query.filter_by(scanner_id=scanner.id).filter(
        Scan.contact_email.isnot(None)
    ).order_by(Scan.created_at.desc()).limit(100).all()
    
    lead_data = []
    for scan in leads:
        lead_data.append({
            'scan_id': scan.scan_id,
            'domain': scan.domain,
            'contact_name': scan.contact_name,
            'contact_email': scan.contact_email,
            'contact_phone': scan.contact_phone,
            'contact_company': scan.contact_company,
            'risk_score': scan.risk_score,
            'vulnerabilities_found': scan.vulnerabilities_found,
            'created_at': scan.created_at.isoformat(),
            'ip_address': scan.ip_address
        })
    
    return jsonify({
        'leads': lead_data,
        'total': len(lead_data)
    })

@scanner_bp.route('/preview/<scanner_key>')
def preview_scanner(scanner_key):
    """Preview scanner without functionality (for testing design)"""
    scanner = Scanner.query.filter_by(api_key=scanner_key).first()
    if not scanner:
        return render_template('error.html', message='Scanner not found'), 404
    
    return render_template('scanner/preview.html', scanner=scanner, preview=True)

@scanner_bp.route('/api/customization/save', methods=['POST'])
def save_customization():
    """Save automatic color customization for a domain"""
    data = request.get_json()
    scanner_id = data.get('scanner_id')
    domain = data.get('domain')
    colors = data.get('colors', {})
    
    if not scanner_id or not domain:
        return jsonify({'error': 'Scanner ID and domain are required'}), 400
    
    # Find or create customization record
    customization = ScannerCustomization.query.filter_by(
        scanner_id=scanner_id,
        domain=domain
    ).first()
    
    if not customization:
        customization = ScannerCustomization(
            scanner_id=scanner_id,
            domain=domain
        )
        db.session.add(customization)
    
    # Update colors
    customization.detected_primary_color = colors.get('primary_color')
    customization.detected_secondary_color = colors.get('secondary_color')
    customization.detected_accent_color = colors.get('accent_color')
    customization.detected_logo_url = colors.get('logo_url')
    
    db.session.commit()
    
    return jsonify({'message': 'Customization saved successfully'})

@scanner_bp.route('/api/customization/<int:scanner_id>/<domain>')
def get_customization(scanner_id, domain):
    """Get saved customization for a domain"""
    customization = ScannerCustomization.query.filter_by(
        scanner_id=scanner_id,
        domain=domain
    ).first()
    
    if not customization:
        return jsonify({'error': 'Customization not found'}), 404
    
    return jsonify({
        'primary_color': customization.detected_primary_color,
        'secondary_color': customization.detected_secondary_color,
        'accent_color': customization.detected_accent_color,
        'logo_url': customization.detected_logo_url
    })