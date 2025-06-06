import os
import logging
import smtplib
from email.message import EmailMessage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
from datetime import datetime
from typing import Dict, Any, Optional

# Set up logging configuration if not already set
if not logging.getLogger().handlers:
    logging.basicConfig(level=logging.DEBUG,
                       format='%(asctime)s - %(levelname)s - %(message)s')

class EmailHandler:
    """Enhanced email handler for CybrScan with branding and MSP features"""
    
    def __init__(self):
        self.smtp_user = os.environ.get('SMTP_USER')
        self.smtp_password = os.environ.get('SMTP_PASSWORD')
        self.smtp_server = os.environ.get('SMTP_SERVER', 'mail.privateemail.com')
        self.smtp_port = int(os.environ.get('SMTP_PORT', 587))
        
    def send_branded_email_report(self, lead_data: Dict[str, Any], scan_results: Dict[str, Any], 
                                 html_report: str, company_name: str, logo_path: Optional[str] = None,
                                 brand_color: str = '#02054c', email_subject: Optional[str] = None, 
                                 email_intro: Optional[str] = None, custom_css: Optional[str] = None) -> bool:
        """Send a fully branded email report to the client"""
        try:
            if not self.smtp_user or not self.smtp_password:
                logging.error("SMTP credentials not found in environment variables")
                return False
                
            logging.debug(f"Attempting to send branded email with SMTP user: {self.smtp_user}")
            
            # Create a multipart message for HTML and text
            msg = MIMEMultipart('alternative')
            
            # Use custom subject or default
            subject = email_subject or f"Your Security Assessment Results - {company_name}"
            msg["Subject"] = subject
            msg["From"] = self.smtp_user
            
            # Send to the user's email address
            user_email = lead_data.get("email", "")
            msg["To"] = user_email
            
            logging.debug(f"Email recipient: {user_email}")
            
            # Create a simple text version as a fallback
            text_body = self.create_comprehensive_text_summary(scan_results)
            
            # Use custom intro or default
            intro = email_intro or f"Thank you for using {company_name}'s security assessment service. Please find your comprehensive security report below."
            
            # Create the branded HTML wrapper
            branded_html = self._create_branded_html_email(
                html_report, company_name, brand_color, intro, 
                lead_data, logo_path, custom_css
            )
            
            # Create text part (fallback for email clients that don't support HTML)
            part1 = MIMEText(text_body, 'plain')
            
            # Create HTML part - use the HTML report
            part2 = MIMEText(branded_html, 'html')
            
            # Add parts to message
            msg.attach(part1)
            msg.attach(part2)
            
            # Add logo as embedded image if provided
            if logo_path and os.path.exists(logo_path):
                with open(logo_path, 'rb') as logo_file:
                    logo_part = MIMEImage(logo_file.read())
                    logo_part.add_header('Content-ID', '<logo>')
                    logo_part.add_header('Content-Disposition', 'inline', filename='logo.png')
                    msg.attach(logo_part)
            
            logging.debug(f"Connecting to SMTP server: {self.smtp_server}:{self.smtp_port}")
            
            # Send the email
            with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30) as server:
                logging.debug("SMTP connection established")
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
                logging.debug("Branded email sent successfully!")
                return True
                
        except Exception as e:
            logging.error(f"Error sending branded email: {e}")
            return False

    def _create_branded_html_email(self, html_report: str, company_name: str, 
                                  brand_color: str, intro: str, lead_data: Dict[str, Any],
                                  logo_path: Optional[str] = None, custom_css: Optional[str] = None) -> str:
        """Create a professional branded HTML email"""
        
        # Default CSS styles
        default_css = f"""
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                margin: 0; 
                padding: 0; 
                background-color: #f8f9fa;
                color: #333;
            }}
            .email-container {{ 
                max-width: 800px; 
                margin: 0 auto; 
                background-color: white;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }}
            .header {{ 
                background: linear-gradient(135deg, {brand_color} 0%, {self._darken_color(brand_color)} 100%); 
                color: white; 
                padding: 30px 20px; 
                text-align: center; 
            }}
            .logo {{ 
                max-width: 200px; 
                max-height: 80px;
                margin-bottom: 15px;
            }}
            .header h1 {{
                margin: 0;
                font-size: 24px;
                font-weight: 600;
            }}
            .content {{ 
                padding: 30px 20px; 
                line-height: 1.6;
            }}
            .intro {{
                background-color: #f8f9fa;
                padding: 20px;
                border-radius: 8px;
                margin-bottom: 30px;
                border-left: 4px solid {brand_color};
            }}
            .report-section {{
                margin-top: 20px;
            }}
            .footer {{ 
                background-color: #f8f9fa; 
                padding: 20px; 
                text-align: center; 
                font-size: 12px; 
                color: #666; 
                border-top: 1px solid #e9ecef;
            }}
            .cta-button {{
                display: inline-block;
                background-color: {brand_color};
                color: white !important;
                padding: 12px 24px;
                text-decoration: none;
                border-radius: 6px;
                font-weight: 600;
                margin: 15px 0;
            }}
            .security-badge {{
                background-color: #d4edda;
                border: 1px solid #c3e6cb;
                border-radius: 6px;
                padding: 15px;
                margin: 20px 0;
                text-align: center;
            }}
            .contact-info {{
                background-color: #fff3cd;
                border: 1px solid #ffeaa7;
                border-radius: 6px;
                padding: 15px;
                margin: 20px 0;
            }}
            .high-risk {{ color: #dc3545; font-weight: 600; }}
            .medium-risk {{ color: #fd7e14; font-weight: 600; }}
            .low-risk {{ color: #28a745; font-weight: 600; }}
        """
        
        # Combine default CSS with custom CSS
        final_css = default_css
        if custom_css:
            final_css += f"\n{custom_css}"
        
        return f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{company_name} Security Report</title>
            <style>
                {final_css}
            </style>
        </head>
        <body>
            <div class="email-container">
                <div class="header">
                    {f'<img src="cid:logo" class="logo" alt="{company_name}">' if logo_path else ''}
                    <h1>{company_name}</h1>
                    <p style="margin: 5px 0 0 0; opacity: 0.9;">Cybersecurity Assessment Report</p>
                </div>
                
                <div class="content">
                    <div class="intro">
                        <h3 style="margin-top: 0; color: {brand_color};">Dear {lead_data.get('name', 'Valued Client')},</h3>
                        <p>{intro}</p>
                    </div>
                    
                    <div class="security-badge">
                        <h4 style="margin-top: 0; color: {brand_color};">🔒 Professional Security Assessment Completed</h4>
                        <p style="margin-bottom: 0;">Generated on {datetime.now().strftime("%B %d, %Y at %I:%M %p")}</p>
                    </div>
                    
                    <div class="report-section">
                        {html_report}
                    </div>
                    
                    <div class="contact-info">
                        <h4 style="margin-top: 0; color: {brand_color};">Need Help Implementing These Recommendations?</h4>
                        <p>Our cybersecurity experts are here to help you secure your business. Contact {company_name} today to discuss how we can help you address these security findings.</p>
                        <p style="margin-bottom: 0;"><strong>Don't wait - cybercriminals won't.</strong></p>
                    </div>
                </div>
                
                <div class="footer">
                    <p><strong>Report Details:</strong></p>
                    <p>Report generated for: {lead_data.get('name', 'N/A')} ({lead_data.get('email', 'N/A')})</p>
                    <p>Company: {lead_data.get('company', 'N/A')}</p>
                    <p>Assessment Date: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
                    <hr style="margin: 15px 0; border: none; border-top: 1px solid #e9ecef;">
                    <p>&copy; {datetime.now().year} {company_name}. All rights reserved.</p>
                    <p style="font-size: 10px; color: #999;">This report contains confidential information. Please handle accordingly.</p>
                </div>
            </div>
        </body>
        </html>
        """

    def _darken_color(self, hex_color: str, factor: float = 0.8) -> str:
        """Darken a hex color by a given factor"""
        try:
            # Remove the # if present
            hex_color = hex_color.lstrip('#')
            
            # Convert to RGB
            rgb = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
            
            # Darken each component
            darkened = tuple(int(c * factor) for c in rgb)
            
            # Convert back to hex
            return f"#{darkened[0]:02x}{darkened[1]:02x}{darkened[2]:02x}"
        except:
            # Fallback to a default dark color
            return "#1a1a1a"

    def send_notification_email(self, to_email: str, subject: str, message: str, 
                               sender_name: str = "CybrScan", template_type: str = "notification") -> bool:
        """Send notification emails (lead alerts, system notifications, etc.)"""
        try:
            if not self.smtp_user or not self.smtp_password:
                logging.error("SMTP credentials not found in environment variables")
                return False
            
            msg = MIMEMultipart('alternative')
            msg["Subject"] = subject
            msg["From"] = f"{sender_name} <{self.smtp_user}>"
            msg["To"] = to_email
            
            # Create simple HTML template
            html_body = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; }}
                    .container {{ max-width: 600px; margin: 0 auto; }}
                    .header {{ background-color: #02054c; color: white; padding: 20px; text-align: center; }}
                    .content {{ padding: 20px; background-color: #f9f9f9; }}
                    .footer {{ padding: 10px; text-align: center; font-size: 12px; color: #666; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h2>{sender_name}</h2>
                    </div>
                    <div class="content">
                        {message}
                    </div>
                    <div class="footer">
                        <p>&copy; {datetime.now().year} {sender_name}. All rights reserved.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            # Add text and HTML parts
            msg.attach(MIMEText(message, 'plain'))
            msg.attach(MIMEText(html_body, 'html'))
            
            # Send the email
            with smtplib.SMTP(self.smtp_server, self.smtp_port, timeout=30) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(self.smtp_user, self.smtp_password)
                server.send_message(msg)
                logging.debug(f"Notification email sent to {to_email}")
                return True
                
        except Exception as e:
            logging.error(f"Error sending notification email: {e}")
            return False

    def create_comprehensive_text_summary(self, scan_results: Dict[str, Any]) -> str:
        """Create a comprehensive text summary of ALL scan results"""
        summary = []
        
        # Overall Risk Assessment
        summary.append("CYBERSECURITY ASSESSMENT REPORT")
        summary.append("=" * 35)
        summary.append("")
        
        if 'risk_assessment' in scan_results and 'overall_score' in scan_results['risk_assessment']:
            risk_level = scan_results['risk_assessment']['risk_level']
            overall_score = scan_results['risk_assessment']['overall_score']
            summary.append(f"OVERALL RISK LEVEL: {risk_level.upper()} (Score: {overall_score}/100)")
            summary.append("")
            
            # Add risk factors if available
            if 'risk_factors' in scan_results['risk_assessment']:
                summary.append("RISK FACTOR BREAKDOWN:")
                summary.append("-" * 22)
                for factor in scan_results['risk_assessment']['risk_factors']:
                    summary.append(f"• {factor.get('name', 'Unknown Factor')}: {factor.get('score', 'N/A')}/10 (Weight: {factor.get('weight', 'N/A')}%)")
                summary.append("")
        
        # Key Recommendations
        if 'recommendations' in scan_results and scan_results['recommendations']:
            summary.append("IMMEDIATE ACTION ITEMS:")
            summary.append("-" * 22)
            for i, rec in enumerate(scan_results['recommendations'], 1):
                summary.append(f"{i}. {rec}")
            summary.append("")
        
        # Network Security Analysis
        if 'network' in scan_results:
            summary.append("NETWORK SECURITY ANALYSIS:")
            summary.append("-" * 26)
            
            # Open Ports
            if 'open_ports' in scan_results['network']:
                open_ports = scan_results['network']['open_ports']
                if 'count' in open_ports:
                    summary.append(f"Open Ports Found: {open_ports['count']} (Risk: {open_ports.get('severity', 'Unknown')})")
                    
                if 'list' in open_ports and open_ports['list']:
                    summary.append("Detected Open Ports:")
                    for port in open_ports['list']:
                        risk_level = self._get_port_risk_level(port)
                        service = self._get_port_service(port)
                        summary.append(f"  • Port {port}: {service} (Risk: {risk_level})")
                summary.append("")
        
        # Web Security Analysis
        web_sections = ['ssl_certificate', 'security_headers', 'cms', 'cookies']
        web_findings = []
        
        for section in web_sections:
            if section in scan_results:
                web_findings.append(section)
        
        if web_findings:
            summary.append("WEB SECURITY ANALYSIS:")
            summary.append("-" * 22)
            
            # SSL Certificate
            if 'ssl_certificate' in scan_results:
                ssl_cert = scan_results['ssl_certificate']
                if 'status' in ssl_cert:
                    summary.append(f"SSL Certificate: {ssl_cert['status']} (Risk: {ssl_cert.get('severity', 'Unknown')})")
                    if 'days_remaining' in ssl_cert:
                        summary.append(f"  Certificate expires in {ssl_cert['days_remaining']} days")
            
            # Security Headers
            if 'security_headers' in scan_results:
                headers = scan_results['security_headers']
                if 'score' in headers:
                    summary.append(f"Security Headers Score: {headers['score']}/100 (Risk: {headers.get('severity', 'Unknown')})")
            
            summary.append("")
        
        # Email Security
        if 'email_security' in scan_results:
            summary.append("EMAIL SECURITY ANALYSIS:")
            summary.append("-" * 24)
            email_sec = scan_results['email_security']
            
            if 'domain' in email_sec:
                summary.append(f"Domain Analyzed: {email_sec['domain']}")
            
            for protocol in ['spf', 'dmarc', 'dkim']:
                if protocol in email_sec:
                    status = email_sec[protocol].get('status', 'Unknown')
                    severity = email_sec[protocol].get('severity', 'Unknown')
                    summary.append(f"{protocol.upper()} Record: {status} (Risk: {severity})")
            summary.append("")
        
        # System Information
        if 'system' in scan_results or 'client_info' in scan_results:
            summary.append("SYSTEM INFORMATION:")
            summary.append("-" * 18)
            
            if 'client_info' in scan_results:
                client_info = scan_results['client_info']
                for key, value in client_info.items():
                    if value:
                        summary.append(f"{key.replace('_', ' ').title()}: {value}")
            
            if 'system' in scan_results:
                system = scan_results['system']
                for key, value in system.items():
                    if isinstance(value, dict) and 'status' in value:
                        summary.append(f"{key.replace('_', ' ').title()}: {value['status']} (Risk: {value.get('severity', 'Unknown')})")
            summary.append("")
        
        # Threat Scenarios
        if 'threat_scenarios' in scan_results and scan_results['threat_scenarios']:
            summary.append("POTENTIAL THREAT SCENARIOS:")
            summary.append("-" * 27)
            for i, threat in enumerate(scan_results['threat_scenarios'], 1):
                summary.append(f"{i}. {threat.get('name', 'Unknown Threat')}")
                summary.append(f"   Impact: {threat.get('impact', 'Unknown')} | Likelihood: {threat.get('likelihood', 'Unknown')}")
                if 'description' in threat:
                    summary.append(f"   {threat['description']}")
                summary.append("")
        
        # Footer
        summary.append("=" * 50)
        summary.append(f"Report generated on {datetime.now().strftime('%Y-%m-%d at %H:%M:%S')}")
        summary.append("For assistance implementing these recommendations,")
        summary.append("please contact your cybersecurity provider.")
        
        return "\n".join(summary)

    def _get_port_risk_level(self, port: int) -> str:
        """Determine risk level for a given port"""
        high_risk_ports = [21, 23, 3389, 5900, 445, 139, 135, 1433, 3306]
        medium_risk_ports = [80, 8080, 110, 143, 25, 993, 995, 465]
        
        if port in high_risk_ports:
            return "High"
        elif port in medium_risk_ports:
            return "Medium"
        else:
            return "Low"

    def _get_port_service(self, port: int) -> str:
        """Get service description for a given port"""
        services = {
            21: "FTP - File Transfer Protocol",
            22: "SSH - Secure Shell",
            23: "Telnet - Insecure remote access",
            25: "SMTP - Email transmission",
            53: "DNS - Domain Name System",
            80: "HTTP - Web traffic (unencrypted)",
            110: "POP3 - Email retrieval",
            135: "RPC - Remote Procedure Call",
            139: "NetBIOS - Network Basic Input/Output",
            143: "IMAP - Email access",
            443: "HTTPS - Secure web traffic",
            445: "SMB - Server Message Block",
            465: "SMTPS - Secure SMTP",
            993: "IMAPS - Secure IMAP",
            995: "POP3S - Secure POP3",
            1433: "MSSQL - Microsoft SQL Server",
            3306: "MySQL - Database server",
            3389: "RDP - Remote Desktop Protocol",
            5900: "VNC - Virtual Network Computing",
            8080: "HTTP Alt - Alternative HTTP port"
        }
        
        return services.get(port, f"Unknown service on port {port}")

# Global instance
email_handler = EmailHandler()

# Backward compatibility functions
def send_branded_email_report(lead_data, scan_results, html_report, company_name, logo_path=None, 
                            brand_color='#02054c', email_subject=None, email_intro=None):
    """Backward compatibility wrapper"""
    return email_handler.send_branded_email_report(
        lead_data, scan_results, html_report, company_name, logo_path,
        brand_color, email_subject, email_intro
    )

def send_email_report(lead_data, scan_results, html_report):
    """Backward compatibility wrapper"""
    return email_handler.send_branded_email_report(
        lead_data, scan_results, html_report, "CybrScan"
    )

def create_comprehensive_text_summary(scan_results):
    """Backward compatibility wrapper"""
    return email_handler.create_comprehensive_text_summary(scan_results)