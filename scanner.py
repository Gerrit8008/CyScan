import socket
import ssl
import requests
import dns.resolver
from datetime import datetime, timezone
import concurrent.futures
from urllib.parse import urlparse
import json
import re
from typing import Dict, List, Any, Optional
import subprocess
import time

class SecurityScanner:
    def __init__(self, timeout=30):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CybrScan Security Scanner/1.0'
        })
        
    def scan_domain(self, domain: str, scan_types: Optional[List[str]] = None) -> Dict[str, Any]:
        """Perform comprehensive security scan on a domain"""
        
        # Clean domain
        domain = self._clean_domain(domain)
        
        # Default scan types
        if not scan_types:
            scan_types = ['ssl', 'ports', 'dns', 'headers', 'vulnerabilities']
        
        results = {
            'domain': domain,
            'scan_timestamp': datetime.utcnow().isoformat(),
            'scan_types': scan_types,
            'results': {},
            'risk_score': 100,
            'vulnerabilities': []
        }
        
        # Run scans concurrently
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {}
            
            if 'ssl' in scan_types:
                futures['ssl'] = executor.submit(self.scan_ssl, domain)
            if 'ports' in scan_types:
                futures['ports'] = executor.submit(self.scan_ports, domain)
            if 'dns' in scan_types:
                futures['dns'] = executor.submit(self.scan_dns, domain)
            if 'headers' in scan_types:
                futures['headers'] = executor.submit(self.scan_headers, domain)
            if 'vulnerabilities' in scan_types:
                futures['vulnerabilities'] = executor.submit(self.scan_vulnerabilities, domain)
            
            # Collect results
            for scan_type, future in futures.items():
                try:
                    results['results'][scan_type] = future.result(timeout=self.timeout)
                except Exception as e:
                    results['results'][scan_type] = {
                        'error': str(e),
                        'status': 'failed'
                    }
        
        # Calculate risk score
        results['risk_score'], results['vulnerabilities'] = self._calculate_risk_score(results['results'])
        
        return results
    
    def scan_ssl(self, domain: str) -> Dict[str, Any]:
        """Scan SSL/TLS certificate"""
        results = {
            'status': 'completed',
            'valid': False,
            'issues': [],
            'certificate': {}
        }
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Certificate details
                    results['certificate'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert.get('version'),
                        'serialNumber': cert.get('serialNumber'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'subjectAltName': [x[1] for x in cert.get('subjectAltName', [])],
                        'protocol': ssock.version(),
                        'cipher': ssock.cipher()
                    }
                    
                    # Check validity
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    now = datetime.now()
                    
                    if now < not_before:
                        results['issues'].append('Certificate not yet valid')
                    elif now > not_after:
                        results['issues'].append('Certificate expired')
                        results['expired'] = True
                    else:
                        results['valid'] = True
                    
                    # Check domain match
                    cert_domains = [results['certificate']['subject'].get('commonName', '')]
                    cert_domains.extend(results['certificate'].get('subjectAltName', []))
                    
                    if not any(self._match_domain(domain, cert_domain) for cert_domain in cert_domains):
                        results['issues'].append('Certificate domain mismatch')
                        results['valid'] = False
                    
                    # Check protocol version
                    if results['certificate']['protocol'] in ['TLSv1', 'TLSv1.1']:
                        results['issues'].append(f"Outdated TLS version: {results['certificate']['protocol']}")
                    
        except socket.timeout:
            results['status'] = 'timeout'
            results['issues'].append('Connection timeout')
        except ssl.SSLError as e:
            results['status'] = 'ssl_error'
            results['issues'].append(f'SSL Error: {str(e)}')
        except Exception as e:
            results['status'] = 'error'
            results['issues'].append(f'Error: {str(e)}')
        
        return results
    
    def scan_ports(self, domain: str) -> Dict[str, Any]:
        """Scan common ports"""
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            135: 'RPC',
            139: 'NetBIOS',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        
        results = {
            'status': 'completed',
            'open_ports': [],
            'closed_ports': [],
            'filtered_ports': [],
            'services': {}
        }
        
        try:
            # Resolve domain to IP
            ip = socket.gethostbyname(domain)
            
            for port, service in common_ports.items():
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                
                try:
                    result = sock.connect_ex((ip, port))
                    if result == 0:
                        results['open_ports'].append(port)
                        results['services'][port] = service
                        
                        # Try to grab banner
                        try:
                            if port not in [80, 443]:  # Skip HTTP/HTTPS
                                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
                                if banner:
                                    results['services'][port] = f"{service} - {banner[:100]}"
                        except:
                            pass
                    else:
                        results['closed_ports'].append(port)
                except socket.timeout:
                    results['filtered_ports'].append(port)
                except Exception:
                    results['filtered_ports'].append(port)
                finally:
                    sock.close()
        
        except socket.gaierror:
            results['status'] = 'dns_error'
            results['error'] = 'Could not resolve domain'
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def scan_dns(self, domain: str) -> Dict[str, Any]:
        """Scan DNS records"""
        results = {
            'status': 'completed',
            'records': {},
            'issues': []
        }
        
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 5
                resolver.lifetime = 5
                
                answers = resolver.resolve(domain, record_type)
                results['records'][record_type] = []
                
                for rdata in answers:
                    if record_type == 'MX':
                        results['records'][record_type].append({
                            'priority': rdata.preference,
                            'exchange': str(rdata.exchange)
                        })
                    else:
                        results['records'][record_type].append(str(rdata))
                
            except dns.resolver.NXDOMAIN:
                results['issues'].append(f'Domain {domain} does not exist')
                results['status'] = 'nxdomain'
                break
            except dns.resolver.NoAnswer:
                continue
            except Exception as e:
                results['issues'].append(f'{record_type} lookup failed: {str(e)}')
        
        # Check for common security records
        security_records = {
            'SPF': None,
            'DMARC': None,
            'DKIM': None
        }
        
        # Check SPF
        txt_records = results['records'].get('TXT', [])
        for record in txt_records:
            if record.startswith('v=spf1'):
                security_records['SPF'] = record
        
        # Check DMARC
        try:
            dmarc_domain = f'_dmarc.{domain}'
            answers = resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                record = str(rdata).strip('"')
                if record.startswith('v=DMARC1'):
                    security_records['DMARC'] = record
        except:
            pass
        
        results['security_records'] = security_records
        
        # Add issues for missing security records
        if not security_records['SPF']:
            results['issues'].append('No SPF record found')
        if not security_records['DMARC']:
            results['issues'].append('No DMARC record found')
        
        return results
    
    def scan_headers(self, domain: str) -> Dict[str, Any]:
        """Scan HTTP security headers"""
        results = {
            'status': 'completed',
            'headers': {},
            'missing': [],
            'issues': []
        }
        
        security_headers = {
            'Strict-Transport-Security': 'HSTS not implemented',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options',
            'X-Frame-Options': 'Clickjacking protection not implemented',
            'X-XSS-Protection': 'XSS protection header missing',
            'Content-Security-Policy': 'No Content Security Policy',
            'Referrer-Policy': 'No referrer policy set',
            'Permissions-Policy': 'No permissions policy set'
        }
        
        try:
            # Try HTTPS first
            url = f'https://{domain}'
            response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
            
            results['headers'] = dict(response.headers)
            
            # Check security headers
            for header, issue in security_headers.items():
                if header not in response.headers:
                    results['missing'].append(header)
                    results['issues'].append(issue)
                else:
                    # Validate header values
                    value = response.headers[header]
                    if header == 'Strict-Transport-Security':
                        if 'max-age' not in value:
                            results['issues'].append('HSTS max-age not set')
                        else:
                            max_age = re.search(r'max-age=(\d+)', value)
                            if max_age and int(max_age.group(1)) < 31536000:
                                results['issues'].append('HSTS max-age less than 1 year')
            
            # Check for insecure headers
            if 'Server' in response.headers:
                results['issues'].append(f"Server header exposes version: {response.headers['Server']}")
            
            if 'X-Powered-By' in response.headers:
                results['issues'].append(f"X-Powered-By header exposes technology: {response.headers['X-Powered-By']}")
            
        except requests.exceptions.SSLError:
            # Try HTTP if HTTPS fails
            try:
                url = f'http://{domain}'
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                results['headers'] = dict(response.headers)
                results['issues'].append('Site not available over HTTPS')
            except Exception as e:
                results['status'] = 'error'
                results['error'] = str(e)
        except Exception as e:
            results['status'] = 'error'
            results['error'] = str(e)
        
        return results
    
    def scan_vulnerabilities(self, domain: str) -> Dict[str, Any]:
        """Scan for common vulnerabilities"""
        results = {
            'status': 'completed',
            'vulnerabilities': [],
            'checks_performed': []
        }
        
        # Check for common vulnerable paths
        vulnerable_paths = [
            '/.git/config',
            '/.env',
            '/.htaccess',
            '/wp-config.php',
            '/config.php',
            '/phpinfo.php',
            '/.DS_Store',
            '/robots.txt',
            '/sitemap.xml',
            '/.well-known/security.txt'
        ]
        
        base_url = f'https://{domain}'
        
        for path in vulnerable_paths:
            results['checks_performed'].append(f'Path check: {path}')
            try:
                response = self.session.get(f'{base_url}{path}', timeout=5, allow_redirects=False)
                if response.status_code == 200:
                    if path in ['/.git/config', '/.env', '/wp-config.php', '/config.php']:
                        results['vulnerabilities'].append({
                            'type': 'exposed_file',
                            'severity': 'high',
                            'path': path,
                            'description': f'Sensitive file exposed: {path}'
                        })
                    elif path == '/phpinfo.php' and 'phpinfo()' in response.text:
                        results['vulnerabilities'].append({
                            'type': 'information_disclosure',
                            'severity': 'medium',
                            'path': path,
                            'description': 'PHP info page exposed'
                        })
            except:
                continue
        
        # Check for open redirects
        results['checks_performed'].append('Open redirect check')
        redirect_payloads = [
            '//evil.com',
            'https://evil.com',
            '//google.com'
        ]
        
        for payload in redirect_payloads:
            try:
                response = self.session.get(
                    f'{base_url}?url={payload}',
                    timeout=5,
                    allow_redirects=False
                )
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    if payload in location or 'evil.com' in location:
                        results['vulnerabilities'].append({
                            'type': 'open_redirect',
                            'severity': 'medium',
                            'description': 'Possible open redirect vulnerability'
                        })
                        break
            except:
                continue
        
        # Check CORS misconfiguration
        results['checks_performed'].append('CORS misconfiguration check')
        try:
            headers = {'Origin': 'https://evil.com'}
            response = self.session.get(base_url, headers=headers, timeout=5)
            acao = response.headers.get('Access-Control-Allow-Origin', '')
            if acao == '*' or acao == 'https://evil.com':
                results['vulnerabilities'].append({
                    'type': 'cors_misconfiguration',
                    'severity': 'medium',
                    'description': f'CORS misconfiguration: Access-Control-Allow-Origin set to {acao}'
                })
        except:
            pass
        
        return results
    
    def _clean_domain(self, domain: str) -> str:
        """Clean and validate domain"""
        # Remove protocol
        domain = re.sub(r'^https?://', '', domain)
        # Remove path
        domain = domain.split('/')[0]
        # Remove port
        domain = domain.split(':')[0]
        # Remove whitespace
        domain = domain.strip()
        
        return domain
    
    def _match_domain(self, domain: str, cert_domain: str) -> bool:
        """Check if domain matches certificate domain (including wildcards)"""
        if cert_domain.startswith('*.'):
            # Wildcard cert
            cert_base = cert_domain[2:]
            return domain.endswith(cert_base) and '.' in domain.replace(cert_base, '')
        return domain == cert_domain
    
    def _calculate_risk_score(self, scan_results: Dict[str, Any]) -> tuple:
        """Calculate overall risk score and compile vulnerabilities"""
        score = 100
        vulnerabilities = []
        
        # SSL scoring
        if 'ssl' in scan_results and scan_results['ssl'].get('status') == 'completed':
            ssl_results = scan_results['ssl']
            if not ssl_results.get('valid', False):
                score -= 20
                vulnerabilities.append({
                    'type': 'ssl',
                    'severity': 'high',
                    'description': 'Invalid SSL certificate'
                })
            
            for issue in ssl_results.get('issues', []):
                score -= 5
                vulnerabilities.append({
                    'type': 'ssl',
                    'severity': 'medium',
                    'description': issue
                })
        
        # Port scoring
        if 'ports' in scan_results and scan_results['ports'].get('status') == 'completed':
            risky_ports = {
                21: ('FTP', 'high'),
                23: ('Telnet', 'critical'),
                135: ('RPC', 'high'),
                139: ('NetBIOS', 'high'),
                445: ('SMB', 'high'),
                3389: ('RDP', 'high')
            }
            
            for port in scan_results['ports'].get('open_ports', []):
                if port in risky_ports:
                    service, severity = risky_ports[port]
                    score -= 15 if severity == 'critical' else 10
                    vulnerabilities.append({
                        'type': 'port',
                        'severity': severity,
                        'description': f'{service} port {port} is open'
                    })
        
        # DNS scoring
        if 'dns' in scan_results and scan_results['dns'].get('status') == 'completed':
            security_records = scan_results['dns'].get('security_records', {})
            if not security_records.get('SPF'):
                score -= 5
                vulnerabilities.append({
                    'type': 'dns',
                    'severity': 'low',
                    'description': 'No SPF record found'
                })
            if not security_records.get('DMARC'):
                score -= 5
                vulnerabilities.append({
                    'type': 'dns',
                    'severity': 'low',
                    'description': 'No DMARC record found'
                })
        
        # Header scoring
        if 'headers' in scan_results and scan_results['headers'].get('status') == 'completed':
            critical_headers = ['Strict-Transport-Security', 'X-Frame-Options', 'Content-Security-Policy']
            for header in scan_results['headers'].get('missing', []):
                if header in critical_headers:
                    score -= 10
                    vulnerabilities.append({
                        'type': 'header',
                        'severity': 'medium',
                        'description': f'Missing security header: {header}'
                    })
                else:
                    score -= 5
                    vulnerabilities.append({
                        'type': 'header',
                        'severity': 'low',
                        'description': f'Missing security header: {header}'
                    })
        
        # Vulnerability scoring
        if 'vulnerabilities' in scan_results and scan_results['vulnerabilities'].get('status') == 'completed':
            for vuln in scan_results['vulnerabilities'].get('vulnerabilities', []):
                if vuln['severity'] == 'critical':
                    score -= 25
                elif vuln['severity'] == 'high':
                    score -= 20
                elif vuln['severity'] == 'medium':
                    score -= 10
                else:
                    score -= 5
                vulnerabilities.append(vuln)
        
        return max(0, score), vulnerabilities