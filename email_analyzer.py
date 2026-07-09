import re
import ipaddress
from datetime import datetime
from typing import Dict, List, Tuple

class EmailHeaderAnalyzer:
    """Analyzes email headers to detect spoofing, forwarding, and origin."""
    
    # Suspicious indicators
    SUSPICIOUS_HEADERS = [
        'X-Authenticated-User', 'X-Original-Authentication-Results',
        'Authentication-Results', 'DKIM-Signature', 'SPF-Pass',
        'X-Forwarded-For', 'X-Originating-IP'
    ]
    
    # IP reputation check (simulated)
    MALICIOUS_IPS = ['185.220.101.23', '194.147.140.12', '45.155.205.233']
    LOCAL_IP_RANGES = ['10.', '172.16.', '192.168.', '127.']
    COMPANY_VPN_RANGE = '192.168.1.'
    
    def __init__(self, header_text: str):
        self.raw_header = header_text
        self.headers = self._parse_headers()
        self.analysis_result = {}
        
    def _parse_headers(self) -> Dict[str, str]:
        """Parse raw headers into key-value pairs."""
        headers = {}
        lines = self.raw_header.strip().split('\n')
        
        for line in lines:
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key.strip()] = value.strip()
            else:
                # Handle folded lines (continuation)
                if headers and line.startswith(' '):
                    last_key = list(headers.keys())[-1]
                    headers[last_key] += ' ' + line.strip()
                    
        return headers
    
    def extract_origin_ip(self) -> Tuple[str, str]:
        """
        Extract originating IP from headers.
        Returns: (ip_address, source_field)
        """
        # Check common fields in order of reliability
        ip_fields = [
            ('X-Originating-IP', 'X-Originating-IP'),
            ('X-Forwarded-For', 'X-Forwarded-For'),
            ('Received', 'Received')  # Parse last Received
        ]
        
        for field, source in ip_fields:
            if field in self.headers:
                if field == 'Received':
                    # Parse IP from Received: from [IP] or Received: from host (IP)
                    match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', self.headers[field])
                    if not match:
                        match = re.search(r'from\s+.*?\(([\d.]+)\)', self.headers[field])
                    if match:
                        return (match.group(1), source)
                else:
                    # Extract IP from field
                    ip_match = re.search(r'[\d.]+', self.headers[field])
                    if ip_match:
                        return (ip_match.group(0), source)
        
        return ('UNKNOWN', 'Not Found')
    
    def check_authentication(self) -> Dict[str, bool]:
        """Check DKIM, SPF, DMARC results."""
        results = {
            'dkim_pass': False,
            'spf_pass': False,
            'dmarc_pass': False,
            'authenticated': False
        }
        
        # Check Authentication-Results
        if 'Authentication-Results' in self.headers:
            auth_text = self.headers['Authentication-Results']
            results['dkim_pass'] = 'dkim=pass' in auth_text.lower()
            results['spf_pass'] = 'spf=pass' in auth_text.lower()
            results['dmarc_pass'] = 'dmarc=pass' in auth_text.lower()
            
        # Check DKIM-Signature existence
        if 'DKIM-Signature' in self.headers:
            results['dkim_pass'] = results['dkim_pass'] or True
            
        results['authenticated'] = all([
            results['dkim_pass'],
            results['spf_pass'],
            results['dmarc_pass']
        ])
        
        return results
    
    def detect_spoofing(self) -> Dict[str, any]:
        """Detect if email appears spoofed."""
        spoof_indicators = {
            'from_mismatch': False,
            'reply_to_mismatch': False,
            'return_path_mismatch': False,
            'missing_auth': False,
            'suspicious_sender': False
        }
        
        # Check From vs Return-Path
        if 'From' in self.headers and 'Return-Path' in self.headers:
            from_domain = self._extract_domain(self.headers['From'])
            return_domain = self._extract_domain(self.headers['Return-Path'])
            spoof_indicators['return_path_mismatch'] = from_domain != return_domain
            
        # Check From vs Reply-To
        if 'From' in self.headers and 'Reply-To' in self.headers:
            from_domain = self._extract_domain(self.headers['From'])
            reply_domain = self._extract_domain(self.headers['Reply-To'])
            spoof_indicators['reply_to_mismatch'] = from_domain != reply_domain
            
        # Check authentication
        auth = self.check_authentication()
        spoof_indicators['missing_auth'] = not auth['authenticated']
        
        # Suspicious sender domain
        if 'From' in self.headers:
            domain = self._extract_domain(self.headers['From'])
            spoof_indicators['suspicious_sender'] = self._is_suspicious_domain(domain)
            
        # Overall spoof score
        spoof_score = sum(1 for v in spoof_indicators.values() if v)
        spoof_indicators['spoof_score'] = spoof_score
        spoof_indicators['is_spoofed'] = spoof_score >= 2
        
        return spoof_indicators
    
    def _extract_domain(self, email_string: str) -> str:
        """Extract domain from email address string."""
        match = re.search(r'@([\w.-]+)', email_string)
        return match.group(1) if match else ''
    
    def _is_suspicious_domain(self, domain: str) -> bool:
        """Check if domain is suspicious (simulated)."""
        suspicious_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']
        # For corporate email, external domains might be suspicious
        return domain in suspicious_domains
    
    def analyze(self) -> Dict[str, any]:
        """Run full analysis and return results."""
        origin_ip, source_field = self.extract_origin_ip()
        auth_results = self.check_authentication()
        spoof_results = self.detect_spoofing()
        
        # Determine if IP is local or external
        ip_type = 'LOCAL' if self._is_local_ip(origin_ip) else 'EXTERNAL'
        
        # Check if IP matches company VPN
        is_vpn = origin_ip.startswith(self.COMPANY_VPN_RANGE)
        
        self.analysis_result = {
            'origin_ip': origin_ip,
            'ip_source_field': source_field,
            'ip_type': ip_type,
            'is_company_vpn': is_vpn,
            'authentication': auth_results,
            'spoofing_indicators': spoof_results,
            'suspicious_headers': self._find_suspicious_headers(),
            'verdict': self._generate_verdict(origin_ip, auth_results, spoof_results)
        }
        
        return self.analysis_result
    
    def _is_local_ip(self, ip: str) -> bool:
        """Check if IP is from local network."""
        if ip == 'UNKNOWN':
            return False
        for prefix in self.LOCAL_IP_RANGES:
            if ip.startswith(prefix):
                return True
        return False
    
    def _find_suspicious_headers(self) -> List[str]:
        """Find suspicious or unusual headers."""
        suspicious = []
        for header in self.SUSPICIOUS_HEADERS:
            if header in self.headers:
                suspicious.append(header)
        return suspicious
    
    def _generate_verdict(self, ip: str, auth: Dict, spoof: Dict) -> Dict:
        """Generate analysis verdict."""
        if ip == 'UNKNOWN':
            return {'conclusion': 'INCONCLUSIVE', 'reason': 'Could not determine source IP'}
        
        if self._is_local_ip(ip):
            return {
                'conclusion': 'INTERNAL_SOURCE',
                'reason': f'Email originated from local network IP: {ip}',
                'likely_employee_sent': True
            }
        
        if auth['authenticated']:
            return {
                'conclusion': 'AUTHENTICATED_EXTERNAL',
                'reason': 'Email passed authentication, but originated externally',
                'likely_employee_sent': False
            }
        
        if spoof['is_spoofed']:
            return {
                'conclusion': 'POSSIBLE_SPOOF',
                'reason': f'Multiple spoofing indicators detected. Score: {spoof["spoof_score"]}',
                'likely_employee_sent': False
            }
        
        return {
            'conclusion': 'INCONCLUSIVE',
            'reason': 'Mixed signals requiring additional investigation',
            'likely_employee_sent': None
        }
