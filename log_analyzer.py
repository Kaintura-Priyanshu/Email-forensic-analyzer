import csv
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import List, Dict, Tuple, Optional

class LogAnalyzer:
    """Analyzes login logs and browser history for correlation."""
    
    def __init__(self, login_log_path: str, browser_path: str):
        self.login_logs = self._load_login_logs(login_log_path)
        self.browser_history = self._load_browser_history(browser_path)
        
    def _load_login_logs(self, path: str) -> List[Dict]:
        """Load login logs from CSV."""
        logs = []
        with open(path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                row['timestamp'] = datetime.fromisoformat(row['timestamp'])
                logs.append(row)
        return sorted(logs, key=lambda x: x['timestamp'])
    
    def _load_browser_history(self, path: str) -> List[Dict]:
        """Load browser history from CSV."""
        history = []
        with open(path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                row['timestamp'] = datetime.fromisoformat(row['timestamp'])
                history.append(row)
        return sorted(history, key=lambda x: x['timestamp'])
    
    def analyze_logins(self, incident_time: datetime, window_hours: int = 24) -> Dict:
        """
        Analyze login logs around incident time.
        Look for:
        - Unusual login locations
        - Multiple failed attempts
        - Logins from different IPs
        """
        start_time = incident_time - timedelta(hours=window_hours)
        end_time = incident_time + timedelta(hours=window_hours)
        
        relevant_logs = [
            log for log in self.login_logs
            if start_time <= log['timestamp'] <= end_time
        ]
        
        # IP analysis
        ip_counts = Counter([log.get('ip_address', 'UNKNOWN') for log in relevant_logs])
        unique_ips = list(ip_counts.keys())
        
        # Failed login attempts
        failed = [log for log in relevant_logs if log.get('status') == 'FAILED']
        
        # Geo-location anomalies (simulated)
        geo_locations = set()
        for log in relevant_logs:
            if 'geo_location' in log:
                geo_locations.add(log['geo_location'])
        
        result = {
            'total_logins_in_window': len(relevant_logs),
            'unique_ips': unique_ips,
            'unique_ip_count': len(unique_ips),
            'failed_attempts': len(failed),
            'failed_attempts_ips': list(set([log.get('ip_address') for log in failed if 'ip_address' in log])),
            'geo_locations': list(geo_locations),
            'unusual_ips': self._detect_unusual_ips(unique_ips),
            'multiple_geolocations': len(geo_locations) > 2,
            'suspicious_activity': False
        }
        
        # Determine if suspicious
        result['suspicious_activity'] = (
            len(unique_ips) > 3 or
            len(failed) > 5 or
            len(geo_locations) > 2 or
            bool(result['unusual_ips'])
        )
        
        return result
    
    def _detect_unusual_ips(self, ips: List[str]) -> List[str]:
        """Detect IPs from unusual locations (simulated)."""
        unusual = []
        known_good_ips = ['192.168.1.100', '10.0.0.5', '203.0.113.1']  # Company IPs
        
        for ip in ips:
            if ip not in known_good_ips and not ip.startswith('192.168.'):
                unusual.append(ip)
        return unusual
    
    def analyze_browser_activity(self, incident_time: datetime, window_hours: int = 6) -> Dict:
        """
        Analyze browser history for:
        - Email access around incident time
        - Deletion activity (if tracked)
        - Suspicious searches
        """
        start_time = incident_time - timedelta(hours=window_hours)
        end_time = incident_time + timedelta(hours=window_hours)
        
        relevant_history = [
            entry for entry in self.browser_history
            if start_time <= entry['timestamp'] <= end_time
        ]
        
        # Check for email access
        email_access = [
            entry for entry in relevant_history
            if 'mail' in entry.get('url', '').lower() or 'outlook' in entry.get('url', '').lower()
        ]
        
        # Check for deletion searches
        deletion_searches = [
            entry for entry in relevant_history
            if 'delete' in entry.get('url', '').lower() or 
               'how to delete' in entry.get('title', '').lower()
        ]
        
        return {
            'total_activities': len(relevant_history),
            'email_access_count': len(email_access),
            'email_access_times': [e['timestamp'] for e in email_access],
            'deletion_searches': deletion_searches,
            'suspicious_activity': len(deletion_searches) > 0
        }
    
    def correlate_login_and_email(self, incident_time: datetime) -> Dict:
        """
        Correlate login times with email access times.
        """
        login_analysis = self.analyze_logins(incident_time)
        browser_analysis = self.analyze_browser_activity(incident_time)
        
        # Check if there was a login from an external IP around the time of email access
        external_login = any(
            not ip.startswith('192.168.') and not ip.startswith('10.')
            for ip in login_analysis['unique_ips']
        )
        
        # Check if browser shows email access
        email_accessed = browser_analysis['email_access_count'] > 0
        
        return {
            'external_login_detected': external_login,
            'email_accessed_in_browser': email_accessed,
            'login_analysis': login_analysis,
            'browser_analysis': browser_analysis,
            'correlation_verdict': self._generate_correlation_verdict(
                external_login, 
                email_accessed,
                login_analysis,
                browser_analysis
            )
        }
    
    def _generate_correlation_verdict(self, external_login: bool, email_accessed: bool, 
                                      login_analysis: Dict, browser_analysis: Dict) -> Dict:
        """Generate correlation verdict."""
        if external_login and not email_accessed:
            return {
                'conclusion': 'POSSIBLE_HACK',
                'reason': 'External login detected but no browser email access - could be API/scripted access',
                'confidence': 'MEDIUM'
            }
        elif external_login and email_accessed:
            return {
                'conclusion': 'POSSIBLE_HACK',
                'reason': 'External login AND email access detected - consistent with compromise',
                'confidence': 'HIGH'
            }
        elif not external_login and email_accessed:
            return {
                'conclusion': 'INTERNAL_ACTIVITY',
                'reason': 'No external login, but email accessed - likely employee activity',
                'confidence': 'HIGH'
            }
        else:
            return {
                'conclusion': 'INCONCLUSIVE',
                'reason': 'No clear correlation between logins and email access',
                'confidence': 'LOW'
            }
