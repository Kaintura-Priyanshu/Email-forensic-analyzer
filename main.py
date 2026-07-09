import json
from datetime import datetime, timedelta
from email_analyzer import EmailHeaderAnalyzer
from log_analyzer import LogAnalyzer
from alibi_checker import AlibiChecker
from timeline_builder import TimelineBuilder
from report_generator import ReportGenerator

class ForensicInvestigator:
    """Orchestrates the entire investigation."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.incident_time = config.get('incident_time', datetime.now())
        self.timeline = TimelineBuilder()
        self.report = ReportGenerator()
        
    def run_investigation(self):
        """Execute full investigation pipeline."""
        print(" FORENSIC INVESTIGATION STARTED")
        print("=" * 50)
        
        # Step 1: Analyze Email Headers
        print("\n STEP 1: Analyzing Email Headers...")
        email_header = self._load_file('email_header.txt')
        self.email_analysis = EmailHeaderAnalyzer(email_header).analyze()
        print(f"   ✓ Origin IP: {self.email_analysis['origin_ip']}")
        print(f"   ✓ Spoof Score: {self.email_analysis['spoofing_indicators']['spoof_score']}")
        
        # Step 2: Analyze Logs
        print("\n  STEP 2: Analyzing Login Logs and Browser History...")
        log_analyzer = LogAnalyzer(
            self.config['login_logs_path'],
            self.config['browser_history_path']
        )
        self.log_analysis = log_analyzer.correlate_login_and_email(self.incident_time)
        print(f"   ✓ External Login Detected: {self.log_analysis['external_login_detected']}")
        print(f"   ✓ Email Accessed in Browser: {self.log_analysis['email_accessed_in_browser']}")
        
        # Step 3: Verify Alibi
        print("\n👤 STEP 3: Verifying Alibi...")
        alibi_checker = AlibiChecker(
            self.config['door_logs_path'],
            self.config['slack_path'],
            self.config['calendar_path']
        )
        self.alibi_analysis = alibi_checker.verify_alibi(
            self.incident_time,
            claimed_location="breakroom",
            claimed_start=self.incident_time - timedelta(minutes=30),
            claimed_end=self.incident_time + timedelta(minutes=30)
        )
        print(f"   ✓ Alibi Support Score: {self.alibi_analysis['support_score']}/10")
        print(f"   ✓ Alibi Verdict: {self.alibi_analysis['verdict']}")
        
        # Step 4: Build Timeline
        print("\n⏱️  STEP 4: Building Chronological Timeline...")
        self._populate_timeline()
        self.timeline.export_json('output/timeline.json')
        print(f"   ✓ {len(self.timeline.events)} events added to timeline")
        
        # Step 5: Generate Verdict
        print("\n  STEP 5: Generating Final Verdict...")
        verdict = self._generate_verdict()
        self.report.generate(verdict, self.email_analysis, self.log_analysis, 
                             self.alibi_analysis, self.timeline)
        print(f"   ✓ Report generated: {self.report.output_path}")
        
        print("\n" + "=" * 50)
        print(" INVESTIGATION COMPLETE")
        
        return verdict
    
    def _populate_timeline(self):
        """Populate timeline with events."""
        # Add incident event
        self.timeline.add_event(
            self.incident_time,
            "OFFENSIVE EMAIL SENT to CEO",
            "Email Analysis",
            "E-001",
            critical=True
        )
        
        # Add login events
        for ip in self.log_analysis['login_analysis']['unique_ips']:
            self.timeline.add_event(
                self.incident_time - timedelta(minutes=10),
                f"Login from IP: {ip}",
                "Login Logs",
                "E-002"
            )
        
        # Add alibi events
        if self.alibi_analysis['door_entries_at_location']:
            for entry in self.alibi_analysis['door_entries_at_location'][:1]:
                self.timeline.add_event(
                    entry['timestamp'],
                    f"Door access at {entry.get('location', 'Unknown')}",
                    "Door Logs",
                    "E-004"
                )
    
    def _generate_verdict(self) -> Dict:
        """Generate final verdict based on all evidence."""
        email = self.email_analysis
        log = self.log_analysis
        alibi = self.alibi_analysis
        
        # Evidence scoring
        points_for_hack = 0
        points_against_hack = 0
        
        # Email evidence
        if email['spoofing_indicators']['is_spoofed']:
            points_for_hack += 3
        
        if email['ip_type'] == 'EXTERNAL':
            points_for_hack += 2
        
        if email['authentication']['authenticated']:
            points_against_hack += 1  # Real email, not spoofed
        
        # Login evidence
        if log['external_login_detected']:
            points_for_hack += 2
        
        if not log['email_accessed_in_browser']:
            points_for_hack += 1  # Could be automated/scripted
        
        # Alibi evidence
        if alibi['alibi_supported']:
            points_against_hack += 3
        
        if 'desk_entries_during_incident' in alibi and alibi['desk_entries_during_incident']:
            points_for_hack += 2  # They were near desk when it happened
        
        # Calculate scores
        total_for_hack = points_for_hack
        total_against_hack = points_against_hack
        
        # Final verdict
        if total_for_hack >= 5 and total_for_hack > total_against_hack:
            verdict = 'EXTERNAL_HACK'
            confidence = 'HIGH' if total_for_hack >= 7 else 'MEDIUM'
        elif total_against_hack >= 5 and total_against_hack > total_for_hack:
            verdict = 'EMPLOYEE_SENT'
            confidence = 'HIGH' if total_against_hack >= 7 else 'MEDIUM'
        else:
            verdict = 'INCONCLUSIVE'
            confidence = 'LOW'
        
        return {
            'verdict': verdict,
            'confidence': confidence,
            'evidence_score': {
                'for_hack': total_for_hack,
                'against_hack': total_against_hack
            },
            'determination': self._get_determination_text(verdict),
            'recommendation': self._get_recommendation(verdict)
        }
    
    def _get_determination_text(self, verdict: str) -> str:
        """Get detailed determination text."""
        determinations = {
            'EXTERNAL_HACK': "This incident was caused by an external compromise of the employee's account. Evidence of spoofing, external IP addresses, and lack of browser access during the incident support this conclusion.",
            'EMPLOYEE_SENT': "The evidence strongly suggests the employee sent the offensive email themselves. Local IP origin, alibi contradictions, and browser history indicating email access support this finding.",
            'INCONCLUSIVE': "The evidence is conflicting or insufficient to reach a definitive conclusion. Further investigation is recommended."
        }
        return determinations.get(verdict, "Verdict pending.")
    
    def _get_recommendation(self, verdict: str) -> str:
        """Get actionable recommendation."""
        recommendations = {
            'EXTERNAL_HACK': "Recommend: Force password reset, enable 2FA, review all active sessions, and conduct security awareness training.",
            'EMPLOYEE_SENT': "Recommend: Initiate HR investigation, conduct one-on-one interview with employee, and review company policies on acceptable use.",
            'INCONCLUSIVE': "Recommend: Collect additional evidence (workstation imaging, network logs, memory forensics) and conduct follow-up interview."
        }
        return recommendations.get(verdict, "Recommend: Continue investigation.")
    
    def _load_file(self, filename: str) -> str:
        """Load file content from data/raw directory."""
        import os
        path = os.path.join('data', 'raw', filename)
        with open(path, 'r') as f:
            return f.read()

# ==== RUN INVESTIGATION ====
if __name__ == "__main__":
    config = {
        'incident_time': datetime(2026, 7, 5, 8, 30),
        'login_logs_path': 'data/raw/login_logs.csv',
        'browser_history_path': 'data/raw/browser_history.csv',
        'door_logs_path': 'data/raw/door_logs.csv',
        'slack_path': 'data/raw/slack_messages.csv',
        'calendar_path': 'data/raw/calendar_entries.csv'
    }
    
    investigator = ForensicInvestigator(config)
    verdict = investigator.run_investigation()
    
    print("\n" + "=" * 50)
    print(f" FINAL VERDICT: {verdict['verdict']}")
    print(f" Confidence: {verdict['confidence']}")
    print(f" {verdict['determination']}")
    print("=" * 50)
