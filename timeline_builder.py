from datetime import datetime, timedelta
from typing import List, Dict, Tuple
import json

class TimelineBuilder:
    """Builds a unified timeline from all evidence sources."""
    
    def __init__(self):
        self.events = []
    
    def add_event(self, timestamp: datetime, description: str, 
                  source: str, evidence_id: str, critical: bool = False):
        self.events.append({
            'timestamp': timestamp,
            'description': description,
            'source': source,
            'evidence_id': evidence_id,
            'critical': critical
        })
    
    def add_email_events(self, email_analysis: Dict):
        """Add email-related events to timeline."""
        self.add_event(
            datetime.now() - timedelta(hours=2),  # Placeholder
            "Offensive email sent to CEO",
            "Email Header Analysis",
            "E-001",
            critical=True
        )
    
    def add_login_events(self, login_analysis: Dict):
        """Add login-related events."""
        # Add each login event
        pass
    
    def build_timeline(self) -> List[Dict]:
        """Sort events chronologically."""
        return sorted(self.events, key=lambda x: x['timestamp'])
    
    def get_narrative(self) -> str:
        """Generate chronological narrative."""
        timeline = self.build_timeline()
        narrative = "## CHRONOLOGICAL NARRATIVE\n\n"
        
        for event in timeline:
            flag = "🚨 " if event['critical'] else "  • "
            narrative += f"{flag} **{event['timestamp']}** - {event['description']}\n"
            narrative += f"   _Source: {event['source']} | Evidence: {event['evidence_id']}_\n\n"
        
        return narrative
    
    def export_json(self, path: str):
        """Export timeline to JSON."""
        with open(path, 'w') as f:
            json.dump(self.build_timeline(), f, indent=2, default=str)
