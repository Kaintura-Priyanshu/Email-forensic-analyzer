import csv
from datetime import datetime, timedelta
from typing import List, Dict, Tuple

class AlibiChecker:
    """Cross-references employee's alibi with physical and digital evidence."""
    
    def __init__(self, door_logs_path: str, slack_path: str, calendar_path: str):
        self.door_logs = self._load_door_logs(door_logs_path)
        self.slack_messages = self._load_slack_messages(slack_path)
        self.calendar_entries = self._load_calendar(calendar_path)
    
    def _load_door_logs(self, path: str) -> List[Dict]:
        logs = []
        with open(path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                row['timestamp'] = datetime.fromisoformat(row['timestamp'])
                logs.append(row)
        return logs
    
    def _load_slack_messages(self, path: str) -> List[Dict]:
        messages = []
        with open(path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                row['timestamp'] = datetime.fromisoformat(row['timestamp'])
                messages.append(row)
        return messages
    
    def _load_calendar(self, path: str) -> List[Dict]:
        entries = []
        with open(path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                row['start'] = datetime.fromisoformat(row['start'])
                row['end'] = datetime.fromisoformat(row['end'])
                entries.append(row)
        return entries
    
    def verify_alibi(self, incident_time: datetime, 
                     claimed_location: str = "breakroom",
                     claimed_start: datetime = None,
                     claimed_end: datetime = None) -> Dict:
        """
        Verify employee's alibi against physical and digital evidence.
        """
        if claimed_start is None:
            claimed_start = incident_time - timedelta(minutes=30)
        if claimed_end is None:
            claimed_end = incident_time + timedelta(minutes=30)
        
        # 1. Check door logs for presence at claimed location
        door_entries = [
            log for log in self.door_logs
            if claimed_start <= log['timestamp'] <= claimed_end
            and log.get('location') == claimed_location
        ]
        
        # 2. Check Slack activity during claimed time
        slack_entries = [
            msg for msg in self.slack_messages
            if claimed_start <= msg['timestamp'] <= claimed_end
        ]
        
        # 3. Check if calendar shows meeting during claimed time
        calendar_conflicts = [
            entry for entry in self.calendar_entries
            if entry['start'] <= incident_time <= entry['end']
        ]
        
        # 4. Find any door entry at employee's desk during incident time
        desk_entries = [
            log for log in self.door_logs
            if claimed_start <= log['timestamp'] <= claimed_end
            and log.get('location') == 'desk_area'
            and log.get('user_id') == 'EMPLOYEE_001'
        ]
        
        result = {
            'alibi_claimed': True,
            'claimed_location': claimed_location,
            'claimed_window': f"{claimed_start} - {claimed_end}",
            'door_entries_at_location': door_entries,
            'slack_activity': slack_entries,
            'calendar_conflicts': calendar_conflicts,
            'desk_entries_during_incident': desk_entries,
            'alibi_supported': False,
            'support_score': 0,
            'details': {}
        }
        
        # Scoring
        support_score = 0
        
        # Door entry supports alibi
        if door_entries:
            support_score += 3
            result['details']['door_evidence'] = f"Found {len(door_entries)} door entries at {claimed_location}"
        
        # Slack activity supports alibi (they were active elsewhere)
        if slack_entries:
            support_score += 1
            result['details']['slack_evidence'] = f"Found {len(slack_entries)} Slack messages during claimed time"
        
        # Calendar shows meeting - strong alibi
        if calendar_conflicts:
            support_score += 2
            result['details']['calendar_evidence'] = f"Meeting: {calendar_conflicts[0].get('title')}"
        
        # Desk activity during incident time - WEAKENS alibi
        if desk_entries:
            support_score -= 3
            result['details']['desk_evidence'] = f"Found desk area access during incident time"
        
        result['support_score'] = max(0, min(10, support_score))
        result['alibi_supported'] = result['support_score'] >= 5
        
        # Verdict
        if result['support_score'] >= 7:
            result['verdict'] = 'ALIBI_VERIFIED'
        elif result['support_score'] >= 4:
            result['verdict'] = 'ALIBI_PARTIALLY_SUPPORTED'
        else:
            result['verdict'] = 'ALIBI_NOT_SUPPORTED'
        
        return result
