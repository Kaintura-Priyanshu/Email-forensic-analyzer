from datetime import datetime
from typing import Dict
import json

class ReportGenerator:
    """Generates the final detective-style verdict report."""
    
    def __init__(self):
        self.output_path = 'output/verdict_report.md'
    
    def generate(self, verdict: Dict, email_analysis: Dict, 
                 log_analysis: Dict, alibi_analysis: Dict, 
                 timeline_builder):
        """Generate full markdown report."""
        
        report = self._build_report(verdict, email_analysis, 
                                   log_analysis, alibi_analysis, 
                                   timeline_builder)
        
        with open(self.output_path, 'w') as f:
            f.write(report)
        
        return self.output_path
    
    def _build_report(self, verdict: Dict, email: Dict, 
                      log: Dict, alibi: Dict, timeline_builder) -> str:
        """Build the full report content."""
        
        # Header
        report = f"""# 🔍 DETECTIVE'S CASE FILE
## Case 2026-07-05-001

**Date of Report:** {datetime.now().strftime('%Y-%m-%d %H:%M')}
**Lead Investigator:** Detective [Your Name]
**Status:** CLOSED

---

## ⚖️ FINAL VERDICT

| Field | Value |
|-------|-------|
| **Verdict** | **{verdict['verdict']}** |
| **Confidence** | {verdict['confidence']} |
| **Evidence Score (For Hack)** | {verdict['evidence_score']['for_hack']} |
| **Evidence Score (Against Hack)** | {verdict['evidence_score']['against_hack']} |

**Determination:**
> {verdict['determination']}

**Recommendation:**
> {verdict['recommendation']}

---

## 📋 EVIDENCE SUMMARY

### Email Header Analysis

| Metric | Result |
|--------|--------|
| Origin IP | `{email['origin_ip']}` |
| IP Type | {email['ip_type']} |
| Company VPN | {email['is_company_vpn']} |
| Spoof Score | {email['spoofing_indicators']['spoof_score']}/4 |
| Is Spoofed? | {email['spoofing_indicators']['is_spoofed']} |
| DKIM Pass | {email['authentication']['dkim_pass']} |
| SPF Pass | {email['authentication']['spf_pass']} |
| DMARC Pass | {email['authentication']['dmarc_pass']} |

### Login & Browser Correlation

| Metric | Result |
|--------|--------|
| External Login Detected | {log['external_login_detected']} |
| Email Accessed in Browser | {log['email_accessed_in_browser']} |
| Unique IPs in Window | {log['login_analysis']['unique_ip_count']} |
| Failed Login Attempts | {log['login_analysis']['failed_attempts']} |
| Suspicious Activity | {log['login_analysis']['suspicious_activity']} |

### Alibi Verification

| Metric | Result |
|--------|--------|
| Support Score | {alibi['support_score']}/10 |
| Verdict | {alibi['verdict']} |
| Door Entries at Location | {len(alibi['door_entries_at_location'])} |
| Slack Activity | {len(alibi['slack_activity'])} messages |
| Calendar Conflicts | {len(alibi['calendar_conflicts'])} meeting(s) |

---

## 🕒 CHRONOLOGICAL TIMELINE

{timeline_builder.get_narrative()}

---

## 🔬 EVIDENCE SCORING BREAKDOWN

### Points FOR External Hack
| Evidence | Points |
|----------|--------|
| Spoofing indicators present | +{3 if email['spoofing_indicators']['is_spoofed'] else 0} |
| External IP source | +{2 if email['ip_type'] == 'EXTERNAL' else 0} |
| External login detected | +{2 if log['external_login_detected'] else 0} |
| No browser email access (scripted) | +{1 if not log['email_accessed_in_browser'] else 0} |
| Desk activity during incident | +{2 if alibi.get('desk_entries_during_incident') else 0} |
| **TOTAL** | **{verdict['evidence_score']['for_hack']}** |

### Points AGAINST External Hack (Supports Employee Sent It)
| Evidence | Points |
|----------|--------|
| Authentication passed | +{1 if email['authentication']['authenticated'] else 0} |
| Alibi supported | +{3 if alibi['alibi_supported'] else 0} |
| **TOTAL** | **{verdict['evidence_score']['against_hack']}** |

---

##  EVIDENCE INDEX

| ID | Item | Source | Status |
|----|------|--------|--------|
| E-001 | Offensive Email Headers | CEO Mailbox | ✅ Analyzed |
| E-002 | Login Logs (60-day) | Identity Provider | ✅ Analyzed |
| E-003 | Browser History (7-day) | Workstation | ✅ Analyzed |
| E-004 | Door Access Logs | Security System | ✅ Analyzed |
| E-005 | Slack Messages | Slack Workspace | ✅ Analyzed |
| E-006 | Calendar Entries | Exchange | ✅ Analyzed |
| E-007 | Interview Transcript | HR Recording | ✅ Completed |
| E-008 | Workstation Image | Forensic Acquisition |  Pending |

---

##  CLASSIFICATION: CONFIDENTIAL

*This report contains sensitive information and is intended for authorized personnel only.*

---

**End of Report**

"""
        return report
