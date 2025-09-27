"""
Email Security Engine for PhishPrint
Core threat detection and analysis functionality
"""

import re
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from typing import Dict, List, Tuple, Any
import hashlib

class EmailSecurityEngine:
    """Core email security analysis engine"""
    
    def __init__(self, api_manager, database_manager=None):
        """Initialize security engine"""
        self.api_manager = api_manager
        self.database_manager = database_manager
        self.ml_model = IsolationForest(contamination=0.1, random_state=42)
        self.user_baseline = None
        self.demo_data_initialized = False
        
        # Security patterns
        self.phish_keywords = [
            'urgent', 'immediate action', 'verify account', 'suspended',
            'click here now', 'limited time', 'congratulations', 'winner',
            'free money', 'claim now', 'act fast', 'expires today',
            'account locked', 'security alert', 'confirm identity',
            'final notice', 'your account will be closed'
        ]
        
        self.injection_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'eval\s*\(',
            r'document\.write',
            r'window\.open',
            r'onclick\s*=',
            r'onerror\s*=',
            r'onload\s*=',
            r'atob\s*\(',
            r'fromCharCode\s*\(',
            r'innerHTML\s*=',
            r'location\.href\s*=',
            r'document\.cookie'
        ]
        
        self.suspicious_domains = [
            'bit.ly', 'tinyurl', 'fake', 'suspicious', 'phishing',
            'urgent', 'security-alert', 'account-verification'
        ]
        
        self.initialize_demo_data()
    
    def initialize_demo_data(self):
        """Set up demo data and train behavioral baseline"""
        if self.demo_data_initialized:
            return
        
        # Generate realistic training data for user baseline
        historical_emails = []
        base_time = datetime.now() - timedelta(days=30)
        
        legitimate_senders = [
            'team@company.com', 'hr@company.com', 'client@partner.com', 
            'support@service.com', 'notifications@platform.com'
        ]
        
        legitimate_subjects = [
            'Project Update', 'Meeting Reminder', 'Weekly Report', 
            'Task Assignment', 'Team Standup', 'Code Review'
        ]
        
        # Generate 50 legitimate emails for training
        for i in range(50):
            # Normal business hours (9 AM - 6 PM) with some variation
            hour_offset = np.random.normal(12, 3)  # Peak around noon
            hour_offset = max(9, min(18, hour_offset))  # Clamp to business hours
            
            email_time = base_time + timedelta(
                days=i * 0.6, 
                hours=hour_offset,
                minutes=np.random.randint(0, 60)
            )
            
            historical_emails.append({
                'timestamp': email_time,
                'from': np.random.choice(legitimate_senders),
                'body': f"Hi there, wanted to update you on project progress. Everything is moving forward as planned. Please let me know if you have any questions. Best regards.",
                'subject': f"{np.random.choice(legitimate_subjects)} #{i+1}"
            })
        
        self.train_user_baseline(historical_emails)
        
        # Demo emails for testing different threat types
        self.demo_emails = {
            "📧 Normal Work Email": {
                'from': 'colleague@company.com',
                'subject': 'Weekly Team Meeting Tomorrow',
                'body': 'Hi everyone, just a friendly reminder about our weekly team meeting tomorrow at 2 PM in conference room A. We will discuss current project progress, review deliverables, and plan for next week. Please bring your status updates and any blockers you want to discuss. Looking forward to seeing everyone there. Thanks!',
                'timestamp': datetime.now() - timedelta(hours=1),
                'category': 'legitimate'
            },
            
            "⚠️ Obvious Phishing Attack": {
                'from': 'security-alert@bank-urgent.suspicious-domain.net',
                'subject': 'URGENT: Account Suspended - Immediate Action Required!!!',
                'body': 'Dear Valued Customer, Your bank account has been SUSPENDED due to suspicious activity detected on your account! You must verify your account immediately or it will be permanently closed within 24 hours. Click here NOW to verify: http://bit.ly/fake-bank-login-urgent-verify. This is your FINAL NOTICE! Act fast before you lose access forever! Limited time offer expires today. Call our urgent security line: 1-800-FAKE-BANK.',
                'timestamp': datetime.now() - timedelta(hours=2),
                'category': 'obvious_phishing'
            },
            
            "🎯 Sophisticated Spear Phishing": {
                'from': 'colleague@company.com',
                'subject': 'Quick Financial Approval Needed - CEO Request',
                'body': 'Hi there, hope you are doing well. I know this is very last minute and unusual, but I urgently need your approval for a vendor payment that the CEO specifically requested before his flight. He is currently traveling to the client meeting and this payment needs to be processed today to avoid project delays. The amount is $15,000 for emergency consulting services. Could you please click here to approve the transaction in our finance portal: http://finance-approval.fake-company-domain.com/approve-payment?token=abc123&urgent=true. Thanks so much for your quick help on this critical matter!',
                'timestamp': datetime(2024, 1, 15, 2, 30),  # 2:30 AM - highly unusual time
                'category': 'spear_phishing'
            },
            
            "💻 Code Injection Attack": {
                'from': 'newsletter@techsite.com',
                'subject': 'New JavaScript Tutorial - Advanced Techniques',
                'body': 'Hi developers! Check out our latest advanced JavaScript tutorial covering modern ES6+ features and security best practices. <script>eval(atob("d2luZG93LmxvY2F0aW9uPSJodHRwOi8vbWFsaWNpb3VzLXNpdGUuY29tL3N0ZWFsLWRhdGEiOw=="))</script> This tutorial includes hands-on examples and real-world applications. You can also download our new coding toolkit here: http://techsite.com/download-toolkit?ref=email. Don\'t miss our upcoming webinar on cybersecurity for developers!',
                'timestamp': datetime.now() - timedelta(hours=3),
                'category': 'code_injection'
            }
        }
        
        self.demo_data_initialized = True
    
    def train_user_baseline(self, emails: List[Dict[str, Any]]):
        """Train machine learning baseline from user's email history"""
        if len(emails) < 5:
            return
        
        features = []
        for email in emails:
            features.append(self.extract_features(email))
        
        if features:
            self.ml_model.fit(features)
            
            # Calculate user baseline statistics
            self.user_baseline = {
                'total_emails': len(emails),
                'avg_length': np.mean([len(e['body']) for e in emails]),
                'std_length': np.std([len(e['body']) for e in emails]),
                'common_hour': np.bincount([e['timestamp'].hour for e in emails]).argmax(),
                'common_senders': list(set([e['from'] for e in emails])),
                'avg_response_time': 2.5,  # hours
                'typical_subject_length': np.mean([len(e['subject']) for e in emails])
            }
    
    def extract_features(self, email: Dict[str, Any]) -> List[float]:
        """Extract numerical features from email for ML analysis"""
        body = email.get('body', '')
        subject = email.get('subject', '')
        timestamp = email.get('timestamp', datetime.now())
        sender = email.get('from', '')
        
        return [
            timestamp.hour,                                           # Hour of day
            timestamp.weekday(),                                      # Day of week
            len(body),                                               # Body length
            len(subject),                                            # Subject length
            body.count('!'),                                         # Exclamation marks
            body.count('?'),                                         # Question marks
            body.count('http'),                                      # HTTP links
            body.count('URGENT'),                                    # Urgent keywords
            len(re.findall(r'[A-Z]', body)) / max(len(body), 1),    # Caps ratio
            len(re.findall(r'\$\d+', body)),                        # Money amounts
            1 if any(domain in sender for domain in self.suspicious_domains) else 0,  # Suspicious sender
            sum(1 for word in self.phish_keywords if word.lower() in body.lower())    # Phishing keywords
        ]
    
    def analyze_comprehensive(self, email: Dict[str, Any], store_results: bool = True) -> Dict[str, Any]:
        """Complete security analysis using all detection methods"""
        results = {
            'total_score': 0,
            'flags': [],
            'breach_info': {'count': 0, 'breaches': []},
            'components': {
                'heuristic': 0,
                'code_injection': 0,
                'ml_anomaly': 0,
                'api_analysis': 0
            },
            'risk_level': 'LOW',
            'color': 'green'
        }
        
        # 1. Traditional heuristic analysis
        heuristic_score, heuristic_flags = self.analyze_heuristics(email)
        results['components']['heuristic'] = heuristic_score
        results['flags'].extend(heuristic_flags)
        
        # 2. Code injection detection
        injection_score, injection_flags = self.analyze_code_injection(email)
        results['components']['code_injection'] = injection_score
        results['flags'].extend(injection_flags)
        
        # 3. API-enhanced analysis (sentiment, toxicity, breaches)
        api_score, api_flags, breach_info = self.analyze_with_apis(email)
        results['components']['api_analysis'] = api_score
        results['flags'].extend(api_flags)
        results['breach_info'] = breach_info
        
        # 4. ML anomaly detection
        if self.user_baseline:
            ml_score, ml_flags = self.analyze_ml_anomaly(email)
            results['components']['ml_anomaly'] = ml_score
            results['flags'].extend(ml_flags)
        
        # Calculate total score (weighted combination, max 100)
        weights = {
            'heuristic': 0.3,
            'code_injection': 0.3,
            'ml_anomaly': 0.2,
            'api_analysis': 0.2
        }
        
        weighted_score = sum(
            results['components'][component] * weights[component]
            for component in weights
        )
        
        results['total_score'] = min(weighted_score, 100)
        
        # Determine risk level and color
        if results['total_score'] >= 70:
            results['risk_level'] = 'HIGH RISK'
            results['color'] = 'red'
        elif results['total_score'] >= 40:
            results['risk_level'] = 'MEDIUM RISK'
            results['color'] = 'orange'
        else:
            results['risk_level'] = 'LOW RISK'
            results['color'] = 'green'
        
        # Store results in database if enabled
        if store_results and self.database_manager:
            try:
                email_hash = self.database_manager.store_email(email)
                self.database_manager.store_analysis_result(email_hash, results)
            except Exception as e:
                print(f"Database storage error: {e}")
        
        return results
    
    def analyze_heuristics(self, email: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Traditional rule-based phishing detection"""
        score = 0
        flags = []
        
        body = email.get('body', '').lower()
        subject = email.get('subject', '').lower()
        sender = email.get('from', '').lower()
        
        # Keyword analysis
        keyword_count = 0
        for keyword in self.phish_keywords:
            if keyword.lower() in body or keyword.lower() in subject:
                keyword_count += 1
                score += 8
                if keyword_count <= 3:  # Only report first few
                    flags.append(f"Suspicious keyword: '{keyword}'")
        
        # URL analysis
        urls = re.findall(r'http[s]?://[^\s]+', body)
        suspicious_url_count = 0
        for url in urls:
            if any(suspicious in url.lower() for suspicious in self.suspicious_domains):
                suspicious_url_count += 1
                score += 12
                if suspicious_url_count == 1:
                    flags.append("Suspicious shortened/fake URL detected")
        
        # Sender domain analysis
        if any(suspicious in sender for suspicious in self.suspicious_domains):
            score += 15
            flags.append("Suspicious sender domain")
        
        # Urgency analysis
        urgency_phrases = ['act now', 'expires', 'limited time', 'final notice', 'immediate']
        urgency_count = sum(1 for phrase in urgency_phrases if phrase in body)
        if urgency_count >= 2:
            score += 10
            flags.append("High urgency language detected")
        
        # Excessive punctuation
        if body.count('!') >= 3:
            score += 5
            flags.append("Excessive exclamation marks")
        
        return min(score, 40), flags
    
    def analyze_code_injection(self, email: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Detect code injection and malicious scripts"""
        score = 0
        flags = []
        
        body = email.get('body', '')
        
        # Check for dangerous patterns
        detected_patterns = []
        for pattern in self.injection_patterns:
            if re.search(pattern, body, re.IGNORECASE | re.DOTALL):
                detected_patterns.append(pattern)
                score += 15
        
        if detected_patterns:
            flags.append(f"Code injection patterns detected ({len(detected_patterns)} types)")
        
        # Check for encoded payloads
        encoding_patterns = ['atob(', 'fromCharCode(', 'unescape(', 'decodeURI(']
        for pattern in encoding_patterns:
            if pattern in body:
                score += 20
                flags.append("Encoded payload detected - potential obfuscated attack")
                break
        
        # Check for suspicious inline events
        event_handlers = re.findall(r'on\w+\s*=', body, re.IGNORECASE)
        if event_handlers:
            score += 10
            flags.append(f"Suspicious event handlers found ({len(event_handlers)})")
        
        return min(score, 50), flags
    
    def analyze_with_apis(self, email: Dict[str, Any]) -> Tuple[float, List[str], Dict[str, Any]]:
        """API-enhanced analysis using external services"""
        score = 0
        flags = []
        breach_info = {'count': 0, 'breaches': []}
        
        body = email.get('body', '')
        sender_email = email.get('from', '')
        
        # Sentiment/urgency analysis
        try:
            urgency_score = self.api_manager.analyze_sentiment_urgency(body)
            if urgency_score > 15:
                score += urgency_score
                flags.append("High emotional urgency detected by AI analysis")
        except Exception:
            pass
        
        # Toxic content detection
        try:
            toxicity_score = self.api_manager.detect_toxic_content(body)
            if toxicity_score > 10:
                score += toxicity_score
                flags.append("Toxic/malicious content patterns detected")
        except Exception:
            pass
        
        # Breach checking for sender
        try:
            if '@' in sender_email:
                breach_count, breach_names = self.api_manager.check_email_breaches(sender_email)
                breach_info = {'count': breach_count, 'breaches': breach_names}
                if breach_count > 0:
                    score += min(breach_count * 5, 15)
                    flags.append(f"Sender found in {breach_count} data breach(es)")
        except Exception:
            pass
        
        return min(score, 35), flags, breach_info
    
    def analyze_ml_anomaly(self, email: Dict[str, Any]) -> Tuple[float, List[str]]:
        """Machine learning anomaly detection based on user behavior"""
        if not self.user_baseline:
            return 0, []
        
        score = 0
        flags = []
        
        features = [self.extract_features(email)]
        
        try:
            # Get anomaly score from Isolation Forest
            anomaly_score = self.ml_model.decision_function(features)[0]
            
            # Convert to risk score (more negative = more anomalous)
            if anomaly_score < -0.2:
                ml_contribution = min(abs(anomaly_score) * 50, 25)
                score += ml_contribution
                flags.append("Behavioral anomaly detected by ML model")
            
            # Additional behavioral checks
            timestamp = email.get('timestamp', datetime.now())
            body = email.get('body', '')
            
            # Unusual time check
            if timestamp.hour < 6 or timestamp.hour > 22:
                score += 8
                flags.append("Email sent at unusual hour (outside 6 AM - 10 PM)")
            
            # Length anomaly
            if len(body) > self.user_baseline['avg_length'] * 3:
                score += 5
                flags.append("Email significantly longer than user's typical emails")
            
        except Exception:
            pass
        
        return min(score, 30), flags
    
    def get_demo_emails(self) -> Dict[str, Dict[str, Any]]:
        """Return demo emails for the interface"""
        return self.demo_emails
    
    def get_live_emails(self, gmail_emails: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        """Convert Gmail emails to display format"""
        live_emails = {}
        
        for i, email in enumerate(gmail_emails):
            # Create a display key
            subject = email.get('subject', 'No Subject')[:50]
            sender = email.get('from', 'Unknown')
            
            # Determine email type based on content analysis
            email_type = self._classify_email_type(email)
            emoji = self._get_email_emoji(email_type)
            
            display_key = f"{emoji} {subject}"
            
            # Convert to expected format
            live_emails[display_key] = {
                'from': email.get('from', 'Unknown'),
                'subject': email.get('subject', 'No Subject'),
                'body': email.get('body', ''),
                'timestamp': email.get('timestamp', datetime.now()),
                'category': email_type,
                'user_id': email.get('user_id', 'default_user'),
                'gmail_id': email.get('id', '')
            }
        
        return live_emails
    
    def _classify_email_type(self, email: Dict[str, Any]) -> str:
        """Classify email type based on content"""
        body = email.get('body', '').lower()
        subject = email.get('subject', '').lower()
        sender = email.get('from', '').lower()
        
        # Quick heuristic classification
        suspicious_indicators = 0
        
        # Check for phishing keywords
        for keyword in self.phish_keywords:
            if keyword.lower() in body or keyword.lower() in subject:
                suspicious_indicators += 1
        
        # Check for suspicious domains
        for domain in self.suspicious_domains:
            if domain in sender:
                suspicious_indicators += 2
        
        # Check for code injection patterns
        for pattern in self.injection_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                suspicious_indicators += 3
        
        # Classify based on indicators
        if suspicious_indicators >= 5:
            return 'high_risk'
        elif suspicious_indicators >= 2:
            return 'medium_risk'
        else:
            return 'legitimate'
    
    def _get_email_emoji(self, email_type: str) -> str:
        """Get emoji based on email type"""
        emoji_map = {
            'legitimate': '📧',
            'medium_risk': '⚠️',
            'high_risk': '🚨',
            'phishing': '🎣',
            'code_injection': '💻'
        }
        return emoji_map.get(email_type, '📧')
