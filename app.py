"""
PhishPrint - Modern Email Security Suite
Modern dark-themed Gmail-like interface with AI-powered security analysis
Inspired by cutting-edge security dashboards
"""

import streamlit as st
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer
import re
import json
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
import time
import os
import requests

# Configure page for dark theme
st.set_page_config(
    page_title="PhishPrint Security Suite", 
    page_icon="🛡️", 
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Modern Dark Theme CSS
st.markdown("""
<style>
/* Dark theme globals */
.stApp {
    background-color: #0f0f23;
    color: #ffffff;
}

/* Hide Streamlit branding */
#MainMenu {visibility: hidden;}
footer {visibility: hidden;}
header {visibility: hidden;}

/* Modern inbox card styling */
.email-card {
    background: linear-gradient(145deg, #1a1a2e, #16213e);
    border: 1px solid #2a2a3e;
    border-radius: 12px;
    padding: 20px;
    margin: 10px 0;
    transition: all 0.3s ease;
    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
}

.email-card:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.4);
    border-color: #3a3a5e;
}

/* Risk score badges */
.risk-score {
    display: inline-block;
    padding: 8px 16px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 14px;
    text-align: center;
    min-width: 60px;
}

.risk-high {
    background: linear-gradient(135deg, #ff3b30, #ff6b6b);
    color: white;
    box-shadow: 0 4px 15px rgba(255, 59, 48, 0.3);
}

.risk-medium {
    background: linear-gradient(135deg, #ff9500, #ffb347);
    color: white;
    box-shadow: 0 4px 15px rgba(255, 149, 0, 0.3);
}

.risk-low {
    background: linear-gradient(135deg, #34c759, #5ac777);
    color: white;
    box-shadow: 0 4px 15px rgba(52, 199, 89, 0.3);
}

/* Security tags */
.security-tag {
    display: inline-block;
    background: #ff3b30;
    color: white;
    padding: 4px 12px;
    border-radius: 16px;
    font-size: 11px;
    font-weight: 600;
    margin: 2px 4px;
    text-transform: uppercase;
}

.tag-phishing { background: #ff3b30; }
.tag-injection { background: #ff9500; }
.tag-anomaly { background: #af52de; }
.tag-breach { background: #ff2d92; }

/* Header styling */
.main-header {
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    padding: 25px;
    border-radius: 15px;
    margin-bottom: 25px;
    text-align: center;
    box-shadow: 0 8px 32px rgba(102, 126, 234, 0.3);
}

/* Analysis panel */
.analysis-panel {
    background: linear-gradient(145deg, #1a1a2e, #16213e);
    border: 1px solid #2a2a3e;
    border-radius: 15px;
    padding: 25px;
    margin: 10px 0;
    box-shadow: 0 8px 25px rgba(0, 0, 0, 0.3);
}

/* Chat interface */
.chat-container {
    background: linear-gradient(145deg, #0f0f23, #1a1a2e);
    border: 1px solid #2a2a3e;
    border-radius: 15px;
    padding: 20px;
    margin-top: 20px;
}

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, #667eea, #764ba2);
    color: white;
    border: none;
    border-radius: 8px;
    padding: 0.5rem 1rem;
    font-weight: 600;
    transition: all 0.3s ease;
}

.stButton > button:hover {
    background: linear-gradient(135deg, #5a6fd8, #6b4190);
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
}

/* Metrics */
.metric-container {
    background: linear-gradient(145deg, #1a1a2e, #16213e);
    border: 1px solid #2a2a3e;
    border-radius: 10px;
    padding: 15px;
    text-align: center;
}
</style>
""", unsafe_allow_html=True)

class APIManager:
    """Handles external API integrations"""
    
    def __init__(self):
        self.gemini_api_key = os.getenv('GEMINI_API_KEY')
        self.hf_api_key = os.getenv('HUGGINGFACE_API_KEY')
        
        self.hf_headers = {"Authorization": f"Bearer {self.hf_api_key}"} if self.hf_api_key else {}
        self.gemini_configured = False
        
        # Initialize Gemini - Using new google-genai SDK per integration blueprint
        self._init_gemini()
    
    def _init_gemini(self):
        """Initialize Gemini AI client with latest SDK"""
        try:
            if not self.gemini_api_key:
                self.gemini_configured = False
                print("⚠️ GEMINI_API_KEY not found - using fallback responses")
                return
                
            # Using latest google-genai SDK from blueprint
            from google import genai
            from google.genai import types
            self.genai_client = genai.Client(api_key=self.gemini_api_key)
            self.genai_types = types
            self.gemini_configured = True
            print("✅ Gemini AI initialized successfully with gemini-2.5-flash")
        except Exception as e:
            self.gemini_configured = False
            print(f"❌ Gemini initialization failed: {e}")
    
    def generate_smart_response(self, question, email_context, analysis_results):
        """Generate intelligent responses using Gemini 2.5-flash"""
        if not self.gemini_configured:
            return self._fallback_response(question, email_context, analysis_results)
        
        try:
            # Build comprehensive context for Gemini
            email_content = email_context.get('body', '')[:1000]  # Limit for token efficiency
            security_flags = analysis_results.get('flags', [])
            risk_score = analysis_results.get('total_score', 0)
            risk_level = analysis_results.get('risk_level', 'UNKNOWN')
            security_tags = analysis_results.get('tags', [])
            
            # Craft intelligent prompt for Gemini
            prompt = f"""You are PhishPrint, an expert cybersecurity AI assistant specializing in email threat analysis. You have extensive knowledge of phishing techniques, social engineering, malware distribution, and email security best practices.

EMAIL ANALYSIS CONTEXT:
📧 From: {email_context.get('from', 'Unknown')}
📧 Subject: {email_context.get('subject', 'Unknown')}
📧 Content: {email_content}

SECURITY ANALYSIS RESULTS:
🛡️ PhishScore: {risk_score}/100 ({risk_level} RISK)
🚩 Security Flags: {', '.join(security_flags) if security_flags else 'None detected'}
🏷️ Threat Categories: {', '.join(security_tags) if security_tags else 'None'}

USER QUESTION: "{question}"

PLEASE PROVIDE:
1. A clear, actionable answer to the user's question
2. Specific security insights based on the email content and analysis
3. Practical recommendations for safe email handling
4. Educational context about the security concepts involved

GUIDELINES:
- Be conversational but authoritative
- Use emojis sparingly for emphasis
- Keep responses under 150 words
- Focus on practical, actionable advice
- Explain technical concepts in simple terms
- Always prioritize user safety"""
            
            # Generate response using Gemini 2.5-flash
            response = self.genai_client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )
            
            if response and response.text:
                return response.text.strip()
            else:
                return self._fallback_response(question, email_context, analysis_results)
                
        except Exception as e:
            print(f"Gemini API error: {e}")
            return self._fallback_response(question, email_context, analysis_results)
    
    def _fallback_response(self, question, email_context, analysis_results):
        """Enhanced fallback responses with comprehensive question handling"""
        q_lower = question.lower()
        score = analysis_results.get('total_score', 0)
        flags = analysis_results.get('flags', [])
        tags = analysis_results.get('tags', [])
        sender = email_context.get('from', 'Unknown sender')
        subject = email_context.get('subject', 'No subject')
        
        # Safety and trust questions
        if any(word in q_lower for word in ['safe', 'trust', 'legitimate', 'real']):
            if score >= 70:
                return f"🚨 **EXTREMELY DANGEROUS**: This email is NOT safe (Risk Score: {score}/100). Detected threats: {', '.join(tags[:3]) if tags else 'multiple security violations'}. NEVER click links or download attachments. Report as phishing immediately and delete."
            elif score >= 40:
                return f"⚠️ **PROCEED WITH CAUTION**: This email has moderate risk (Score: {score}/100). Verify sender identity through separate communication channel. Be suspicious of urgency tactics and unexpected requests for sensitive information."
            else:
                return f"✅ **APPEARS SAFE**: Email shows low risk indicators (Score: {score}/100). However, always verify unexpected requests and avoid sharing sensitive information via email."
        
        # Risk score explanations
        elif any(phrase in q_lower for phrase in ['why score', 'why risk', 'how calculated', 'explain score']):
            if flags:
                threat_details = '; '.join(flags[:4])
                return f"🔍 **Risk Analysis**: Score based on: {threat_details}. Our AI analyzes keywords, URL patterns, sender reputation, content structure, and behavioral anomalies to detect threats."
            else:
                return f"📊 **Low Risk Indicators**: Score ({score}/100) reflects normal email patterns with legitimate sender behavior, appropriate content tone, and no suspicious technical elements."
        
        # Phishing and scam questions
        elif any(word in q_lower for word in ['phish', 'scam', 'fake', 'fraud']):
            if 'phishing' in tags:
                return "🎣 **CONFIRMED PHISHING**: Email uses social engineering tactics - urgent language, fake authority, credential harvesting attempts. Classic signs: pressure to act fast, suspicious links, requests for passwords/personal info."
            else:
                return "🛡️ **Phishing Prevention**: No obvious phishing detected, but stay vigilant for: urgency tactics, grammar errors, unexpected prize notifications, requests for sensitive data, or links to unfamiliar domains."
        
        # Malware and code injection
        elif any(word in q_lower for word in ['malware', 'virus', 'code', 'injection', 'script', 'dangerous']):
            if 'injection' in tags:
                return "⚠️ **MALICIOUS CODE DETECTED**: Email contains executable scripts that could compromise your device. These run automatically when email opens. IMMEDIATE ACTION: Don't interact with email, report to IT security, scan device."
            else:
                return "🔒 **Code Security**: No malicious scripts detected. Still avoid: executable attachments (.exe, .scr, .bat), macro-enabled documents, or clicking suspicious links that could download malware."
        
        # Action recommendations
        elif any(phrase in q_lower for phrase in ['what do', 'should i do', 'next steps', 'action', 'how respond']):
            if score >= 70:
                return "🚨 **CRITICAL ACTIONS**: 1) DO NOT interact with email 2) Mark as phishing/spam 3) Report to security team 4) Delete immediately 5) If you clicked anything: change passwords, scan device, monitor accounts for suspicious activity."
            elif score >= 40:
                return "⚠️ **VERIFICATION STEPS**: 1) Contact sender via phone/separate channel 2) Don't respond to urgency pressure 3) Hover over (don't click) links to check destinations 4) Forward to security team for review 5) When unsure, err on side of caution."
            else:
                return "✅ **STANDARD SECURITY**: 1) Verify any unexpected requests 2) Check sender's email carefully 3) Be cautious with attachments 4) Use 2FA where possible 5) Keep software updated 6) Trust your instincts."
        
        # Sender verification
        elif any(word in q_lower for word in ['sender', 'from', 'who sent', 'legitimate sender']):
            return f"👤 **Sender Analysis**: From '{sender}'. {'⚠️ Suspicious domain detected' if any(suspicious in sender.lower() for suspicious in ['fake', 'verification', 'security-', '-security']) else '✓ Domain appears normal'}. Always verify sender identity through alternative contact methods for important requests."
        
        # URL and link safety
        elif any(word in q_lower for word in ['link', 'url', 'click', 'website']):
            urls_detected = len([flag for flag in flags if 'url' in flag.lower() or 'link' in flag.lower()])
            if urls_detected > 0:
                return f"🔗 **SUSPICIOUS LINKS DETECTED**: Found {urls_detected} potentially dangerous URLs. NEVER click these links. They may: steal credentials, download malware, or redirect to phishing sites. Use hover-preview to check destinations safely."
            else:
                return "🔗 **Link Safety**: No obviously suspicious links detected, but always: 1) Hover to preview destinations 2) Look for misspelled domains 3) Avoid shortened URLs from unknown senders 4) Type URLs manually when possible."
        
        # Email content analysis
        elif any(word in q_lower for word in ['content', 'message', 'text', 'body']):
            urgency_words = ['urgent', 'immediate', 'expires', 'limited time', 'act now']
            urgency_detected = sum(1 for word in urgency_words if word in email_context.get('body', '').lower())
            if urgency_detected >= 2:
                return f"⏰ **URGENCY MANIPULATION**: Email uses {urgency_detected} urgency tactics to pressure quick action. This is a classic manipulation technique. Legitimate organizations rarely demand immediate action via email."
            else:
                return f"📝 **Content Analysis**: Email tone appears {'professional and measured' if score < 40 else 'potentially manipulative'}. Key indicators: urgency level, grammar quality, personalization, and request appropriateness."
        
        # General help and education
        elif any(word in q_lower for word in ['help', 'explain', 'learn', 'understand', 'tell me']):
            return f"🎓 **Security Education**: Current email risk level: {analysis_results.get('risk_level', 'UNKNOWN')} ({score}/100). I can help with: 'Is this safe?', 'Why this score?', 'What should I do?', 'Is this phishing?', 'Check the sender', 'Analyze the content', or 'Explain the links'."
        
        # Default response with suggested questions
        else:
            suggestions = [
                "Is this email safe to trust?",
                "Why did this get a high/low risk score?", 
                "What should I do about this email?",
                "Is this a phishing attempt?",
                "Who is the sender and are they legitimate?",
                "Are there any dangerous links?",
                "What makes this email suspicious?",
                "How can I protect myself?"
            ]
            random_suggestions = np.random.choice(suggestions, 3, replace=False)
            return f"🤖 **AI Security Assistant**: Risk Level {analysis_results.get('risk_level', 'UNKNOWN')} ({score}/100). Try asking: '{random_suggestions[0]}', '{random_suggestions[1]}', or '{random_suggestions[2]}'. I can analyze any aspect of this email's security."

class EmailSecurityEngine:
    """Core security analysis engine"""
    
    def __init__(self, api_manager=None, database_manager=None):
        self.api_manager = api_manager or APIManager()
        self.database_manager = database_manager
        self.phish_model = IsolationForest(contamination=0.1, random_state=42)
        self.user_baseline = None
        self.vectorizer = TfidfVectorizer(max_features=50, stop_words='english')
        
        # Security patterns
        self.phish_keywords = [
            'urgent', 'immediate action', 'verify account', 'suspended',
            'click here now', 'limited time', 'congratulations', 'winner',
            'free money', 'claim now', 'act fast', 'expires today'
        ]
        
        self.injection_patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'eval\(',
            r'document\.write',
            r'window\.open',
            r'onclick\s*=',
            r'onerror\s*=',
            r'onload\s*='
        ]
        
        self.setup_demo_data()
    
    def setup_demo_data(self):
        """Initialize with expanded demo data"""
        # Comprehensive demo emails with diverse scenarios
        self.demo_emails = {
            # LEGITIMATE EMAILS (LOW RISK)
            "📧 Normal Work Email": {
                'from': 'sarah.johnson@company.com',
                'subject': 'Weekly Team Status Update',
                'body': 'Hi everyone, here\'s the weekly progress report for Project Alpha. We\'ve completed 85% of the development phase and are on track for the deadline. Please review the attached documents and provide feedback by Friday.',
                'timestamp': datetime.now() - timedelta(hours=2),
                'risk_level': 'low'
            },
            "📅 Meeting Reminder": {
                'from': 'calendar@company.com',
                'subject': 'Reminder: Quarterly Review Meeting Tomorrow at 2 PM',
                'body': 'This is a friendly reminder about tomorrow\'s quarterly review meeting. Please prepare your project reports and join us in Conference Room B at 2:00 PM. Looking forward to seeing everyone there!',
                'timestamp': datetime.now() - timedelta(hours=18),
                'risk_level': 'low'
            },
            "📦 Amazon Order": {
                'from': 'shipment-tracking@amazon.com',
                'subject': 'Your order has been shipped - Track your package',
                'body': 'Great news! Your recent order #112-4567890-1234567 has been shipped and is on its way. You can track your package using the tracking number: 1Z999AA1234567890. Expected delivery: Tomorrow by 8 PM.',
                'timestamp': datetime.now() - timedelta(hours=4),
                'risk_level': 'low'
            },
            "💰 Bank Statement": {
                'from': 'statements@wellsfargo.com',
                'subject': 'Your monthly statement is ready',
                'body': 'Your Wells Fargo monthly statement for December 2025 is now available in your online banking portal. Please log in to review your account activity and transactions.',
                'timestamp': datetime.now() - timedelta(hours=8),
                'risk_level': 'low'
            },
            
            # PHISHING EMAILS (HIGH RISK)
            "🚨 PayPal Phishing": {
                'from': 'security@paypal-security.net',
                'subject': 'URGENT: Account Suspended - Immediate Action Required!',
                'body': 'Your PayPal account has been suspended due to suspicious activity! Click here NOW to verify: http://bit.ly/fake-paypal. Act fast or lose access forever! Limited time offer expires in 24 hours!',
                'timestamp': datetime.now() - timedelta(minutes=45),
                'risk_level': 'high'
            },
            "🏦 Bank Phishing": {
                'from': 'security@chase-verification.net',
                'subject': 'Urgent: Verify Your Account to Prevent Closure',
                'body': 'Dear Valued Customer, We detected unusual activity on your account. Your online banking will be suspended in 24 hours unless you verify immediately. Click here to verify: http://chase-verify.suspicious-domain.com/login',
                'timestamp': datetime.now() - timedelta(hours=1),
                'risk_level': 'high'
            },
            "🎁 Lottery Scam": {
                'from': 'winner@internationallottery.org',
                'subject': 'CONGRATULATIONS! You\'ve Won $500,000 in International Lottery!',
                'body': 'Congratulations! You have been selected as a winner in our international lottery promotion. You have won $500,000 USD! To claim your prize, send us your personal details and banking information immediately. Act now - this offer expires in 48 hours!',
                'timestamp': datetime.now() - timedelta(hours=3),
                'risk_level': 'high'
            },
            "📱 Apple ID Phishing": {
                'from': 'security@apple-verification.com',
                'subject': 'Your Apple ID has been locked due to suspicious activity',
                'body': 'Your Apple ID was used to sign in to a device we don\'t recognize. If this wasn\'t you, your account may be compromised. Click here immediately to verify: http://appleid-verify.fake-site.com/secure',
                'timestamp': datetime.now() - timedelta(minutes=30),
                'risk_level': 'high'
            },
            
            # SPEAR PHISHING (HIGH RISK)
            "🎯 CEO Fraud": {
                'from': 'john.smith@company-ceo.com',
                'subject': 'Urgent: Confidential Wire Transfer Needed Today',
                'body': 'Hi, I need you to process an urgent wire transfer for a confidential acquisition deal. Transfer $50,000 to account 123456789 at First National Bank immediately. This is time-sensitive and confidential. Don\'t discuss with anyone.',
                'timestamp': datetime.now() - timedelta(minutes=20),
                'risk_level': 'high'
            },
            "🎯 HR Impersonation": {
                'from': 'hr.admin@company.com',
                'subject': 'Action Required: Update Your Payroll Information',
                'body': 'Dear Employee, Due to system updates, you must re-verify your payroll information by end of day or your next paycheck will be delayed. Click here to update: http://company-payroll-update.malicious-site.com',
                'timestamp': datetime.now() - timedelta(hours=2),
                'risk_level': 'high'
            },
            
            # CODE INJECTION (HIGH RISK)
            "💻 Newsletter Injection": {
                'from': 'newsletter@techdeals.com',
                'subject': 'Weekly Tech Deals Newsletter - 50% Off Selected Items',
                'body': 'Don\'t miss out on this week\'s amazing tech deals! <script>eval(atob("d2luZG93LmxvY2F0aW9uPSJodHRwOi8vbWFsaWNpb3VzLXNpdGUuY29tIjs="))</script> Click here for more: http://techdeals.com/deals',
                'timestamp': datetime.now() - timedelta(hours=12),
                'risk_level': 'high'
            },
            "💻 HTML Injection": {
                'from': 'updates@social-network.com',
                'subject': 'You have 5 new notifications',
                'body': 'You have new activity on your account! <img src="x" onerror="javascript:window.location=\'http://malicious-site.com/steal-cookies\'"> Check your notifications now: http://social-network.com/notifications',
                'timestamp': datetime.now() - timedelta(hours=6),
                'risk_level': 'high'
            },
            
            # SUSPICIOUS BUT MEDIUM RISK
            "⚠️ Unknown Sender": {
                'from': 'info@random-marketing.biz',
                'subject': 'Limited Time Offer - Make Money Online Fast!',
                'body': 'Discover the secret to making $5000 per month from home! Our exclusive system has helped thousands of people quit their day jobs. Limited time offer - only $97 (usually $497). Order now!',
                'timestamp': datetime.now() - timedelta(hours=10),
                'risk_level': 'medium'
            },
            "⚠️ Shortened URL": {
                'from': 'marketing@deals-today.com',
                'subject': 'Flash Sale: 80% Off Everything - Today Only!',
                'body': 'Don\'t miss our biggest sale of the year! Get 80% off everything in our store. Use code FLASH80 at checkout. Shop now: http://tinyurl.com/suspicious-deal Act fast - sale ends tonight at midnight!',
                'timestamp': datetime.now() - timedelta(hours=5),
                'risk_level': 'medium'
            },
            "⚠️ Romance Scam": {
                'from': 'beautifulwoman2025@email.com',
                'subject': 'Hello Handsome! I saw your profile...',
                'body': 'Hi there! I came across your profile and was impressed. I\'m a beautiful single woman looking for a serious relationship. I\'d love to get to know you better. Can you help me with a small financial situation? I promise to pay you back.',
                'timestamp': datetime.now() - timedelta(hours=14),
                'risk_level': 'medium'
            }
        }
        
        # Train baseline with historical data
        historical_emails = []
        base_time = datetime.now() - timedelta(days=30)
        
        for i in range(40):
            email_time = base_time + timedelta(days=i*0.7, hours=np.random.normal(11, 2))
            historical_emails.append({
                'timestamp': email_time,
                'sender': np.random.choice(['team@company.com', 'hr@company.com', 'client@partner.com']),
                'body': f"Hi, wanted to update you on project status. Everything is progressing well. Best regards.",
                'subject': f"Project Update {i}"
            })
        
        self.train_baseline(historical_emails)
    
    def train_baseline(self, emails):
        """Train user behavior baseline"""
        if len(emails) < 5:
            return
        
        features = []
        for email in emails:
            features.append(self.extract_features(email))
        
        if features:
            self.phish_model.fit(features)
            self.user_baseline = {
                'total_emails': len(emails),
                'avg_length': np.mean([len(e['body']) for e in emails]),
                'common_hour': np.bincount([e['timestamp'].hour for e in emails]).argmax()
            }
    
    def extract_features(self, email):
        """Extract numerical features from email"""
        body = email.get('body', '')
        timestamp = email.get('timestamp', datetime.now())
        
        return [
            timestamp.hour,
            timestamp.weekday(),
            len(body),
            body.count('!'),
            body.count('http'),
            sum(1 for word in self.phish_keywords if word.lower() in body.lower()),
            len(re.findall(r'[A-Z]', body)) / max(len(body), 1)
        ]
    
    def analyze_comprehensive(self, email):
        """Complete security analysis"""
        results = {
            'total_score': 0,
            'risk_level': 'LOW',
            'risk_color': 'green',
            'flags': [],
            'tags': [],
            'components': {}
        }
        
        # Heuristic analysis
        heuristic_score, heuristic_flags = self.analyze_heuristics(email)
        results['components']['heuristic'] = heuristic_score
        results['flags'].extend(heuristic_flags)
        
        # Code injection detection
        injection_score, injection_flags = self.analyze_code_injection(email)
        results['components']['code_injection'] = injection_score
        results['flags'].extend(injection_flags)
        
        # ML anomaly detection
        if self.user_baseline:
            ml_score, ml_flags = self.analyze_ml_anomaly(email)
            results['components']['ml_anomaly'] = ml_score
            results['flags'].extend(ml_flags)
        
        # Calculate total score
        total = sum(results['components'].values())
        results['total_score'] = min(total, 100)
        
        # Determine risk level and color
        if results['total_score'] >= 70:
            results['risk_level'] = 'HIGH'
            results['risk_color'] = 'red'
        elif results['total_score'] >= 40:
            results['risk_level'] = 'MEDIUM'
            results['risk_color'] = 'orange'
        else:
            results['risk_level'] = 'LOW'
            results['risk_color'] = 'green'
        
        # Generate security tags
        results['tags'] = self.generate_security_tags(results['flags'])
        
        return results
    
    def analyze_heuristics(self, email):
        """Traditional rule-based analysis"""
        score = 0
        flags = []
        
        body = email.get('body', '').lower()
        
        # Keyword analysis
        for keyword in self.phish_keywords:
            if keyword.lower() in body:
                score += 15
                flags.append(f"Suspicious keyword: '{keyword}'")
        
        # URL analysis
        urls = re.findall(r'http[s]?://[^\s]+', body)
        for url in urls:
            if any(suspicious in url.lower() for suspicious in ['bit.ly', 'tinyurl', 'fake', 'suspicious']):
                score += 20
                flags.append("Suspicious URL detected")
        
        return min(score, 40), flags
    
    def analyze_code_injection(self, email):
        """Detect code injection attempts"""
        score = 0
        flags = []
        
        body = email.get('body', '')
        
        for pattern in self.injection_patterns:
            matches = re.findall(pattern, body, re.IGNORECASE | re.DOTALL)
            if matches:
                score += 25
                flags.append(f"Code injection pattern detected")
        
        # Check for encoded payloads
        if 'atob(' in body or 'fromCharCode(' in body:
            score += 30
            flags.append("Encoded payload detected")
        
        return min(score, 40), flags
    
    def analyze_ml_anomaly(self, email):
        """ML-based anomaly detection"""
        score = 0
        flags = []
        
        if self.user_baseline:
            features = [self.extract_features(email)]
            anomaly_score = self.phish_model.decision_function(features)[0]
            if anomaly_score < -0.1:
                ml_contribution = min(20, abs(anomaly_score) * 100)
                score += ml_contribution
                flags.append("Unusual communication pattern detected")
        
        return score, flags
    
    def generate_security_tags(self, flags):
        """Generate security tags based on analysis flags"""
        tags = []
        flag_text = ' '.join(flags).lower()
        
        if any(term in flag_text for term in ['phish', 'suspicious', 'fake']):
            tags.append('phishing')
        if any(term in flag_text for term in ['injection', 'script', 'encoded']):
            tags.append('injection')
        if 'anomaly' in flag_text or 'unusual' in flag_text:
            tags.append('anomaly')
        if 'breach' in flag_text:
            tags.append('breach')
        
        return tags
    
    def get_live_emails(self, gmail_emails):
        """Convert Gmail emails to display format"""
        # For now, return demo emails as this integration is complex
        return self.demo_emails

class PhishPrintUI:
    """Modern UI components"""
    
    def __init__(self, email_engine, api_manager):
        self.email_engine = email_engine
        self.api_manager = api_manager
        # Initialize session state if not exists
        if 'selected_email' not in st.session_state:
            st.session_state.selected_email = None
        if 'chat_responses' not in st.session_state:
            st.session_state.chat_responses = {}
    
    def render_main_interface(self, custom_emails=None):
        """Render the main modern interface"""
        # Header
        st.markdown("""
        <div class="main-header">
            <h1>🛡️ PhishPrint Inbox</h1>
            <p style="margin: 0; opacity: 0.9;">AI-Powered Email Security Analysis</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Layout
        col1, col2 = st.columns([2, 1])
        
        with col1:
            self.render_inbox(custom_emails)
        
        with col2:
            self.render_analysis_panel()
    
    def render_inbox(self, custom_emails=None):
        """Render modern inbox with email cards"""
        st.markdown("### 📬 Inbox")
        
        emails = custom_emails or self.email_engine.demo_emails
        total_emails = len(emails)
        
        # Stats
        st.markdown(f"**{total_emails} emails analyzed**")
        st.markdown("---")
        
        # Email cards
        for email_name, email_data in emails.items():
            analysis = self.email_engine.analyze_comprehensive(email_data)
            
            # Calculate display values
            score = int(analysis['total_score'])
            risk_class = f"risk-{analysis['risk_color']}"
            timestamp_str = self.format_timestamp(email_data.get('timestamp', datetime.now()))
            
            # Email card
            card_html = f"""
            <div class="email-card {risk_class}">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 10px;">
                    <div style="flex: 1;">
                        <strong style="color: #ffffff; font-size: 16px;">{email_data['from']}</strong>
                        <div style="margin: 8px 0;">
                            <h4 style="margin: 0; color: #e1e1e1;">{email_data['subject']}</h4>
                        </div>
                        <p style="color: #b1b1b1; margin: 0; font-size: 14px;">
                            {email_data['body'][:80]}...
                        </p>
                    </div>
                    <div style="text-align: right; margin-left: 20px;">
                        <div class="risk-score {risk_class}">{score}</div>
                        <div style="margin-top: 8px; color: #888;">{timestamp_str}</div>
                    </div>
                </div>
            """
            
            # Add security tags
            if analysis['tags']:
                card_html += '<div style="margin-top: 10px;">'
                for tag in analysis['tags'][:3]:
                    card_html += f'<span class="security-tag tag-{tag}">{tag}</span>'
                if len(analysis['tags']) > 3:
                    card_html += '<span class="security-tag">+{} more</span>'.format(len(analysis['tags']) - 3)
                card_html += '</div>'
            
            card_html += "</div>"
            
            st.markdown(card_html, unsafe_allow_html=True)
            
            # Invisible button for selection
            if st.button(f"Select {email_name}", key=f"select_{email_name}", help="Click to analyze this email"):
                st.session_state.selected_email = (email_name, email_data, analysis)
                # Clear previous chat when selecting a new email
                st.session_state.chat_responses = {}
                st.rerun()
            
            st.markdown("<br>", unsafe_allow_html=True)
    
    def render_analysis_panel(self):
        """Render detailed analysis panel"""
        st.markdown("### 🔍 Security Analysis")
        
        # Gmail Input Section
        st.markdown("""<div class="analysis-panel" style="margin-bottom: 20px; padding: 15px;">
        <h4 style="color: #667eea; margin-bottom: 10px;">📧 Connect Your Gmail</h4>
        </div>""", unsafe_allow_html=True)
        
        gmail_email = st.text_input(
            "Enter your Gmail address to fetch and analyze your real inbox:",
            placeholder="your.email@gmail.com",
            help="This will connect to Gmail API to fetch your emails for analysis"
        )
        
        if gmail_email:
            col1, col2 = st.columns([1, 1])
            with col1:
                if st.button("🔗 Connect Gmail", type="primary"):
                    st.info("📧 Gmail integration coming soon! For now, enjoy analyzing our comprehensive demo emails below.")
            with col2:
                if st.button("📥 Refresh Inbox"):
                    st.info("🔄 Demo mode active - showing sample emails with various threat scenarios")
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        if not st.session_state.selected_email:
            st.markdown("""
            <div class="analysis-panel">
                <div style="text-align: center; padding: 30px;">
                    <h3 style="color: #888;">Select an email to analyze</h3>
                    <p style="color: #666;">Choose an email from the inbox to see detailed security analysis</p>
                </div>
            </div>
            """, unsafe_allow_html=True)
            return
        
        email_name, email_data, analysis = st.session_state.selected_email
        
        # Analysis panel
        st.markdown("""
        <div class="analysis-panel">
        """, unsafe_allow_html=True)
        
        # Risk gauge
        score = analysis['total_score']
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=score,
            title={'text': "PhishScore", 'font': {'color': 'white'}},
            domain={'x': [0, 1], 'y': [0, 1]},
            gauge={
                'axis': {'range': [None, 100], 'tickcolor': 'white'},
                'bar': {'color': analysis['risk_color']},
                'steps': [
                    {'range': [0, 40], 'color': "rgba(52, 199, 89, 0.3)"},
                    {'range': [40, 70], 'color': "rgba(255, 149, 0, 0.3)"},
                    {'range': [70, 100], 'color': "rgba(255, 59, 48, 0.3)"}
                ],
                'threshold': {
                    'line': {'color': "white", 'width': 4},
                    'thickness': 0.75,
                    'value': 70
                }
            }
        ))
        fig.update_layout(
            height=250,
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font={'color': 'white'}
        )
        st.plotly_chart(fig, use_container_width=True)
        
        # Risk level display
        risk_level = analysis['risk_level']
        if risk_level == 'HIGH':
            st.error(f"🚨 **{risk_level} RISK**")
        elif risk_level == 'MEDIUM':
            st.warning(f"⚠️ **{risk_level} RISK**")
        else:
            st.success(f"✅ **{risk_level} RISK**")
        
        # Security flags
        if analysis['flags']:
            st.markdown("#### 🚩 Security Flags:")
            for flag in analysis['flags'][:5]:
                st.markdown(f"• {flag}")
        
        st.markdown("</div>", unsafe_allow_html=True)
        
        # Chat interface
        self.render_chat_interface(email_data, analysis)
    
    def render_chat_interface(self, email_data, analysis):
        """Render security assistant chat"""
        st.markdown("""
        <div class="chat-container">
            <h4>💬 Security Assistant</h4>
        </div>
        """, unsafe_allow_html=True)
        
        # Enhanced chat input with better prompts
        with st.form(key="chat_form", clear_on_submit=True):
            user_question = st.text_input(
                "💬 Ask PhishPrint anything about this email:", 
                key="chat_question",
                placeholder="Try: 'Is this safe?', 'Why is the risk high?', 'What should I do?', 'Is this phishing?'"
            )
            col1, col2 = st.columns([3, 1])
            with col1:
                submit_button = st.form_submit_button("🤖 Ask PhishPrint", use_container_width=True)
            with col2:
                if st.form_submit_button("🧹 Clear Chat"):
                    if email_key in st.session_state.chat_responses:
                        del st.session_state.chat_responses[email_key]
                    st.rerun()
        
        # Display previous chat responses for this email
        email_key = f"{email_data['from']}_{email_data['subject']}"
        if email_key in st.session_state.chat_responses:
            for qa_pair in st.session_state.chat_responses[email_key]:
                st.markdown(f"**You:** {qa_pair['question']}")
                st.markdown(f"**🤖 PhishPrint:** {qa_pair['response']}")
                st.markdown("---")
        
        if submit_button and user_question:
            with st.spinner("Analyzing..."):
                response = self.api_manager.generate_smart_response(
                    user_question, email_data, analysis
                )
                
                # Store the Q&A pair in session state
                if email_key not in st.session_state.chat_responses:
                    st.session_state.chat_responses[email_key] = []
                
                st.session_state.chat_responses[email_key].append({
                    'question': user_question,
                    'response': response
                })
                
                # Display the new response
                st.markdown(f"**You:** {user_question}")
                st.markdown(f"**🤖 PhishPrint:** {response}")
                
                # Rerun to update the display
                st.rerun()
    
    def format_timestamp(self, timestamp):
        """Format timestamp for display"""
        now = datetime.now()
        diff = now - timestamp
        
        if diff.total_seconds() < 3600:  # Less than 1 hour
            minutes = int(diff.total_seconds() / 60)
            return f"{minutes}m ago"
        elif diff.total_seconds() < 86400:  # Less than 1 day
            hours = int(diff.total_seconds() / 3600)
            return f"{hours}h ago"
        else:
            days = diff.days
            return f"{days}d ago"

class PhishPrintApp:
    """Main PhishPrint application class"""
    
    def __init__(self):
        """Initialize the application"""
        # Initialize components
        try:
            # No database for now, will add later if needed
            self.database_manager = None
        except Exception as e:
            st.warning(f"Database connection failed: {e}")
            self.database_manager = None
        
        self.api_manager = APIManager()
        self.email_engine = EmailSecurityEngine(self.api_manager, self.database_manager)
        self.ui = PhishPrintUI(self.email_engine, self.api_manager)
        
        # Initialize session state
        self._init_session_state()
    
    def _init_session_state(self):
        """Initialize Streamlit session state"""
        if 'selected_email' not in st.session_state:
            st.session_state.selected_email = None
        if 'chat_history' not in st.session_state:
            st.session_state.chat_history = []
        if 'analysis_cache' not in st.session_state:
            st.session_state.analysis_cache = {}
    
    def run(self):
        """Run the main application"""
        # Render main interface with modern UI
        self.ui.render_main_interface()

def main():
    """Application entry point"""
    app = PhishPrintApp()
    app.run()

if __name__ == "__main__":
    main()