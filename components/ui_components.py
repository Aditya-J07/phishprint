"""
UI Components for PhishPrint
Gmail-like interface components and styling
"""

import streamlit as st
import plotly.graph_objects as go
from datetime import datetime
from typing import Dict, Any, Optional

class PhishPrintUI:
    """Main UI component manager for PhishPrint"""
    
    def __init__(self, email_engine, api_manager):
        """Initialize UI with required engines"""
        self.email_engine = email_engine
        self.api_manager = api_manager
        self.apply_custom_styles()
    
    def apply_custom_styles(self):
        """Apply Gmail-like custom CSS styles"""
        st.markdown("""
        <style>
        /* Main container styles */
        .main > div {
            padding-top: 1rem;
        }
        
        /* Email item styles */
        .email-item {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 12px;
            margin: 8px 0;
            background: white;
            transition: all 0.2s ease;
            cursor: pointer;
        }
        
        .email-item:hover {
            background-color: #f8f9fa;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        
        /* Risk indicator borders */
        .risk-high { 
            border-left: 5px solid #dc3545;
            background: linear-gradient(90deg, #fff5f5 0%, white 20%);
        }
        .risk-medium { 
            border-left: 5px solid #fd7e14;
            background: linear-gradient(90deg, #fff8f0 0%, white 20%);
        }
        .risk-low { 
            border-left: 5px solid #198754;
            background: linear-gradient(90deg, #f0fff4 0%, white 20%);
        }
        
        /* Score badges */
        .score-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            color: white;
            font-weight: bold;
            font-size: 0.85em;
            margin-left: 10px;
        }
        
        .score-high { background: linear-gradient(135deg, #dc3545, #c82333); }
        .score-medium { background: linear-gradient(135deg, #fd7e14, #e8590c); }
        .score-low { background: linear-gradient(135deg, #198754, #146c43); }
        
        /* Header styles */
        .phishprint-header {
            background: linear-gradient(135deg, #1f77b4, #2e86de);
            color: white;
            padding: 20px;
            border-radius: 12px;
            margin-bottom: 20px;
            text-align: center;
        }
        
        .phishprint-header h1 {
            margin: 0;
            font-size: 2.5em;
        }
        
        .phishprint-header p {
            margin: 5px 0 0 0;
            opacity: 0.9;
            font-size: 1.1em;
        }
        
        /* Analysis panel styles */
        .analysis-panel {
            background: #f8f9fa;
            border-radius: 12px;
            padding: 20px;
            border: 1px solid #dee2e6;
        }
        
        .security-flag {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 6px;
            padding: 8px 12px;
            margin: 4px 0;
            font-size: 0.9em;
        }
        
        .chat-container {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 12px;
            padding: 15px;
            margin-top: 15px;
        }
        
        /* Button styles */
        .stButton > button {
            width: 100%;
            border-radius: 8px;
            border: 1px solid #dee2e6;
            background: white;
            color: #333;
            padding: 12px;
            text-align: left;
            transition: all 0.2s ease;
        }
        
        .stButton > button:hover {
            background: #f8f9fa;
            border-color: #adb5bd;
        }
        
        /* Metric cards */
        .metric-card {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            text-align: center;
        }
        
        /* Plotly gauge container */
        .gauge-container {
            background: white;
            border-radius: 12px;
            padding: 15px;
            border: 1px solid #dee2e6;
            margin: 15px 0;
        }
        </style>
        """, unsafe_allow_html=True)
    
    def render_main_interface(self, custom_emails=None):
        """Render the main PhishPrint interface"""
        # Header
        self.render_header()
        
        # Main layout: inbox on left, analysis on right
        col1, col2 = st.columns([2, 1])
        
        with col1:
            self.render_inbox(custom_emails)
        
        with col2:
            self.render_analysis_panel()
    
    def render_header(self):
        """Render the main header"""
        st.markdown("""
        <div class="phishprint-header">
            <h1>🛡️ PhishPrint Security Suite</h1>
            <p>AI-Powered Gmail-Integrated Email Security Assistant</p>
        </div>
        """, unsafe_allow_html=True)
    
    def render_inbox(self, custom_emails=None):
        """Render Gmail-like inbox with emails"""
        st.markdown("## 📬 Inbox")
        
        # Use custom emails if provided, otherwise use demo emails
        if custom_emails:
            emails_to_display = custom_emails
            st.markdown("*Real Gmail emails - Click on any email to see detailed security analysis*")
        else:
            emails_to_display = self.email_engine.get_demo_emails()
            st.markdown("*Demo emails - Click on any email to see detailed security analysis*")
        
        for email_key, email_data in emails_to_display.items():
            # Analyze email if not cached
            cache_key = f"analysis_{hash(str(email_data))}"
            if cache_key not in st.session_state.analysis_cache:
                with st.spinner(f"Analyzing {email_key}..."):
                    analysis = self.email_engine.analyze_comprehensive(email_data)
                    st.session_state.analysis_cache[cache_key] = analysis
            else:
                analysis = st.session_state.analysis_cache[cache_key]
            
            # Render email item
            self.render_email_item(email_key, email_data, analysis)
    
    def render_email_item(self, email_key: str, email_data: Dict[str, Any], 
                         analysis: Dict[str, Any]):
        """Render individual email item in inbox"""
        score = analysis['total_score']
        risk_level = analysis['risk_level']
        color = analysis['color']
        
        # Email container with risk styling
        risk_class = f"risk-{color.replace('red', 'high').replace('orange', 'medium').replace('green', 'low')}"
        
        # Email selection button
        if st.button(email_key, key=f"btn_{email_key}", help=f"PhishScore: {score:.1f}/100"):
            st.session_state.selected_email = {
                'key': email_key,
                'data': email_data,
                'analysis': analysis
            }
            st.rerun()
        
        # Email preview in columns
        col_a, col_b = st.columns([3, 1])
        
        with col_a:
            st.markdown(f"**From:** {email_data['from']}")
            st.markdown(f"**Subject:** {email_data['subject']}")
            
            # Preview body text (truncated)
            preview_text = email_data['body'][:120] + "..." if len(email_data['body']) > 120 else email_data['body']
            st.markdown(f"*{preview_text}*")
            
            # Timestamp
            timestamp = email_data.get('timestamp', datetime.now())
            st.markdown(f"📅 {timestamp.strftime('%Y-%m-%d %H:%M')}")
        
        with col_b:
            # Risk score badge
            if color == "red":
                st.error(f"🚨 {score:.0f}/100\n{risk_level}")
            elif color == "orange":
                st.warning(f"⚠️ {score:.0f}/100\n{risk_level}")
            else:
                st.success(f"✅ {score:.0f}/100\n{risk_level}")
        
        st.markdown("---")
    
    def render_analysis_panel(self):
        """Render detailed analysis panel"""
        if st.session_state.selected_email is None:
            st.markdown("## 🔍 Security Analysis")
            st.info("👈 Select an email from the inbox to see detailed security analysis")
            self.render_dashboard_metrics()
            return
        
        email_info = st.session_state.selected_email
        email_data = email_info['data']
        analysis = email_info['analysis']
        
        st.markdown("## 🔍 Security Analysis")
        st.markdown(f"**Analyzing:** {email_info['key']}")
        
        # PhishScore gauge
        self.render_phish_score_gauge(analysis)
        
        # Risk assessment
        self.render_risk_assessment(analysis)
        
        # Security flags
        self.render_security_flags(analysis)
        
        # Component breakdown
        self.render_component_breakdown(analysis)
        
        # Interactive chat
        self.render_interactive_chat(email_data, analysis)
    
    def render_phish_score_gauge(self, analysis: Dict[str, Any]):
        """Render Plotly gauge for PhishScore"""
        score = analysis['total_score']
        
        # Create Plotly gauge
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=score,
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "PhishScore", 'font': {'size': 24}},
            delta={'reference': 50, 'increasing': {'color': "red"}, 'decreasing': {'color': "green"}},
            gauge={
                'axis': {'range': [None, 100], 'tickwidth': 1, 'tickcolor': "darkblue"},
                'bar': {'color': analysis['color']},
                'bgcolor': "white",
                'borderwidth': 2,
                'bordercolor': "gray",
                'steps': [
                    {'range': [0, 40], 'color': '#d4edda'},
                    {'range': [40, 70], 'color': '#fff3cd'},
                    {'range': [70, 100], 'color': '#f8d7da'}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 70
                }
            }
        ))
        
        fig.update_layout(
            height=300,
            font={'color': "darkblue", 'family': "Arial"},
            margin=dict(l=20, r=20, t=40, b=20)
        )
        
        st.plotly_chart(fig, use_container_width=True)
    
    def render_risk_assessment(self, analysis: Dict[str, Any]):
        """Render risk level assessment"""
        risk_level = analysis['risk_level']
        color = analysis['color']
        
        if color == "red":
            st.error(f"🚨 **{risk_level}** - Do not interact with this email")
        elif color == "orange":
            st.warning(f"⚠️ **{risk_level}** - Exercise caution, verify sender")
        else:
            st.success(f"✅ **{risk_level}** - Email appears safe")
    
    def render_security_flags(self, analysis: Dict[str, Any]):
        """Render security flags and warnings"""
        flags = analysis['flags']
        
        if flags:
            st.markdown("### 🚩 Security Flags:")
            for i, flag in enumerate(flags[:6]):  # Show top 6 flags
                st.markdown(f"""
                <div class="security-flag">
                    <strong>{i+1}.</strong> {flag}
                </div>
                """, unsafe_allow_html=True)
            
            if len(flags) > 6:
                st.markdown(f"*... and {len(flags) - 6} more security concerns*")
        else:
            st.markdown("### ✅ No Security Flags")
            st.markdown("No obvious security threats detected in this email.")
    
    def render_component_breakdown(self, analysis: Dict[str, Any]):
        """Render analysis component breakdown"""
        st.markdown("### 📊 Analysis Breakdown")
        
        components = analysis['components']
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.metric("Heuristic Analysis", f"{components['heuristic']:.1f}", help="Rule-based pattern detection")
            st.metric("ML Anomaly Score", f"{components['ml_anomaly']:.1f}", help="Behavioral pattern analysis")
        
        with col2:
            st.metric("Code Injection", f"{components['code_injection']:.1f}", help="Malicious script detection")
            st.metric("AI Analysis", f"{components['api_analysis']:.1f}", help="Sentiment & toxicity analysis")
        
        # Breach information
        breach_info = analysis.get('breach_info', {})
        if breach_info.get('count', 0) > 0:
            st.markdown("### 🔓 Data Breach Information")
            st.warning(f"Sender found in {breach_info['count']} known data breach(es):")
            for breach in breach_info.get('breaches', []):
                st.markdown(f"• {breach}")
    
    def render_interactive_chat(self, email_data: Dict[str, Any], analysis: Dict[str, Any]):
        """Render interactive chat interface"""
        st.markdown("### 💬 Ask PhishPrint")
        st.markdown("*Ask questions about this email's security*")
        
        # Chat input
        user_question = st.text_input(
            "Your question:", 
            placeholder="e.g., 'Is this email safe?', 'Why is the score high?', 'Any code threats?'",
            key="chat_input"
        )
        
        if user_question:
            with st.spinner("PhishPrint is analyzing..."):
                response = self.api_manager.generate_smart_response(
                    user_question, email_data, analysis
                )
            
            # Display response in chat format
            st.markdown("**PhishPrint:** ")
            st.markdown(f"> {response}")
            
            # Add to chat history
            if 'chat_history' not in st.session_state:
                st.session_state.chat_history = []
            
            st.session_state.chat_history.append({
                'question': user_question,
                'response': response,
                'timestamp': datetime.now()
            })
        
        # Show recent chat history
        if hasattr(st.session_state, 'chat_history') and st.session_state.chat_history:
            with st.expander("Recent Chat History", expanded=False):
                for chat in st.session_state.chat_history[-3:]:  # Show last 3
                    st.markdown(f"**Q:** {chat['question']}")
                    st.markdown(f"**A:** {chat['response']}")
                    st.markdown("---")
    
    def render_dashboard_metrics(self):
        """Render dashboard metrics when no email is selected"""
        st.markdown("### 📈 Security Dashboard")
        
        # Overall statistics from session state or demo emails
        if 'gmail_emails' in st.session_state and st.session_state.gmail_emails:
            total_emails = len(st.session_state.gmail_emails)
            email_source = "Gmail emails loaded"
        else:
            demo_emails = self.email_engine.get_demo_emails()
            total_emails = len(demo_emails)
            email_source = "Demo emails available"
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Total Emails", total_emails, help=email_source)
        
        with col2:
            # For now, show placeholder for high risk count
            st.metric("Analysis Ready", "✓", help="Security analysis enabled")
        
        with col3:
            st.metric("ML Model", "Active", help="Behavioral analysis active")
        
        # Feature highlights
        st.markdown("### 🛡️ Protection Features")
        
        features = [
            "🎯 **Phishing Detection** - Advanced pattern recognition",
            "💻 **Code Injection Scanning** - JavaScript & script analysis", 
            "🤖 **ML Behavioral Analysis** - Isolation Forest anomaly detection",
            "🧠 **AI-Powered Chat** - Gemini & Hugging Face integration",
            "📊 **Real-time Scoring** - Dynamic PhishScore calculation",
            "🔍 **Multi-layer Analysis** - Heuristic + ML + API detection"
        ]
        
        for feature in features:
            st.markdown(feature)
