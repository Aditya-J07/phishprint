"""
Gmail UI Components for PhishPrint
Handles Gmail authentication and email selection interface
"""

import streamlit as st
from typing import Dict, Any, List
from components.gmail_manager import GmailManager

class GmailUI:
    """Gmail authentication and email management UI"""
    
    def __init__(self, gmail_manager: GmailManager):
        """Initialize Gmail UI with manager"""
        self.gmail_manager = gmail_manager
    
    def render_auth_section(self) -> bool:
        """Render Gmail authentication section, returns True if authenticated"""
        st.markdown("### 📧 Gmail Integration")
        
        if self.gmail_manager.is_authenticated():
            self._render_authenticated_view()
            return True
        else:
            self._render_authentication_flow()
            return False
    
    def _render_authenticated_view(self):
        """Render view for authenticated users"""
        user_stats = self.gmail_manager.get_user_stats()
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.success(f"✅ Connected: {user_stats.get('email', 'Unknown')}")
        
        with col2:
            if st.button("🔄 Refresh Emails", help="Fetch latest emails from Gmail"):
                st.session_state.refresh_emails = True
                st.rerun()
        
        with col3:
            if st.button("🚪 Disconnect", help="Disconnect from Gmail"):
                self.gmail_manager.logout()
                st.session_state.pop('gmail_emails', None)
                st.success("Disconnected from Gmail")
                st.rerun()
        
        # Display Gmail stats
        if user_stats:
            st.markdown(f"""
            **Gmail Account Info:**
            - Total Messages: {user_stats.get('total_messages', 'Unknown'):,}
            - Total Threads: {user_stats.get('total_threads', 'Unknown'):,}
            """)
    
    def _render_authentication_flow(self):
        """Render Gmail authentication flow"""
        st.info("Connect your Gmail account to analyze real emails for security threats.")
        
        # Check if OAuth credentials are configured
        if not self._check_oauth_config():
            self._render_oauth_setup_guide()
            return
        
        # Show authentication button
        if st.button("🔗 Connect Gmail Account", type="primary"):
            auth_url = self.gmail_manager.get_auth_url()
            if auth_url:
                st.markdown(f"""
                **Step 1:** Click the link below to authorize PhishPrint:
                
                [🔑 Authorize Gmail Access]({auth_url})
                
                **Step 2:** Copy the authorization code from the browser and paste it below.
                """)
                
                # Show authorization code input
                self._render_auth_code_input()
            else:
                st.error("Failed to generate authorization URL. Please check your OAuth configuration.")
    
    def _check_oauth_config(self) -> bool:
        """Check if OAuth credentials are properly configured"""
        client_id = self.gmail_manager.client_config["web"]["client_id"]
        client_secret = self.gmail_manager.client_config["web"]["client_secret"]
        return bool(client_id and client_secret)
    
    def _render_oauth_setup_guide(self):
        """Render OAuth setup guide"""
        st.warning("⚠️ Gmail OAuth credentials not configured")
        
        with st.expander("📋 How to Setup Gmail API Access", expanded=True):
            st.markdown("""
            To connect Gmail, you need to configure OAuth credentials:
            
            **1. Create Google Cloud Project:**
            - Go to [Google Cloud Console](https://console.cloud.google.com/)
            - Create a new project or select existing one
            
            **2. Enable Gmail API:**
            - Navigate to APIs & Services > Library
            - Search for "Gmail API" and enable it
            
            **3. Create OAuth Credentials:**
            - Go to APIs & Services > Credentials
            - Click "Create Credentials" > "OAuth 2.0 Client IDs"
            - Application type: Web application
            - Add authorized redirect URI: `http://localhost:5000/auth/callback`
            
            **4. Add Credentials to Replit:**
            - Copy Client ID and Client Secret
            - Add them as Replit Secrets:
              - `GOOGLE_CLIENT_ID`: Your OAuth Client ID
              - `GOOGLE_CLIENT_SECRET`: Your OAuth Client Secret
            
            **5. Restart the application** after adding the secrets.
            """)
    
    def _render_auth_code_input(self):
        """Render authorization code input field"""
        st.markdown("---")
        
        auth_code = st.text_input(
            "Authorization Code:",
            placeholder="Paste the authorization code here...",
            help="Copy the code from the browser after authorizing the application"
        )
        
        if st.button("✅ Complete Authentication") and auth_code:
            with st.spinner("Authenticating with Gmail..."):
                if self.gmail_manager.handle_auth_callback(auth_code):
                    st.success("🎉 Successfully connected to Gmail!")
                    st.balloons()
                    st.rerun()
                else:
                    st.error("Authentication failed. Please try again.")
    
    def render_email_controls(self) -> Dict[str, Any]:
        """Render email fetching controls, returns settings"""
        settings = {}
        
        if not self.gmail_manager.is_authenticated():
            return settings
        
        st.markdown("### ⚙️ Email Fetch Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            settings['max_emails'] = st.slider(
                "Number of emails to analyze",
                min_value=5,
                max_value=50,
                value=15,
                help="More emails provide better analysis but take longer to process"
            )
        
        with col2:
            settings['days_back'] = st.slider(
                "Days to look back",
                min_value=1,
                max_value=30,
                value=7,
                help="How far back to search for emails"
            )
        
        return settings
    
    def fetch_and_display_emails(self, settings: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Fetch emails from Gmail and display progress"""
        if not self.gmail_manager.is_authenticated():
            return []
        
        # Check if we should refresh emails
        if (st.session_state.get('refresh_emails', False) or 
            'gmail_emails' not in st.session_state):
            
            max_emails = settings.get('max_emails', 15)
            days_back = settings.get('days_back', 7)
            
            with st.spinner(f"Fetching {max_emails} emails from the last {days_back} days..."):
                emails = self.gmail_manager.fetch_emails(max_emails, days_back)
                st.session_state.gmail_emails = emails
                st.session_state.refresh_emails = False
                
                if emails:
                    st.success(f"📬 Fetched {len(emails)} emails from Gmail")
                else:
                    st.warning("No emails found for the specified criteria")
        
        return st.session_state.get('gmail_emails', [])
    
    def render_email_preview(self, emails: List[Dict[str, Any]]):
        """Render a preview of fetched emails"""
        if not emails:
            st.info("No emails to display. Try adjusting your fetch settings.")
            return
        
        st.markdown("### 📋 Fetched Emails Preview")
        
        for i, email in enumerate(emails[:5]):  # Show first 5 emails
            with st.expander(f"📧 {email.get('subject', 'No Subject')[:50]}...", expanded=False):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.markdown(f"**From:** {email.get('from', 'Unknown')}")
                    st.markdown(f"**Date:** {email.get('date', 'Unknown')}")
                
                with col2:
                    st.markdown(f"**To:** {email.get('to', 'Unknown')}")
                    st.markdown(f"**ID:** {email.get('id', 'Unknown')[:20]}...")
                
                # Show body preview
                body_preview = email.get('body', '')[:200] + "..." if len(email.get('body', '')) > 200 else email.get('body', '')
                st.markdown(f"**Body Preview:** {body_preview}")
        
        if len(emails) > 5:
            st.info(f"Showing 5 of {len(emails)} emails. All emails will be analyzed for security threats.")
    
    def render_connection_status(self):
        """Render Gmail connection status in sidebar"""
        if self.gmail_manager.is_authenticated():
            st.sidebar.success("✅ Gmail Connected")
            user_stats = self.gmail_manager.get_user_stats()
            st.sidebar.markdown(f"**User:** {user_stats.get('email', 'Unknown')}")
            
            # Test connection
            if st.sidebar.button("🔍 Test Connection"):
                if self.gmail_manager.test_connection():
                    st.sidebar.success("Connection OK")
                else:
                    st.sidebar.error("Connection Failed")
        else:
            st.sidebar.warning("❌ Gmail Not Connected")
            st.sidebar.markdown("Connect Gmail to analyze real emails")