"""
Gmail API Manager for PhishPrint
Handles Gmail API authentication and email fetching
"""

import os
import json
import base64
import email
import streamlit as st
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
import email.utils
import tempfile

class GmailManager:
    """Manages Gmail API authentication and email operations"""
    
    SCOPES = [
        'https://www.googleapis.com/auth/gmail.readonly',
        'https://www.googleapis.com/auth/userinfo.email'
    ]
    
    def __init__(self):
        """Initialize Gmail manager"""
        self.service = None
        self.credentials = None
        self.user_email = None
        
        # OAuth configuration for Replit
        self.client_config = {
            "web": {
                "client_id": os.getenv('GOOGLE_CLIENT_ID', ''),
                "client_secret": os.getenv('GOOGLE_CLIENT_SECRET', ''),
                "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                "token_uri": "https://oauth2.googleapis.com/token",
                "redirect_uris": ["http://localhost:5000/auth/callback"]
            }
        }
        
        # Check if user is already authenticated
        self._load_credentials()
    
    def _load_credentials(self):
        """Load saved credentials from session state"""
        if 'gmail_credentials' in st.session_state:
            creds_data = st.session_state.gmail_credentials
            self.credentials = Credentials.from_authorized_user_info(creds_data, self.SCOPES)
            
            # Refresh if expired
            if self.credentials.expired and self.credentials.refresh_token:
                try:
                    self.credentials.refresh(Request())
                    st.session_state.gmail_credentials = json.loads(self.credentials.to_json())
                except Exception as e:
                    st.error(f"Failed to refresh credentials: {e}")
                    self.credentials = None
            
            if self.credentials and self.credentials.valid:
                self._build_service()
    
    def _save_credentials(self):
        """Save credentials to session state"""
        if self.credentials:
            st.session_state.gmail_credentials = json.loads(self.credentials.to_json())
    
    def _build_service(self):
        """Build Gmail API service"""
        try:
            self.service = build('gmail', 'v1', credentials=self.credentials)
            # Get user email
            profile = self.service.users().getProfile(userId='me').execute()
            self.user_email = profile.get('emailAddress')
        except Exception as e:
            st.error(f"Failed to build Gmail service: {e}")
            self.service = None
    
    def is_authenticated(self) -> bool:
        """Check if user is authenticated"""
        return self.service is not None and self.credentials is not None
    
    def get_auth_url(self) -> Optional[str]:
        """Get OAuth authorization URL"""
        if not self.client_config["web"]["client_id"]:
            return None
            
        # Create flow with temporary file for client config
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(self.client_config, f)
            client_secrets_file = f.name
        
        try:
            flow = Flow.from_client_secrets_file(
                client_secrets_file,
                scopes=self.SCOPES,
                redirect_uri=self.client_config["web"]["redirect_uris"][0]
            )
            
            auth_url, state = flow.authorization_url(
                access_type='offline',
                include_granted_scopes='true',
                prompt='consent'  # Ensure refresh token
            )
            
            # Store flow and state in session for security
            st.session_state.oauth_flow = flow
            st.session_state.oauth_state = state
            return auth_url
            
        except Exception as e:
            st.error(f"Failed to create auth URL: {e}")
            return None
        finally:
            os.unlink(client_secrets_file)
    
    def handle_auth_callback(self, authorization_code: str, state: str = None) -> bool:
        """Handle OAuth callback and exchange code for credentials"""
        if 'oauth_flow' not in st.session_state:
            return False
        
        # Verify state parameter for CSRF protection
        expected_state = st.session_state.get('oauth_state')
        if state and expected_state and state != expected_state:
            st.error("Invalid state parameter. Possible CSRF attack.")
            return False
        
        try:
            flow = st.session_state.oauth_flow
            flow.fetch_token(code=authorization_code)
            
            self.credentials = flow.credentials
            self._save_credentials()
            self._build_service()
            
            # Clean up session
            st.session_state.pop('oauth_flow', None)
            st.session_state.pop('oauth_state', None)
            
            return True
        except Exception as e:
            st.error(f"Failed to authenticate: {e}")
            return False
    
    def logout(self):
        """Clear authentication"""
        self.service = None
        self.credentials = None
        self.user_email = None
        if 'gmail_credentials' in st.session_state:
            del st.session_state.gmail_credentials
        if 'oauth_flow' in st.session_state:
            del st.session_state.oauth_flow
    
    def fetch_emails(self, max_results: int = 10, days_back: int = 7) -> List[Dict[str, Any]]:
        """Fetch emails from Gmail"""
        if not self.is_authenticated() or not self.service:
            return []
        
        try:
            # Calculate date range
            after_date = (datetime.now() - timedelta(days=days_back)).strftime('%Y/%m/%d')
            query = f'after:{after_date}'
            
            # Get message list
            results = self.service.users().messages().list(
                userId='me',
                q=query,
                maxResults=max_results
            ).execute()
            
            messages = results.get('messages', [])
            emails = []
            
            for message in messages:
                email_data = self._get_email_details(message['id'])
                if email_data:
                    emails.append(email_data)
            
            return emails
            
        except Exception as e:
            st.error(f"Failed to fetch emails: {e}")
            return []
    
    def _get_email_details(self, message_id: str) -> Optional[Dict[str, Any]]:
        """Get detailed email information"""
        if not self.service:
            return None
        try:
            message = self.service.users().messages().get(
                userId='me',
                id=message_id,
                format='full'
            ).execute()
            
            payload = message['payload']
            headers = payload.get('headers', [])
            
            # Extract headers
            email_data = {
                'id': message_id,
                'from': self._get_header_value(headers, 'From'),
                'to': self._get_header_value(headers, 'To'),
                'subject': self._get_header_value(headers, 'Subject'),
                'date': self._get_header_value(headers, 'Date'),
                'body': '',
                'timestamp': datetime.now(),
                'user_id': self.user_email or 'default_user'
            }
            
            # Parse date
            try:
                if email_data['date']:
                    # Parse email date format
                    email_data['timestamp'] = email.utils.parsedate_to_datetime(email_data['date'])
            except:
                pass
            
            # Extract body
            email_data['body'] = self._extract_body(payload)
            
            return email_data
            
        except Exception as e:
            print(f"Failed to get email details for {message_id}: {e}")
            return None
    
    def _get_header_value(self, headers: List[Dict], name: str) -> str:
        """Extract header value by name"""
        for header in headers:
            if header['name'].lower() == name.lower():
                return header['value']
        return ''
    
    def _extract_body(self, payload: Dict) -> str:
        """Extract email body from payload with improved MIME handling"""
        def extract_from_parts(parts):
            text_body = ""
            html_body = ""
            
            for part in parts:
                mime_type = part.get('mimeType', '')
                
                # Recursively handle nested parts
                if 'parts' in part:
                    nested_text, nested_html = extract_from_parts(part['parts'])
                    text_body = text_body or nested_text
                    html_body = html_body or nested_html
                elif mime_type == 'text/plain' and 'data' in part.get('body', {}):
                    text_body = self._decode_base64(part['body']['data'])
                elif mime_type == 'text/html' and 'data' in part.get('body', {}):
                    html_body = self._decode_base64(part['body']['data'])
            
            return text_body, html_body
        
        if 'parts' in payload:
            # Multipart message
            text_body, html_body = extract_from_parts(payload['parts'])
            # Prefer text/plain over HTML
            body = text_body or self._strip_html_tags(html_body)
        else:
            # Single part message
            mime_type = payload.get('mimeType', '')
            if mime_type == 'text/plain' and 'data' in payload.get('body', {}):
                body = self._decode_base64(payload['body']['data'])
            elif mime_type == 'text/html' and 'data' in payload.get('body', {}):
                html_body = self._decode_base64(payload['body']['data'])
                body = self._strip_html_tags(html_body)
            else:
                body = ""
        
        return body[:2000]  # Increase limit for better analysis
    
    def _decode_base64(self, data: str) -> str:
        """Decode base64 URL-safe data"""
        try:
            # Add padding if needed
            missing_padding = len(data) % 4
            if missing_padding:
                data += '=' * (4 - missing_padding)
            
            decoded = base64.urlsafe_b64decode(data)
            return decoded.decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"Failed to decode base64 data: {e}")
            return ""
    
    def _strip_html_tags(self, html_content: str) -> str:
        """Simple HTML tag removal for text extraction"""
        if not html_content:
            return ""
        
        import re
        # Remove HTML tags
        clean = re.sub(r'<[^>]+>', '', html_content)
        # Replace HTML entities
        clean = clean.replace('&nbsp;', ' ').replace('&amp;', '&')
        clean = clean.replace('&lt;', '<').replace('&gt;', '>')
        clean = clean.replace('&quot;', '"').replace('&#39;', "'")
        # Clean up whitespace
        clean = re.sub(r'\s+', ' ', clean).strip()
        return clean
    
    def get_user_stats(self) -> Dict[str, Any]:
        """Get user Gmail statistics"""
        if not self.is_authenticated() or not self.service:
            return {}
        
        try:
            profile = self.service.users().getProfile(userId='me').execute()
            return {
                'email': profile.get('emailAddress'),
                'total_messages': profile.get('messagesTotal', 0),
                'total_threads': profile.get('threadsTotal', 0),
                'history_id': profile.get('historyId', '')
            }
        except Exception as e:
            print(f"Failed to get user stats: {e}")
            return {}
    
    def test_connection(self) -> bool:
        """Test Gmail API connection"""
        if not self.is_authenticated() or not self.service:
            return False
        
        try:
            self.service.users().getProfile(userId='me').execute()
            return True
        except Exception as e:
            print(f"Gmail connection test failed: {e}")
            return False