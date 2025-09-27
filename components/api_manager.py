"""
API Manager for PhishPrint
Handles Gemini AI and Hugging Face API integrations
"""

import os
import requests
import json
from typing import Tuple, List, Dict, Any
import time
import random

class APIManager:
    """Manages all external API integrations"""
    
    def __init__(self):
        """Initialize API manager with credentials"""
        self.gemini_api_key = os.getenv('GEMINI_API_KEY')
        self.hf_api_key = os.getenv('HUGGINGFACE_API_KEY')
        
        self.hf_headers = {"Authorization": f"Bearer {self.hf_api_key}"}
        self.gemini_configured = False
        
        # Initialize Gemini
        self._init_gemini()
    
    def _init_gemini(self):
        """Initialize Gemini AI client"""
        try:
            if not self.gemini_api_key:
                self.gemini_configured = False
                print("Gemini API key not configured")
                return
                
            from google import genai
            from google.genai import types
            self.genai_client = genai.Client(api_key=self.gemini_api_key)
            self.genai_types = types
            self.gemini_configured = True
        except Exception as e:
            self.gemini_configured = False
            print(f"Gemini initialization failed: {e}")
    
    def check_email_breaches(self, email: str) -> Tuple[int, List[str]]:
        """Check Have I Been Pwned for email breaches"""
        hibp_api_key = os.getenv('HIBP_API_KEY')
        
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
            headers = {
                "User-Agent": "PhishPrint-Security-Tool",
            }
            
            # Add API key if available (required for production use)
            if hibp_api_key:
                headers["hibp-api-key"] = hibp_api_key
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                breaches = response.json()
                return len(breaches), [breach.get('Name', 'Unknown') for breach in breaches[:3]]
            elif response.status_code == 404:
                return 0, []
            elif response.status_code == 401:
                # Return demo data if API key not configured
                return 1, ["Demo Breach Alert"]
            elif response.status_code == 429:
                return 0, ["Rate Limited"]
            else:
                return 0, ["Service Unavailable"]
        except Exception as e:
            return 0, ["Connection Error"]
    
    def analyze_sentiment_urgency(self, text: str) -> float:
        """Analyze urgency/sentiment using Hugging Face with retry logic"""
        if not self.hf_api_key:
            return 0.0
            
        try:
            # Truncate text to avoid API limits
            text = text[:500]
            
            api_url = "https://api-inference.huggingface.co/models/j-hartmann/emotion-english-distilroberta-base"
            
            # Retry logic for model loading
            max_retries = 3
            for attempt in range(max_retries):
                response = requests.post(
                    api_url,
                    headers=self.hf_headers,
                    json={"inputs": text},
                    timeout=15
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if isinstance(result, list) and len(result) > 0:
                        emotions = result[0]
                        
                        # Calculate urgency from fear, anger, surprise
                        urgency_emotions = ['fear', 'anger', 'surprise']
                        urgency_score = sum(
                            emotion.get('score', 0) for emotion in emotions
                            if emotion.get('label', '').lower() in urgency_emotions
                        )
                        return min(urgency_score * 40, 25)  # Cap at 25 points
                elif response.status_code == 503:  # Model loading
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt + random.uniform(0, 1)
                        time.sleep(wait_time)
                        continue
                else:
                    break
            
            return 0.0
        except Exception as e:
            return 0.0
    
    def detect_toxic_content(self, text: str) -> float:
        """Detect toxic/malicious content using Hugging Face with retry logic"""
        if not self.hf_api_key:
            return 0.0
            
        try:
            text = text[:500]
            
            api_url = "https://api-inference.huggingface.co/models/unitary/toxic-bert"
            
            # Retry logic for model loading
            max_retries = 3
            for attempt in range(max_retries):
                response = requests.post(
                    api_url,
                    headers=self.hf_headers,
                    json={"inputs": text},
                    timeout=15
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if isinstance(result, list) and len(result) > 0:
                        for item in result[0]:
                            if item.get('label') == 'TOXIC':
                                return item.get('score', 0) * 30  # Convert to 0-30 scale
                elif response.status_code == 503:  # Model loading
                    if attempt < max_retries - 1:
                        wait_time = 2 ** attempt + random.uniform(0, 1)
                        time.sleep(wait_time)
                        continue
                else:
                    break
            
            return 0.0
        except Exception as e:
            return 0.0
    
    def generate_smart_response(self, question: str, email_context: Dict[str, Any], 
                              analysis_results: Dict[str, Any]) -> str:
        """Generate intelligent responses using Gemini AI"""
        if not self.gemini_configured:
            return self._fallback_response(question, email_context, analysis_results)
        
        try:
            prompt = f"""You are PhishPrint, an expert email security assistant. Provide clear, educational responses about email threats.

Email Details:
- From: {email_context.get('from', 'Unknown')}
- Subject: {email_context.get('subject', 'Unknown')}
- Content Preview: {email_context.get('body', '')[:300]}...

Security Analysis:
- PhishScore: {analysis_results.get('total_score', 0)}/100
- Risk Flags: {', '.join(analysis_results.get('flags', [])[:3])}
- Breaches Found: {analysis_results.get('breach_info', {}).get('count', 0)}
- API Analysis Score: {analysis_results.get('components', {}).get('api_analysis', 0)}

User Question: {question}

Provide a helpful, educational response under 100 words. Focus on practical security advice and explain why this email is risky or safe."""

            response = self.genai_client.models.generate_content(
                model="gemini-2.5-flash",
                contents=prompt
            )
            
            return response.text if response.text else self._fallback_response(question, email_context, analysis_results)
        
        except Exception as e:
            return self._fallback_response(question, email_context, analysis_results)
    
    def _fallback_response(self, question: str, email_context: Dict[str, Any], 
                          analysis_results: Dict[str, Any]) -> str:
        """Fallback responses when AI is unavailable"""
        q_lower = question.lower()
        score = analysis_results.get('total_score', 0)
        flags = analysis_results.get('flags', [])
        
        if 'safe' in q_lower:
            if score >= 70:
                return "❌ This email is NOT safe. Multiple security threats detected including suspicious URLs, phishing keywords, or code injection attempts. Do not interact with links or attachments."
            elif score >= 40:
                return "⚠️ This email has moderate risk. Exercise caution - verify sender through alternate means before taking any action requested in the email."
            else:
                return "✅ This email appears safe based on our comprehensive analysis. Normal communication patterns detected."
        
        elif 'why' in q_lower and ('score' in q_lower or 'risk' in q_lower):
            if flags:
                main_flags = ', '.join(flags[:3])
                return f"Risk score based on: {main_flags}. Our ML model detected {len(flags)} security concerns including behavioral anomalies and threat patterns."
            else:
                return "Low risk score due to normal communication patterns, legitimate sender behavior, and absence of phishing indicators."
        
        elif 'code' in q_lower or 'script' in q_lower or 'injection' in q_lower:
            code_flags = [f for f in flags if any(term in f.lower() for term in ['injection', 'script', 'code', 'eval', 'javascript'])]
            if code_flags:
                return "🚨 YES - Malicious code detected! This email contains JavaScript, eval() functions, or encoded payloads that could execute harmful scripts. Do not open."
            else:
                return "✅ No malicious code patterns detected in this email's content. The message appears to contain only text and safe HTML."
        
        elif 'phish' in q_lower or 'fake' in q_lower:
            phish_flags = [f for f in flags if any(term in f.lower() for term in ['suspicious', 'phish', 'urgent', 'fake'])]
            if phish_flags:
                return "🎣 Phishing indicators detected! This email uses urgency tactics, suspicious URLs, or impersonation techniques common in phishing attacks."
            else:
                return "✅ No obvious phishing patterns detected. Sender and content appear legitimate based on our analysis."
        
        else:
            return "I can help explain email security. Ask about: 'Is this safe?', 'Why this score?', 'Any code threats?', or 'Phishing signs?'"
