"""
PhishPrint - Email Security Suite
Main entry point for Replit deployment
"""

import streamlit as st
import subprocess
import sys
import os

def main():
    """Main application entry point"""
    try:
        from app import PhishPrintApp
        app = PhishPrintApp()
        app.run()
    except Exception as e:
        st.error(f"Application Error: {str(e)}")
        st.info("Please ensure all dependencies are installed.")

if __name__ == "__main__":
    main()