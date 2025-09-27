# PhishPrint - Modern Email Security Suite

## Overview
PhishPrint is a modern, AI-powered email security application with a Gmail-like interface. It provides comprehensive phishing detection, code injection analysis, and behavioral anomaly detection using machine learning and heuristic analysis.

## Recent Changes (2025-09-27)
- ✅ Imported GitHub project and set up for Replit environment
- ✅ Updated to modern dark theme UI inspired by Lovable design
- ✅ Configured Streamlit for proper Replit deployment (0.0.0.0:5000)
- ✅ Set up automated workflow for development
- ✅ Configured production deployment settings

## Project Architecture
- **Frontend**: Streamlit with custom dark theme CSS
- **Backend**: Python-based security analysis engine
- **Dependencies**: scikit-learn, pandas, numpy, plotly for analysis and visualization
- **Security Features**: 
  - Heuristic phishing detection
  - Code injection pattern recognition
  - ML-based anomaly detection
  - Interactive security assistant

## Key Features
- 🛡️ Modern dark-themed inbox interface
- 📊 Real-time risk scoring (0-100 scale)
- 🏷️ Security tagging system (phishing, injection, anomaly, breach)
- 💬 Interactive security assistant chat
- 📈 Visual risk analysis with gauges and charts
- 🎯 Demo emails showcasing different threat types

## User Preferences
- **Theme**: Dark theme with gradient colors and modern styling
- **UI Style**: Gmail-inspired card-based layout
- **Analysis**: Comprehensive multi-layer security analysis

## Technical Configuration
- **Development Port**: 5000 (Replit environment)
- **Production Port**: 8080 (deployment)
- **Host**: 0.0.0.0 (required for Replit proxy)
- **Package Manager**: uv (for fast dependency management)

## Demo Data
The application includes realistic demo emails showcasing:
- Normal work communications (low risk)
- Obvious phishing attempts (high risk)
- Sophisticated spear phishing (high risk)
- Code injection attacks (high risk)

## Deployment
Configured for Replit autoscale deployment with proper host settings and production-ready Streamlit configuration.