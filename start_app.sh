#!/bin/bash
# Automatically provide empty input to Streamlit email prompt
echo "" | uv run streamlit run main.py --server.address=0.0.0.0 --server.port=5000 --browser.gatherUsageStats=false