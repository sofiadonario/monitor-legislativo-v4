#!/bin/bash
# Background LexML Collection Script with Corrected Implementation

echo "🚀 Starting CORRECTED LexML Collection in Background..."
echo "📁 Working directory: $(pwd)"
echo "⏰ Started at: $(date)"
echo "🔧 Using corrected implementation that actually works!"

# Kill any existing Python processes for this script
pkill -f "run_corrected_lexml.py" 2>/dev/null || true
pkill -f "run_lexml_fixed.py" 2>/dev/null || true

# Start the corrected collection process in background
nohup python3 run_corrected_lexml.py > corrected_collection_progress.log 2>&1 &

# Get the process ID
PROCESS_ID=$!

echo "🔢 Process ID: $PROCESS_ID"
echo "📄 Log file: corrected_collection_progress.log"
echo ""
echo "📊 To monitor progress, use:"
echo "  tail -f corrected_collection_progress.log"
echo ""
echo "🔍 To check process status:"
echo "  ps aux | grep $PROCESS_ID"
echo ""
echo "⏹️  To stop the process:"
echo "  kill $PROCESS_ID"
echo ""
echo "💾 Results will be saved to: ./data/processed/"
echo "📈 Expected: 15,000-50,000 documents (based on corrected implementation)"
echo ""
echo "✅ CORRECTED Collection started successfully!"
echo "🎯 This version uses the proper URL and HTML parsing logic!"