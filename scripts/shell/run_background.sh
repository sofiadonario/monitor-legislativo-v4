#!/bin/bash
# Background LexML Collection Script

echo "🚀 Starting LexML Collection in Background..."
echo "📁 Working directory: $(pwd)"
echo "⏰ Started at: $(date)"

# Kill any existing Python processes for this script
pkill -f "run_lexml_fixed.py" 2>/dev/null || true

# Start the collection process in background
nohup python3 run_lexml_fixed.py > collection_progress.log 2>&1 &

# Get the process ID
PROCESS_ID=$!

echo "🔢 Process ID: $PROCESS_ID"
echo "📄 Log file: collection_progress.log"
echo ""
echo "📊 To monitor progress, use:"
echo "  tail -f collection_progress.log"
echo ""
echo "🔍 To check process status:"
echo "  ps aux | grep $PROCESS_ID"
echo ""
echo "⏹️  To stop the process:"
echo "  kill $PROCESS_ID"
echo ""
echo "💾 Results will be saved to: ./data/processed/"
echo ""
echo "✅ Collection started successfully!"