#!/bin/bash

# Simple Nuclear Git History Cleanup
echo "🚀 Starting Simple Nuclear Git History Cleanup..."

cd "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4"

# Backup current state
git branch -D backup-original-1009-commits 2>/dev/null || true
git branch backup-original-1009-commits HEAD

# Create new branch from current state
git branch -D clean-history 2>/dev/null || true
git checkout -b clean-history

# Reset to initial commit and start fresh
FIRST_COMMIT=$(git rev-list --max-parents=0 HEAD)
git reset --soft $FIRST_COMMIT

# Stage all files
git add .

# Create single squashed commit
git commit --amend -m "feat: Complete Brazilian Legislative Monitoring Platform v4

- Full Shiny application with modern UI/UX framework
- Advanced search engine with Redis caching and Portuguese NLP
- Geographic analysis with IBGE integration and choropleth mapping
- Brazilian legislative citation system with ABNT formatting
- Comprehensive REST API with OpenAPI documentation and R SDK
- Analytics dashboard with ML pipeline and executive reporting
- Production-ready deployment with Railway.app optimization
- Security framework with LGPD compliance and vulnerability scanning

🇧🇷 Brazilian Legislative Monitoring Platform - Complete Implementation
🎯 Academic Research & Government Institution Ready
🤖 Generated with Claude Code Development Guide"

echo "✅ Nuclear cleanup completed!"
echo "📊 Repository now has clean history suitable for academic/government use"

# Show final state
git log --oneline -10
echo ""
echo "🔍 Final commit count: $(git rev-list --count HEAD)"