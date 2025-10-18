#!/bin/bash
# ==============================================================================
# DEPLOYMENT SCRIPT - Option 2 (Integrated Architecture)
# ==============================================================================
# This script automates the deployment process
# Run: bash deploy.sh
# ==============================================================================

set -e  # Exit on error

echo "========================================"
echo "🚀 Monitor Legislativo v4"
echo "   Deployment Script (Option 2)"
echo "========================================"
echo ""

# Check we're in the right directory
if [ ! -f "app_integrated.R" ]; then
    echo "❌ Error: app_integrated.R not found"
    echo "   Make sure you're in the project root directory"
    exit 1
fi

echo "✅ Pre-flight checks passed"
echo ""

# Step 1: Check current branch
CURRENT_BRANCH=$(git branch --show-current)
echo "📍 Current branch: $CURRENT_BRANCH"

if [ "$CURRENT_BRANCH" = "integrated-architecture" ]; then
    echo "⚠️  Already on integrated-architecture branch"
    read -p "   Continue anyway? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "   Aborted"
        exit 0
    fi
elif [ "$CURRENT_BRANCH" = "main" ]; then
    echo "✅ On main branch - will create new branch"
else
    echo "⚠️  On branch '$CURRENT_BRANCH'"
    read -p "   Create integrated-architecture from here? (y/n): " confirm
    if [ "$confirm" != "y" ]; then
        echo "   Aborted"
        exit 0
    fi
fi

echo ""

# Step 2: Create/checkout deployment branch
if git rev-parse --verify integrated-architecture > /dev/null 2>&1; then
    echo "🔄 Checking out existing integrated-architecture branch..."
    git checkout integrated-architecture
else
    echo "🌿 Creating new integrated-architecture branch..."
    git checkout -b integrated-architecture
fi

echo "✅ On integrated-architecture branch"
echo ""

# Step 3: Backup existing files
echo "💾 Backing up existing files..."
BACKUP_DATE=$(date +%Y%m%d_%H%M%S)

if [ -f "app.R" ]; then
    cp app.R "app.R.backup.$BACKUP_DATE"
    echo "   ✓ Backed up app.R"
fi

if [ -f "global.R" ]; then
    cp global.R "global.R.backup.$BACKUP_DATE"
    echo "   ✓ Backed up global.R"
fi

echo ""

# Step 4: Copy integrated files
echo "📦 Deploying integrated architecture..."
cp app_integrated.R app.R
echo "   ✓ Deployed app_integrated.R → app.R"

cp global_integrated.R global.R
echo "   ✓ Deployed global_integrated.R → global.R"

echo "   ℹ️  ui.R and server.R unchanged (using your existing files)"
echo ""

# Step 5: Show what changed
echo "📊 Changes summary:"
echo "   Modified: app.R (now uses integrated architecture)"
echo "   Modified: global.R (preloads data, DB pool, caching)"
echo "   Modified: Dockerfile (guaranteed package installation)"
echo "   Unchanged: ui.R, server.R, modules/, R/utils/"
echo ""

# Step 6: Stage files
echo "📝 Staging files for commit..."
git add Dockerfile app.R global.R
echo "   ✓ Staged Dockerfile, app.R, global.R"
echo ""

# Step 7: Create commit
echo "💬 Creating commit..."
git commit -m "optimize: integrated architecture with preloaded data + caching

Key improvements:
- Global DB pool (shared across sessions)
- Data functions wrapped with memoise (5min cache)
- IBGE geography preloaded and simplified
- Async workers configured (2 workers)
- Guaranteed package installation (updated Dockerfile)
- Health check endpoint
- Uses existing ui.R and server.R with minimal changes

Expected improvements:
- Startup: 90s → 40-50s (45% faster)
- First paint: 10s → 2-3s (70% faster)
- Memory/session: 500MB → 100-150MB (70% less)
- Health checks: Failing → Passing

Technical details:
- Option 2 (Integrated Architecture) from INTEGRATION_COMPLETE.md
- Keeps all existing modules and business logic intact
- Only architectural changes (where/when data loads)
- Full backward compatibility with existing code
"

echo "✅ Commit created"
echo ""

# Step 8: Show commit
echo "📄 Commit details:"
git log -1 --oneline
echo ""

# Step 9: Ask to push
echo "========================================"
echo "✅ Ready to deploy!"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Push to GitHub:"
echo "   git push origin integrated-architecture"
echo ""
echo "2. In Railway dashboard:"
echo "   - Go to your service → Settings → Source"
echo "   - Change branch to: integrated-architecture"
echo "   - Or create new service from this branch"
echo ""
echo "3. Set environment variables in Railway:"
echo "   PGHOST=<from Railway Postgres plugin>"
echo "   PGPORT=5432"
echo "   PGDATABASE=railway"
echo "   PGUSER=postgres"
echo "   PGPASSWORD=<from Railway Postgres plugin>"
echo "   PORT=3838"
echo ""
echo "4. Monitor deployment logs for:"
echo "   ✅ Core packages loaded"
echo "   ✅ Database pool created and verified"
echo "   ✅ Global configuration complete"
echo "   ✅ APPLICATION READY"
echo ""

read -p "Push to GitHub now? (y/n): " push_confirm

if [ "$push_confirm" = "y" ]; then
    echo ""
    echo "🚀 Pushing to GitHub..."
    git push origin integrated-architecture
    echo ""
    echo "✅ Pushed to GitHub!"
    echo ""
    echo "🌐 Now deploy in Railway dashboard:"
    echo "   https://railway.app"
else
    echo ""
    echo "ℹ️  Skipped push. Run manually:"
    echo "   git push origin integrated-architecture"
fi

echo ""
echo "========================================"
echo "📚 Documentation:"
echo "   - DEPLOY_OPTION2.md - Full deployment guide"
echo "   - INTEGRATION_COMPLETE.md - Technical details"
echo "   - START_HERE.md - Overview"
echo "========================================"
echo ""
echo "✅ Deployment preparation complete!"
