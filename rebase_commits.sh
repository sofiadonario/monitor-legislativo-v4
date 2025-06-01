#!/bin/bash

# Git Rebase Helper Script for Monitor Legislativo v4
# This script helps manage the rebase process systematically

echo "=== Monitor Legislativo v4 Git Rebase Helper ==="
echo "Current branch: $(git branch --show-current)"
echo "Starting commit: $(git rev-parse HEAD)"
echo ""

# Show current status
echo "Recent commits to rebase:"
git log --oneline -15
echo ""

# Group 1: Database Integration (recent 8 commits)
echo "GROUP 1: Database Integration Commits"
echo "- 9e9e2e8 feat: Comprehensive dashboard debugging and critical fixes complete"  
echo "- ee36244 fix: Install database packages and fix Railway PostgreSQL integration"
echo "- 7900f60 fix: Resolve 0 documents issue and executive summary errors"
echo "- 4241609 feat: complete database integration with Railway PostgreSQL"
echo "- 2f91279 fix: CRITICAL - correct data loading priority in all modules"
echo "- 5532c9f fix: enhance Real Data System with timeout protection and caching"
echo "- da665f1 fix: prioritize full 134k dataset over railway 50k fallback"
echo "- dd76b07 fix: restore full 134k+ document access in library tab"
echo ""
echo "TARGET: Single commit 'feat: Complete Railway PostgreSQL integration with full dataset support'"
echo ""

# Group 2: Database Optimization
echo "GROUP 2: Database Optimization Commits" 
echo "- 00166ae feat(db): use DB when connected regardless of SSL flag"
echo "- dd99972 perf(db): remove 50k safety cap in optimized library query"
echo "- d5d2514 revert(docker): remove COPY of full CSV from image"
echo "- bc25f19 chore(docker): include full 134k dataset CSV in build" 
echo "- 949dd99 fix(db): stop incorrect CSV fallback"
echo ""
echo "TARGET: Single commit 'feat: Optimize database queries and eliminate CSV fallbacks'"
echo ""

# Group 3: System Fixes
echo "GROUP 3: System Fix Commits"
echo "- d82e008 fix: FINALLY fix library tab 50k limit"
echo "- 46876bc fix: System monitoring dashboard no longer shows ERROR status"
echo ""
echo "TARGET: Single commit 'fix: Resolve system monitoring and data access issues'"
echo ""

echo "=== EXECUTION PLAN ==="
echo "1. Reset to 15 commits back: git reset --soft HEAD~15"
echo "2. Create consolidated commits for each group"
echo "3. Test functionality after each group"  
echo "4. Validate Railway deployment compatibility"
echo ""
echo "SAFETY: All changes are preserved in backup branches"
echo "        - backup-main-original"
echo "        - backup-pre-rebase-$(date +%Y%m%d-%H%M%S)"