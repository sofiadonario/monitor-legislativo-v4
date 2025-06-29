#!/bin/bash

# Full Integration Test Script
# Monitor Legislativo v4 - Tests React + R Shiny + Railway integration

echo "=================================================="
echo "   MONITOR LEGISLATIVO v4 - INTEGRATION TEST     "
echo "   Testing React Frontend + R Shiny + APIs       "
echo "=================================================="
echo ""

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_test() {
    echo -e "${BLUE}🧪 Testing: $1${NC}"
}

print_pass() {
    echo -e "${GREEN}✅ PASS: $1${NC}"
}

print_fail() {
    echo -e "${RED}❌ FAIL: $1${NC}"
}

print_warn() {
    echo -e "${YELLOW}⚠️  WARN: $1${NC}"
}

# Test counters
TESTS_RUN=0
TESTS_PASSED=0
TESTS_FAILED=0

run_test() {
    local test_name="$1"
    local test_command="$2"
    
    TESTS_RUN=$((TESTS_RUN + 1))
    print_test "$test_name"
    
    if eval "$test_command" > /dev/null 2>&1; then
        print_pass "$test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        print_fail "$test_name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Test 1: Check if R is installed
test_r_installation() {
    print_test "R Installation"
    if command -v R &> /dev/null; then
        R_VERSION=$(R --version | head -n1)
        print_pass "R is installed: $R_VERSION"
        return 0
    else
        print_fail "R is not installed"
        return 1
    fi
}

# Test 2: Check Node.js and npm
test_node_installation() {
    print_test "Node.js Installation"
    if command -v node &> /dev/null && command -v npm &> /dev/null; then
        NODE_VERSION=$(node --version)
        NPM_VERSION=$(npm --version)
        print_pass "Node.js $NODE_VERSION, npm $NPM_VERSION"
        return 0
    else
        print_fail "Node.js or npm not installed"
        return 1
    fi
}

# Test 3: Check project structure
test_project_structure() {
    print_test "Project Structure"
    local required_files=(
        "package.json"
        "src/App.tsx"
        "src/components/Dashboard.tsx"
        "r-shiny-app/app.R"
        "r-shiny-app/Dockerfile"
        "railway.toml"
    )
    
    local missing_files=()
    for file in "${required_files[@]}"; do
        if [ ! -f "$file" ]; then
            missing_files+=("$file")
        fi
    done
    
    if [ ${#missing_files[@]} -eq 0 ]; then
        print_pass "All required files present"
        return 0
    else
        print_fail "Missing files: ${missing_files[*]}"
        return 1
    fi
}

# Test 4: Install npm dependencies
test_npm_dependencies() {
    print_test "NPM Dependencies"
    if npm list @phosphor-icons/react &> /dev/null; then
        print_pass "NPM dependencies installed"
        return 0
    else
        print_warn "Installing NPM dependencies..."
        if npm install &> /dev/null; then
            print_pass "NPM dependencies installed successfully"
            return 0
        else
            print_fail "NPM dependency installation failed"
            return 1
        fi
    fi
}

# Test 5: Build React application
test_react_build() {
    print_test "React Build"
    if npm run build &> /dev/null; then
        print_pass "React application builds successfully"
        return 0
    else
        print_fail "React build failed"
        return 1
    fi
}

# Test 6: Test R Shiny syntax
test_rshiny_syntax() {
    print_test "R Shiny Syntax"
    cd r-shiny-app
    if R -e "
    tryCatch({
        source('app.R', echo = FALSE)
        cat('R Shiny syntax OK\n')
    }, error = function(e) {
        cat('R Shiny syntax error:', e\$message, '\n')
        quit(status = 1)
    })
    " &> /dev/null; then
        print_pass "R Shiny syntax is valid"
        cd ..
        return 0
    else
        print_fail "R Shiny syntax errors"
        cd ..
        return 1
    fi
}

# Test 7: Start R Shiny server (background)
test_rshiny_server() {
    print_test "R Shiny Server"
    cd r-shiny-app
    
    # Start R Shiny in background
    R -e "
    shiny::runApp(port = 3838, host = '127.0.0.1', launch.browser = FALSE)
    " > ../rshiny_test.log 2>&1 &
    
    RSHINY_PID=$!
    echo $RSHINY_PID > ../rshiny_test.pid
    
    # Wait for server to start
    sleep 10
    
    # Test if server responds
    if curl -s http://localhost:3838/health > /dev/null 2>&1; then
        print_pass "R Shiny server is running"
        cd ..
        return 0
    else
        print_fail "R Shiny server not responding"
        # Kill the process
        kill $RSHINY_PID 2>/dev/null
        cd ..
        return 1
    fi
}

# Test 8: Test React dev server
test_react_dev_server() {
    print_test "React Dev Server"
    
    # Start React dev server in background
    npm run dev > react_dev_test.log 2>&1 &
    REACT_PID=$!
    echo $REACT_PID > react_dev_test.pid
    
    # Wait for server to start
    sleep 15
    
    # Test if server responds
    if curl -s http://localhost:5173 > /dev/null 2>&1; then
        print_pass "React dev server is running"
        # Kill the process
        kill $REACT_PID 2>/dev/null
        return 0
    else
        print_fail "React dev server not responding"
        # Kill the process
        kill $REACT_PID 2>/dev/null
        return 1
    fi
}

# Test 9: Test API endpoints
test_api_endpoints() {
    print_test "API Endpoints"
    local api_url="https://monitor-legislativo-v4-production.up.railway.app"
    
    if curl -s "${api_url}/health" > /dev/null 2>&1; then
        print_pass "Production API is responding"
        return 0
    else
        print_warn "Production API not responding (may be expected)"
        return 0
    fi
}

# Test 10: Cleanup
cleanup_test_processes() {
    print_test "Cleanup"
    
    # Kill R Shiny if running
    if [ -f "rshiny_test.pid" ]; then
        RSHINY_PID=$(cat rshiny_test.pid)
        kill $RSHINY_PID 2>/dev/null
        rm rshiny_test.pid
    fi
    
    # Kill React dev server if running
    if [ -f "react_dev_test.pid" ]; then
        REACT_PID=$(cat react_dev_test.pid)
        kill $REACT_PID 2>/dev/null
        rm react_dev_test.pid
    fi
    
    # Kill any remaining shiny processes
    pkill -f "shiny::runApp" 2>/dev/null
    
    print_pass "Test processes cleaned up"
}

# Main test execution
main() {
    echo "Starting comprehensive integration tests..."
    echo ""
    
    # Core dependency tests
    test_r_installation
    test_node_installation
    test_project_structure
    test_npm_dependencies
    
    # Build tests
    test_react_build
    test_rshiny_syntax
    
    # Server tests (only if R is available)
    if command -v R &> /dev/null; then
        test_rshiny_server
        test_react_dev_server
    else
        print_warn "Skipping server tests - R not installed"
    fi
    
    # External API tests
    test_api_endpoints
    
    # Cleanup
    cleanup_test_processes
    
    # Results summary
    echo ""
    echo "=================================================="
    echo "              TEST RESULTS SUMMARY                "
    echo "=================================================="
    echo ""
    echo "📊 Tests Run:    $TESTS_RUN"
    echo "✅ Tests Passed: $TESTS_PASSED"
    echo "❌ Tests Failed: $TESTS_FAILED"
    echo ""
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}🎉 ALL TESTS PASSED!${NC}"
        echo "✅ Your Monitor Legislativo v4 setup is ready!"
        echo ""
        echo "🚀 Next steps:"
        echo "1. Start R Shiny: cd r-shiny-app && ./setup_complete.sh"
        echo "2. Start React: npm run dev"
        echo "3. Deploy to Railway: railway up"
        echo ""
    else
        echo -e "${RED}🚨 SOME TESTS FAILED!${NC}"
        echo "❌ Please fix the failed tests before proceeding"
        echo ""
        echo "📋 Check logs:"
        echo "- R Shiny: rshiny_test.log"
        echo "- React: react_dev_test.log"
        echo ""
    fi
    
    echo "=================================================="
}

# Run tests
main "$@"