# Development Directory

Development tools, utilities, scripts, and research materials for Monitor Legislativo v4.

## 🔧 Structure

### 📜 Scripts (`/scripts/`)
Development and utility scripts for environment setup and maintenance:
- **dev-setup.sh** - Development environment setup script
- **debug-start.sh** - Debug mode startup script
- **setup_database.bat** - Database setup for Windows
- **setup_database.sh** - Database setup for Unix/Linux
- **initialize_database.py** - Database initialization script

### 🧪 Test Scripts (`/test-scripts/`)
Testing, validation, and demonstration scripts:
- **test_api_endpoints.py** - API endpoint testing suite
- **test_database.py** - Database functionality testing
- **test_lexml_standalone.py** - Standalone LexML testing
- **test_search_issue.py** - Search functionality validation
- **test_simple_fallback.py** - Fallback mechanism testing
- **test_tier3_fallback.py** - Tier 3 fallback testing
- **verify_lexml_implementation.py** - LexML integration verification
- **verify_setup.py** - Complete setup verification
- **demo_lexml_features.py** - LexML features demonstration
- **minimal_app.py** - Minimal application for testing
- **launch.py** - Application launcher and orchestrator

### 🔬 Research (`/research/`)
Research materials and experimental code:
- **transport_research/** - Transport legislation research modules
- **transport_terms.txt** - Transport terminology and keywords

## 🛠️ Development Workflow

### Environment Setup
1. **Initial Setup**: Run `./scripts/dev-setup.sh`
2. **Database Setup**: Execute `./scripts/setup_database.sh` (Unix) or `setup_database.bat` (Windows)
3. **Database Initialization**: Run `python ./scripts/initialize_database.py`
4. **Verification**: Execute `python ./test-scripts/verify_setup.py`

### Testing Workflow
1. **API Testing**: `python ./test-scripts/test_api_endpoints.py`
2. **Database Testing**: `python ./test-scripts/test_database.py`
3. **LexML Integration**: `python ./test-scripts/test_lexml_standalone.py`
4. **Search Functionality**: `python ./test-scripts/test_search_issue.py`
5. **Fallback Systems**: Run fallback tests as needed

### Debug Mode
- **Start Debug Session**: `./scripts/debug-start.sh`
- **Minimal App Testing**: `python ./test-scripts/minimal_app.py`
- **Component Launcher**: `python ./test-scripts/launch.py`

## 📊 Script Descriptions

### Core Scripts

#### `dev-setup.sh`
**Purpose**: Complete development environment setup
- Installs Python dependencies
- Sets up Node.js environment
- Configures Git hooks
- Initializes configuration files

#### `initialize_database.py`
**Purpose**: Database schema and initial data setup
- Creates database tables
- Loads initial configuration
- Sets up user permissions
- Validates database connectivity

#### `verify_setup.py`
**Purpose**: Comprehensive setup verification
- Tests database connectivity
- Validates API endpoints
- Checks service dependencies
- Confirms configuration integrity

### Testing Scripts

#### `test_api_endpoints.py`
**Purpose**: API endpoint validation
- Tests all REST endpoints
- Validates response formats
- Checks error handling
- Measures response times

#### `test_lexml_standalone.py`
**Purpose**: LexML integration testing
- Standalone LexML service testing
- Vocabulary validation
- SKOS processing verification
- API connectivity testing

#### `demo_lexml_features.py`
**Purpose**: LexML feature demonstration
- Interactive feature showcase
- Search capability demonstration
- Vocabulary expansion examples
- Real-time data processing

### Research Materials

#### `transport_research/`
**Purpose**: Transport legislation research
- **enhanced_lexml_search.py** - Advanced search implementations
- **lexml_search_example.py** - Search usage examples
- **lexml_transport_search.py** - Transport-specific search logic
- **lexml_working_scraper.py** - Working scraper implementations
- **transport_terms.txt** - Transport domain terminology

## 🚀 Usage Examples

### Quick Development Setup
```bash
# Clone repository and navigate to development
cd development/

# Run complete setup
./scripts/dev-setup.sh

# Initialize database
python scripts/initialize_database.py

# Verify installation
python test-scripts/verify_setup.py
```

### Testing Suite Execution
```bash
# Run all tests
python test-scripts/test_api_endpoints.py
python test-scripts/test_database.py
python test-scripts/test_lexml_standalone.py

# Validate specific functionality
python test-scripts/test_search_issue.py
python test-scripts/test_simple_fallback.py
```

### Research and Experimentation
```bash
# Explore transport research
cd research/transport_research/

# Run enhanced search
python enhanced_lexml_search.py

# Test search examples
python lexml_search_example.py
```

## 🔬 Research Guidelines

### Adding New Research
1. Create descriptive filename with purpose
2. Include comprehensive docstrings
3. Add usage examples and test cases
4. Document research findings and conclusions
5. Update research index when applicable

### Experimental Code Standards
- Use clear, self-documenting code
- Include extensive comments for complex logic
- Provide sample data and test cases
- Document limitations and known issues
- Reference related academic papers or sources

## 🧪 Testing Standards

### Test Script Requirements
- Include comprehensive test coverage
- Provide clear success/failure indicators
- Log detailed results and timing information
- Handle edge cases and error conditions
- Include cleanup procedures

### Naming Conventions
- `test_*.py` - Functional testing scripts
- `verify_*.py` - Validation and verification scripts
- `demo_*.py` - Demonstration and example scripts
- `*_research.py` - Research and experimental code

## 📝 Maintenance

### Regular Tasks
- **Weekly**: Update test scripts for new features
- **Monthly**: Review and clean up experimental code
- **Per Release**: Update setup scripts and dependencies
- **As Needed**: Archive completed research to documentation

### Best Practices
- Keep scripts modular and reusable
- Maintain backward compatibility where possible
- Document breaking changes clearly
- Version control for significant script updates
- Regular testing on clean environments

## 🔍 Troubleshooting

### Common Issues
- **Setup Failures**: Check `verify_setup.py` output for specific errors
- **Database Issues**: Review database logs and connectivity
- **API Problems**: Use `test_api_endpoints.py` for diagnosis
- **LexML Integration**: Run `test_lexml_standalone.py` for isolation testing

### Debug Resources
- Script logs in respective directories
- Error outputs with stack traces
- Configuration validation results
- Service dependency status checks

---

**Last Updated**: Phase 3 Week 10  
**Development Tools Version**: 2.0  
**Categories**: Scripts, Testing, Research