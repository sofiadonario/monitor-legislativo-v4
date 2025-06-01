# Monitor Legislativo v4.0 - Launch Guide

## 🚀 Quick Start

### Option 1: Using the Launch Script (Recommended)
```bash
# Check status and dependencies
python3 launch.py

# Install dependencies (if needed)
python3 launch.py --install

# Launch web application
python3 launch.py web

# Launch desktop application  
python3 launch.py desktop
```

### Option 2: Manual Installation
```bash
# Install dependencies
pip install -r requirements.txt

# For Playwright (ANVISA JavaScript rendering)
playwright install chromium
```

## 🌐 Web Application

```bash
python3 launch.py web
```

**Access at:** http://localhost:8000
- **API Documentation:** http://localhost:8000/api/docs
- **Alternative Docs:** http://localhost:8000/api/redoc

### Key Endpoints:
- `GET /api/v1/search` - Search propositions across all sources
- `GET /api/v1/sources` - List available data sources
- `GET /api/v1/status` - Check API health status
- `POST /api/v1/export` - Export search results

## 🖥️ Desktop Application

```bash
python3 launch.py desktop
```

**Requirements:** PySide6 or PyQt5
```bash
pip install PySide6
```

## 📊 Data Sources (14 Total)

### Government Sources (3)
- **Câmara dos Deputados** - Federal deputies and bills
- **Senado Federal** - Senate and legislative proposals  
- **Diário Oficial** - Official gazette publications

### Regulatory Agencies (11)
- **ANEEL** - Energia Elétrica
- **ANATEL** - Telecomunicações
- **ANVISA** - Vigilância Sanitária (with JavaScript rendering)
- **ANS** - Saúde Suplementar
- **ANA** - Águas
- **ANCINE** - Cinema
- **ANTT** - Transportes Terrestres
- **ANTAQ** - Transportes Aquaviários
- **ANAC** - Aviação Civil
- **ANP** - Petróleo
- **ANM** - Mineração

## ✨ Key Features

- **Async API Integration** - High-performance concurrent requests
- **Smart Caching** - Two-tier caching (memory + disk) with TTL
- **Multi-format Export** - CSV, JSON, PDF, Excel, HTML
- **Real-time Monitoring** - Health checks and status monitoring
- **JavaScript Rendering** - Playwright support for dynamic content
- **Error Resilience** - Retry mechanisms and graceful degradation

## 🛠️ Configuration

Key configuration files:
- `core/config/config.py` - Main configuration
- `core/config/api_endpoints.py` - API endpoints and selectors
- `requirements.txt` - Python dependencies

## 🔧 Development

### Running Tests
```bash
# Unit tests
python -m pytest tests/unit/

# Integration tests  
python -m pytest tests/integration/
```

### Project Structure
```
monitor_legislativo_v4/
├── core/                 # Shared business logic
│   ├── api/             # API service implementations
│   ├── models/          # Data models
│   ├── config/          # Configuration
│   └── utils/           # Utilities
├── desktop/             # Desktop GUI application
├── web/                 # Web API application  
├── tests/               # Test suites
└── launch.py           # Launch script
```

## 📝 Notes

- **ANVISA** requires Playwright for JavaScript rendering
- **Cache** is automatically managed with configurable TTL
- **Rate limiting** is implemented per API
- **Error handling** includes circuit breaker patterns
- **Logging** is configured for production monitoring

## 🐛 Troubleshooting

### Common Issues:

1. **Missing dependencies:**
   ```bash
   python3 launch.py --install
   ```

2. **Qt GUI issues:**
   ```bash
   pip install PySide6
   ```

3. **ANVISA JavaScript rendering:**
   ```bash
   pip install playwright
   playwright install chromium
   ```

4. **Import errors:**
   - Ensure you're in the project root directory
   - Check Python path configuration

---

© 2025 MackIntegridade - Monitor de Políticas Públicas v4.0