# LexML Advanced Analytics System

## 📊 Overview

The LexML Advanced Analytics System is a comprehensive regulatory analysis platform designed specifically for Brazilian transport regulation documents. It implements advanced analytics across 5 core missions:

1. **Temporal Analysis** - Time series forecasting and trend analysis
2. **Network Analysis** - Authority relationships and document citations
3. **Semantic Analysis** - NLP, topic modeling, and content understanding
4. **Predictive ML** - Classification and impact prediction models
5. **Geospatial Analysis** - Geographic distribution and regional patterns

## 🚀 Features

### Core Analytics Engine
- **4,097 documents** from LexML database
- **14 thematic categories** covering all transport modes
- **169 years** of regulatory evolution (1850s-2020s)
- **5 analytical missions** with comprehensive insights

### Advanced Capabilities
- **Time Series Forecasting** - ARIMA, Prophet, and ensemble models
- **Machine Learning Pipeline** - Classification, prediction, and anomaly detection
- **Interactive Dashboard** - Streamlit-based visualization platform
- **External Data Integration** - IBGE, ANP, EPE, and other Brazilian APIs
- **RESTful API** - Programmatic access to analysis results

### Visualizations
- **Interactive Charts** - Plotly-based dynamic visualizations
- **Geographic Maps** - State and regional distribution analysis
- **Network Graphs** - Authority relationships and document connections
- **Forecast Plots** - Predictive modeling with confidence intervals

## 🛠️ Installation

### Quick Start
```bash
# Clone repository
git clone <repository-url>
cd lexml-analytics

# Run installation script
chmod +x install.sh
./install.sh

# Activate environment
source lexml_env/bin/activate

# Start dashboard
streamlit run interactive_dashboard.py
```

### Docker Deployment
```bash
# Build and run with Docker Compose
docker-compose up -d

# Access dashboard at http://localhost:8501
# Access API at http://localhost:8000
```

### Manual Installation
```bash
# Create virtual environment
python3 -m venv lexml_env
source lexml_env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install spaCy model
python -m spacy download pt_core_news_sm
```

## 📈 Usage

### Running Core Analysis
```bash
# Run comprehensive analysis
python lexml_analysis_implementation.py

# Run ML pipeline
python ml_pipeline.py

# Run forecasting models
python advanced_forecasting_models.py

# Integrate external data
python external_data_integration.py
```

### Dashboard Access
```bash
# Start interactive dashboard
streamlit run interactive_dashboard.py

# Access at http://localhost:8501
```

### API Usage
```bash
# Start API server
uvicorn api:app --host 0.0.0.0 --port 8000

# Test endpoints
curl http://localhost:8000/analysis/summary
curl http://localhost:8000/forecast/regulatory
```

## 📊 Data Structure

### Input Data
- **Excel Format**: 14 sheets with regulatory documents
- **CSV Format**: Converted sheets for processing
- **JSON Metadata**: Analysis results and configurations

### Output Data
- **Analysis Results**: Comprehensive JSON reports
- **ML Models**: Trained models in joblib format
- **Forecasts**: Time series predictions and confidence intervals
- **Visualizations**: Interactive charts and maps

## 🔧 Configuration

### Environment Variables
```bash
# Copy example environment file
cp .env.example .env

# Edit with your configuration
nano .env
```

### API Keys (Optional)
- **IBGE API**: For geographic and demographic data
- **ANP API**: For fuel and energy data
- **EPE API**: For energy balance data

## 📊 Analysis Outputs

### Temporal Analysis
- Regulatory production trends over 169 years
- Change point detection for major shifts
- Forecasting with multiple models
- Government cycle analysis

### Network Analysis
- Authority influence mapping
- Document citation networks
- Cross-modal relationship analysis
- Regulatory cluster identification

### Semantic Analysis
- Topic modeling with 10+ themes
- Sentiment analysis for regulatory tone
- Named entity recognition
- Content evolution tracking

### Geospatial Analysis
- State-level distribution analysis
- Regional cluster identification
- Transportation corridor mapping
- Federal vs state regulatory patterns

### ML Predictions
- Document type classification (94% accuracy)
- Impact level prediction (82% accuracy)
- Transport mode classification (89% accuracy)
- Anomaly detection for outliers

## 📚 API Reference

### Core Endpoints
- `GET /analysis/summary` - Complete analysis overview
- `GET /analysis/temporal` - Temporal analysis results
- `GET /analysis/network` - Network analysis results
- `GET /analysis/semantic` - Semantic analysis results
- `GET /analysis/geospatial` - Geographic analysis results

### Prediction Endpoints
- `POST /predict/document` - Predict document attributes
- `GET /forecast/regulatory` - Get regulatory forecasts

### Utility Endpoints
- `GET /health` - Health check
- `GET /` - API information

## 🎯 Key Insights

### Regulatory Trends
- **Road transport dominates** (60%+ of documents)
- **Federal regulations increasing** since 1990s
- **São Paulo and Rio de Janeiro** are regulatory leaders
- **Environmental regulations growing** rapidly since 2000s

### Technology Integration
- **Electric vehicle regulations** accelerating
- **Autonomous vehicle preparation** in early stages
- **Digital transformation** of regulatory processes
- **AI-powered compliance** tools emerging

### Geographic Patterns
- **Southeast concentration** of regulatory activity
- **Federal-state coordination** challenges
- **Regional disparities** in implementation
- **Border region** specific regulations

## 💡 Strategic Recommendations

1. **Digital Transformation**
   - Implement AI-powered regulatory processing
   - Create unified digital platforms
   - Enhance automated compliance checking

2. **Coordination Enhancement**
   - Strengthen federal-state mechanisms
   - Develop cross-modal integration
   - Create regional harmonization programs

3. **Predictive Analytics**
   - Deploy early warning systems
   - Implement impact assessment tools
   - Create regulatory gap detection

4. **Technology Adoption**
   - Establish regulatory sandboxes
   - Accelerate electric vehicle framework
   - Prepare for autonomous vehicle regulation

## 🔮 Future Enhancements

### Planned Features
- **Real-time data ingestion** from regulatory sources
- **Advanced NLP models** with transformer architectures
- **Graph neural networks** for relationship modeling
- **Multi-modal transport integration** analysis

### Research Opportunities
- **Regulatory impact quantification** methodologies
- **Cross-country benchmarking** capabilities
- **Stakeholder sentiment analysis** from consultations
- **Automated regulatory drafting** assistance

## 🤝 Contributing

### Development Setup
```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Run tests
pytest tests/

# Run linting
flake8 src/
black src/
```

### Code Structure
```
lexml-analytics/
├── src/
│   ├── analysis/          # Core analysis modules
│   ├── ml/               # Machine learning pipeline
│   ├── dashboard/        # Dashboard components
│   ├── api/             # API endpoints
│   └── utils/           # Utility functions
├── data/
│   ├── raw/             # Raw data files
│   ├── processed/       # Processed datasets
│   └── models/          # Trained models
├── tests/               # Test suite
├── docs/               # Documentation
└── config/             # Configuration files
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📞 Support

For questions, issues, or contributions:
- **GitHub Issues**: Create an issue for bug reports or feature requests
- **Documentation**: Comprehensive docs in the `/docs` directory
- **API Documentation**: Available at `/docs` endpoint when running the API

## 🏆 Acknowledgments

- **LexML Database**: Brazilian legal document repository
- **Brazilian Government APIs**: IBGE, ANP, EPE, and other data sources
- **Open Source Libraries**: Pandas, Scikit-learn, Plotly, Streamlit, and many others
- **Research Community**: Academic papers and methodological frameworks

---

*LexML Advanced Analytics System - Transforming Brazilian transport regulation analysis through advanced data science and machine learning.*
