# LexML Refinado - Advanced Brazilian Legislative Document Analysis System

[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/MackIntegridade/monitor_legislativo_v4)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A comprehensive Python package for analyzing Brazilian legislative documents with advanced Natural Language Processing, Machine Learning, and statistical analysis capabilities.

## 🚀 Features

### Core Capabilities
- **Multi-level Document Classification**: Hierarchical classification system with 3 levels (category, type, subtype)
- **Brazilian Portuguese NLP**: Specialized text processing for Brazilian legal documents
- **Machine Learning Models**: Support for various ML algorithms (Random Forest, SVM, XGBoost, Neural Networks)
- **Large-scale Processing**: Optimized for analyzing 134k+ legislative documents
- **PostgreSQL Integration**: Efficient data storage and retrieval
- **Academic Research Support**: Built for scholarly analysis and research

### Advanced Features
- **Thematic Analysis**: Advanced topic modeling and thematic enrichment
- **Quality Assessment**: Automated quality validation and scoring
- **Temporal Analysis**: Time series analysis of legislative patterns
- **Geospatial Analytics**: Jurisdictional analysis by state and municipality
- **Regulatory Complexity Assessment**: Automated complexity scoring
- **Citation Network Analysis**: Legal document relationship mapping

## 📦 Installation

### Basic Installation

```bash
# Install from source
cd src/lexml_refinado
pip install -e .

# Or with setuptools
python setup.py develop
```

### Development Installation

```bash
# Install with development dependencies
pip install -e ".[dev]"

# Install all optional dependencies
pip install -e ".[all]"
```

### Optional Dependencies

```bash
# Advanced ML capabilities
pip install -e ".[ml-advanced]"

# Visualization support
pip install -e ".[viz]"

# Geospatial analysis
pip install -e ".[geo]"

# Documentation building
pip install -e ".[docs]"
```

## 🔧 Quick Start

### Basic Document Classification

```python
from lexml_refinado import RefinedDocumentClassifier

# Initialize classifier
classifier = RefinedDocumentClassifier()

# Classify a document
result = classifier.classify_document(
    urn="urn:lex:br:federal:lei:2021-04-01;14.133",
    title="Lei nº 14.133, de 1º de abril de 2021",
    document_summary="Lei de Licitações e Contratos Administrativos",
    document_type_original="Lei"
)

print(f"Category: {result['main_category']}")
print(f"Type: {result['document_type']}")
print(f"Subtype: {result['document_subtype']}")
```

### Comprehensive Document Analysis

```python
from lexml_refinado import EnhancedLexMLStrategy

# Initialize the main analysis system
analyzer = EnhancedLexMLStrategy()

# Execute comprehensive search and analysis
results = analyzer.execute_comprehensive_search(
    categories=['transporte_geral', 'combustiveis_energia'],
    max_results_per_category=50,
    include_all_document_types=True
)

# Save results
output_file = analyzer.save_enhanced_results(results)
print(f"Analysis complete! Results saved to: {output_file}")
```

### NLP Analysis

```python
from lexml_refinado.nlp import BrazilianLegalNLP

# Initialize NLP pipeline
nlp = BrazilianLegalNLP()

# Analyze a single document
text = "Lei nº 14.133, de 1º de abril de 2021. Estabelece normas gerais..."
analysis = nlp.analyze_text(text, analysis_type='comprehensive')

print(f"Regulatory Complexity: {analysis.regulatory_complexity:.2f}")
print(f"Primary Topics: {analysis.primary_topics}")
print(f"Legal Entities: {analysis.legal_entities}")

# Analyze a corpus
documents = ["Document 1 text...", "Document 2 text..."]
corpus_analysis = nlp.analyze_corpus(documents)
```

### Machine Learning Classification

```python
from lexml_refinado.ml import DocumentClassifier, ClassificationConfig

# Configure classifier
config = ClassificationConfig(
    algorithm='random_forest',
    max_features=1000,
    tune_hyperparameters=True
)

# Initialize and train
classifier = DocumentClassifier(config)
classifier.fit(training_documents, labels)

# Make predictions
predictions = classifier.predict(new_documents, return_confidence=True)
print(f"Predictions: {predictions.predictions}")
print(f"Confidence: {predictions.confidence_scores}")
```

### Database Operations

```python
from lexml_refinado.database import DatabaseManager

# Connect to database
db = DatabaseManager("postgresql://user:pass@localhost:5432/monitor_legislativo")
db.connect()

# Query documents
documents = db.get_documents(
    limit=100,
    filters={'state': 'São Paulo', 'year': {'min': 2020, 'max': 2023}}
)

# Search documents
results = db.search_documents("transporte rodoviário", limit=50)

# Get statistics
stats = db.get_document_statistics()
print(f"Total documents: {stats['total_documents']}")
```

## 🖥️ Command Line Interface

The package includes a comprehensive CLI for common operations:

### Document Scraping

```bash
# Scrape all categories
lexml-scraper scrape --categories all --max-results 1000 --output results.csv

# Scrape specific categories
lexml-scraper scrape --categories transporte_geral combustiveis_energia --max-results 500
```

### Document Classification

```bash
# Classify documents
lexml-classify documents.csv --output classifications.csv

# Use trained model
lexml-classify documents.csv --model trained_model.joblib --confidence-threshold 0.7
```

### Document Analysis

```bash
# Comprehensive analysis
lexml-analyze --input documents.csv --output analysis.json --analysis-type comprehensive --include-nlp --include-ml
```

### Database Operations

```bash
# Health check
lexml-scraper database --operation health-check

# Get statistics
lexml-scraper database --operation stats

# Search documents
lexml-scraper database --operation search --query "transporte" --output-file search_results.csv
```

### Model Training

```bash
# Train classification model
lexml-scraper train --data training_data.csv --model-type classification --algorithm random_forest --output model.joblib
```

## 🏗️ Architecture

### Package Structure

```
lexml_refinado/
├── __init__.py                 # Main package interface
├── classification_system.py   # Document classification
├── parsing_prompts.py         # Document parsing
├── thematic_enrichment.py     # Thematic analysis
├── quality_controller.py      # Quality assessment
├── enhanced_strategy.py       # Main orchestration
├── nlp/                       # NLP components
│   ├── __init__.py
│   ├── brazilian_legal_nlp.py
│   ├── text_preprocessor.py
│   ├── feature_extractor.py
│   └── ...
├── ml/                        # Machine learning
│   ├── __init__.py
│   ├── document_classifier.py
│   ├── topic_modeler.py
│   └── ...
├── database/                  # Database integration
│   ├── __init__.py
│   ├── database_manager.py
│   └── ...
├── utils/                     # Utilities
│   ├── __init__.py
│   ├── config_manager.py
│   └── ...
├── tests/                     # Test suite
└── cli.py                     # Command line interface
```

### Core Components

1. **Classification System**: Multi-level hierarchical document classification
2. **NLP Pipeline**: Brazilian Portuguese text processing and analysis
3. **ML Framework**: Machine learning models for various tasks
4. **Database Layer**: PostgreSQL integration with connection pooling
5. **Quality Control**: Automated validation and quality scoring
6. **CLI Interface**: Command-line tools for common operations

## 📊 Data Models

### Document Structure

```python
{
    'urn': 'urn:lex:br:federal:lei:2021-04-01;14.133',
    'title': 'Lei nº 14.133, de 1º de abril de 2021',
    'document_summary': 'Lei de Licitações e Contratos Administrativos',
    'document_type_full': 'Lei',
    'enacting_date': '2021-04-01',
    'state': 'Federal',
    'country': 'br',
    'classification': {
        'main_category': 'legislation',
        'document_type': 'lei_ordinaria',
        'document_subtype': 'regulamentacao_normas'
    },
    'nlp_analysis': {
        'regulatory_complexity': 0.75,
        'readability_score': 0.45,
        'primary_topics': ['licitações', 'contratos', 'administração pública']
    }
}
```

### Classification Hierarchy

```
Level 1 (Main Category):
├── legislation (Legislação)
├── jurisprudence (Jurisprudência)  
└── doctrine (Doutrina)

Level 2 (Document Type):
├── lei_ordinaria, decreto_presidencial, resolucao_agencia...
├── stf_adi, stj_resp, trf_apelacao...
└── tese_doutorado, artigo_cientifico, relatorio_pesquisa...

Level 3 (Thematic Subtype):
├── combustiveis_energia, tecnologia_inovacao, infraestrutura...
├── jurisprudencia_tributaria, jurisprudencia_ambiental...
└── doutrina_regulatoria, doutrina_economica...
```

## 🔬 Research Applications

### Academic Use Cases

- **Legislative Trend Analysis**: Temporal patterns in Brazilian legislation
- **Policy Impact Assessment**: Quantitative analysis of regulatory changes
- **Jurisdictional Comparison**: Cross-state legislative pattern analysis
- **Topic Evolution**: Tracking thematic changes over time
- **Regulatory Complexity**: Measuring and comparing document complexity
- **Citation Network Analysis**: Understanding legislative interconnections

### Data Science Applications

- **Text Classification**: Multi-class document categorization
- **Topic Modeling**: Unsupervised thematic discovery
- **Anomaly Detection**: Identifying unusual legislative patterns  
- **Time Series Forecasting**: Predicting legislative activity
- **Network Analysis**: Mapping document relationships
- **Statistical Modeling**: Hypothesis testing on legislative data

## ⚡ Performance

### Benchmarks

- **Document Classification**: ~1000 documents/second
- **NLP Analysis**: ~100 documents/second (comprehensive)
- **Database Queries**: Optimized for 134k+ document corpus
- **Batch Processing**: Efficient handling of large datasets
- **Memory Usage**: Optimized for production environments

### Scalability

- **Horizontal Scaling**: Support for distributed processing
- **Connection Pooling**: Efficient database connection management
- **Caching**: Intelligent caching for repeated operations
- **Batch Operations**: Optimized bulk insert/update operations

## 🧪 Testing

### Running Tests

```bash
# Run all tests
pytest

# Run specific test categories
pytest tests/unit/
pytest tests/integration/
pytest tests/performance/

# Run with coverage
pytest --cov=lexml_refinado --cov-report=html

# Run performance benchmarks
pytest tests/performance/ --benchmark-only
```

### Test Categories

- **Unit Tests**: Individual component testing
- **Integration Tests**: Component interaction testing
- **Performance Tests**: Scalability validation
- **Data Quality Tests**: Input/output validation
- **End-to-end Tests**: Complete workflow testing

## 📖 Documentation

### API Documentation

```bash
# Build documentation
cd docs
make html

# Serve documentation locally
python -m http.server 8000 -d _build/html
```

### Configuration

The package supports configuration via YAML files:

```yaml
# config.yaml
database:
  host: localhost
  port: 5432
  database: monitor_legislativo
  
nlp:
  language: pt
  max_features: 5000
  
ml:
  default_algorithm: random_forest
  cross_validation_folds: 5
  
logging:
  level: INFO
  format: structured
```

## 🤝 Contributing

### Development Setup

```bash
# Clone repository
git clone https://github.com/MackIntegridade/monitor_legislativo_v4.git
cd monitor_legislativo_v4/src/lexml_refinado

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate  # Windows

# Install in development mode
pip install -e ".[dev,all]"

# Install pre-commit hooks
pre-commit install
```

### Code Quality

```bash
# Format code
black lexml_refinado/
isort lexml_refinado/

# Lint code
flake8 lexml_refinado/
mypy lexml_refinado/

# Security check
bandit -r lexml_refinado/
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- **MackIntegridade Research Team** - *Initial work and ongoing development*
- **Sofia Researcher** - *Lead researcher and package architecture*

## 🙏 Acknowledgments

- **Universidade Presbiteriana Mackenzie** - Research support
- **LexML Brasil** - Legislative document database
- **Brazilian Ministry of Transportation** - Domain expertise
- **ANTT, CONTRAN, ANP** - Regulatory guidance

## 📞 Support

- **Documentation**: [https://monitor-legislativo-v4.readthedocs.io/](https://monitor-legislativo-v4.readthedocs.io/)
- **Issues**: [GitHub Issues](https://github.com/MackIntegridade/monitor_legislativo_v4/issues)
- **Email**: dev@mackintegridade.com

## 🔮 Roadmap

### Version 2.1 (Upcoming)
- [ ] BERT-based document embeddings
- [ ] Real-time document monitoring
- [ ] REST API for remote access
- [ ] Docker containerization
- [ ] Kubernetes deployment support

### Version 2.2 (Future)
- [ ] Graph neural networks for citation analysis
- [ ] Multi-language support (Spanish, English)
- [ ] Advanced visualization dashboard
- [ ] Automated report generation
- [ ] Integration with other legal databases

---

**LexML Refinado v2.0.0** - Empowering Brazilian legislative analysis through advanced AI and data science.