#!/usr/bin/env python3
"""
Setup script for lexml-refinado package
Provides backward compatibility for older pip versions and setuptools
"""

from setuptools import setup, find_packages
import os
import sys

# Ensure we're in the right directory
if __name__ == "__main__":
    here = os.path.abspath(os.path.dirname(__file__))
    
    # Read version from __init__.py
    version_file = os.path.join(here, "lexml_refinado", "__init__.py")
    version = {}
    with open(version_file) as f:
        exec(f.read(), version)
    
    # Read README
    readme_path = os.path.join(here, "README.md")
    long_description = ""
    if os.path.exists(readme_path):
        with open(readme_path, "r", encoding="utf-8") as f:
            long_description = f.read()
    
    # Core dependencies
    install_requires = [
        "requests>=2.28.0",
        "urllib3>=1.26.0",
        "pandas>=1.4.0",
        "numpy>=1.21.0",
        "scipy>=1.8.0",
        "beautifulsoup4>=4.11.0",
        "lxml>=4.9.0",
        "nltk>=3.7",
        "spacy>=3.4.0",
        "transformers>=4.15.0",
        "torch>=1.12.0",
        "scikit-learn>=1.1.0",
        "unidecode>=1.3.0",
        "pyuca>=1.2",
        "psycopg2-binary>=2.9.0",
        "sqlalchemy>=1.4.0",
        "alembic>=1.8.0",
        "pydantic>=1.10.0",
        "pyyaml>=6.0",
        "toml>=0.10.0",
        "python-dotenv>=0.20.0",
        "structlog>=22.1.0",
        "rich>=12.0.0",
        "python-dateutil>=2.8.0",
        "pytz>=2022.1",
        "statsmodels>=0.13.0",
        "joblib>=1.1.0",
        "tqdm>=4.64.0",
    ]
    
    # Extra dependencies
    extras_require = {
        'dev': [
            "pytest>=7.0.0",
            "pytest-cov>=3.0.0",
            "pytest-asyncio>=0.20.0",
            "black>=22.0.0",
            "isort>=5.10.0",
            "flake8>=5.0.0",
            "mypy>=0.991",
            "pre-commit>=2.20.0",
            "bandit>=1.7.0",
        ],
        'docs': [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.0.0",
            "sphinx-autodoc-typehints>=1.19.0",
            "myst-parser>=0.18.0",
        ],
        'ml-advanced': [
            "tensorflow>=2.10.0",
            "keras>=2.10.0",
            "gensim>=4.2.0",
            "flair>=0.11.0",
        ],
        'viz': [
            "matplotlib>=3.5.0",
            "seaborn>=0.11.0",
            "plotly>=5.10.0",
            "wordcloud>=1.9.0",
        ],
        'geo': [
            "geopandas>=0.11.0",
            "shapely>=1.8.0",
            "folium>=0.12.0",
        ]
    }
    
    # Add 'all' extra that includes everything
    all_extras = []
    for deps in extras_require.values():
        all_extras.extend(deps)
    extras_require['all'] = list(set(all_extras))
    
    setup(
        name="lexml-refinado",
        version=version.get("__version__", "2.0.0"),
        description="Advanced Brazilian Legislative Document Analysis System with NLP and Machine Learning",
        long_description=long_description,
        long_description_content_type="text/markdown",
        author="MackIntegridade Team",
        author_email="dev@mackintegridade.com",
        maintainer="Sofia Researcher",
        maintainer_email="sofia@mackintegridade.com",
        url="https://github.com/MackIntegridade/monitor_legislativo_v4",
        project_urls={
            "Documentation": "https://monitor-legislativo-v4.readthedocs.io/",
            "Source": "https://github.com/MackIntegridade/monitor_legislativo_v4",
            "Tracker": "https://github.com/MackIntegridade/monitor_legislativo_v4/issues",
        },
        packages=find_packages(),
        include_package_data=True,
        package_data={
            'lexml_refinado': [
                'data/*.json',
                'data/*.yaml',
                'data/*.txt',
                'models/*.pkl',
                'models/*.joblib',
                'config/*.yaml',
                'config/*.json',
            ],
        },
        install_requires=install_requires,
        extras_require=extras_require,
        python_requires=">=3.8",
        license="MIT",
        classifiers=[
            "Development Status :: 4 - Beta",
            "Intended Audience :: Science/Research",
            "Intended Audience :: Legal Industry",
            "Topic :: Scientific/Engineering :: Artificial Intelligence",
            "Topic :: Text Processing :: Linguistic",
            "Topic :: Software Development :: Libraries :: Python Modules",
            "License :: OSI Approved :: MIT License",
            "Programming Language :: Python :: 3",
            "Programming Language :: Python :: 3.8",
            "Programming Language :: Python :: 3.9",
            "Programming Language :: Python :: 3.10",
            "Programming Language :: Python :: 3.11",
            "Programming Language :: Python :: 3.12",
            "Natural Language :: Portuguese (Brazilian)",
        ],
        keywords=[
            "nlp", "legal-text-analysis", "brazilian-legislation",
            "document-classification", "machine-learning", "data-mining",
            "text-analytics"
        ],
        entry_points={
            'console_scripts': [
                'lexml-scraper=lexml_refinado.cli:main',
                'lexml-classify=lexml_refinado.cli:classify_documents',
                'lexml-analyze=lexml_refinado.cli:analyze_corpus',
            ],
            'lexml_refinado.analyzers': [
                'document-classifier=lexml_refinado.classification_system:RefinedDocumentClassifier',
                'thematic-enricher=lexml_refinado.thematic_enrichment:ThematicEnrichmentSystem',
                'quality-controller=lexml_refinado.quality_controller:ParsingQualityController',
            ],
        },
        zip_safe=False,
    )