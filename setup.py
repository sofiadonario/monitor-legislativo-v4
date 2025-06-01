"""
Setup script for Monitor Legislativo v4
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="monitor-legislativo",
    version="4.0.0",
    author="MackIntegridade",
    author_email="contato@mackintegridade.org",
    description="Monitor de Políticas Públicas - Busca integrada em fontes legislativas brasileiras",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/mackintegridade/monitor-legislativo",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Science/Research",
        "Topic :: Scientific/Engineering :: Information Analysis",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=[
        # Core dependencies
        "aiohttp>=3.8.0",
        "requests>=2.28.0",
        "beautifulsoup4>=4.11.0",
        "lxml>=4.9.0",
        
        # Desktop GUI (optional)
        "PySide6>=6.4.0; python_version>='3.8'",
        
        # Web scraping
        "playwright>=1.30.0",
        
        # Data processing
        "python-dateutil>=2.8.0",
        
        # Export formats
        "openpyxl>=3.1.0",  # Excel export
        "weasyprint>=58.0; platform_system!='Windows'",  # PDF export (non-Windows)
        "reportlab>=3.6.0",  # PDF export (fallback)
        
        # Web framework (for web version)
        "fastapi>=0.95.0",
        "uvicorn>=0.21.0",
        "python-multipart>=0.0.6",
        
        # Utilities
        "python-dotenv>=1.0.0",
        "pyyaml>=6.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.2.0",
            "pytest-asyncio>=0.20.0",
            "pytest-cov>=4.0.0",
            "black>=23.1.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.1.0",
        ],
        "pdf": [
            "pdfkit>=1.0.0",
            "wkhtmltopdf>=0.2",
        ],
    },
    entry_points={
        "console_scripts": [
            "monitor-legislativo=desktop.main:main",
            "monitor-legislativo-web=web.main:main",
        ],
    },
    package_data={
        "": ["*.json", "*.yaml", "*.yml", "*.html", "*.css", "*.js"],
        "resources": ["logos/*", "docs/*"],
    },
    include_package_data=True,
    zip_safe=False,
)