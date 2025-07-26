# Brazilian Legislative Analytics Framework

A comprehensive R analytical framework for processing, analyzing, and visualizing Brazilian legislative data from the LexML portal. This framework converts 150k+ legislative documents from CSV to optimized Parquet format and provides advanced text mining, temporal analysis, network analysis, and geospatial analytics capabilities.

## 🎯 Overview

This framework addresses the challenge of analyzing large-scale Brazilian legislative data by providing:

- **Efficient Data Processing**: CSV to Parquet conversion with 60-80% size reduction
- **Advanced Analytics**: Text mining, topic modeling, sentiment analysis, network analysis
- **Temporal Intelligence**: Policy evolution tracking, change point detection, forecasting
- **Geospatial Insights**: Jurisdiction mapping, policy diffusion analysis
- **Quality Assurance**: Comprehensive data validation and integrity checks
- **Reproducibility**: Modular architecture with complete documentation

## 📊 Dataset Description

The dataset contains metadata from the LexML (Brazilian legislative portal) including:

- **Volume**: 286,901+ legislative documents
- **Time Range**: 1900-2025+ (pre-1990 data included)
- **Geographic Scope**: Federal, State, and Municipal levels
- **Document Types**: Laws, Decrees, Resolutions, Jurisprudence, Doctrine
- **Content**: URNs, dates, authorities, document types, subjects, full-text content

### Data Categories by Modal
- **Geral**: General transportation policy
- **Rodoviário**: Road transportation
- **Aéreo**: Aviation
- **Marítimo**: Maritime transportation

## 🏗️ Architecture

### Phase 1: Data Assessment and Conversion
1. **Data Quality Assessment** (`01_data_assessment_quality.R`)
   - Schema validation and completeness analysis
   - URN format compliance checking
   - Authority-jurisdiction consistency validation
   - Temporal coverage gap identification

2. **CSV to Parquet Conversion** (`02_csv_to_parquet_conversion.R`)
   - Optimal compression with snappy algorithm
   - Partitioning by authority level (Federal/State/Municipal)
   - Data type optimization (dates, factors, UTF-8 text)
   - SQLite alternative for complex joins

3. **Performance Benchmarking** (`03_performance_benchmarking.R`)
   - Read/write performance comparison
   - Memory usage optimization
   - Query performance evaluation

### Phase 2: Analytical Infrastructure
4. **Text Mining Pipeline** (`04_text_mining_pipeline.R`)
   - Portuguese text preprocessing with stopword removal
   - Topic modeling (LDA, STM) with temporal components
   - Sentiment analysis with custom legal terminology
   - Named Entity Recognition for legal entities

5. **Temporal Analysis Framework** (`05_temporal_analysis_framework.R`)
   - Topic evolution over time using dynamic modeling
   - Policy wave detection with change point analysis
   - Legislative timeline visualizations
   - Survival analysis for policy lifespan
   - Forecasting using fable/tsibble

6. **Network Analysis Tools** (`06_network_analysis_tools.R`)
   - Citation/amendment relationship parsing
   - Network graph construction with multiple relationship types
   - Centrality measures (degree, betweenness, PageRank)
   - Community detection for policy clustering

7. **Geospatial Analytics** (`07_geospatial_analytics.R`)
   - Brazilian boundary mapping with geobr integration
   - Regulatory density choropleth visualizations
   - Federal vs State vs Municipal policy adoption analysis
   - Spatial diffusion analysis with Moran's I

### Phase 3: Quality Control and Validation
8. **Data Integrity Validation** (`08_data_integrity_validation.R`)
   - URN format compliance validation
   - Cross-reference metadata consistency
   - Orphaned record identification
   - Automated data lineage tracking
   - Analytical method validation

9. **Master Execution Script** (`09_master_execution_script.R`)
   - Orchestrates complete analytical pipeline
   - Generates comprehensive executive summary
   - Provides modular execution options

## 🚀 Quick Start

### Prerequisites

```r
# Install required packages
required_packages <- c(
  # Data manipulation
  "dplyr", "stringr", "lubridate", "purrr", "tibble",
  
  # Data I/O
  "arrow", "data.table", "readr", "DBI", "RSQLite",
  
  # Text mining
  "tm", "quanteda", "tidytext", "topicmodels", "stm", 
  "sentimentr", "udpipe", "spacyr",
  
  # Temporal analysis
  "tsibble", "fable", "fabletools", "feasts", "survival",
  "changepoint", "bcp", "forecast", "prophet",
  
  # Network analysis
  "igraph", "tidygraph", "ggraph", "networkD3", "visNetwork",
  
  # Geospatial analysis
  "sf", "leaflet", "tmap", "geobr", "spdep", "mapview",
  
  # Visualization
  "ggplot2", "plotly", "viridis", "RColorBrewer", "wordcloud",
  
  # Quality control
  "testthat", "validate", "checkmate", "VIM", "janitor",
  
  # Utilities
  "logger", "tictoc", "glue", "here", "digest"
)

install.packages(required_packages)
```

### Basic Usage

```r
# 1. Set working directory to the framework location
setwd("/path/to/R_analytical_framework")

# 2. Run complete pipeline
source("09_master_execution_script.R")
results <- main_pipeline_execution()

# 3. Or run individual components
source("01_data_assessment_quality.R")
quality_results <- main_quality_assessment("/path/to/csv/files", "output_dir")
```

### Advanced Usage

```r
# Custom configuration
config <- setup_pipeline_config("/custom/base/directory")

# Run specific phases
source("04_text_mining_pipeline.R")
text_results <- run_text_mining_pipeline("data.parquet", "output_dir")

# Load existing results
all_results <- readRDS("analytical_results/complete_pipeline_results.rds")
```

## 📈 Key Features

### Text Mining
- **Preprocessing**: Portuguese-specific cleaning, stemming, stopword removal
- **Topic Modeling**: Both static (LDA) and dynamic (STM) approaches
- **Sentiment Analysis**: Custom legal terminology dictionaries
- **NER**: Legal entity extraction (agencies, laws, authorities)

### Temporal Analysis
- **Evolution Tracking**: Topic trends over decades
- **Change Point Detection**: Policy wave identification
- **Survival Analysis**: Policy lifespan studies
- **Forecasting**: Future legislative activity prediction

### Network Analysis
- **Relationship Types**: Citations, amendments, subjects, authority, temporal
- **Centrality Measures**: Identifies foundational laws and key documents
- **Community Detection**: Policy clustering and thematic groupings
- **Interactive Visualization**: Web-based network exploration

### Geospatial Analytics
- **Jurisdiction Mapping**: Federal, state, and municipal policy distribution
- **Density Analysis**: Regulatory intensity by geographic region
- **Diffusion Studies**: Policy adoption patterns across jurisdictions
- **Spatial Autocorrelation**: Geographic clustering of regulatory activity

## 📊 Performance Metrics

### Compression and Speed
- **Size Reduction**: 60-80% compression ratio (CSV → Parquet)
- **Read Speed**: 3-5x faster data loading
- **Query Performance**: Optimized for analytical workloads
- **Memory Efficiency**: Reduced RAM usage for large datasets

### Data Quality
- **URN Compliance**: Automated format validation
- **Completeness**: Field-by-field analysis
- **Consistency**: Cross-reference validation
- **Integrity Score**: Overall data quality metrics

## 📁 Output Structure

```
analytical_results/
├── master_summary/
│   ├── executive_summary.txt
│   ├── pipeline_dashboard.csv
│   └── pipeline_completion_status.png
├── quality_reports/
│   ├── missing_data_analysis.csv
│   ├── temporal_coverage.png
│   └── completeness_by_field.png
├── parquet_dataset/
│   ├── combined_legislative_dataset.parquet
│   ├── partitioned_dataset/
│   └── legislative_dataset.sqlite
├── text_mining_results/
│   ├── sentiment_analysis_results.parquet
│   ├── lda_topics.png
│   └── wordcloud_top_terms.png
├── temporal_analysis_results/
│   ├── legislative_activity_timeline.png
│   ├── policy_waves_detection.png
│   └── activity_forecasts.png
├── network_analysis_results/
│   ├── network_by_category.png
│   ├── centrality_ranking.png
│   └── interactive_network.html
├── geospatial_analysis_results/
│   ├── regulatory_density_map.png
│   ├── interactive_density_map.html
│   └── policy_diffusion_heatmap.png
└── integrity_validation_results/
    ├── data_integrity_metrics.png
    ├── problematic_urns.csv
    └── integrity_summary.txt
```

## 🔧 Technical Specifications

### Data Formats
- **Input**: CSV files with Brazilian legislative metadata
- **Output**: Parquet (primary), SQLite (secondary), RDS (R objects)
- **Compression**: Snappy algorithm for optimal balance
- **Partitioning**: By authority level for efficient querying

### Memory Management
- **Streaming Processing**: Large files processed in chunks
- **Lazy Evaluation**: Arrow/dplyr integration for efficiency
- **Garbage Collection**: Automatic memory cleanup
- **Scalability**: Designed for datasets up to millions of records

### Reproducibility
- **Seed Setting**: Consistent results across runs
- **Version Control**: Package version logging
- **Environment**: renv compatibility for dependency management
- **Documentation**: Comprehensive function documentation

## 🧪 Testing and Validation

### Automated Tests
```r
# Run built-in validation tests
source("08_data_integrity_validation.R")
validation_results <- run_integrity_validation("data.parquet", "output_dir")
```

### Quality Checks
- **Data Integrity**: URN format, metadata consistency
- **Analytical Validation**: Topic model stability, sentiment accuracy
- **Performance Testing**: Benchmarking across data formats
- **Reproducibility**: Cross-platform compatibility testing

## 📚 Sample Analyses

### Topic Evolution Example
```r
# Analyze transportation policy evolution
source("05_temporal_analysis_framework.R")
temporal_results <- run_temporal_analysis("dataset.parquet", "output_dir")

# Extract topic trends
topic_evolution <- temporal_results$topic_evolution$topic_time_series
```

### Network Centrality Example
```r
# Find most influential documents
source("06_network_analysis_tools.R")
network_results <- run_network_analysis("dataset.parquet", "output_dir")

# Top 10 most central documents
top_documents <- network_results$centrality_data %>%
  arrange(desc(centrality_composite)) %>%
  slice_head(n = 10)
```

### Geospatial Analysis Example
```r
# Map regulatory density by state
source("07_geospatial_analytics.R")
geo_results <- run_geospatial_analysis("dataset.parquet", "output_dir")

# View interactive map
file.show("output_dir/interactive_density_map.html")
```

## 🤝 Contributing

### Code Style
- Follow tidyverse conventions
- Use roxygen2 for documentation
- Include unit tests for core functions
- Maintain modular architecture

### Testing
```r
# Run tests
library(testthat)
test_dir("tests/")
```

### Issues and Enhancements
- Report bugs via GitHub issues
- Suggest features with use case descriptions
- Submit pull requests with comprehensive tests

## 📜 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📧 Contact

For questions, support, or collaboration opportunities:

- **Project Lead**: Brazilian Legislative Analytics Framework Team
- **Email**: [Contact information]
- **Documentation**: [Additional documentation links]

## 🙏 Acknowledgments

- **LexML Portal**: For providing comprehensive Brazilian legislative data
- **geobr Package**: For Brazilian geographic boundaries
- **R Community**: For excellent analytical packages
- **Academic Partners**: For domain expertise and validation

## 📖 Citation

If you use this framework in your research, please cite:

```
Brazilian Legislative Analytics Framework (2025). 
A Comprehensive R Framework for Brazilian Legislative Data Analysis.
Version 1.0.0. [URL]
```

---

**Note**: This framework is designed for academic and research purposes. Ensure compliance with data usage policies and terms of service when working with legislative data.