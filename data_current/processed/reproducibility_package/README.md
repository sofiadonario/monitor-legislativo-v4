
# Brazilian Legislative Analytics - Academic Research Package

## Overview
Comprehensive analytical framework for studying Brazilian legislative documents with focus on temporal evolution, geographic policy diffusion, and transport decarbonization themes.

## Dataset Summary
- **Records**: 134,014 legislative documents
- **Temporal Coverage**: 1942-2025 (84 years)
- **Geographic Scope**: 26 Brazilian states + Federal District
- **Transport Focus**: 2,037 transport-related documents
- **Data Quality**: 77.7% average completeness

## Key Research Findings

### Temporal Evolution
- **Exponential growth** post-1988 Constitution (116,142 documents in current era)
- **Peak decade**: 2010s with 53,488 documents
- **Digital transformation**: Massive increase in 2000s-2010s
- **Constitutional era distinctions**: Clear policy evolution patterns

### Geographic Distribution
- **São Paulo leads** with 8,234 documents (43% of geographic data)
- **Regional hierarchy**: Sudeste (78.5%), Centro-Oeste (16%), Sul (3.2%)
- **Innovation patterns**: Urban centers drive policy development
- **Policy diffusion**: Clear center-periphery adoption patterns

### Transport Themes
- **2,037 transport documents** across 6 themes
- **Carbon/Environment dominance**: 1,117 documents (55%)
- **Temporal span**: 1942-2022 (80-year evolution)
- **Policy shift**: Infrastructure → Environmental focus over time

### Text Mining Results
- **179,273 unique words** from Portuguese legal text
- **Domain classification**: 7 categories with transport specialization
- **Most frequent**: 'direito' (84,515 occurrences)
- **Legal entity extraction**: 13 regulatory agencies identified

### Citation Networks
- **65,313 documents** with valid URNs
- **21,745 legal cross-references** across 6 document types
- **Authority patterns**: State-level leads citation activity
- **Network density**: Rich legal interconnectedness

## Repository Structure
```
brazilian-legislative-analytics/
├── data/
│   ├── raw/                          # Original CSV files
│   ├── production_parquet/           # Optimized Parquet datasets
│   ├── text_mining_results/          # NLP analysis outputs
│   ├── temporal_analysis_results/    # Time series analysis
│   ├── geospatial_analysis_results/  # Geographic analysis
│   └── citation_network_results/     # Network analysis
├── code/
│   ├── production_parquet_converter.R
│   ├── advanced_text_mining.R
│   ├── temporal_evolution_analysis.R
│   ├── geospatial_policy_analysis.R
│   ├── citation_network_analysis.R
│   └── interactive_dashboard.R
├── docs/
│   ├── methodology_documentation.md
│   ├── reproducibility_checklist.csv
│   └── environment_snapshot.md
└── dashboard/
    ├── launch_dashboard.R
    └── analysis_summary.html
```

## Quick Start

### Prerequisites
- R 4.0+ with packages: data.table, arrow, stringr
- 8GB+ RAM (16GB recommended)
- 1GB disk space for outputs

### Basic Usage
```r
# 1. Load the framework
source('production_parquet_converter.R')
source('advanced_text_mining.R')
source('temporal_evolution_analysis.R')

# 2. Run analysis pipeline (or use pre-processed data)
# See methodology_documentation.md for full workflow

# 3. Launch interactive dashboard
source('interactive_dashboard.R')
```

### Using Pre-processed Data
If using the provided Parquet files, you can skip data processing and go directly to analysis:
```r
library(arrow)
library(data.table)

# Load main dataset
dt <- as.data.table(read_parquet('production_parquet/single_file/brazilian_legislative_complete.parquet'))

# Explore the data
dim(dt)  # 134,014 x 23
summary(dt)
```

## Research Applications

### Policy Evolution Studies
- Track legislative development across constitutional eras
- Analyze policy innovation and adoption patterns
- Compare federal vs state policy dynamics

### Geographic Analysis
- Model policy diffusion across Brazilian states
- Identify innovation centers and adoption patterns
- Study regional specialization in policy domains

### Transport Decarbonization Research
- Analyze green transport policy development timeline
- Track electrification and alternative fuel policies
- Study authority-level transport policy focus

### Text Mining Applications
- Portuguese legal domain terminology analysis
- Policy language evolution over time
- Cross-reference and citation pattern analysis

## Data Quality and Limitations

### Strengths
- **Comprehensive coverage**: 84 years of legislative history
- **Multi-dimensional analysis**: Temporal, geographic, thematic
- **High-quality processing**: Extensive cleaning and validation
- **Reproducible workflow**: Fully documented methodology

### Limitations
- **Digital bias**: Recent documents over-represented
- **Language specificity**: Portuguese legal terminology
- **Geographic resolution**: Limited municipal-level data
- **Citation completeness**: URN citations underutilized

## Citation

### APA Format
Brazilian Legislative Analytics Team. (2025). Comprehensive Analysis of Brazilian Legislative Dataset: Temporal Evolution, Geographic Diffusion, and Transport Policy Innovation (1942-2025) (Version 2.0.0) [Data set and code]. 10.xxxx/brazilian-legislative-analytics-2025

### BibTeX
```
@dataset{brazilian_legislative_2025,
  title = {Comprehensive Analysis of Brazilian Legislative Dataset: Temporal Evolution, Geographic Diffusion, and Transport Policy Innovation (1942-2025)},
  author = {Brazilian Legislative Analytics Team},
  year = {2025},
  version = {2.0.0},
  doi = {10.xxxx/brazilian-legislative-analytics-2025},
  url = {https://github.com/your-repo/brazilian-legislative-analytics},
  note = {Comprehensive analysis of Brazilian legislative documents with temporal, geographic, and thematic analysis}
}
```

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Contact
For questions, issues, or collaboration inquiries:
- Email: researcher@institution.edu
- Repository: https://github.com/your-repo/brazilian-legislative-analytics
- DOI: 10.xxxx/brazilian-legislative-analytics-2025

## Acknowledgments
- LexML Portal for providing access to Brazilian legislative data
- Brazilian government institutions for data transparency
- Open source R community for analytical tools

---
**Version**: 2.0.0  
**Last Updated**: 2025-07-26  
**Status**: Research Complete - Ready for Academic Use

