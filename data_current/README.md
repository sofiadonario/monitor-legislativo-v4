# Monitor Legislativo v4 - Data Directory Structure

**Last Updated:** 2025-10-21
**Data Version:** Production (Cleaned & Verified)

## 📊 Overview

This directory contains the complete Brazilian legislative monitoring dataset (1829-2025) with 134,015 deduplicated records from federal, state, and municipal levels.

## 🎯 Source of Truth

**Primary Dataset:** `processed/production/lexml_unified_dataset.csv`
- **Records:** 134,015 (deduplicated from 786,833 raw records)
- **Date Range:** 1829-2025
- **Coverage:** Federal, State (all 27 UFs), Municipal (5,570+ municipalities)
- **Categories:** Transportation, mobility, infrastructure, sustainability
- **Verification Status:** ✅ Verified 2025-10-21

### Quick Stats
- **São Paulo (SP):** 8,234 documents
- **Minas Gerais (MG):** 6,739 documents
- **Deduplication Rate:** 83% (652,818 duplicates removed)

## 📁 Directory Structure

```
data_current/
├── raw/                                    # Raw scraped data (786k records)
│   ├── lexml_*.csv                        # Original LexML extracts
│   └── ...                                # 21 source CSV files
│
├── processed/
│   ├── production/                        # ⭐ ACTIVE PRODUCTION DATA
│   │   ├── lexml_unified_dataset.csv      # 134k records (SOURCE OF TRUTH)
│   │   └── parquet/                       # Optimized format (64% compression)
│   │       └── brazilian_legislative_complete.parquet
│   │
│   ├── intermediate/                      # Processing artifacts
│   │   ├── 01_quality_metrics/            # Data quality assessments
│   │   ├── 02_analytics_output/           # Temporary analytics
│   │   └── 03_deduplication/              # Deduplication logs
│   │
│   ├── geospatial_analysis_results/       # 80 KB - Geographic analysis
│   ├── transport_decarbonization_research/ # 80 KB - Transport policy research
│   ├── temporal_analysis_results/          # 136 KB - Time series analysis
│   ├── text_mining_results/                # 4.8 MB - NLP outputs
│   ├── citation_network_results/           # 16 MB - Citation networks
│   ├── analytical_results/                 # Summary statistics
│   ├── reproducibility_package/            # Research reproducibility metadata
│   │
│   └── legacy_versions_20251021.tar.gz    # 459 MB - Archived old versions
│
└── README.md                              # This file
```

## 🔄 Data Processing Pipeline

1. **Collection** → Raw LexML scrapes (786k records)
2. **Quality Assessment** → `R/analysis/01_data_assessment_quality.R`
3. **Parquet Conversion** → `R/analysis/02_csv_to_parquet_conversion.R`
4. **Deduplication** → Automated URN-based deduplication (83% reduction)
5. **Production Export** → Final 134k dataset
6. **Analytics Generation** → Specialized analysis scripts (04-08)
7. **Database Population** → `R/database/setup/populate_full_database.R`

## 📋 Data Schema (30 fields)

### Core Fields
- `titulo`, `tipo`, `data`, `urn` - Document identification
- `autor`, `assuntos`, `ementa` - Content metadata
- `pais`, `estado`, `municipio` - Geographic hierarchy
- `categoria`, `modal` - Transportation classification

### System Fields
- `_source_file` - Original collection source
- `_extracted_category` - ML-extracted category
- `_deduplication_source` - Deduplication metadata
- `_original_count` - Pre-deduplication count

## 🗄️ Database Mapping

The production CSV is loaded into PostgreSQL with the following structure:

```sql
-- Main documents table (134,015 records)
CREATE TABLE documents (
    id SERIAL PRIMARY KEY,
    titulo TEXT,
    tipo VARCHAR(50),
    data DATE,
    urn TEXT UNIQUE,
    categoria VARCHAR(100),
    modal VARCHAR(50),
    estado VARCHAR(2),
    municipio VARCHAR(100),
    ...
);

-- Indexes for performance
CREATE INDEX idx_documents_date ON documents(data);
CREATE INDEX idx_documents_estado ON documents(estado);
CREATE INDEX idx_documents_categoria ON documents(categoria);
```

## 📊 Analytics Outputs

### Geospatial Analysis (`geospatial_analysis_results/`)
- State-level document distribution
- Capital vs. interior analysis
- Regional policy diffusion patterns
- Municipal innovation profiles

### Transport Research (`transport_decarbonization_research/`)
- Technology diffusion timelines (electric, hydrogen, biofuels)
- Policy instrument evolution
- Climate milestone analysis
- Urban-rural mobility patterns

### Temporal Analysis (`temporal_analysis_results/`)
- Time series decomposition
- Decade-level policy trends
- Legislative activity patterns
- Historical policy evolution

### Text Mining (`text_mining_results/`)
- Topic modeling outputs
- Keyword extraction results
- Document similarity matrices
- Thematic clustering

### Citation Networks (`citation_network_results/`)
- Inter-document citation graphs
- Policy influence networks
- Authority reference patterns

## 🔧 Usage Examples

### R - Load Production Data
```r
# CSV (simple)
library(readr)
df <- read_csv("processed/production/lexml_unified_dataset.csv")

# Parquet (optimized)
library(arrow)
df <- read_parquet("processed/production/parquet/brazilian_legislative_complete.parquet")
```

### Python - Load Production Data
```python
# CSV
import pandas as pd
df = pd.read_csv("processed/production/lexml_unified_dataset.csv")

# Parquet
df = pd.read_parquet("processed/production/parquet/brazilian_legislative_complete.parquet")
```

### PostgreSQL - Query via Database
```r
library(DBI)
library(RPostgres)

con <- dbConnect(RPostgres::Postgres(), dbname = "monitor_legislativo")
df <- dbGetQuery(con, "SELECT * FROM documents WHERE estado = 'SP' LIMIT 100")
```

## 📦 Archive Information

**Legacy Versions Archive:** `legacy_versions_20251021.tar.gz` (459 MB compressed)

Contains:
- Previous dataset versions (pre-deduplication)
- Old enhanced formats
- Historical production snapshots
- Intermediate processing outputs

**To extract:**
```bash
tar -xzf legacy_versions_20251021.tar.gz -C ./archive_restored/
```

## 🧹 Cleanup History

**2025-10-21:**
- ✅ Removed duplicate `analytics/` subdirectory (21 MB, 111 files)
- ✅ Compressed legacy versions: 1.3 GB → 459 MB (65% reduction)
- ✅ Total space saved: 871 MB
- ✅ Verified all analytics match 134k source dataset

## 🔍 Data Quality Verification

Run verification checks:
```r
source("R/analysis/01_data_assessment_quality.R")
verify_dataset_integrity("processed/production/lexml_unified_dataset.csv")
```

Expected output:
- ✅ 134,015 total records
- ✅ 0 duplicated URNs
- ✅ 100% valid dates
- ✅ 27 unique states (all Brazilian UFs)
- ✅ Geographic coverage: Federal + State + Municipal

## 📚 Related Documentation

- Pipeline documentation: `/R/analysis/README.md`
- Database schema: `/R/database/setup/schema.sql`
- Analysis scripts: `/R/analysis/04_*.R` through `08_*.R`
- API documentation: `/docs/api.md`

## 🔗 Cloud Deployment

**Production Database:** Google Cloud SQL PostgreSQL
**Region:** southamerica-east1 (São Paulo)
**Application:** Google Cloud Run
**URL:** https://mackmonitor-667999538255.southamerica-east1.run.app

---

**Maintained by:** MackIntegridade Research Team
**Institution:** Universidade Presbiteriana Mackenzie
**Contact:** sofia.donario@mackenzie.br
**License:** Academic Research Use
