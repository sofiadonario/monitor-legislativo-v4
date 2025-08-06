# Municipality Data Analysis Report
## Brazilian Legislative Monitoring System Database

**Analysis Date:** August 6, 2025  
**Database:** PostgreSQL (railway)  
**Total Documents Analyzed:** 134,014

---

## Executive Summary

The municipality data analysis reveals **critical gaps** in geographic coverage within the Brazilian Legislative Monitoring System database. Only **2.23%** of documents contain municipality information, representing a significant opportunity for data enhancement and improved legislative analysis capabilities.

### Key Findings:
- **Municipality Coverage:** 2.23% (2,994 of 134,014 documents)
- **Estado Coverage:** 84.98% (113,887 documents) 
- **Jurisdiction Coverage:** 88.74% (118,920 documents)
- **Localidade Coverage:** 0.00% (0 documents)
- **Unique Municipalities:** 1 (Brasília only)

---

## Detailed Analysis Results

### 1. Municipality Data Coverage

**Critical Issue Identified:** All municipality data is concentrated in a single location - Brasília (DF). This represents a severe limitation in geographic diversity and coverage.

| Municipality | Documents | Percentage | Date Range |
|--------------|-----------|------------|------------|
| Brasília | 2,994 | 100% | 1960-2023 |

### 2. Data Quality Assessment

The municipality field shows good data quality where it exists:
- **No empty strings** or whitespace-only entries
- **No abnormally short or long entries**
- **Consistent naming** (all entries are "Brasília")
- **97.77% NULL values** indicate missing data rather than poor quality

### 3. Geographic Distribution Analysis

**Estado (State) Level Distribution:**
- Federal documents: 94,730 (83.18% of state-level data)
- São Paulo (SP): 8,234 documents
- Minas Gerais (MG): 6,739 documents  
- Distrito Federal (DF): 2,994 documents (100% have municipality data)
- Other states: 27 additional states with varying document counts

**Jurisdiction Distribution:**
- Federal: 95,127 documents (79.99%)
- Municipal: 10,548 documents (8.87%)
- State: 10,289 documents (8.65%)
- Distrital: 2,956 documents (2.49% - all have municipality data)

### 4. Document Type Analysis

**By Category (categoria_original):**
- Legislação: 51,086 documents (5.80% have municipality data)
- Jurisprudência: 54,617 documents (0.00% have municipality data)
- Doutrina: 12,809 documents (0.23% have municipality data)
- Outros: 13,850 documents (0.01% have municipality data)

**By Transport Mode (modal_original):**
- Geral: 82,296 documents (2.89% have municipality data)
- Rodoviário: 46,074 documents (1.28% have municipality data)
- Aéreo: 2,074 documents (1.06% have municipality data)
- Marítimo: 3,569 documents (0.14% have municipality data)

### 5. Temporal Analysis

**Historical Coverage Patterns:**
- Municipality data exists from 1960 to 2023
- **Peak coverage periods:** 1992 (7.81%), 1991 (6.37%), 1994 (5.57%)
- **Recent trends:** Coverage has declined in recent years (2023: 0.38%, 2024-2025: 0%)
- **Average coverage:** Approximately 2-4% in most years with data

---

## Priority Areas for Enhancement

### High-Priority States (No Municipality Data)
1. **Federal Level:** 94,730 documents (massive enhancement opportunity)
2. **São Paulo (SP):** 8,234 documents (largest state by document count)
3. **Minas Gerais (MG):** 6,739 documents (second largest state)
4. **Santa Catarina (SC):** 591 documents
5. **Amazonas (AM):** 170 documents

### Document Categories with Enhancement Potential
1. **Jurisprudência:** 54,617 documents (0% coverage)
2. **Legislação:** 51,086 documents (5.80% coverage - improvement possible)
3. **Outros:** 13,850 documents (near 0% coverage)

---

## Actionable Recommendations

### Immediate Actions (Priority 1)

#### 1. **Data Enrichment Strategy**
- **Target:** Federal documents (94,730 documents with 83.18% of all state data)
- **Method:** Implement automated geographic inference using existing fields
- **Timeline:** 30-60 days for implementation

#### 2. **Geographic Inference Implementation**
```sql
-- Example query to identify enhancement opportunities
SELECT estado, jurisdicao_original, COUNT(*) as potential_documents
FROM documents 
WHERE municipio IS NULL 
  AND (estado IS NOT NULL OR jurisdicao_original = 'Municipal')
GROUP BY estado, jurisdicao_original
ORDER BY potential_documents DESC;
```

### Medium-Term Strategies (Priority 2)

#### 1. **Text Mining and NLP Enhancement**
- **Extract municipalities from:**
  - Document titles (`titulo` field)
  - Document abstracts (`ementa` field) 
  - Subject keywords (`assuntos` field)
- **Implementation:** Use Brazilian municipality name databases for validation
- **Expected Impact:** 15-25% coverage improvement

#### 2. **Authority-Based Geographic Inference**
- **Method:** Map issuing authorities (`autoridade` field) to their locations
- **Target:** Municipal and State jurisdiction documents
- **Validation:** Cross-reference with official government entity databases

### Long-Term Solutions (Priority 3)

#### 1. **External Database Integration**
- **IBGE Integration:** Brazilian Institute of Geography and Statistics
- **Municipal Code Standardization:** Implement official 7-digit IBGE codes
- **Validation Rules:** Automated geographic consistency checks

#### 2. **Data Collection Process Enhancement**
- **Source Enhancement:** Improve metadata capture during document ingestion
- **Quality Controls:** Implement mandatory geographic fields for new documents
- **Retroactive Processing:** Systematic review of historical documents

### Technical Implementation Plan

#### Phase 1: Quick Wins (Weeks 1-4)
```r
# R script framework for immediate enhancements
enhance_municipality_data <- function() {
  # 1. Estado-to-Municipality mapping for DF documents
  # 2. Authority-based location inference
  # 3. Jurisdiction-based geographic assignment
}
```

#### Phase 2: Advanced Processing (Weeks 5-12)
- NLP implementation for text extraction
- Machine learning models for geographic prediction
- Batch processing of historical documents

#### Phase 3: System Integration (Weeks 13-16)
- Database schema updates
- Real-time enhancement workflows
- Quality monitoring dashboards

---

## Expected Outcomes

### Short-term (3 months):
- **Municipality coverage:** 2.23% → 15-20%
- **Geographic diversity:** 1 → 50-100 municipalities
- **Enhanced documents:** ~15,000-20,000 additional records

### Medium-term (6 months):
- **Municipality coverage:** 25-35%
- **Geographic diversity:** 200+ municipalities
- **Complete state coverage:** All 27 Brazilian states represented

### Long-term (12 months):
- **Municipality coverage:** 50-70%
- **Geographic diversity:** 500+ municipalities
- **Data quality:** Standardized IBGE codes implementation

---

## Risk Assessment and Mitigation

### Risks:
1. **Data Quality Concerns:** Automated inference may introduce errors
2. **Processing Complexity:** Large-scale text processing requirements
3. **Resource Intensive:** Significant computational and storage needs

### Mitigation Strategies:
1. **Validation Framework:** Multi-source verification of inferred locations
2. **Phased Implementation:** Gradual rollout with quality monitoring
3. **Human Review:** Sample validation of automated enhancements

---

## Conclusion

The municipality data analysis reveals both significant challenges and tremendous opportunities. With only 2.23% coverage and data limited to Brasília, there is substantial room for improvement. The strong coverage in related fields (estado: 84.98%, jurisdiction: 88.74%) provides an excellent foundation for enhancement strategies.

**Immediate action is recommended** to implement geographic inference techniques, which could rapidly improve coverage to 15-20% within 3 months. Long-term strategies involving NLP and external database integration could achieve 50-70% coverage within one year.

The investment in municipality data enhancement will dramatically improve the system's analytical capabilities, enabling more sophisticated geographic analysis of Brazilian legislative documents and supporting better policy research and decision-making.

---

**Files Generated:**
- `/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/municipality_analysis.R`
- `/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/municipality_report.R`
- `/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/municipality_visualizations.R`
- Visualization files (.png) in the project directory