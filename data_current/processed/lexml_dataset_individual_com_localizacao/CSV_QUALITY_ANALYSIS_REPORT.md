# CSV Data Quality Analysis Report

**Date:** 2025-07-26  
**Directory:** `/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao/`

## Executive Summary

Analyzed 21 CSV files containing Brazilian legislative data with a total of 286,901 records. All files exhibit significant data quality issues that require attention before reliable data processing.

### Critical Issues Found:
1. **100% of files have critical data quality problems**
2. **Severe missing data** - Multiple columns are completely empty across all files
3. **Delimiter inconsistencies** - Variable comma counts suggesting malformed CSV structure
4. **Embedded newlines** - 71% of files contain newlines within data fields
5. **Quote handling issues** - 76% of files have potential quote mismatch problems
6. **Encoding issues** - Filenames show UTF-8 encoding problems

## Detailed Findings

### 1. File Overview

| Category | Modal | Row Count | File Size Category |
|----------|-------|-----------|-------------------|
| Dataset (complete) | - | 134,014 | Large |
| Doutrina | Aéreo | 238 | Small |
| Doutrina | Geral | 10,124 | Medium |
| Doutrina | Marítimo | 602 | Small |
| Doutrina | Rodoviário | 1,846 | Small |
| Jurisprudência | Aéreo | 1,032 | Small |
| Jurisprudência | Geral | 26,981 | Large |
| Jurisprudência | Marítimo | 810 | Small |
| Jurisprudência | Rodoviário | 25,794 | Large |
| Legislação | Aéreo | 544 | Small |
| Legislação | Geral | 37,218 | Large |
| Legislação | Marítimo | 1,618 | Small |
| Legislação | Rodoviário | 11,706 | Medium |
| Outros | Aéreo | 246 | Small |
| Outros | Geral | 7,097 | Medium |
| Outros | Marítimo | 526 | Small |
| Outros | Rodoviário | 5,981 | Medium |
| Proposições | Aéreo | 14 | Tiny |
| Proposições | Geral | 877 | Small |
| Proposições | Marítimo | 13 | Tiny |
| Proposições | Rodoviário | 747 | Small |

### 2. Critical Data Quality Issues

#### 2.1 Missing Data (Severity: CRITICAL)

**Completely Empty Columns (100% missing) across all files:**
- `autor` - Author information completely missing
- `classificacao` - Classification data absent
- `autoridade` - Authority information missing
- `url` - No URL data
- `localidade` - Location data missing
- `numero` - Number field empty
- `ano` - Year information missing

**High Missing Value Rates (>50%):**
- `tipo` (type): 94-100% missing in most files
- `assuntos` (subjects): 50-100% missing
- `municipio` (municipality): 93-100% missing
- `ementa` (summary): 57-63% missing in Doutrina files

#### 2.2 Structural Issues (Severity: HIGH)

**Delimiter Inconsistencies:**
- All files show variable comma counts per row
- Maximum variation: 0-200 commas per row
- Indicates potential issues with:
  - Unescaped commas in data fields
  - Improper quote handling
  - Malformed CSV structure

**Embedded Newlines:**
- Found in 15 out of 21 files (71%)
- Most affected columns:
  - `assuntos`: Up to 2,389 rows with embedded newlines
  - `ementa`: Up to 4,661 rows with embedded newlines
- Can cause parsing errors and data misalignment

#### 2.3 Encoding Issues (Severity: MODERATE)

**Filename Encoding Problems:**
- Characters corrupted in filenames:
  - ├® instead of é
  - ├¬ instead of ê
  - ├º instead of ç
  - ├í instead of á
  - ├ú instead of ã
  - ├Á instead of õ

**File Content Encoding:**
- All files detected as UTF-8
- However, filename corruption suggests potential encoding mismatches

#### 2.4 Quote Handling (Severity: MODERATE)

- 16 out of 21 files (76%) show potential quote mismatch issues
- Unmatched quotes can cause:
  - Field spillover
  - Row misalignment
  - Parser errors

### 3. Data Integrity Concerns

1. **Inconsistent Schema**: While all files have 23 columns, the data population varies drastically
2. **Data Type Inconsistencies**: Date fields may have format variations
3. **Potential Data Loss**: Empty columns suggest data collection or processing issues
4. **Cross-file Inconsistencies**: Same categories have different data completeness levels

### 4. Recommendations

#### Immediate Actions Required:

1. **Fix Delimiter Issues**
   - Properly escape or quote fields containing commas
   - Ensure consistent field counts across all rows
   - Use a robust CSV library that handles edge cases

2. **Handle Missing Data**
   - Investigate why critical columns are empty
   - Decide on imputation strategy or accept data limitations
   - Document which analyses are possible with missing data

3. **Address Embedded Newlines**
   - Clean newlines from within fields
   - Ensure proper quote encapsulation for multi-line fields
   - Consider using a different delimiter if commas are problematic

4. **Resolve Encoding Issues**
   - Standardize encoding across all files
   - Fix filename encoding problems
   - Ensure consistent UTF-8 handling throughout pipeline

5. **Implement Data Validation**
   - Add schema validation before processing
   - Create data quality metrics and monitoring
   - Implement automated testing for CSV integrity

#### Long-term Improvements:

1. Consider using a more robust data format (Parquet, JSON) for complex hierarchical data
2. Implement data quality checks at the source/collection point
3. Create comprehensive documentation of expected vs actual data schemas
4. Develop automated data cleaning pipelines

### 5. File-Specific Issues Summary

**Most Problematic Files:**
1. `lexml_outros_rodoviário` - 245,549 rows with extensive embedded newlines
2. `lexml_dataset_limpo_classificado` - Largest file with multiple structural issues
3. All `proposições` files - Nearly all data missing except basic fields

**Least Problematic Files:**
1. Small `proposições` files - Fewer structural issues due to minimal data
2. `doutrina` files - More consistent structure despite missing fields

## Conclusion

The CSV files contain valuable Brazilian legislative data but require significant cleaning and preprocessing before use. The primary concerns are:

1. **Data Completeness**: With 7-10 columns completely empty, the dataset's utility is limited
2. **Structural Integrity**: Delimiter and quote issues pose risks for data corruption during processing
3. **Scalability**: Larger files exhibit more severe issues, suggesting processing challenges at scale

**Recommendation**: Implement a comprehensive data cleaning pipeline addressing all identified issues before using these files for analysis or application development. Consider reaching out to the data source to understand why certain fields are systematically empty.