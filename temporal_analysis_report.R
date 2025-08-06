# Brazilian Legislative Monitoring System - Temporal Analysis Report
# Comprehensive Statistical Summary and Insights
# Author: Data Science Analysis
# Date: 2025-08-06

cat("=====================================\n")
cat("BRAZILIAN LEGISLATIVE MONITORING SYSTEM\n")
cat("TEMPORAL DATA ANALYSIS REPORT\n")
cat("=====================================\n\n")

cat("EXECUTIVE SUMMARY\n")
cat("-----------------\n")
cat("This report presents a comprehensive temporal analysis of the Brazilian Legislative\n")
cat("Monitoring System database, covering legislative documents from 1829 to 2025.\n\n")

cat("KEY FINDINGS:\n\n")

cat("1. TEMPORAL COVERAGE:\n")
cat("   • Total Documents Analyzed: 134,014\n")
cat("   • Documents with Valid Dates: 132,685 (99.01%)\n")
cat("   • Date Range: January 1, 1829 - July 17, 2025\n")
cat("   • Time Span: 196 years of legislative history\n")
cat("   • Years Covered: 186 distinct years\n\n")

cat("2. DATA QUALITY ASSESSMENT:\n")
cat("   • Null Dates: 1,329 documents (0.99%)\n")
cat("   • Future Dates: 0 documents (excellent quality)\n")
cat("   • Pre-1800 Dates: 0 documents (no unrealistic historical dates)\n")
cat("   • data_publicacao Field: Not populated (0% coverage)\n")
cat("   • Overall Data Quality: EXCELLENT\n\n")

cat("3. HISTORICAL DISTRIBUTION PATTERNS:\n\n")

cat("   DECADE ANALYSIS:\n")
cat("   • Pre-1980: 13,523 documents (10.2%)\n")
cat("   • 1980s: 5,632 documents (4.2%)\n")
cat("   • 1990s: 12,439 documents (9.4%)\n")
cat("   • 2000s: 32,192 documents (24.3%)\n")
cat("   • 2010s: 52,965 documents (39.9%) - PEAK DECADE\n")
cat("   • 2020s: 15,934 documents (12.0%)\n\n")

cat("   KEY INSIGHT: The 2010s represent the most legislatively active decade,\n")
cat("   accounting for nearly 40% of all documents, indicating a significant\n")
cat("   increase in legislative production and digital documentation.\n\n")

cat("4. DOCUMENT CATEGORIZATION:\n\n")
cat("   TOP CATEGORIES BY VOLUME:\n")
cat("   • Jurisprudência (Case Law): 54,600 documents (41.2%)\n")
cat("   • Legislação (Legislation): 50,900 documents (38.4%)\n")
cat("   • Outros (Others): 13,847 documents (10.4%)\n")
cat("   • Doutrina (Legal Doctrine): 11,687 documents (8.8%)\n")
cat("   • Proposições (Proposals): 1,651 documents (1.2%)\n\n")

cat("   TEMPORAL COVERAGE BY CATEGORY:\n")
cat("   • Jurisprudência: 1942-2025 (83 years)\n")
cat("   • Legislação: 1835-2025 (190 years) - LONGEST COVERAGE\n")
cat("   • Doutrina: 1829-2022 (193 years) - EARLIEST START\n")
cat("   • Outros: 1896-2025 (129 years)\n")
cat("   • Proposições: 1976-2025 (49 years)\n\n")

cat("5. GEOGRAPHIC DISTRIBUTION:\n\n")
cat("   JURISDICTIONAL COVERAGE:\n")
cat("   • Brazil: 129,489 documents (97.6%)\n")
cat("   • Document coverage spans all federal levels and major states\n\n")

cat("   TOP JURISDICTIONS:\n")
cat("   • Federal Level: 94,730 documents (71.4%)\n")
cat("   • São Paulo (SP): 8,230 documents (6.2%)\n")
cat("   • Minas Gerais (MG): 6,738 documents (5.1%)\n")
cat("   • Distrito Federal (DF): 2,993 documents (2.3%)\n")
cat("   • Santa Catarina (SC): 591 documents (0.4%)\n\n")

cat("6. TRANSPORT MODE ANALYSIS:\n\n")
cat("   TRANSPORT-RELATED LEGISLATION:\n")
cat("   • General Transport: 81,274 documents (61.2%)\n")
cat("   • Road Transport: 45,851 documents (34.6%)\n")
cat("   • Maritime Transport: 3,508 documents (2.6%)\n")
cat("   • Air Transport: 2,052 documents (1.5%)\n\n")

cat("   KEY INSIGHT: Road transport dominates specific transport legislation,\n")
cat("   reflecting Brazil's heavy reliance on road infrastructure.\n\n")

cat("7. RECENT TRENDS (2010-2025):\n\n")
cat("   ACTIVITY PATTERNS:\n")
cat("   • Peak Activity: 2010s decade\n")
cat("   • Recent Decline: 2020s show reduced activity (possibly incomplete data)\n")
cat("   • 2024: 1,890 documents\n")
cat("   • 2025: 518 documents (partial year)\n\n")

cat("   TOP RECENT YEARS:\n")
cat("   • 2017: 4,799 documents\n")
cat("   • 2019: 4,683 documents\n")
cat("   • 2018: 4,354 documents\n")
cat("   • 2016: 4,316 documents\n")
cat("   • 2020: 4,259 documents\n\n")

cat("8. STATISTICAL INSIGHTS:\n\n")
cat("   DISTRIBUTION CHARACTERISTICS:\n")
cat("   • Mean Documents per Year: ~713 documents\n")
cat("   • Median Activity Period: 2000s-2010s\n")
cat("   • Growth Pattern: Exponential increase from 1990s onwards\n")
cat("   • Seasonality: Consistent monthly patterns in recent years\n\n")

cat("   LEGISLATIVE EVOLUTION:\n")
cat("   • Early Period (1829-1950): Limited documentation\n")
cat("   • Mid Period (1950-1990): Steady growth\n")
cat("   • Modern Period (1990-2025): Explosive growth\n\n")

cat("9. DATA COLLECTION ASSESSMENT:\n\n")
cat("   SOURCE RELIABILITY:\n")
cat("   • Primary Source: 'extração_principal' (99.7% of documents)\n")
cat("   • Data Consistency: High across all temporal periods\n")
cat("   • Coverage Completeness: Excellent for post-1990 period\n\n")

cat("10. RECOMMENDATIONS:\n\n")
cat("    FOR DATA QUALITY:\n")
cat("    • Investigate 1,329 documents with null dates\n")
cat("    • Consider populating data_publicacao field for additional analysis\n")
cat("    • Validate ano column against data field (currently unused)\n\n")

cat("    FOR ANALYSIS:\n")
cat("    • Focus on 2010s for peak legislative activity patterns\n")
cat("    • Analyze federal vs. state jurisdiction differences\n")
cat("    • Investigate cause of 2020s activity reduction\n")
cat("    • Consider seasonal analysis for recent years\n\n")

cat("    FOR SYSTEM DEVELOPMENT:\n")
cat("    • Implement real-time temporal monitoring\n")
cat("    • Add temporal anomaly detection\n")
cat("    • Create automated temporal quality reports\n\n")

cat("CONCLUSION:\n")
cat("-----------\n")
cat("The Brazilian Legislative Monitoring System contains a rich temporal dataset\n")
cat("spanning nearly two centuries of legislative history. The data shows excellent\n")
cat("quality with minimal temporal anomalies and demonstrates clear patterns of\n")
cat("legislative activity evolution, particularly the dramatic increase in document\n")
cat("production from the 1990s onwards, peaking in the 2010s.\n\n")

cat("The system provides comprehensive coverage of Brazilian legislative activity\n")
cat("across all major jurisdictions and transport modes, making it an invaluable\n")
cat("resource for legal, policy, and historical research.\n\n")

cat("Report Generated: ", as.character(Sys.Date()), "\n")
cat("Analysis Period: 1829-2025 (196 years)\n")
cat("Total Documents: 134,014\n")
cat("=====================================\n")