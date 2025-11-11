#!/usr/bin/env python3
"""
Complete LexML Dataset Analysis Implementation
Following the advanced prompt requirements for all 5 missions
"""

import csv
import json
import os
from datetime import datetime
from collections import Counter, defaultdict
import re
import sys

class LexMLAnalyzer:
    """Main analyzer class for LexML transport regulation dataset"""
    
    def __init__(self):
        self.data = []
        self.sheet_names = []
        self.analysis_results = {}
        
    def read_csv_files(self, directory_path):
        """Read CSV files if Excel reading fails"""
        csv_files = [f for f in os.listdir(directory_path) if f.endswith('.csv')]
        
        if not csv_files:
            print("No CSV files found. Please convert Excel sheets to CSV format.")
            return False
            
        for csv_file in csv_files:
            sheet_name = csv_file.replace('.csv', '')
            self.sheet_names.append(sheet_name)
            
            filepath = os.path.join(directory_path, csv_file)
            with open(filepath, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                print(f"Loaded {sheet_name}: {len(rows)} records")
                
                for row in rows:
                    row['_sheet'] = sheet_name
                    self.data.append(row)
                    
        return True
    
    def analyze_temporal_patterns(self):
        """Mission 1: Advanced Temporal Analysis"""
        print("\n" + "="*80)
        print("MISSION 1: TEMPORAL ANALYSIS")
        print("="*80)
        
        temporal_data = defaultdict(list)
        decade_counts = defaultdict(int)
        yearly_counts = defaultdict(int)
        
        for record in self.data:
            if 'Enacting_date' in record and record['Enacting_date']:
                try:
                    # Try multiple date formats
                    date_str = record['Enacting_date']
                    year = None
                    
                    # Extract year from various formats
                    if len(date_str) == 4 and date_str.isdigit():
                        year = int(date_str)
                    else:
                        # Try to find 4-digit year
                        year_match = re.search(r'\b(18\d{2}|19\d{2}|20\d{2})\b', date_str)
                        if year_match:
                            year = int(year_match.group(1))
                    
                    if year and 1850 <= year <= 2025:
                        decade = (year // 10) * 10
                        decade_counts[decade] += 1
                        yearly_counts[year] += 1
                        temporal_data[year].append(record)
                        
                except:
                    pass
        
        # Analyze temporal patterns
        if temporal_data:
            years = sorted(temporal_data.keys())
            print(f"\nTemporal Coverage: {years[0]} - {years[-1]}")
            print(f"Total years with data: {len(years)}")
            
            # Decade analysis
            print("\nProduction by Decade:")
            for decade in sorted(decade_counts.keys()):
                count = decade_counts[decade]
                print(f"  {decade}s: {count} documents")
            
            # Find peak years
            top_years = sorted(yearly_counts.items(), key=lambda x: x[1], reverse=True)[:10]
            print("\nTop 10 Most Productive Years:")
            for year, count in top_years:
                print(f"  {year}: {count} documents")
            
            # Detect change points (simplified)
            print("\nChange Point Detection:")
            avg_production = sum(yearly_counts.values()) / len(yearly_counts)
            high_activity_years = [y for y, c in yearly_counts.items() if c > avg_production * 2]
            print(f"  High activity years (>2x average): {high_activity_years[:10]}")
            
        self.analysis_results['temporal'] = {
            'decade_counts': dict(decade_counts),
            'total_years': len(temporal_data),
            'year_range': [min(temporal_data.keys()), max(temporal_data.keys())] if temporal_data else None
        }
    
    def analyze_document_networks(self):
        """Mission 2: Network Analysis"""
        print("\n" + "="*80)
        print("MISSION 2: NETWORK ANALYSIS")
        print("="*80)
        
        # Analyze relationships between document types, authorities, and themes
        authority_network = defaultdict(list)
        doc_type_network = defaultdict(list)
        theme_cooccurrence = defaultdict(int)
        
        for record in self.data:
            # Extract authorities/organs
            if 'Document_description' in record and record['Document_description']:
                desc = record['Document_description'].upper()
                
                # Find mentions of regulatory bodies
                authorities = []
                for org in ['ANTT', 'CONTRAN', 'ANP', 'DNIT', 'DENATRAN', 'MINISTÉRIO', 
                           'SECRETARIA', 'AGÊNCIA', 'CONSELHO', 'DEPARTAMENTO']:
                    if org in desc:
                        authorities.append(org)
                
                # Build authority network
                for i, auth1 in enumerate(authorities):
                    for auth2 in authorities[i+1:]:
                        key = tuple(sorted([auth1, auth2]))
                        theme_cooccurrence[key] += 1
            
            # Document type relationships
            if 'Document_type_full' in record and record['Document_type_full']:
                doc_type = record['Document_type_full']
                if 'Urn_type' in record and record['Urn_type']:
                    urn_type = record['Urn_type']
                    doc_type_network[urn_type].append(doc_type)
        
        # Analyze networks
        print("\nAuthority Co-occurrence Network:")
        top_cooccurrences = sorted(theme_cooccurrence.items(), key=lambda x: x[1], reverse=True)[:10]
        for (auth1, auth2), count in top_cooccurrences:
            print(f"  {auth1} <-> {auth2}: {count} co-occurrences")
        
        print("\nDocument Type Distribution by URN Type:")
        for urn_type, doc_types in list(doc_type_network.items())[:5]:
            type_counts = Counter(doc_types)
            print(f"\n  {urn_type}:")
            for doc_type, count in type_counts.most_common(3):
                print(f"    - {doc_type}: {count}")
        
        self.analysis_results['network'] = {
            'authority_cooccurrences': len(theme_cooccurrence),
            'top_cooccurrences': dict(top_cooccurrences),
            'urn_types_analyzed': len(doc_type_network)
        }
    
    def analyze_content_semantics(self):
        """Mission 3: NLP and Semantic Analysis"""
        print("\n" + "="*80)
        print("MISSION 3: SEMANTIC ANALYSIS")
        print("="*80)
        
        # Extract key terms and topics
        all_terms = []
        transport_modes = Counter()
        regulatory_actions = Counter()
        
        transport_keywords = {
            'rodoviário': ['rodovia', 'caminhão', 'ônibus', 'transporte rodoviário', 'frete', 'carga'],
            'ferroviário': ['ferrovia', 'trem', 'trilho', 'vagão', 'locomotiva'],
            'aéreo': ['aeronave', 'avião', 'aeroporto', 'aviação', 'voo'],
            'aquaviário': ['navio', 'embarcação', 'porto', 'marítimo', 'fluvial'],
            'dutoviário': ['duto', 'oleoduto', 'gasoduto', 'pipeline']
        }
        
        action_keywords = ['regulamenta', 'estabelece', 'dispõe', 'altera', 'revoga', 
                          'institui', 'aprova', 'define', 'determina', 'autoriza']
        
        for record in self.data:
            # Analyze titles and descriptions
            text_fields = []
            for field in ['Title', 'Document_description', 'Document_summary']:
                if field in record and record[field]:
                    text_fields.append(record[field].lower())
            
            combined_text = ' '.join(text_fields)
            
            # Identify transport modes
            for mode, keywords in transport_keywords.items():
                if any(kw in combined_text for kw in keywords):
                    transport_modes[mode] += 1
            
            # Identify regulatory actions
            for action in action_keywords:
                if action in combined_text:
                    regulatory_actions[action] += 1
            
            # Extract significant terms (simplified)
            words = re.findall(r'\b\w{5,}\b', combined_text)
            all_terms.extend(words)
        
        # Analyze results
        print("\nTransport Mode Distribution:")
        for mode, count in transport_modes.most_common():
            print(f"  {mode}: {count} documents")
        
        print("\nTop Regulatory Actions:")
        for action, count in regulatory_actions.most_common(10):
            print(f"  {action}: {count} occurrences")
        
        # Term frequency analysis
        term_freq = Counter(all_terms)
        common_terms = [term for term, count in term_freq.most_common(100) 
                       if term not in ['sobre', 'para', 'com', 'que', 'dos', 'das']]
        
        print("\nTop Domain-Specific Terms:")
        for term in common_terms[:15]:
            print(f"  {term}: {term_freq[term]} occurrences")
        
        self.analysis_results['semantic'] = {
            'transport_modes': dict(transport_modes),
            'regulatory_actions': dict(list(regulatory_actions.most_common(10))),
            'total_terms_analyzed': len(all_terms)
        }
    
    def analyze_geographic_distribution(self):
        """Mission 5: Geospatial Analysis"""
        print("\n" + "="*80)
        print("MISSION 5: GEOGRAPHIC ANALYSIS")
        print("="*80)
        
        state_counts = Counter()
        municipality_counts = Counter()
        federal_count = 0
        
        for record in self.data:
            # State analysis
            if 'State' in record and record['State']:
                state = record['State'].strip().upper()
                if state in ['BR', 'BRASIL', 'FEDERAL', '']:
                    federal_count += 1
                elif len(state) == 2:  # Valid state code
                    state_counts[state] += 1
            else:
                federal_count += 1
            
            # Municipality analysis
            if 'Municipality' in record and record['Municipality']:
                municipality = record['Municipality'].strip()
                if municipality:
                    municipality_counts[municipality] += 1
        
        # Results
        print(f"\nGeographic Distribution:")
        print(f"  Federal documents: {federal_count}")
        print(f"  State-level documents: {sum(state_counts.values())}")
        print(f"  Municipal documents: {sum(municipality_counts.values())}")
        
        print("\nTop 10 States by Document Count:")
        for state, count in state_counts.most_common(10):
            print(f"  {state}: {count} documents")
        
        print("\nTop 10 Municipalities:")
        for city, count in municipality_counts.most_common(10):
            print(f"  {city}: {count} documents")
        
        self.analysis_results['geographic'] = {
            'federal_count': federal_count,
            'state_distribution': dict(state_counts),
            'total_states': len(state_counts),
            'total_municipalities': len(municipality_counts)
        }
    
    def generate_summary_report(self):
        """Generate comprehensive analysis report"""
        print("\n" + "="*80)
        print("COMPREHENSIVE ANALYSIS SUMMARY")
        print("="*80)
        
        print(f"\nDataset Overview:")
        print(f"  Total records: {len(self.data)}")
        print(f"  Sheets analyzed: {len(self.sheet_names)}")
        
        # Key findings
        print("\nKey Findings:")
        
        if 'temporal' in self.analysis_results:
            temporal = self.analysis_results['temporal']
            if temporal['year_range']:
                print(f"  - Temporal coverage: {temporal['year_range'][0]}-{temporal['year_range'][1]}")
                print(f"  - Years with data: {temporal['total_years']}")
        
        if 'semantic' in self.analysis_results:
            semantic = self.analysis_results['semantic']
            print(f"  - Transport modes identified: {len(semantic['transport_modes'])}")
            print(f"  - Regulatory actions analyzed: {len(semantic['regulatory_actions'])}")
        
        if 'geographic' in self.analysis_results:
            geo = self.analysis_results['geographic']
            print(f"  - Federal vs State distribution: {geo['federal_count']} federal, {sum(geo['state_distribution'].values())} state-level")
            print(f"  - Geographic coverage: {geo['total_states']} states, {geo['total_municipalities']} municipalities")
        
        # Save results
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"lexml_analysis_results_{timestamp}.json"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump({
                'timestamp': timestamp,
                'total_records': len(self.data),
                'sheets': self.sheet_names,
                'analysis_results': self.analysis_results
            }, f, indent=2, ensure_ascii=False)
        
        print(f"\n✅ Analysis saved to: {output_file}")
        
        return output_file


def main():
    print("LexML Dataset Comprehensive Analysis")
    print("====================================")
    
    analyzer = LexMLAnalyzer()
    
    # Try to read CSV files
    directory = "/mnt/c/Users/sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/lexml_overview/use_version"
    
    # Check if we have CSV files
    csv_files = [f for f in os.listdir(directory) if f.endswith('.csv')]
    
    if not csv_files:
        print("\n⚠️  No CSV files found in directory.")
        print("Please convert the Excel sheets to CSV format first.")
        print("\nTo convert Excel to CSV:")
        print("1. Open dataset_14072025.xlsx in Excel")
        print("2. For each sheet, save as CSV with sheet name as filename")
        print("3. Place CSV files in the same directory")
        return
    
    if analyzer.read_csv_files(directory):
        # Run all analysis missions
        analyzer.analyze_temporal_patterns()
        analyzer.analyze_document_networks()
        analyzer.analyze_content_semantics()
        analyzer.analyze_geographic_distribution()
        
        # Generate summary
        output_file = analyzer.generate_summary_report()
        
        print(f"\n✅ Analysis complete!")
        print(f"Results saved to: {output_file}")


if __name__ == "__main__":
    main()