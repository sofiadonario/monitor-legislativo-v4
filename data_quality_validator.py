#!/usr/bin/env python3
"""
Data Quality Validation Framework for Monitor Legislativo v4
Comprehensive validation and quality assurance for enhanced Brazilian legislative data

Focus: Validate and ensure >90% data completeness with high accuracy
"""

import pandas as pd
import numpy as np
import re
import json
import logging
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime, timedelta
from collections import Counter, defaultdict
import warnings
warnings.filterwarnings('ignore')

# Statistical analysis
from scipy import stats
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data_quality_validation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class DataQualityValidator:
    """Comprehensive validation framework for enhanced legislative data"""
    
    def __init__(self, data_path: str, reference_data_path: Optional[str] = None):
        """Initialize validator with data and optional reference"""
        self.data_path = data_path
        self.reference_data_path = reference_data_path
        
        # Load main dataset
        logger.info(f"Loading dataset from {data_path}")
        self.df = pd.read_csv(data_path, low_memory=False)
        logger.info(f"Loaded {len(self.df):,} documents for validation")
        
        # Load reference data if available
        self.reference_df = None
        if reference_data_path:
            try:
                self.reference_df = pd.read_csv(reference_data_path, low_memory=False)
                logger.info(f"Loaded {len(self.reference_df):,} reference documents")
            except Exception as e:
                logger.warning(f"Could not load reference data: {e}")
        
        # Initialize validation rules
        self.setup_validation_rules()
        
        # Results storage
        self.validation_results = {}
    
    def setup_validation_rules(self):
        """Setup comprehensive validation rules for Brazilian legal data"""
        
        # Brazilian states validation
        self.valid_states = {
            'AC', 'AL', 'AP', 'AM', 'BA', 'CE', 'DF', 'ES', 'GO', 'MA', 'MT', 'MS',
            'MG', 'PA', 'PB', 'PR', 'PE', 'PI', 'RJ', 'RN', 'RS', 'RO', 'RR', 'SC',
            'SP', 'SE', 'TO', 'Federal'
        }
        
        # Valid document categories
        self.valid_categories = {
            'Legislação', 'Jurisprudência', 'Doutrina', 'Proposições', 'Outros'
        }
        
        # Valid modal types
        self.valid_modals = {
            'geral', 'rodoviário', 'aéreo', 'marítimo', 'ferroviário'
        }
        
        # Valid jurisdictions
        self.valid_jurisdictions = {
            'Federal', 'Estadual', 'Municipal'
        }
        
        # Date validation ranges
        self.min_date = datetime(1500, 1, 1)  # Early colonial period
        self.max_date = datetime.now() + timedelta(days=365)  # Allow future dates
        
        # URN pattern for Brazilian legal documents
        self.urn_pattern = re.compile(
            r'^urn:lex:br:(federal|[a-z]{2}):([a-z\.\-]+):(\d{4}-\d{2}-\d{2})(;\d+)?$',
            re.IGNORECASE
        )
        
        # Author name patterns (person vs institution)
        self.person_name_pattern = re.compile(
            r'^[A-ZÀÁÂÃÄÇÈÉÊËÌÍÎÏÑÒÓÔÕÖÙÚÛÜÝ][a-zA-ZÀ-ÿ\s\-\'\.]+$'
        )
        
        # Institutional author patterns
        self.institutional_patterns = [
            r'ANTT|ANTAQ|ANAC|ANP|ANEEL',
            r'Ministério',
            r'Tribunal',
            r'Câmara|Senado',
            r'Presidência da República'
        ]

class CompletenessValidator:
    """Validate data completeness and coverage"""
    
    def __init__(self, validator: DataQualityValidator):
        self.validator = validator
        self.df = validator.df
        
    def validate_completeness(self) -> Dict[str, any]:
        """Comprehensive completeness validation"""
        logger.info("Validating data completeness...")
        
        results = {
            'field_completeness': {},
            'overall_completeness': 0.0,
            'critical_fields_completeness': 0.0,
            'completeness_by_category': {},
            'completeness_trends': {},
            'quality_score': 0.0
        }
        
        # 1. Field-level completeness
        results['field_completeness'] = self.calculate_field_completeness()
        
        # 2. Overall completeness score
        results['overall_completeness'] = self.calculate_overall_completeness()
        
        # 3. Critical fields completeness
        results['critical_fields_completeness'] = self.calculate_critical_completeness()
        
        # 4. Completeness by category
        results['completeness_by_category'] = self.analyze_completeness_by_category()
        
        # 5. Temporal completeness trends
        results['completeness_trends'] = self.analyze_completeness_trends()
        
        # 6. Quality score
        results['quality_score'] = self.calculate_quality_score(results)
        
        return results
    
    def calculate_field_completeness(self) -> Dict[str, Dict[str, float]]:
        """Calculate completeness for each field"""
        completeness = {}
        
        for column in self.df.columns:
            total = len(self.df)
            
            # Count non-null values
            non_null = self.df[column].notna().sum()
            
            # Count non-empty strings
            if self.df[column].dtype == 'object':
                non_empty = ((self.df[column].notna()) & (self.df[column] != '')).sum()
                meaningful = ((self.df[column].notna()) & 
                            (self.df[column] != '') & 
                            (self.df[column].str.len() > 2)).sum()
            else:
                non_empty = non_null
                meaningful = non_null
            
            completeness[column] = {
                'total_records': total,
                'non_null': non_null,
                'non_empty': non_empty,
                'meaningful': meaningful,
                'completeness_pct': (meaningful / total) * 100,
                'null_pct': ((total - non_null) / total) * 100,
                'empty_pct': ((total - non_empty) / total) * 100
            }
        
        return completeness
    
    def calculate_overall_completeness(self) -> float:
        """Calculate overall data completeness score"""
        # Weight critical fields more heavily
        field_weights = {
            'titulo': 1.0,
            'tipo': 0.9,
            'data': 1.0,
            'estado': 0.8,
            'municipio': 0.7,
            'autor': 0.8,
            'classificacao': 0.8,
            'ementa': 0.7,
            'urn': 0.9,
            'jurisdicao': 0.6
        }
        
        weighted_completeness = 0.0
        total_weight = 0.0
        
        for field, weight in field_weights.items():
            if field in self.df.columns:
                # Calculate meaningful completeness
                total = len(self.df)
                if self.df[field].dtype == 'object':
                    meaningful = ((self.df[field].notna()) & 
                                (self.df[field] != '') & 
                                (self.df[field].str.len() > 2)).sum()
                else:
                    meaningful = self.df[field].notna().sum()
                
                completeness = (meaningful / total) * 100
                weighted_completeness += completeness * weight
                total_weight += weight
        
        return weighted_completeness / total_weight if total_weight > 0 else 0.0
    
    def calculate_critical_completeness(self) -> float:
        """Calculate completeness for critical fields only"""
        critical_fields = ['titulo', 'data', 'autor', 'classificacao', 'estado', 'urn']
        
        completeness_scores = []
        
        for field in critical_fields:
            if field in self.df.columns:
                total = len(self.df)
                if self.df[field].dtype == 'object':
                    meaningful = ((self.df[field].notna()) & 
                                (self.df[field] != '') & 
                                (self.df[field].str.len() > 2)).sum()
                else:
                    meaningful = self.df[field].notna().sum()
                
                completeness = (meaningful / total) * 100
                completeness_scores.append(completeness)
        
        return np.mean(completeness_scores) if completeness_scores else 0.0
    
    def analyze_completeness_by_category(self) -> Dict[str, Dict[str, float]]:
        """Analyze completeness by document category"""
        if 'categoria' not in self.df.columns:
            return {}
        
        results = {}
        
        for category in self.df['categoria'].unique():
            if pd.notna(category):
                category_df = self.df[self.df['categoria'] == category]
                category_completeness = {}
                
                # Calculate completeness for key fields in this category
                key_fields = ['autor', 'classificacao', 'estado', 'municipio', 'urn', 'ementa']
                
                for field in key_fields:
                    if field in self.df.columns:
                        total = len(category_df)
                        if category_df[field].dtype == 'object':
                            meaningful = ((category_df[field].notna()) & 
                                        (category_df[field] != '') & 
                                        (category_df[field].str.len() > 2)).sum()
                        else:
                            meaningful = category_df[field].notna().sum()
                        
                        category_completeness[field] = (meaningful / total) * 100 if total > 0 else 0.0
                
                results[category] = category_completeness
        
        return results
    
    def analyze_completeness_trends(self) -> Dict[str, any]:
        """Analyze completeness trends over time"""
        if 'data' not in self.df.columns:
            return {}
        
        # Convert dates and extract years
        try:
            self.df['year'] = pd.to_datetime(self.df['data'], errors='coerce').dt.year
        except:
            return {}
        
        # Group by decades
        self.df['decade'] = (self.df['year'] // 10) * 10
        
        trends = {}
        key_fields = ['autor', 'classificacao', 'municipio', 'urn']
        
        for decade in sorted(self.df['decade'].dropna().unique()):
            decade_df = self.df[self.df['decade'] == decade]
            decade_completeness = {}
            
            for field in key_fields:
                if field in self.df.columns:
                    total = len(decade_df)
                    if decade_df[field].dtype == 'object':
                        meaningful = ((decade_df[field].notna()) & 
                                    (decade_df[field] != '') & 
                                    (decade_df[field].str.len() > 2)).sum()
                    else:
                        meaningful = decade_df[field].notna().sum()
                    
                    decade_completeness[field] = (meaningful / total) * 100 if total > 0 else 0.0
            
            trends[f"{int(decade)}s"] = decade_completeness
        
        return trends
    
    def calculate_quality_score(self, results: Dict) -> float:
        """Calculate overall quality score based on multiple factors"""
        
        # Base score from overall completeness
        base_score = results['overall_completeness']
        
        # Bonus for achieving targets
        target_bonus = 0
        if results['overall_completeness'] >= 90:
            target_bonus = 10
        elif results['overall_completeness'] >= 85:
            target_bonus = 5
        
        # Critical fields bonus
        critical_bonus = 0
        if results['critical_fields_completeness'] >= 90:
            critical_bonus = 5
        elif results['critical_fields_completeness'] >= 80:
            critical_bonus = 2
        
        # Category balance bonus (check if all categories have reasonable completeness)
        balance_bonus = 0
        if results['completeness_by_category']:
            category_scores = []
            for category_data in results['completeness_by_category'].values():
                if category_data:
                    avg_completeness = np.mean(list(category_data.values()))
                    category_scores.append(avg_completeness)
            
            if category_scores and min(category_scores) >= 70:
                balance_bonus = 3
        
        total_score = min(100, base_score + target_bonus + critical_bonus + balance_bonus)
        return total_score


class AccuracyValidator:
    """Validate accuracy of enhanced data"""
    
    def __init__(self, validator: DataQualityValidator):
        self.validator = validator
        self.df = validator.df
        
    def validate_accuracy(self) -> Dict[str, any]:
        """Comprehensive accuracy validation"""
        logger.info("Validating data accuracy...")
        
        results = {
            'field_accuracy': {},
            'consistency_checks': {},
            'format_validation': {},
            'business_rules_validation': {},
            'cross_field_validation': {},
            'accuracy_score': 0.0
        }
        
        # 1. Field-level accuracy validation
        results['field_accuracy'] = self.validate_field_accuracy()
        
        # 2. Consistency checks
        results['consistency_checks'] = self.validate_consistency()
        
        # 3. Format validation
        results['format_validation'] = self.validate_formats()
        
        # 4. Business rules validation
        results['business_rules_validation'] = self.validate_business_rules()
        
        # 5. Cross-field validation
        results['cross_field_validation'] = self.validate_cross_fields()
        
        # 6. Overall accuracy score
        results['accuracy_score'] = self.calculate_accuracy_score(results)
        
        return results
    
    def validate_field_accuracy(self) -> Dict[str, Dict[str, any]]:
        """Validate accuracy of individual fields"""
        accuracy_results = {}
        
        # State validation
        if 'estado' in self.df.columns:
            accuracy_results['estado'] = self.validate_states()
        
        # Date validation
        if 'data' in self.df.columns:
            accuracy_results['data'] = self.validate_dates()
        
        # URN validation
        if 'urn' in self.df.columns:
            accuracy_results['urn'] = self.validate_urns()
        
        # Author validation
        if 'autor' in self.df.columns:
            accuracy_results['autor'] = self.validate_authors()
        
        # Category validation
        if 'categoria' in self.df.columns:
            accuracy_results['categoria'] = self.validate_categories()
        
        return accuracy_results
    
    def validate_states(self) -> Dict[str, any]:
        """Validate state field accuracy"""
        estado_series = self.df['estado'].dropna()
        
        valid_count = 0
        invalid_states = []
        
        for estado in estado_series:
            if estado in self.validator.valid_states:
                valid_count += 1
            else:
                invalid_states.append(estado)
        
        accuracy = (valid_count / len(estado_series)) * 100 if len(estado_series) > 0 else 0
        
        return {
            'total_records': len(estado_series),
            'valid_count': valid_count,
            'invalid_count': len(invalid_states),
            'accuracy_pct': accuracy,
            'invalid_values': list(set(invalid_states))[:10],  # Sample of invalid values
            'valid': accuracy >= 95
        }
    
    def validate_dates(self) -> Dict[str, any]:
        """Validate date field accuracy"""
        date_series = self.df['data'].dropna()
        
        valid_count = 0
        invalid_dates = []
        out_of_range_dates = []
        
        for date_str in date_series:
            try:
                # Try to parse the date
                if isinstance(date_str, str):
                    parsed_date = pd.to_datetime(date_str, errors='raise')
                else:
                    parsed_date = pd.to_datetime(date_str)
                
                # Check if date is in reasonable range
                if self.validator.min_date <= parsed_date <= self.validator.max_date:
                    valid_count += 1
                else:
                    out_of_range_dates.append(date_str)
                    
            except:
                invalid_dates.append(date_str)
        
        accuracy = (valid_count / len(date_series)) * 100 if len(date_series) > 0 else 0
        
        return {
            'total_records': len(date_series),
            'valid_count': valid_count,
            'invalid_format_count': len(invalid_dates),
            'out_of_range_count': len(out_of_range_dates),
            'accuracy_pct': accuracy,
            'invalid_formats': list(set(invalid_dates))[:5],
            'out_of_range': list(set(out_of_range_dates))[:5],
            'valid': accuracy >= 90
        }
    
    def validate_urns(self) -> Dict[str, any]:
        """Validate URN field accuracy"""
        urn_series = self.df['urn'].dropna()
        
        valid_count = 0
        invalid_urns = []
        
        for urn in urn_series:
            if self.validator.urn_pattern.match(str(urn)):
                valid_count += 1
            else:
                invalid_urns.append(urn)
        
        accuracy = (valid_count / len(urn_series)) * 100 if len(urn_series) > 0 else 0
        
        return {
            'total_records': len(urn_series),
            'valid_count': valid_count,
            'invalid_count': len(invalid_urns),
            'accuracy_pct': accuracy,
            'invalid_urns': list(set([str(u) for u in invalid_urns]))[:10],
            'valid': accuracy >= 98
        }
    
    def validate_authors(self) -> Dict[str, any]:
        """Validate author field accuracy"""
        author_series = self.df['autor'].dropna()
        
        person_names = 0
        institutions = 0
        invalid_authors = []
        
        for author in author_series:
            author_str = str(author).strip()
            
            # Check if it looks like a person name
            if self.validator.person_name_pattern.match(author_str) and len(author_str.split()) >= 2:
                person_names += 1
            # Check if it's an institution
            elif any(re.search(pattern, author_str, re.IGNORECASE) 
                    for pattern in self.validator.institutional_patterns):
                institutions += 1
            # Check if it's too short or doesn't look like a name
            elif len(author_str) < 3 or author_str.lower() in ['autor', 'autoria', 'n/a', 'na']:
                invalid_authors.append(author_str)
            else:
                # Could be valid but unusual format
                pass
        
        valid_count = person_names + institutions
        accuracy = (valid_count / len(author_series)) * 100 if len(author_series) > 0 else 0
        
        return {
            'total_records': len(author_series),
            'person_names': person_names,
            'institutions': institutions,
            'invalid_count': len(invalid_authors),
            'accuracy_pct': accuracy,
            'invalid_authors': list(set(invalid_authors))[:10],
            'valid': accuracy >= 85
        }
    
    def validate_categories(self) -> Dict[str, any]:
        """Validate category field accuracy"""
        category_series = self.df['categoria'].dropna()
        
        valid_count = 0
        invalid_categories = []
        
        for category in category_series:
            if category in self.validator.valid_categories:
                valid_count += 1
            else:
                invalid_categories.append(category)
        
        accuracy = (valid_count / len(category_series)) * 100 if len(category_series) > 0 else 0
        
        return {
            'total_records': len(category_series),
            'valid_count': valid_count,
            'invalid_count': len(invalid_categories),
            'accuracy_pct': accuracy,
            'invalid_categories': list(set(invalid_categories)),
            'valid': accuracy >= 95
        }
    
    def validate_consistency(self) -> Dict[str, any]:
        """Validate internal consistency of data"""
        consistency_results = {}
        
        # Check state-jurisdiction consistency
        if 'estado' in self.df.columns and 'jurisdicao' in self.df.columns:
            consistency_results['estado_jurisdicao'] = self.check_state_jurisdiction_consistency()
        
        # Check category-type consistency
        if 'categoria' in self.df.columns and 'tipo' in self.df.columns:
            consistency_results['categoria_tipo'] = self.check_category_type_consistency()
        
        # Check date-URN consistency
        if 'data' in self.df.columns and 'urn' in self.df.columns:
            consistency_results['data_urn'] = self.check_date_urn_consistency()
        
        return consistency_results
    
    def check_state_jurisdiction_consistency(self) -> Dict[str, any]:
        """Check consistency between state and jurisdiction fields"""
        df_subset = self.df[['estado', 'jurisdicao']].dropna()
        
        inconsistent_count = 0
        inconsistent_records = []
        
        for _, row in df_subset.iterrows():
            estado = row['estado']
            jurisdicao = row['jurisdicao']
            
            # Federal documents should have Federal state
            if jurisdicao == 'Federal' and estado != 'Federal':
                inconsistent_count += 1
                inconsistent_records.append({'estado': estado, 'jurisdicao': jurisdicao})
            # State documents should not have Federal state
            elif jurisdicao == 'Estadual' and estado == 'Federal':
                inconsistent_count += 1
                inconsistent_records.append({'estado': estado, 'jurisdicao': jurisdicao})
        
        consistency = ((len(df_subset) - inconsistent_count) / len(df_subset)) * 100 if len(df_subset) > 0 else 100
        
        return {
            'total_records': len(df_subset),
            'consistent_count': len(df_subset) - inconsistent_count,
            'inconsistent_count': inconsistent_count,
            'consistency_pct': consistency,
            'inconsistent_samples': inconsistent_records[:5],
            'valid': consistency >= 90
        }
    
    def check_category_type_consistency(self) -> Dict[str, any]:
        """Check consistency between category and document type"""
        df_subset = self.df[['categoria', 'tipo']].dropna()
        
        # Define expected type patterns for each category
        category_type_patterns = {
            'Legislação': ['lei', 'decreto', 'portaria', 'resolução', 'instrução'],
            'Jurisprudência': ['acórdão', 'decisão', 'sentença', 'despacho'],
            'Doutrina': ['livro', 'artigo', 'tese', 'dissertação'],
            'Proposições': ['projeto', 'proposta', 'indicação', 'requerimento']
        }
        
        consistent_count = 0
        inconsistent_records = []
        
        for _, row in df_subset.iterrows():
            categoria = row['categoria']
            tipo = str(row['tipo']).lower()
            
            if categoria in category_type_patterns:
                patterns = category_type_patterns[categoria]
                if any(pattern in tipo for pattern in patterns):
                    consistent_count += 1
                else:
                    inconsistent_records.append({'categoria': categoria, 'tipo': row['tipo']})
            else:
                # Unknown category, can't validate
                consistent_count += 1
        
        consistency = (consistent_count / len(df_subset)) * 100 if len(df_subset) > 0 else 100
        
        return {
            'total_records': len(df_subset),
            'consistent_count': consistent_count,
            'inconsistent_count': len(df_subset) - consistent_count,
            'consistency_pct': consistency,
            'inconsistent_samples': inconsistent_records[:5],
            'valid': consistency >= 80
        }
    
    def check_date_urn_consistency(self) -> Dict[str, any]:
        """Check consistency between date and URN date component"""
        df_subset = self.df[['data', 'urn']].dropna()
        
        consistent_count = 0
        inconsistent_records = []
        
        for _, row in df_subset.iterrows():
            try:
                # Parse document date
                doc_date = pd.to_datetime(row['data'], errors='raise')
                
                # Extract date from URN
                urn_match = self.validator.urn_pattern.match(str(row['urn']))
                if urn_match:
                    urn_date_str = urn_match.group(3)  # Date component
                    urn_date = datetime.strptime(urn_date_str, '%Y-%m-%d')
                    
                    # Check if dates match (allowing for some tolerance)
                    if abs((doc_date - urn_date).days) <= 1:
                        consistent_count += 1
                    else:
                        inconsistent_records.append({
                            'data': row['data'],
                            'urn': row['urn'],
                            'urn_date': urn_date_str
                        })
                else:
                    # Invalid URN format
                    inconsistent_records.append({
                        'data': row['data'],
                        'urn': row['urn'],
                        'error': 'invalid_urn_format'
                    })
                    
            except:
                # Date parsing error
                inconsistent_records.append({
                    'data': row['data'],
                    'urn': row['urn'],
                    'error': 'date_parsing_error'
                })
        
        consistency = (consistent_count / len(df_subset)) * 100 if len(df_subset) > 0 else 100
        
        return {
            'total_records': len(df_subset),
            'consistent_count': consistent_count,
            'inconsistent_count': len(df_subset) - consistent_count,
            'consistency_pct': consistency,
            'inconsistent_samples': inconsistent_records[:5],
            'valid': consistency >= 85
        }
    
    def validate_formats(self) -> Dict[str, any]:
        """Validate data formats"""
        # This is covered in field accuracy validation
        return {
            'date_format_valid': True,
            'urn_format_valid': True,
            'state_format_valid': True
        }
    
    def validate_business_rules(self) -> Dict[str, any]:
        """Validate business rules specific to legal documents"""
        return {
            'federal_documents_no_municipality': self.check_federal_municipality_rule(),
            'jurisprudencia_has_ementa': self.check_jurisprudencia_ementa_rule(),
            'legislation_has_number': self.check_legislation_number_rule()
        }
    
    def check_federal_municipality_rule(self) -> Dict[str, any]:
        """Federal documents should not have municipality information"""
        if 'estado' not in self.df.columns or 'municipio' not in self.df.columns:
            return {'valid': True, 'message': 'Required fields not available'}
        
        federal_with_municipality = self.df[
            (self.df['estado'] == 'Federal') & 
            (self.df['municipio'].notna()) & 
            (self.df['municipio'] != '')
        ]
        
        rule_violations = len(federal_with_municipality)
        total_federal = len(self.df[self.df['estado'] == 'Federal'])
        
        compliance = ((total_federal - rule_violations) / total_federal) * 100 if total_federal > 0 else 100
        
        return {
            'total_federal_docs': total_federal,
            'violations': rule_violations,
            'compliance_pct': compliance,
            'valid': compliance >= 95
        }
    
    def check_jurisprudencia_ementa_rule(self) -> Dict[str, any]:
        """Jurisprudence documents should have ementa (summary)"""
        if 'categoria' not in self.df.columns or 'ementa' not in self.df.columns:
            return {'valid': True, 'message': 'Required fields not available'}
        
        jurisprudencia_docs = self.df[self.df['categoria'] == 'Jurisprudência']
        jurisprudencia_without_ementa = jurisprudencia_docs[
            (jurisprudencia_docs['ementa'].isna()) | 
            (jurisprudencia_docs['ementa'] == '')
        ]
        
        rule_violations = len(jurisprudencia_without_ementa)
        total_jurisprudencia = len(jurisprudencia_docs)
        
        compliance = ((total_jurisprudencia - rule_violations) / total_jurisprudencia) * 100 if total_jurisprudencia > 0 else 100
        
        return {
            'total_jurisprudencia_docs': total_jurisprudencia,
            'violations': rule_violations,
            'compliance_pct': compliance,
            'valid': compliance >= 85
        }
    
    def check_legislation_number_rule(self) -> Dict[str, any]:
        """Legislation documents should have numbers"""
        # This is more complex as number might be embedded in title
        return {'valid': True, 'message': 'Rule validation not implemented'}
    
    def validate_cross_fields(self) -> Dict[str, any]:
        """Validate relationships between fields"""
        # Already covered in consistency checks
        return {'cross_validation_complete': True}
    
    def calculate_accuracy_score(self, results: Dict) -> float:
        """Calculate overall accuracy score"""
        
        scores = []
        
        # Field accuracy scores
        if 'field_accuracy' in results:
            for field_result in results['field_accuracy'].values():
                if 'accuracy_pct' in field_result:
                    scores.append(field_result['accuracy_pct'])
        
        # Consistency scores
        if 'consistency_checks' in results:
            for consistency_result in results['consistency_checks'].values():
                if 'consistency_pct' in consistency_result:
                    scores.append(consistency_result['consistency_pct'])
        
        # Business rules scores
        if 'business_rules_validation' in results:
            for rule_result in results['business_rules_validation'].values():
                if 'compliance_pct' in rule_result:
                    scores.append(rule_result['compliance_pct'])
        
        return np.mean(scores) if scores else 0.0


class ComprehensiveValidator:
    """Main validator that coordinates all validation components"""
    
    def __init__(self, data_path: str, reference_data_path: Optional[str] = None):
        """Initialize comprehensive validator"""
        self.data_quality_validator = DataQualityValidator(data_path, reference_data_path)
        self.completeness_validator = CompletenessValidator(self.data_quality_validator)
        self.accuracy_validator = AccuracyValidator(self.data_quality_validator)
    
    def run_full_validation(self) -> Dict[str, any]:
        """Run complete validation suite"""
        logger.info("Starting comprehensive data validation...")
        
        validation_results = {
            'metadata': {
                'validation_timestamp': datetime.now().isoformat(),
                'total_documents': len(self.data_quality_validator.df),
                'data_path': self.data_quality_validator.data_path,
                'reference_path': self.data_quality_validator.reference_data_path
            },
            'completeness_validation': {},
            'accuracy_validation': {},
            'overall_assessment': {}
        }
        
        # Run completeness validation
        try:
            validation_results['completeness_validation'] = self.completeness_validator.validate_completeness()
            logger.info("Completeness validation completed")
        except Exception as e:
            logger.error(f"Completeness validation failed: {e}")
            validation_results['completeness_validation'] = {'error': str(e)}
        
        # Run accuracy validation
        try:
            validation_results['accuracy_validation'] = self.accuracy_validator.validate_accuracy()
            logger.info("Accuracy validation completed")
        except Exception as e:
            logger.error(f"Accuracy validation failed: {e}")
            validation_results['accuracy_validation'] = {'error': str(e)}
        
        # Generate overall assessment
        validation_results['overall_assessment'] = self.generate_overall_assessment(validation_results)
        
        return validation_results
    
    def generate_overall_assessment(self, results: Dict) -> Dict[str, any]:
        """Generate overall quality assessment"""
        
        assessment = {
            'quality_grade': 'F',
            'completeness_grade': 'F',
            'accuracy_grade': 'F',
            'target_achievement': {},
            'recommendations': [],
            'summary': ''
        }
        
        # Completeness assessment
        if 'completeness_validation' in results and 'overall_completeness' in results['completeness_validation']:
            completeness_score = results['completeness_validation']['overall_completeness']
            
            if completeness_score >= 95:
                assessment['completeness_grade'] = 'A'
            elif completeness_score >= 90:
                assessment['completeness_grade'] = 'B'
            elif completeness_score >= 80:
                assessment['completeness_grade'] = 'C'
            elif completeness_score >= 70:
                assessment['completeness_grade'] = 'D'
            else:
                assessment['completeness_grade'] = 'F'
        
        # Accuracy assessment
        if 'accuracy_validation' in results and 'accuracy_score' in results['accuracy_validation']:
            accuracy_score = results['accuracy_validation']['accuracy_score']
            
            if accuracy_score >= 95:
                assessment['accuracy_grade'] = 'A'
            elif accuracy_score >= 90:
                assessment['accuracy_grade'] = 'B'
            elif accuracy_score >= 80:
                assessment['accuracy_grade'] = 'C'
            elif accuracy_score >= 70:
                assessment['accuracy_grade'] = 'D'
            else:
                assessment['accuracy_grade'] = 'F'
        
        # Overall grade (weighted average)
        grade_values = {'A': 95, 'B': 85, 'C': 75, 'D': 65, 'F': 50}
        
        completeness_value = grade_values.get(assessment['completeness_grade'], 50)
        accuracy_value = grade_values.get(assessment['accuracy_grade'], 50)
        
        overall_score = (completeness_value * 0.6) + (accuracy_value * 0.4)  # Weight completeness more
        
        if overall_score >= 95:
            assessment['quality_grade'] = 'A'
        elif overall_score >= 90:
            assessment['quality_grade'] = 'B'
        elif overall_score >= 80:
            assessment['quality_grade'] = 'C'
        elif overall_score >= 70:
            assessment['quality_grade'] = 'D'
        else:
            assessment['quality_grade'] = 'F'
        
        # Target achievement
        if 'completeness_validation' in results:
            completeness_data = results['completeness_validation']
            assessment['target_achievement'] = {
                'overall_completeness_target_90': completeness_data.get('overall_completeness', 0) >= 90,
                'critical_fields_target_90': completeness_data.get('critical_fields_completeness', 0) >= 90,
                'author_enhancement_success': completeness_data.get('field_completeness', {}).get('autor', {}).get('completeness_pct', 0) >= 80,
                'classification_enhancement_success': completeness_data.get('field_completeness', {}).get('classificacao', {}).get('completeness_pct', 0) >= 85,
                'geographic_enhancement_success': completeness_data.get('field_completeness', {}).get('municipio', {}).get('completeness_pct', 0) >= 80
            }
        
        # Generate recommendations
        assessment['recommendations'] = self.generate_recommendations(results, assessment)
        
        # Generate summary
        assessment['summary'] = self.generate_summary(results, assessment)
        
        return assessment
    
    def generate_recommendations(self, results: Dict, assessment: Dict) -> List[str]:
        """Generate specific recommendations for improvement"""
        recommendations = []
        
        # Completeness recommendations
        if 'completeness_validation' in results:
            completeness_data = results['completeness_validation']
            
            if completeness_data.get('overall_completeness', 0) < 90:
                recommendations.append("Implement additional data enhancement techniques to reach 90% completeness target")
            
            field_completeness = completeness_data.get('field_completeness', {})
            
            if field_completeness.get('autor', {}).get('completeness_pct', 0) < 80:
                recommendations.append("Enhance author extraction algorithms with additional NLP patterns")
            
            if field_completeness.get('classificacao', {}).get('completeness_pct', 0) < 85:
                recommendations.append("Improve document classification models with more training data")
            
            if field_completeness.get('municipio', {}).get('completeness_pct', 0) < 80:
                recommendations.append("Expand geographic data enhancement with external geographic databases")
        
        # Accuracy recommendations
        if 'accuracy_validation' in results:
            accuracy_data = results['accuracy_validation']
            
            if accuracy_data.get('accuracy_score', 0) < 90:
                recommendations.append("Implement data validation rules to improve accuracy")
            
            field_accuracy = accuracy_data.get('field_accuracy', {})
            
            for field, field_data in field_accuracy.items():
                if not field_data.get('valid', True):
                    recommendations.append(f"Review and correct {field} field validation issues")
        
        return recommendations
    
    def generate_summary(self, results: Dict, assessment: Dict) -> str:
        """Generate executive summary"""
        
        total_docs = results.get('metadata', {}).get('total_documents', 0)
        completeness_score = results.get('completeness_validation', {}).get('overall_completeness', 0)
        accuracy_score = results.get('accuracy_validation', {}).get('accuracy_score', 0)
        
        summary = f"""
Data Quality Validation Summary:

📊 Dataset: {total_docs:,} Brazilian legislative documents
🎯 Overall Quality Grade: {assessment['quality_grade']}
📈 Completeness Score: {completeness_score:.1f}% (Grade: {assessment['completeness_grade']})
✅ Accuracy Score: {accuracy_score:.1f}% (Grade: {assessment['accuracy_grade']})

Target Achievement:
- 90% Completeness Target: {'✅ ACHIEVED' if assessment['target_achievement'].get('overall_completeness_target_90', False) else '❌ NOT ACHIEVED'}
- Author Enhancement: {'✅ SUCCESS' if assessment['target_achievement'].get('author_enhancement_success', False) else '❌ NEEDS IMPROVEMENT'}
- Classification Enhancement: {'✅ SUCCESS' if assessment['target_achievement'].get('classification_enhancement_success', False) else '❌ NEEDS IMPROVEMENT'}
- Geographic Enhancement: {'✅ SUCCESS' if assessment['target_achievement'].get('geographic_enhancement_success', False) else '❌ NEEDS IMPROVEMENT'}

Recommendations: {len(assessment['recommendations'])} improvement areas identified.
        """.strip()
        
        return summary
    
    def save_validation_report(self, results: Dict, output_path: str):
        """Save comprehensive validation report"""
        logger.info(f"Saving validation report to {output_path}")
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False, default=str)
        
        # Save summary report as text
        summary_path = output_path.replace('.json', '_summary.txt')
        with open(summary_path, 'w', encoding='utf-8') as f:
            f.write(results['overall_assessment']['summary'])
        
        logger.info(f"Validation summary saved to {summary_path}")


def main():
    """Main execution function for validation"""
    
    # Configuration
    DATA_PATH = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/enhanced/lexml_dataset_enhanced_v4.csv"
    REFERENCE_PATH = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/lexml_dataset_individual_com_localizacao/lexml_dataset_limpo_classificado_20250722_102507_com_localizacao.csv"
    OUTPUT_PATH = "/mnt/c/Users/Sofia/OneDrive/Doutorado Stuff/MackIntegridade/monitor_legislativo_v4/data_current/processed/validation/comprehensive_validation_report.json"
    
    try:
        # Initialize validator
        validator = ComprehensiveValidator(DATA_PATH, REFERENCE_PATH)
        
        # Run validation
        validation_results = validator.run_full_validation()
        
        # Save results
        validator.save_validation_report(validation_results, OUTPUT_PATH)
        
        # Print summary
        print("\n" + "="*80)
        print("DATA QUALITY VALIDATION COMPLETED")
        print("="*80)
        print(validation_results['overall_assessment']['summary'])
        print("="*80)
        
        logger.info("Data quality validation completed successfully!")
        
    except Exception as e:
        logger.error(f"Validation failed: {e}")
        raise

if __name__ == "__main__":
    main()