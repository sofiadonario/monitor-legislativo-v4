"""
Document validation utilities for collection service
Ensures data quality and consistency
"""

import logging
import re
from typing import Dict, Any, List, Optional
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class DocumentValidationError(Exception):
    """Custom exception for document validation errors"""
    pass


def validate_document(document: Dict[str, Any]) -> bool:
    """
    Validate a collected document
    
    Args:
        document: Document dictionary to validate
        
    Returns:
        True if document is valid
        
    Raises:
        DocumentValidationError: If document is invalid
    """
    
    # Required fields
    required_fields = ['urn', 'title']
    for field in required_fields:
        if field not in document or not document[field]:
            raise DocumentValidationError(f"Missing required field: {field}")
    
    # Validate URN format
    if not validate_urn_format(document['urn']):
        raise DocumentValidationError(f"Invalid URN format: {document['urn']}")
    
    # Validate title length
    if len(document['title']) > 1000:
        raise DocumentValidationError("Title too long (max 1000 characters)")
    
    # Validate description length if present
    if 'description' in document and document['description']:
        if len(document['description']) > 5000:
            logger.warning(f"Description truncated for {document['urn']}")
            document['description'] = document['description'][:5000] + "..."
    
    # Validate document type
    if 'document_type' in document:
        if not validate_document_type(document['document_type']):
            logger.warning(f"Unknown document type: {document['document_type']}")
            # Don't fail validation, just log warning
    
    # Validate document date
    if 'document_date' in document and document['document_date']:
        if not validate_date_format(document['document_date']):
            logger.warning(f"Invalid date format for {document['urn']}: {document['document_date']}")
            document['document_date'] = None
    
    # Validate metadata
    if 'metadata' in document and document['metadata']:
        if not validate_metadata(document['metadata']):
            logger.warning(f"Invalid metadata for {document['urn']}")
            document['metadata'] = {}
    
    # Add validation timestamp
    if 'metadata' not in document:
        document['metadata'] = {}
    document['metadata']['validated_at'] = datetime.now().isoformat()
    
    return True


def validate_urn_format(urn: str) -> bool:
    """
    Validate URN:LEX format
    
    Expected format: urn:lex:br:authority:type:date;number
    """
    if not urn:
        return False
    
    # Basic URN structure check
    if not urn.startswith('urn:'):
        return False
    
    # Split URN parts
    parts = urn.split(':')
    if len(parts) < 4:
        return False
    
    # Check URN scheme
    if parts[0] != 'urn':
        return False
    
    # For LEX URNs, check second part
    if parts[1] == 'lex':
        if len(parts) < 6:
            return False
        # urn:lex:br:authority:type:date;number
        if parts[2] != 'br':  # Brazilian legislation
            return False
    
    return True


def validate_document_type(doc_type: str) -> bool:
    """Validate document type against known types"""
    valid_types = {
        'Lei', 'Decreto', 'Decreto-Lei', 'Medida Provisória', 'MP',
        'Portaria', 'Resolução', 'Instrução Normativa', 'IN',
        'Emenda Constitucional', 'EC', 'Acórdão', 'Parecer',
        'PL', 'PEC', 'PDC', 'PLS', 'PRS', 'PSC'
    }
    
    return doc_type in valid_types or any(vt.lower() in doc_type.lower() for vt in valid_types)


def validate_date_format(date_str: str) -> bool:
    """Validate date string format"""
    if not date_str:
        return False
    
    # Common date formats
    date_formats = [
        '%Y-%m-%d',
        '%d/%m/%Y',
        '%d-%m-%Y',
        '%Y',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S.%f'
    ]
    
    for fmt in date_formats:
        try:
            datetime.strptime(date_str[:len(fmt)], fmt)
            return True
        except ValueError:
            continue
    
    return False


def validate_metadata(metadata: Any) -> bool:
    """Validate metadata structure"""
    if not isinstance(metadata, dict):
        return False
    
    # Check for excessively large metadata
    try:
        metadata_str = json.dumps(metadata)
        if len(metadata_str) > 10000:  # 10KB limit
            return False
    except (TypeError, ValueError):
        return False
    
    return True


def sanitize_document(document: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitize document data for safe storage
    
    Args:
        document: Document to sanitize
        
    Returns:
        Sanitized document
    """
    sanitized = document.copy()
    
    # Sanitize strings
    string_fields = ['urn', 'title', 'description', 'document_type']
    for field in string_fields:
        if field in sanitized and sanitized[field]:
            sanitized[field] = sanitize_string(sanitized[field])
    
    # Ensure URN is lowercase for consistency
    if 'urn' in sanitized:
        sanitized['urn'] = sanitized['urn'].lower()
    
    # Standardize document type
    if 'document_type' in sanitized:
        sanitized['document_type'] = standardize_document_type(sanitized['document_type'])
    
    # Clean metadata
    if 'metadata' in sanitized and sanitized['metadata']:
        sanitized['metadata'] = sanitize_metadata(sanitized['metadata'])
    
    return sanitized


def sanitize_string(text: str) -> str:
    """Sanitize string for safe database storage"""
    if not text:
        return ""
    
    # Remove null bytes
    text = text.replace('\x00', '')
    
    # Normalize whitespace
    text = re.sub(r'\s+', ' ', text)
    text = text.strip()
    
    # Remove control characters except newlines and tabs
    text = re.sub(r'[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    
    return text


def standardize_document_type(doc_type: str) -> str:
    """Standardize document type names"""
    if not doc_type:
        return "Unknown"
    
    # Mapping of variations to standard names
    type_mapping = {
        'lei': 'Lei',
        'decreto': 'Decreto',
        'decreto-lei': 'Decreto-Lei',
        'medida provisoria': 'Medida Provisória',
        'medida provisória': 'Medida Provisória',
        'mp': 'Medida Provisória',
        'portaria': 'Portaria',
        'resolucao': 'Resolução',
        'resolução': 'Resolução',
        'instrucao normativa': 'Instrução Normativa',
        'instrução normativa': 'Instrução Normativa',
        'in': 'Instrução Normativa',
        'emenda constitucional': 'Emenda Constitucional',
        'ec': 'Emenda Constitucional',
        'acordao': 'Acórdão',
        'acórdão': 'Acórdão',
        'parecer': 'Parecer',
        'pl': 'Projeto de Lei',
        'pec': 'Proposta de Emenda Constitucional',
        'pdc': 'Projeto de Decreto Legislativo',
        'pls': 'Projeto de Lei do Senado',
        'prs': 'Projeto de Resolução do Senado',
        'psc': 'Projeto de Sustação'
    }
    
    # Try exact match first
    normalized_type = doc_type.lower().strip()
    if normalized_type in type_mapping:
        return type_mapping[normalized_type]
    
    # Try partial match
    for key, value in type_mapping.items():
        if key in normalized_type:
            return value
    
    # Return capitalized version if no match found
    return doc_type.title()


def sanitize_metadata(metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize metadata dictionary"""
    sanitized = {}
    
    for key, value in metadata.items():
        # Sanitize key
        clean_key = sanitize_string(str(key))
        if not clean_key:
            continue
        
        # Sanitize value based on type
        if isinstance(value, str):
            clean_value = sanitize_string(value)
        elif isinstance(value, (int, float, bool)):
            clean_value = value
        elif isinstance(value, list):
            clean_value = [sanitize_string(str(item)) for item in value if item is not None]
        elif isinstance(value, dict):
            clean_value = sanitize_metadata(value)
        else:
            clean_value = sanitize_string(str(value))
        
        sanitized[clean_key] = clean_value
    
    return sanitized


def validate_batch_documents(documents: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Validate a batch of documents
    
    Args:
        documents: List of documents to validate
        
    Returns:
        Dict with validation results
    """
    results = {
        'valid': [],
        'invalid': [],
        'warnings': [],
        'stats': {
            'total': len(documents),
            'valid_count': 0,
            'invalid_count': 0,
            'warning_count': 0
        }
    }
    
    for i, doc in enumerate(documents):
        try:
            # Sanitize first
            sanitized_doc = sanitize_document(doc)
            
            # Then validate
            if validate_document(sanitized_doc):
                results['valid'].append(sanitized_doc)
                results['stats']['valid_count'] += 1
        
        except DocumentValidationError as e:
            results['invalid'].append({
                'index': i,
                'document': doc,
                'error': str(e)
            })
            results['stats']['invalid_count'] += 1
            logger.warning(f"Document {i} validation failed: {e}")
        
        except Exception as e:
            results['invalid'].append({
                'index': i,
                'document': doc,
                'error': f"Unexpected validation error: {e}"
            })
            results['stats']['invalid_count'] += 1
            logger.error(f"Unexpected validation error for document {i}: {e}")
    
    # Log summary
    logger.info(
        f"Batch validation completed: "
        f"{results['stats']['valid_count']} valid, "
        f"{results['stats']['invalid_count']} invalid out of {results['stats']['total']}"
    )
    
    return results


def check_duplicate_urns(documents: List[Dict[str, Any]]) -> List[str]:
    """Check for duplicate URNs in document batch"""
    seen_urns = set()
    duplicates = []
    
    for doc in documents:
        urn = doc.get('urn')
        if urn:
            if urn in seen_urns:
                duplicates.append(urn)
            else:
                seen_urns.add(urn)
    
    return duplicates


def generate_validation_report(validation_results: Dict[str, Any]) -> str:
    """Generate human-readable validation report"""
    stats = validation_results['stats']
    
    report = f"""
Document Validation Report
========================

Total Documents: {stats['total']}
Valid Documents: {stats['valid_count']}
Invalid Documents: {stats['invalid_count']}
Success Rate: {(stats['valid_count'] / stats['total'] * 100):.1f}%

"""
    
    if validation_results['invalid']:
        report += "Invalid Documents:\n"
        for invalid in validation_results['invalid'][:10]:  # Show first 10
            report += f"  - Index {invalid['index']}: {invalid['error']}\n"
        
        if len(validation_results['invalid']) > 10:
            report += f"  ... and {len(validation_results['invalid']) - 10} more\n"
    
    return report