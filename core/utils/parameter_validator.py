"""
Parameter Validation Utilities
Provides robust parameter validation for API calls
"""

from typing import Dict, Any, Optional, List, Union
from datetime import datetime
import re


class ParameterValidator:
    """Validates and sanitizes parameters for API calls"""
    
    @staticmethod
    def validate_search_params(params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate and sanitize search parameters
        Removes None values and ensures proper types
        """
        validated = {}
        
        for key, value in params.items():
            if value is not None:
                # Convert to string if not already
                if isinstance(value, (str, int, float, bool)):
                    validated[key] = str(value) if not isinstance(value, str) else value
                elif isinstance(value, list):
                    # Join list values with comma
                    validated[key] = ",".join(str(v) for v in value if v is not None)
                else:
                    # For other types, convert to string
                    validated[key] = str(value)
        
        return validated
    
    @staticmethod
    def validate_date_filters(filters: Dict[str, Any]) -> Dict[str, str]:
        """
        Validate and format date filters
        Returns only valid date strings in ISO format
        """
        date_params = {}
        
        # Handle start_date
        start_date = filters.get("start_date")
        if start_date:
            formatted_date = ParameterValidator._format_date(start_date)
            if formatted_date:
                date_params["start_date"] = formatted_date
        
        # Handle end_date
        end_date = filters.get("end_date")
        if end_date:
            formatted_date = ParameterValidator._format_date(end_date)
            if formatted_date:
                date_params["end_date"] = formatted_date
        
        return date_params
    
    @staticmethod
    def _format_date(date_input: Union[str, datetime]) -> Optional[str]:
        """
        Format date input to ISO string format (YYYY-MM-DD)
        Handles various input formats
        """
        if isinstance(date_input, datetime):
            return date_input.strftime("%Y-%m-%d")
        
        if isinstance(date_input, str):
            # Try common date formats
            formats = [
                "%Y-%m-%d",
                "%d/%m/%Y",
                "%m/%d/%Y",
                "%Y-%m-%d %H:%M:%S",
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f"
            ]
            
            for fmt in formats:
                try:
                    dt = datetime.strptime(date_input, fmt)
                    return dt.strftime("%Y-%m-%d")
                except ValueError:
                    continue
        
        return None
    
    @staticmethod
    def validate_query(query: str) -> str:
        """
        Validate and sanitize search query
        """
        if not query or not isinstance(query, str):
            return ""
        
        # Remove excessive whitespace
        query = re.sub(r'\s+', ' ', query.strip())
        
        # Basic length validation
        if len(query) > 1000:
            query = query[:1000]
        
        return query
    
    @staticmethod
    def validate_pagination(filters: Dict[str, Any]) -> Dict[str, int]:
        """
        Validate pagination parameters
        """
        pagination = {}
        
        # Page number
        page = filters.get("page", 1)
        try:
            page = int(page)
            pagination["page"] = max(1, page)
        except (ValueError, TypeError):
            pagination["page"] = 1
        
        # Page size
        page_size = filters.get("page_size", 50)
        try:
            page_size = int(page_size)
            pagination["page_size"] = min(max(1, page_size), 100)  # Limit to 100
        except (ValueError, TypeError):
            pagination["page_size"] = 50
        
        return pagination
    
    @staticmethod
    def build_camara_params(query: str, filters: Dict[str, Any]) -> Dict[str, str]:
        """
        Build validated parameters for Câmara API
        Note: Câmara API doesn't support keyword search directly
        """
        query = ParameterValidator.validate_query(query)
        
        # Câmara API v2 valid parameters
        params = {
            "ordenarPor": "id",  # Valid values: "id" or "ano"
            "ordem": "DESC",
            "itens": "100"
        }
        
        # Add date filters if valid
        date_params = ParameterValidator.validate_date_filters(filters)
        if date_params.get("start_date"):
            params["dataInicio"] = date_params["start_date"]
        if date_params.get("end_date"):
            params["dataFim"] = date_params["end_date"]
        
        # Add type filter if specified
        if "types" in filters and filters["types"]:
            if isinstance(filters["types"], list):
                params["siglaTipo"] = ",".join(str(t) for t in filters["types"] if t)
            else:
                params["siglaTipo"] = str(filters["types"])
        
        # Add year filter if available (improves performance)
        if filters.get("year"):
            params["ano"] = str(filters["year"])
        
        # Note: query text will be used for local filtering after API call
        return params
    
    @staticmethod
    def build_senado_params(query: str, filters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build validated parameters for Senado API
        """
        query = ParameterValidator.validate_query(query)
        
        # Senado API uses different approach - validate dates for local filtering
        validated_filters = {}
        
        date_params = ParameterValidator.validate_date_filters(filters)
        if date_params.get("start_date"):
            validated_filters["start_date"] = date_params["start_date"]
        if date_params.get("end_date"):
            validated_filters["end_date"] = date_params["end_date"]
        
        return {
            "query": query,
            "filters": validated_filters
        }
    
    @staticmethod
    def build_planalto_params(query: str, filters: Dict[str, Any]) -> Dict[str, Any]:
        """
        Build validated parameters for Planalto/DOU search
        """
        query = ParameterValidator.validate_query(query)
        
        validated_filters = {}
        
        # Add date filters for Playwright form filling
        date_params = ParameterValidator.validate_date_filters(filters)
        if date_params.get("start_date"):
            validated_filters["publishFrom"] = date_params["start_date"]
        if date_params.get("end_date"):
            validated_filters["publishTo"] = date_params["end_date"]
        
        return {
            "query": query,
            "filters": validated_filters
        }
    
    @staticmethod
    def validate_regulatory_params(query: str, filters: Dict[str, Any], 
                                 agency: str) -> Dict[str, Any]:
        """
        Build validated parameters for regulatory agency searches
        """
        query = ParameterValidator.validate_query(query)
        
        validated_filters = filters.copy()
        
        # Validate dates
        date_params = ParameterValidator.validate_date_filters(filters)
        validated_filters.update(date_params)
        
        # Agency-specific validations
        agency_configs = {
            "ANEEL": {"query_field": "texto", "date_format": "%d/%m/%Y"},
            "ANATEL": {"query_field": "palavras", "date_format": "%Y-%m-%d"},
            "ANVISA": {"query_field": "q", "date_format": "%Y-%m-%d"},
            "ANS": {"query_field": "termo", "date_format": "%d/%m/%Y"},
            "ANA": {"query_field": "busca", "date_format": "%Y-%m-%d"},
            "ANCINE": {"query_field": "search", "date_format": "%Y-%m-%d"},
            "ANTT": {"query_field": "texto", "date_format": "%d/%m/%Y"},
            "ANTAQ": {"query_field": "busca", "date_format": "%Y-%m-%d"},
            "ANAC": {"query_field": "termo", "date_format": "%Y-%m-%d"},
            "ANP": {"query_field": "q", "date_format": "%Y-%m-%d"},
            "ANM": {"query_field": "buscar", "date_format": "%Y-%m-%d"}
        }
        
        config = agency_configs.get(agency, {"query_field": "q", "date_format": "%Y-%m-%d"})
        
        # Format dates according to agency requirements
        if date_params.get("start_date") and config["date_format"] != "%Y-%m-%d":
            try:
                dt = datetime.strptime(date_params["start_date"], "%Y-%m-%d")
                validated_filters["start_date"] = dt.strftime(config["date_format"])
            except ValueError:
                pass
        
        if date_params.get("end_date") and config["date_format"] != "%Y-%m-%d":
            try:
                dt = datetime.strptime(date_params["end_date"], "%Y-%m-%d")
                validated_filters["end_date"] = dt.strftime(config["date_format"])
            except ValueError:
                pass
        
        return {
            "query": query,
            "query_field": config["query_field"],
            "filters": validated_filters
        }