"""
LexML Integration Exceptions

Custom exceptions for LexML integration module providing
clear error handling and debugging information.
"""


class LexMLError(Exception):
    """Base exception for LexML integration errors"""
    pass


class VocabularyError(LexMLError):
    """Exception for SKOS vocabulary related errors"""
    
    def __init__(self, message: str, vocabulary_name: str = None, url: str = None):
        super().__init__(message)
        self.vocabulary_name = vocabulary_name
        self.url = url
        
    def __str__(self):
        base_msg = super().__str__()
        if self.vocabulary_name:
            base_msg += f" (Vocabulary: {self.vocabulary_name})"
        if self.url:
            base_msg += f" (URL: {self.url})"
        return base_msg


class URNError(LexMLError):
    """Exception for LexML URN parsing and validation errors"""
    
    def __init__(self, message: str, urn: str = None, component: str = None):
        super().__init__(message)
        self.urn = urn
        self.component = component
        
    def __str__(self):
        base_msg = super().__str__()
        if self.urn:
            base_msg += f" (URN: {self.urn})"
        if self.component:
            base_msg += f" (Component: {self.component})"
        return base_msg


class CacheError(LexMLError):
    """Exception for vocabulary caching errors"""
    pass


class NetworkError(LexMLError):
    """Exception for network-related errors during vocabulary loading"""
    
    def __init__(self, message: str, url: str = None, status_code: int = None):
        super().__init__(message)
        self.url = url
        self.status_code = status_code
        
    def __str__(self):
        base_msg = super().__str__()
        if self.status_code:
            base_msg += f" (HTTP {self.status_code})"
        if self.url:
            base_msg += f" (URL: {self.url})"
        return base_msg