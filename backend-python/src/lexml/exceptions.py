"""
Custom Exceptions for LexML Services
====================================

Defines specialized exception types for handling errors related to
LexML integration, vocabulary management, and URN parsing.
"""

class LexMLError(Exception):
    """Base exception class for all LexML-related errors."""
    def __init__(self, message="An unspecified error occurred in the LexML service."):
        self.message = message
        super().__init__(self.message)

class VocabularyError(LexMLError):
    """Exception raised for errors in vocabulary loading, parsing, or processing."""
    def __init__(self, message="An error occurred with a SKOS vocabulary.", vocab_name: str = None):
        self.vocab_name = vocab_name
        full_message = f"Vocabulary '{vocab_name}': {message}" if vocab_name else message
        super().__init__(full_message)

class URNError(LexMLError):
    """Exception raised for errors related to URN parsing or validation."""
    def __init__(self, message="Invalid or malformed LexML URN.", urn: str = None):
        self.urn = urn
        full_message = f"URN '{urn}': {message}" if urn else message
        super().__init__(full_message)

class ConfigError(LexMLError):
    """Exception raised for configuration-related errors."""
    def __init__(self, message="A configuration error occurred."):
        super().__init__(message)

class NetworkError(LexMLError):
    """Exception for network-related issues when fetching resources."""
    def __init__(self, message="A network error occurred.", url: str = None):
        self.url = url
        full_message = f"URL '{url}': {message}" if url else message
        super().__init__(full_message)