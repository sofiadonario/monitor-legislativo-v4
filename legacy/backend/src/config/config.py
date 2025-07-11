import os

class Config:
    """
    A placeholder for the main Config class.
    Provides basic, default values to allow the application to start.
    """
    def __init__(self):
        self.CACHE_TTL = int(os.getenv("CACHE_TTL", 3600))
        self.LEXML_API_URL = os.getenv("LEXML_API_URL", "http://www.lexml.gov.br/servico/busca")

    def get(self, key, default=None):
        return getattr(self, key, default) 