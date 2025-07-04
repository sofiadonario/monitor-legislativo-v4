import logging
import csv
from typing import List, Optional
from pathlib import Path
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

class Document(BaseModel):
    id: str = Field(alias='urn')
    urn: str
    title: str
    summary: Optional[str] = Field(alias='description', default=None)
    url: Optional[str] = Field(alias='full_text_url', default=None)
    type: Optional[str] = Field(alias='document_type', default=None)
    date: Optional[str] = None
    author: Optional[str] = Field(alias='authority', default=None)
    keywords: List[str] = []
    source: str = "processed_csv"

class SimpleSearchService:
    def __init__(self):
        # Adjust path: move three levels up to project root, then into data/processed
        self.csv_path = (
            Path(__file__).resolve().parent.parent.parent
            / "data"
            / "processed"
            / "lexml_parsed_enhanced.csv"
        )
        self.csv_data: Optional[List[dict]] = None
        self._load_csv_data()

    def _load_csv_data(self):
        """Loads the processed data from the CSV file into memory."""
        try:
            if not self.csv_path.exists():
                logger.error(f"CRITICAL: Processed data file not found at {self.csv_path}")
                self.csv_data = []
                return

            self.csv_data = []
            with open(self.csv_path, 'r', encoding='utf-8-sig') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    self.csv_data.append(row)
            logger.info(f"Successfully loaded {len(self.csv_data)} documents from {self.csv_path}")
        except Exception as e:
            logger.error(f"FATAL: Error loading processed CSV data: {e}", exc_info=True)
            self.csv_data = []

    async def search(self, query: str, limit: int = 1000) -> List[Document]:
        """
        Returns all documents from the processed CSV file.
        The 'query' parameter is ignored to ensure all data is returned.
        """
        if self.csv_data is None:
            self._load_csv_data()

        if not self.csv_data:
            logger.warning("No data available from processed CSV file.")
            return []

        document_objects = []
        for row in self.csv_data[:limit]:
            try:
                # Manually map and validate fields to match the frontend model
                doc_data = {
                    'id': row.get('urn', ''),
                    'urn': row.get('urn', ''),
                    'title': row.get('title', ''),
                    'summary': row.get('description', ''),
                    'url': row.get('full_text_url', ''),
                    'type': row.get('document_type', ''),
                    'date': row.get('publication_date', ''),
                    'author': row.get('authority', ''),
                    'keywords': [kw.strip() for kw in row.get('subject_keywords', '').strip('{}').split(',') if kw.strip()],
                    'source': 'processed_csv'
                }
                document_objects.append(Document.model_validate(doc_data))
            except Exception as e:
                logger.warning(f"Error parsing row into Document object: {row}. Error: {e}")
                continue
        
        logger.info(f"Returning {len(document_objects)} documents from processed file.")
        return document_objects

# Singleton instance for dependency injection
_search_service_instance = None

async def get_simple_search_service() -> SimpleSearchService:
    global _search_service_instance
    if _search_service_instance is None:
        _search_service_instance = SimpleSearchService()
    return _search_service_instance 