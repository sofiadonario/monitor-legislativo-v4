"""
Senado Federal API Service
Implements improved search with fuzzy matching and better error handling
"""

import asyncio
import logging
import re
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import aiohttp
from bs4 import BeautifulSoup
import xml.etree.ElementTree as ET
from difflib import SequenceMatcher

from .base_service import BaseAPIService, retry_on_failure
from ..models.models import (
    SearchResult, Proposition, Author, PropositionType, 
    PropositionStatus, DataSource
)
from ..config.config import APIConfig


class SenadoService(BaseAPIService):
    """Service for interacting with Senado Federal API"""
    
    def __init__(self, config: APIConfig, cache_manager=None):
        super().__init__(config, cache_manager)
        self.search_threshold = 0.25  # Lower threshold for better recall
        
    async def search(self, query: str, filters: Dict[str, Any]) -> SearchResult:
        """Search for propositions in Senado Federal"""
        start_time = datetime.now()
        
        # Check cache first
        cache_key = self._get_cache_key(query, filters)
        cached_result = self.cache_manager.get(cache_key)
        if cached_result:
            self.logger.info(f"Returning cached results for query: {query}")
            return cached_result
        
        # Senado API doesn't support text search, so we need to:
        # 1. Fetch all propositions for the date range
        # 2. Filter locally based on the search query
        
        try:
            # Determine date range
            end_date = datetime.now()
            start_date = end_date - timedelta(days=365)  # Default to last year
            
            if filters.get("start_date"):
                start_date = datetime.fromisoformat(filters["start_date"])
            if filters.get("end_date"):
                end_date = datetime.fromisoformat(filters["end_date"])
            
            # Search by year and aggregate results
            all_propositions = []
            current_year = start_date.year
            
            while current_year <= end_date.year:
                year_props = await self._fetch_year_propositions(current_year)
                all_propositions.extend(year_props)
                current_year += 1
            
            # Filter propositions based on search query
            filtered_props = self._filter_propositions(all_propositions, query, filters)
            
            # Sort by relevance and date
            filtered_props.sort(key=lambda p: (
                self._calculate_relevance(p, query),
                p.publication_date
            ), reverse=True)
            
            # Limit results
            filtered_props = filtered_props[:100]  # Max 100 results
            
            result = SearchResult(
                query=query,
                filters=filters,
                propositions=filtered_props,
                total_count=len(filtered_props),
                source=DataSource.SENADO,
                search_time=(datetime.now() - start_time).total_seconds()
            )
            
            if filtered_props:  # Only cache if we got results
                self.cache_manager.set(cache_key, result, ttl=self.config.cache_ttl)
            
            return result
            
        except Exception as e:
            self.logger.error(f"Search failed: {str(e)}")
            return SearchResult(
                query=query,
                filters=filters,
                propositions=[],
                total_count=0,
                source=DataSource.SENADO,
                error=f"Search failed: {str(e)}",
                search_time=(datetime.now() - start_time).total_seconds()
            )
    
    @retry_on_failure(max_retries=3, backoff_factor=0.5)
    async def _fetch_year_propositions(self, year: int) -> List[Proposition]:
        """Fetch all propositions for a specific year"""
        url = f"{self.config.base_url}/materia/pesquisa/lista"
        params = {"ano": year}
        
        # Use the base class session management
        session = await self._get_aiohttp_session()
        
        async with session.get(
            url,
            params=params,
            headers=self.config.headers,
            timeout=aiohttp.ClientTimeout(total=self.config.timeout)
        ) as response:
                response.raise_for_status()
                xml_text = await response.text()
                
                # Parse XML response
                root = ET.fromstring(xml_text)
                propositions = []
                
                for materia in root.findall(".//Materia"):
                    prop = self._parse_materia(materia)
                    if prop:
                        propositions.append(prop)
                
                self.logger.info(f"Fetched {len(propositions)} propositions for year {year}")
                return propositions
    
    def _parse_materia(self, materia_elem: ET.Element) -> Optional[Proposition]:
        """Parse a materia (proposition) from XML element"""
        try:
            # Extract basic info
            codigo = materia_elem.findtext("CodigoMateria", "")
            sigla = materia_elem.findtext("SiglaSubtipoMateria", "")
            numero = materia_elem.findtext("NumeroMateria", "")
            ano = materia_elem.findtext("AnoMateria", "")
            ementa = materia_elem.findtext("EmentaMateria", "")
            
            # Get proposition type
            prop_type = self._get_proposition_type(sigla)
            
            # Parse date
            data_str = materia_elem.findtext("DataApresentacao", "")
            pub_date = self._parse_date(data_str)
            
            # Get status
            status_str = materia_elem.findtext("DescricaoSituacao", "")
            status = self._get_status(status_str)
            
            # Get author
            autor_nome = materia_elem.findtext("NomeAutor", "")
            autor_tipo = materia_elem.findtext("DescricaoTipoAutor", "")
            
            authors = []
            if autor_nome:
                authors.append(Author(
                    name=autor_nome,
                    type=autor_tipo or "Senador"
                ))
            
            # Build URL
            url = f"https://www25.senado.leg.br/web/atividade/materias/-/materia/{codigo}"
            
            # Extract keywords from indexacao
            indexacao = materia_elem.findtext("IndexacaoMateria", "")
            keywords = self._extract_keywords(indexacao)
            
            return Proposition(
                id=codigo,
                type=prop_type,
                number=numero,
                year=int(ano) if ano else datetime.now().year,
                title=ementa[:200] if ementa else "",
                summary=ementa or "",
                source=DataSource.SENADO,
                status=status,
                url=url,
                publication_date=pub_date,
                authors=authors,
                keywords=keywords,
                extra_data={
                    "indexacao": indexacao,
                    "sigla_completa": f"{sigla} {numero}/{ano}"
                }
            )
            
        except Exception as e:
            self.logger.error(f"Error parsing materia: {str(e)}")
            return None
    
    def _filter_propositions(self, propositions: List[Proposition], 
                           query: str, filters: Dict[str, Any]) -> List[Proposition]:
        """Filter propositions based on search query and filters"""
        if not query:
            return propositions
        
        # Normalize query for better matching
        query_lower = query.lower()
        query_terms = set(query_lower.split())
        
        filtered = []
        
        for prop in propositions:
            # Check date range
            if filters.get("start_date"):
                start_date = datetime.fromisoformat(filters["start_date"])
                if prop.publication_date < start_date:
                    continue
            
            if filters.get("end_date"):
                end_date = datetime.fromisoformat(filters["end_date"])
                if prop.publication_date > end_date:
                    continue
            
            # Check proposition type
            if filters.get("types"):
                if prop.type.name not in filters["types"]:
                    continue
            
            # Check text relevance
            if self._is_relevant(prop, query_lower, query_terms):
                filtered.append(prop)
        
        return filtered
    
    def _is_relevant(self, prop: Proposition, query_lower: str, 
                    query_terms: set) -> bool:
        """Check if a proposition is relevant to the search query"""
        # Combine all searchable text
        searchable_text = " ".join([
            prop.summary.lower(),
            prop.title.lower(),
            " ".join(prop.keywords).lower(),
            prop.extra_data.get("indexacao", "").lower()
        ])
        
        # Strategy 1: Exact substring match
        if query_lower in searchable_text:
            return True
        
        # Strategy 2: All terms present
        if all(term in searchable_text for term in query_terms):
            return True
        
        # Strategy 3: Fuzzy matching for each term
        matches = 0
        for term in query_terms:
            # Check if term appears as substring
            if term in searchable_text:
                matches += 1
                continue
            
            # Check fuzzy match for longer terms
            if len(term) > 3:
                words = searchable_text.split()
                for word in words:
                    if SequenceMatcher(None, term, word).ratio() > 0.8:
                        matches += 1
                        break
        
        # Return true if enough terms match
        return matches / len(query_terms) >= self.search_threshold
    
    def _calculate_relevance(self, prop: Proposition, query: str) -> float:
        """Calculate relevance score for ranking"""
        query_lower = query.lower()
        score = 0.0
        
        # Exact match in title
        if query_lower in prop.title.lower():
            score += 5.0
        
        # Exact match in summary
        if query_lower in prop.summary.lower():
            score += 3.0
        
        # Keywords match
        for keyword in prop.keywords:
            if query_lower in keyword.lower():
                score += 1.0
        
        # Partial matches
        query_terms = query_lower.split()
        for term in query_terms:
            if term in prop.title.lower():
                score += 0.5
            if term in prop.summary.lower():
                score += 0.3
        
        return score
    
    def _get_proposition_type(self, sigla: str) -> PropositionType:
        """Map Senado sigla to PropositionType"""
        sigla_upper = sigla.upper()
        
        mapping = {
            "PLS": PropositionType.PL,
            "PLC": PropositionType.PL,
            "PEC": PropositionType.PEC,
            "MPV": PropositionType.MPV,
            "PLV": PropositionType.PLV,
            "PDL": PropositionType.PDL,
            "PDS": PropositionType.PDL,
            "PRS": PropositionType.PRC,
            "RQS": PropositionType.REQ,
        }
        
        return mapping.get(sigla_upper, PropositionType.OTHER)
    
    def _get_status(self, status_str: str) -> PropositionStatus:
        """Map status string to PropositionStatus"""
        if not status_str:
            return PropositionStatus.UNKNOWN
        
        status_lower = status_str.lower()
        
        if "tramitando" in status_lower or "tramitação" in status_lower:
            return PropositionStatus.ACTIVE
        elif "aprovad" in status_lower:
            return PropositionStatus.APPROVED
        elif "rejeitad" in status_lower:
            return PropositionStatus.REJECTED
        elif "arquivad" in status_lower:
            return PropositionStatus.ARCHIVED
        elif "retirad" in status_lower:
            return PropositionStatus.WITHDRAWN
        else:
            return PropositionStatus.UNKNOWN
    
    def _parse_date(self, date_str: str) -> datetime:
        """Parse date from various formats"""
        if not date_str:
            return datetime.now()
        
        # Try different date formats
        formats = ["%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y"]
        
        for fmt in formats:
            try:
                return datetime.strptime(date_str.strip(), fmt)
            except ValueError:
                continue
        
        # If all fail, return current date
        self.logger.warning(f"Could not parse date: {date_str}")
        return datetime.now()
    
    def _extract_keywords(self, indexacao: str) -> List[str]:
        """Extract keywords from indexacao text"""
        if not indexacao:
            return []
        
        # Split by common delimiters
        keywords = re.split(r'[,;.\n]', indexacao)
        
        # Clean and filter keywords
        cleaned = []
        for kw in keywords:
            kw = kw.strip()
            if kw and len(kw) > 2:  # Skip very short keywords
                cleaned.append(kw)
        
        return cleaned[:10]  # Limit to 10 keywords
    
    async def get_proposition_details(self, proposition_id: str) -> Optional[Proposition]:
        """Get detailed information about a specific proposition"""
        try:
            url = f"{self.config.base_url}/materia/{proposition_id}"
            
            # Use the base class session management
            session = await self._get_aiohttp_session()
            
            async with session.get(
                url,
                headers=self.config.headers,
                timeout=aiohttp.ClientTimeout(total=self.config.timeout)
            ) as response:
                    response.raise_for_status()
                    xml_text = await response.text()
                    
                    root = ET.fromstring(xml_text)
                    materia = root.find(".//Materia")
                    
                    if materia:
                        return self._parse_materia(materia)
                    
        except Exception as e:
            self.logger.error(f"Failed to get proposition details: {str(e)}")
        
        return None
    
    async def check_health(self) -> bool:
        """Check if the API is healthy"""
        try:
            # Try to fetch propositions for current year
            url = f"{self.config.base_url}/materia/pesquisa/lista"
            params = {"ano": datetime.now().year, "limite": 1}
            
            # Use the base class session management
            session = await self._get_aiohttp_session()
            
            async with session.get(
                url,
                params=params,
                headers=self.config.headers,
                timeout=aiohttp.ClientTimeout(total=10)
            ) as response:
                    return response.status == 200
                    
        except Exception as e:
            self.logger.error(f"Health check failed: {str(e)}")
            return False