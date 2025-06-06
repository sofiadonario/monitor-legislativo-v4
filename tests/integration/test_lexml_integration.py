#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Test suite for LexML Integration
"""

import pytest
import json
import xml.etree.ElementTree as ET
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path
import tempfile

from core.api.lexml_integration import LexMLIntegration
from core.api.lexml_monitor import LexMLMonitor


class TestLexMLIntegration:
    """Test cases for LexML Integration"""
    
    @pytest.fixture
    def integration(self):
        """Create integration instance with temp directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield LexMLIntegration(output_dir=tmpdir)
    
    @pytest.fixture
    def mock_api_response(self):
        """Mock successful API response"""
        return '''<?xml version="1.0" encoding="UTF-8"?>
        <srw:searchRetrieveResponse xmlns:srw="http://www.loc.gov/zing/srw/">
            <srw:numberOfRecords>2</srw:numberOfRecords>
            <srw:records>
                <srw:record>
                    <srw:recordData>
                        <dc:record xmlns:dc="http://purl.org/dc/elements/1.1/">
                            <dc:identifier>urn:lex:br:federal:lei:2021-12-30;14310</dc:identifier>
                            <dc:title>Lei nº 14.310, de 30 de dezembro de 2021</dc:title>
                            <dc:date>2021-12-30</dc:date>
                            <dc:type>Lei</dc:type>
                            <dc:description>Institui o Programa Rota 2030</dc:description>
                            <dc:subject>Transporte</dc:subject>
                            <dc:subject>Mobilidade</dc:subject>
                            <dc:publisher>Federal</dc:publisher>
                        </dc:record>
                    </srw:recordData>
                </srw:record>
                <srw:record>
                    <srw:recordData>
                        <dc:record xmlns:dc="http://purl.org/dc/elements/1.1/">
                            <dc:identifier>urn:lex:br:federal:decreto:2022-06-14;11075</dc:identifier>
                            <dc:title>Decreto nº 11.075, de 14 de junho de 2022</dc:title>
                            <dc:date>2022-06-14</dc:date>
                            <dc:type>Decreto</dc:type>
                            <dc:description>Regulamenta transporte rodoviário de cargas</dc:description>
                            <dc:publisher>Federal</dc:publisher>
                        </dc:record>
                    </srw:recordData>
                </srw:record>
            </srw:records>
        </srw:searchRetrieveResponse>'''
    
    @pytest.fixture
    def mock_scraper_results(self):
        """Mock scraper results"""
        return [
            {
                'search_term': 'transporte',
                'date_searched': '2024-01-01T10:00:00',
                'url': 'https://www.lexml.gov.br/urn/urn:lex:br:federal:lei:2020-01-01;12345',
                'title': 'Lei de Transporte',
                'urn': 'urn:lex:br:federal:lei:2020-01-01;12345',
                'source': 'web_scraper'
            }
        ]
    
    def test_load_search_terms(self, integration, tmp_path):
        """Test loading search terms from file"""
        # Create test terms file
        terms_file = tmp_path / "test_terms.txt"
        terms_file.write_text('''# Test terms
"transporte rodoviário"
"combustível sustentável"
biometano

# Another comment
"Rota 2030"
''')
        
        terms = integration._load_search_terms(str(terms_file))
        
        assert len(terms) == 4
        assert "transporte rodoviário" in terms
        assert "combustível sustentável" in terms
        assert "biometano" in terms
        assert "Rota 2030" in terms
    
    def test_parse_sru_response(self, integration, mock_api_response):
        """Test parsing SRU XML response"""
        results, total = integration._parse_sru_response(mock_api_response, "transporte")
        
        assert total == 2
        assert len(results) == 2
        
        # Check first result
        assert results[0]['urn'] == 'urn:lex:br:federal:lei:2021-12-30;14310'
        assert results[0]['title'] == 'Lei nº 14.310, de 30 de dezembro de 2021'
        assert results[0]['document_date'] == '2021-12-30'
        assert results[0]['document_type'] == 'Lei'
        assert 'Rota 2030' in results[0]['description']
        assert results[0]['authority'] == 'Federal'
        assert 'Transporte' in results[0]['subjects']
    
    def test_is_unique_result(self, integration):
        """Test deduplication logic"""
        # First result should be unique
        result1 = {'urn': 'urn:lex:br:test:123'}
        assert integration._is_unique_result(result1) is True
        
        # Same URN should not be unique
        result2 = {'urn': 'urn:lex:br:test:123'}
        assert integration._is_unique_result(result2) is False
        
        # Different URN should be unique
        result3 = {'urn': 'urn:lex:br:test:456'}
        assert integration._is_unique_result(result3) is True
    
    @patch('requests.Session.get')
    def test_search_api_success(self, mock_get, integration, mock_api_response):
        """Test successful API search"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = mock_api_response
        mock_get.return_value = mock_response
        
        results = integration._search_api("transporte")
        
        assert results is not None
        assert len(results) == 2
        assert integration.stats['api_successes'] == 1
        assert integration.stats['api_failures'] == 0
    
    @patch('requests.Session.get')
    def test_search_api_failure_with_fallback(self, mock_get, integration):
        """Test API failure triggers fallback"""
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        results = integration._search_api("transporte")
        
        assert results is None
        assert integration.stats['api_failures'] == 1
    
    def test_save_results(self, integration):
        """Test saving results to CSV"""
        results = [
            {
                'search_term': 'transporte',
                'urn': 'urn:test:123',
                'title': 'Test Law',
                'document_date': '2024-01-01',
                'document_type': 'Lei',
                'url': 'https://test.com',
                'source': 'api',
                'date_searched': '2024-01-01T10:00:00'
            }
        ]
        
        csv_file = integration.save_results(results)
        
        assert Path(csv_file).exists()
        
        # Read and verify CSV content
        with open(csv_file, 'r') as f:
            content = f.read()
            assert 'Test Law' in content
            assert 'urn:test:123' in content
    
    def test_generate_summary_report(self, integration):
        """Test summary report generation"""
        results = [
            {
                'search_term': 'transporte',
                'document_type': 'Lei',
                'authority': 'Federal',
                'document_date': '2024-01-01',
                'subjects': 'Transporte; Logística'
            },
            {
                'search_term': 'combustível',
                'document_type': 'Decreto',
                'authority': 'Federal',
                'document_date': '2023-12-01',
                'subjects': 'Energia; Combustível'
            }
        ]
        
        report_file = integration.generate_summary_report(results)
        
        assert Path(report_file).exists()
        
        # Read and verify report
        with open(report_file, 'r') as f:
            report = json.load(f)
        
        assert report['statistics']['total_results'] == 2
        assert report['results_by_type']['Lei'] == 1
        assert report['results_by_type']['Decreto'] == 1
        assert report['results_by_authority']['Federal'] == 2


class TestLexMLMonitor:
    """Test cases for LexML Monitor"""
    
    @pytest.fixture
    def monitor(self, tmp_path):
        """Create monitor instance with temp config"""
        config_file = tmp_path / "config.json"
        config = {
            "output_dir": str(tmp_path / "output"),
            "state_file": str(tmp_path / "state.json"),
            "check_interval_hours": 1,
            "priority_terms": ["Rota 2030", "CONTRAN"],
            "notification_settings": {
                "email_enabled": False,
                "webhook_enabled": False
            }
        }
        config_file.write_text(json.dumps(config))
        
        return LexMLMonitor(str(config_file))
    
    def test_document_hash(self, monitor):
        """Test document hash creation"""
        doc1 = {
            'title': 'Test Law',
            'description': 'Test description',
            'subjects': 'Transport',
            'document_date': '2024-01-01'
        }
        
        doc2 = {
            'title': 'Test Law',
            'description': 'Test description',
            'subjects': 'Transport',
            'document_date': '2024-01-01'
        }
        
        doc3 = {
            'title': 'Different Law',
            'description': 'Test description',
            'subjects': 'Transport',
            'document_date': '2024-01-01'
        }
        
        hash1 = monitor._create_document_hash(doc1)
        hash2 = monitor._create_document_hash(doc2)
        hash3 = monitor._create_document_hash(doc3)
        
        assert hash1 == hash2  # Same content
        assert hash1 != hash3  # Different content
    
    def test_contains_priority_terms(self, monitor):
        """Test priority term detection"""
        doc1 = {
            'title': 'Lei do Rota 2030',
            'description': 'Programa de mobilidade'
        }
        
        doc2 = {
            'title': 'Resolução CONTRAN',
            'description': 'Normas de trânsito'
        }
        
        doc3 = {
            'title': 'Lei comum',
            'description': 'Outras disposições'
        }
        
        assert monitor._contains_priority_terms(doc1) is True
        assert monitor._contains_priority_terms(doc2) is True
        assert monitor._contains_priority_terms(doc3) is False
    
    @patch.object(LexMLIntegration, 'search_all_terms')
    def test_check_for_updates(self, mock_search, monitor):
        """Test update checking"""
        # Mock search results
        mock_search.return_value = [
            {
                'urn': 'urn:new:123',
                'title': 'New Law with Rota 2030',
                'description': 'Test',
                'url': 'https://test.com/new'
            },
            {
                'urn': 'urn:existing:456',
                'title': 'Existing Law',
                'description': 'Test',
                'url': 'https://test.com/existing'
            }
        ]
        
        # Add existing document to state
        monitor.state['known_documents']['urn:existing:456'] = {
            'hash': 'old_hash',
            'first_seen': '2024-01-01',
            'last_updated': '2024-01-01'
        }
        
        updates = monitor.check_for_updates()
        
        assert updates['new_documents'] == 1
        assert updates['priority_alerts'] == 1
        assert len(updates['new_docs']) == 1
        assert updates['new_docs'][0]['urn'] == 'urn:new:123'


if __name__ == "__main__":
    pytest.main([__file__, "-v"])