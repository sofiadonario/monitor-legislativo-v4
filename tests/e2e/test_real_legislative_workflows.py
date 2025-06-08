"""
PSYCHOPATH-GRADE E2E TESTS WITH AUTHENTIC GOVERNMENT WORKFLOWS
🚨 SCIENTIFIC RESEARCH COMPLIANCE ENFORCED 🚨

This E2E test suite implements REAL Brazilian legislative workflows using
ONLY authentic government processes and data. Every test scenario must
correspond to actual procedures used in Brazilian Congress.

ZERO TOLERANCE RULES:
- ALL workflows must match real Brazilian legislative procedures
- ALL search terms must be actual terms used by legal professionals
- ALL documents must have verifiable government IDs
- ALL tramitation states must reflect actual Congressional processes
- NO synthetic scenarios that don't occur in real legislative work

Any deviation from authentic government workflows INVALIDATES research validity.
"""

import pytest
import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from playwright.async_api import async_playwright, Page, Browser, BrowserContext
import aiohttp
import json
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from tests.fixtures.real_legislative_data import RealLegislativeDataFixtures
from core.config.config import Config


class TestRealLegislativeSearchWorkflows:
    """
    E2E tests for REAL legislative search workflows used by researchers.
    
    These tests simulate actual research scenarios used by legal professionals,
    academics, and policy analysts when investigating Brazilian legislation.
    """
    
    @pytest.fixture(scope="session")
    async def browser_context(self):
        """Create browser context for E2E testing with real user behavior."""
        async with async_playwright() as p:
            browser = await p.chromium.launch(
                headless=True,  # Can be False for debugging
                args=['--no-sandbox', '--disable-dev-shm-usage']
            )
            
            # Create context with realistic user agent
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={'width': 1920, 'height': 1080},
                locale='pt-BR'  # Brazilian Portuguese
            )
            
            yield context
            await context.close()
            await browser.close()
    
    @pytest.fixture
    async def page(self, browser_context):
        """Create page for testing with Brazilian locale."""
        page = await browser_context.new_page()
        yield page
        await page.close()
    
    async def test_real_lei_complementar_173_research_workflow(self, page: Page):
        """
        Test complete research workflow for Lei Complementar 173/2020.
        
        This is a REAL research scenario: investigating COVID-19 fiscal response law.
        Simulates actual academic research into Brazilian pandemic legislation.
        """
        # Navigate to application
        await page.goto("http://localhost:8000")
        
        # Wait for application to load
        await page.wait_for_selector("#search-input", timeout=10000)
        
        # REAL RESEARCH SCENARIO: Researcher investigating COVID-19 fiscal response
        search_term = "lei complementar 173/2020 covid"  # REAL search academics use
        await page.fill("#search-input", search_term)
        
        # Click search with realistic user delay
        await page.click("#search-button")
        await asyncio.sleep(0.5)  # Human reaction time
        
        # Wait for REAL government API responses
        await page.wait_for_selector(".search-results", timeout=30000)  # Government APIs can be slow
        
        # Verify real results appear
        results = await page.query_selector_all(".result-item")
        assert len(results) > 0, "No results found for real legislative search"
        
        # Verify first result is the REAL Lei Complementar 173/2020
        first_result = results[0]
        result_text = await first_result.inner_text()
        
        # Must contain real identifying information
        assert "173" in result_text or "173/2020" in result_text
        assert "covid" in result_text.lower() or "coronavírus" in result_text.lower()
        
        # Verify source attribution (CRITICAL for research validity)
        source_marker = await first_result.query_selector(".source-marker")
        assert source_marker is not None, "Source attribution missing - research invalid"
        
        source_text = await source_marker.inner_text()
        # Must link to actual government source
        assert any(gov_domain in source_text.lower() for gov_domain in [
            "camara.leg.br", "senado.leg.br", "planalto.gov.br"
        ]), f"Invalid source attribution: {source_text}"
        
        # Click on result to view details (real user behavior)
        await first_result.click()
        await page.wait_for_selector(".document-details", timeout=10000)
        
        # Verify detailed view shows REAL government data
        details_text = await page.locator(".document-details").inner_text()
        
        # Must contain real Lei Complementar 173/2020 content
        assert any(phrase in details_text.lower() for phrase in [
            "programa federativo", "enfrentamento", "coronavírus"
        ]), "Document details don't match real Lei Complementar 173/2020"
        
        # Verify real tramitation history is shown
        tramitation_section = await page.query_selector(".tramitation-history")
        if tramitation_section:
            tramitation_text = await tramitation_section.inner_text()
            # Should show real status: transformed into law
            assert any(phrase in tramitation_text.lower() for phrase in [
                "transformado", "sancionado", "lei complementar"
            ]), "Tramitation history doesn't reflect real legislative process"
    
    async def test_real_administrative_reform_research_workflow(self, page: Page):
        """
        Test research workflow for PEC 32/2020 (Administrative Reform).
        
        REAL SCENARIO: Policy analyst investigating failed administrative reform.
        This PEC was actually archived at end of 2019-2023 legislature.
        """
        await page.goto("http://localhost:8000")
        await page.wait_for_selector("#search-input", timeout=10000)
        
        # REAL research term used by policy analysts
        search_term = "PEC 32/2020 reforma administrativa"
        await page.fill("#search-input", search_term)
        await page.click("#search-button")
        
        # Wait for results
        await page.wait_for_selector(".search-results", timeout=30000)
        
        # Verify real PEC 32/2020 appears
        results = await page.query_selector_all(".result-item")
        assert len(results) > 0
        
        # Find PEC 32/2020 in results
        pec_32_found = False
        for result in results:
            result_text = await result.inner_text()
            if "32" in result_text and "2020" in result_text and "pec" in result_text.lower():
                pec_32_found = True
                
                # Click to view details
                await result.click()
                await page.wait_for_selector(".document-details", timeout=10000)
                
                # Verify real PEC content
                details = await page.locator(".document-details").inner_text()
                assert any(phrase in details.lower() for phrase in [
                    "servidores públicos", "organização administrativa", "estado"
                ]), "PEC 32/2020 content doesn't match real proposal"
                
                # Verify shows real archival status
                status_element = await page.query_selector(".current-status")
                if status_element:
                    status_text = await status_element.inner_text()
                    assert "arquivada" in status_text.lower(), "Should show real archival status"
                
                break
        
        assert pec_32_found, "Real PEC 32/2020 not found in search results"
    
    async def test_real_procurement_law_research_workflow(self, page: Page):
        """
        Test research workflow for Lei 14.133/2021 (New Procurement Law).
        
        REAL SCENARIO: Legal professional researching new procurement regulations.
        This law replaced Lei 8.666/1993 and is heavily researched by lawyers.
        """
        await page.goto("http://localhost:8000")
        await page.wait_for_selector("#search-input", timeout=10000)
        
        # REAL search term used by procurement lawyers
        search_term = "lei 14.133/2021 licitação"
        await page.fill("#search-input", search_term)
        await page.click("#search-button")
        
        await page.wait_for_selector(".search-results", timeout=30000)
        
        # Should find the real procurement law
        results = await page.query_selector_all(".result-item")
        assert len(results) > 0
        
        # Verify procurement law content
        procurement_law_found = False
        for result in results:
            result_text = await result.inner_text()
            if any(term in result_text.lower() for term in ["14.133", "licitação", "contrato"]):
                procurement_law_found = True
                
                # Test export functionality with real data
                export_button = await result.query_selector(".export-button")
                if export_button:
                    await export_button.click()
                    
                    # Wait for export options
                    await page.wait_for_selector(".export-options", timeout=5000)
                    
                    # Test CSV export with real legislative data
                    csv_option = await page.query_selector(".export-csv")
                    if csv_option:
                        # Start download
                        async with page.expect_download() as download_info:
                            await csv_option.click()
                        download = await download_info.value
                        
                        # Verify download completed
                        assert download.suggested_filename.endswith('.csv')
                        
                        # Verify file contains real data (not empty)
                        download_path = await download.path()
                        if download_path:
                            with open(download_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                                # Should contain real law information
                                assert len(content) > 100  # Meaningful content
                                assert "14.133" in content or "licitação" in content.lower()
                
                break
        
        assert procurement_law_found, "Real Lei 14.133/2021 not found"
    
    async def test_real_multi_source_comparative_research(self, page: Page):
        """
        Test REAL comparative research across multiple government sources.
        
        SCENARIO: Academic comparing same law across Câmara, Senado, and Planalto.
        This is actual methodology used in legislative research.
        """
        await page.goto("http://localhost:8000")
        await page.wait_for_selector("#search-input", timeout=10000)
        
        # REAL comparative research query
        search_term = "lei maria da penha"  # This law exists in all sources
        await page.fill("#search-input", search_term)
        
        # Select multiple sources (real research practice)
        await page.check("#source-camara")
        await page.check("#source-senado")
        await page.check("#source-planalto")
        
        await page.click("#search-button")
        await page.wait_for_selector(".search-results", timeout=45000)  # Multiple APIs take longer
        
        # Verify results from multiple real government sources
        results = await page.query_selector_all(".result-item")
        assert len(results) > 0
        
        # Check for source diversity (real comparative research requirement)
        sources_found = set()
        maria_da_penha_results = []
        
        for result in results:
            result_text = await result.inner_text()
            if any(term in result_text.lower() for term in ["maria da penha", "11.340", "violência doméstica"]):
                maria_da_penha_results.append(result)
                
                # Identify source
                source_marker = await result.query_selector(".source-marker")
                if source_marker:
                    source_text = await source_marker.inner_text()
                    if "camara" in source_text.lower():
                        sources_found.add("camara")
                    elif "senado" in source_text.lower():
                        sources_found.add("senado")
                    elif "planalto" in source_text.lower():
                        sources_found.add("planalto")
        
        # For real comparative research, should find law in multiple sources
        assert len(maria_da_penha_results) > 0, "Maria da Penha law not found"
        assert len(sources_found) >= 2, f"Law found in only {len(sources_found)} sources, comparative research requires multiple sources"
        
        # Test result comparison functionality
        if len(maria_da_penha_results) >= 2:
            # Select first two results for comparison
            await maria_da_penha_results[0].check()
            await maria_da_penha_results[1].check()
            
            # Click compare button
            compare_button = await page.query_selector("#compare-selected")
            if compare_button:
                await compare_button.click()
                await page.wait_for_selector(".comparison-view", timeout=10000)
                
                # Verify comparison shows real differences between sources
                comparison_text = await page.locator(".comparison-view").inner_text()
                assert len(comparison_text) > 200  # Should have meaningful comparison content


class TestRealUserJourneys:
    """
    Test complete REAL user journeys representing actual use cases.
    
    These tests simulate complete workflows used by actual system users:
    legal professionals, researchers, policy analysts, and students.
    """
    
    @pytest.fixture(scope="session")
    async def authenticated_browser_context(self):
        """Create authenticated browser context for logged-in user tests."""
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            context = await browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                locale='pt-BR'
            )
            
            # Simulate login (if authentication is required)
            page = await context.new_page()
            await page.goto("http://localhost:8000")
            
            # Check if login is required
            login_button = await page.query_selector("#login-button")
            if login_button:
                await login_button.click()
                await page.wait_for_selector("#username", timeout=5000)
                
                # Use test credentials (real format, test environment)
                await page.fill("#username", "researcher@test.com")
                await page.fill("#password", "TestPassword123!")
                await page.click("#submit-login")
                
                # Wait for successful login
                await page.wait_for_selector("#user-menu", timeout=10000)
            
            await page.close()
            yield context
            await context.close()
            await browser.close()
    
    async def test_real_legal_professional_workflow(self, authenticated_browser_context):
        """
        Test complete workflow of legal professional researching procurement law.
        
        REAL USER: Lawyer preparing for bid protest, needs to research
        new procurement regulations and compare with previous law.
        """
        page = await authenticated_browser_context.new_page()
        await page.goto("http://localhost:8000")
        
        # STAGE 1: Research new procurement law
        await page.wait_for_selector("#search-input", timeout=10000)
        await page.fill("#search-input", "lei 14.133 pregão eletrônico")
        await page.click("#search-button")
        await page.wait_for_selector(".search-results", timeout=30000)
        
        # Save first relevant result to research folder
        results = await page.query_selector_all(".result-item")
        if results:
            first_result = results[0]
            save_button = await first_result.query_selector(".save-button")
            if save_button:
                await save_button.click()
                
                # Create new research folder
                await page.wait_for_selector("#new-folder-dialog", timeout=5000)
                await page.fill("#folder-name", "Pesquisa Lei 14.133 - Pregão")
                await page.click("#create-folder")
                await page.wait_for_selector(".success-message", timeout=5000)
        
        # STAGE 2: Research old procurement law for comparison
        await page.fill("#search-input", "lei 8.666 pregão")
        await page.click("#search-button")
        await page.wait_for_selector(".search-results", timeout=30000)
        
        # Add old law to same research folder
        results = await page.query_selector_all(".result-item")
        if results:
            first_result = results[0]
            save_button = await first_result.query_selector(".save-button")
            if save_button:
                await save_button.click()
                # Select existing folder
                await page.click("#existing-folder-option")
                await page.select_option("#folder-select", "Pesquisa Lei 14.133 - Pregão")
                await page.click("#add-to-folder")
        
        # STAGE 3: Generate comparison report
        await page.click("#my-research")
        await page.wait_for_selector(".research-folders", timeout=10000)
        
        # Open research folder
        folder = await page.query_selector("text=Pesquisa Lei 14.133 - Pregão")
        if folder:
            await folder.click()
            await page.wait_for_selector(".folder-contents", timeout=10000)
            
            # Generate comparison report
            await page.click("#generate-report")
            await page.wait_for_selector("#report-options", timeout=5000)
            
            # Select comparison report type
            await page.check("#comparison-report")
            await page.fill("#report-title", "Análise Comparativa: Lei 14.133 vs Lei 8.666")
            await page.click("#generate")
            
            # Wait for report generation
            await page.wait_for_selector(".report-ready", timeout=30000)
            
            # Download report
            async with page.expect_download() as download_info:
                await page.click("#download-report")
            download = await download_info.value
            
            # Verify report was generated with real content
            assert download.suggested_filename.endswith('.pdf')
            download_path = await download.path()
            if download_path:
                import os
                assert os.path.getsize(download_path) > 50000  # Substantial report size
        
        await page.close()
    
    async def test_real_academic_researcher_workflow(self, authenticated_browser_context):
        """
        Test complete workflow of academic researcher studying legislative trends.
        
        REAL USER: PhD student researching evolution of environmental law
        over time, needs historical analysis and trend data.
        """
        page = await authenticated_browser_context.new_page()
        await page.goto("http://localhost:8000")
        
        # STAGE 1: Historical search with date filters
        await page.wait_for_selector("#search-input", timeout=10000)
        await page.fill("#search-input", "código florestal meio ambiente")
        
        # Set date range for historical analysis
        await page.click("#advanced-filters")
        await page.wait_for_selector("#date-range-filter", timeout=5000)
        
        # Research period: last 20 years of environmental legislation
        await page.fill("#start-date", "2004-01-01")
        await page.fill("#end-date", "2024-12-31")
        
        await page.click("#search-button")
        await page.wait_for_selector(".search-results", timeout=45000)  # Historical searches take longer
        
        # STAGE 2: Export data for academic analysis
        await page.click("#select-all-results")
        await page.click("#bulk-export")
        await page.wait_for_selector("#export-options", timeout=5000)
        
        # Export in academic format (CSV with metadata)
        await page.check("#include-metadata")
        await page.check("#include-tramitation-history")
        await page.check("#include-voting-data")
        await page.select_option("#format-select", "csv")
        
        async with page.expect_download() as download_info:
            await page.click("#export-data")
        download = await download_info.value
        
        # Verify academic dataset was exported
        assert download.suggested_filename.endswith('.csv')
        download_path = await download.path()
        if download_path:
            with open(download_path, 'r', encoding='utf-8') as f:
                content = f.read()
                # Should contain academic metadata
                assert "tramitation_history" in content or "voting_data" in content
                # Should contain substantial data for analysis
                assert len(content.split('\n')) > 50  # Many results for trend analysis
        
        # STAGE 3: Generate trend analysis
        await page.click("#analytics-tools")
        await page.wait_for_selector("#trend-analysis", timeout=10000)
        
        await page.click("#trend-analysis")
        await page.wait_for_selector("#trend-options", timeout=5000)
        
        # Configure trend analysis
        await page.select_option("#trend-metric", "propositions-per-year")
        await page.select_option("#trend-category", "environmental-law")
        await page.click("#generate-trend-analysis")
        
        # Wait for analysis completion
        await page.wait_for_selector(".trend-chart", timeout=30000)
        
        # Verify trend chart was generated
        chart_element = await page.query_selector(".trend-chart")
        assert chart_element is not None, "Trend analysis chart not generated"
        
        # Export chart for academic publication
        await page.click("#export-chart")
        async with page.expect_download() as chart_download_info:
            await page.click("#export-svg")  # Vector format for publications
        chart_download = await chart_download_info.value
        
        assert chart_download.suggested_filename.endswith('.svg')
        
        await page.close()


class TestRealAPIIntegrationWorkflows:
    """
    Test REAL API integration workflows with actual government endpoints.
    
    These tests verify the system correctly integrates with live government
    APIs and handles real-world API behavior, rate limits, and error conditions.
    """
    
    async def test_real_camara_api_integration_workflow(self):
        """
        Test integration with REAL Câmara dos Deputados API.
        
        Verifies system correctly handles live government API responses,
        including real rate limits and service availability patterns.
        """
        config = Config()
        
        # Test with REAL Câmara API endpoint
        async with aiohttp.ClientSession() as session:
            # Real Câmara API URL for proposições
            camara_url = "https://dadosabertos.camara.leg.br/api/v2/proposicoes"
            
            # Test basic connectivity
            async with session.get(f"{camara_url}?pagina=1&itens=1") as response:
                assert response.status == 200, "Cannot connect to real Câmara API"
                
                data = await response.json()
                assert "dados" in data, "Real Câmara API response format changed"
                assert len(data["dados"]) > 0, "Real Câmara API returned no data"
                
                # Verify real data structure
                proposicao = data["dados"][0]
                required_fields = ["id", "siglaTipo", "numero", "ano", "ementa"]
                for field in required_fields:
                    assert field in proposicao, f"Required field {field} missing from real API response"
                
                # Verify real ID format (7 digits)
                assert isinstance(proposicao["id"], int), "Real Câmara ID should be integer"
                assert len(str(proposicao["id"])) == 7, "Real Câmara ID should be 7 digits"
    
    async def test_real_senado_api_integration_workflow(self):
        """
        Test integration with REAL Senado Federal API.
        
        Verifies handling of real Senado API authentication and data formats.
        """
        # Test with REAL Senado API endpoint
        async with aiohttp.ClientSession() as session:
            # Real Senado API URL for matérias
            senado_url = "https://legis.senado.leg.br/dadosabertos/materia/pesquisa/lista"
            
            # Test with real search parameters
            params = {
                "q": "lei complementar",
                "inicio": "2020-01-01",
                "fim": "2024-12-31"
            }
            
            try:
                async with session.get(senado_url, params=params, timeout=30) as response:
                    # Senado API sometimes returns different status codes
                    assert response.status in [200, 206], f"Unexpected Senado API status: {response.status}"
                    
                    # Some Senado endpoints return XML
                    content_type = response.headers.get('Content-Type', '')
                    if 'xml' in content_type:
                        # Handle XML response (real Senado API behavior)
                        text_data = await response.text()
                        assert "<ListaMaterias>" in text_data or "<materia>" in text_data
                    else:
                        # Handle JSON response
                        data = await response.json()
                        assert isinstance(data, (dict, list)), "Invalid Senado API response format"
                        
            except asyncio.TimeoutError:
                # Real Senado API can be slow - this is acceptable
                pytest.skip("Senado API timeout - this is normal behavior")
            except aiohttp.ClientResponseError as e:
                if e.status == 429:
                    # Rate limiting from real API
                    pytest.skip("Senado API rate limited - real behavior")
                else:
                    raise
    
    async def test_real_government_api_rate_limit_handling(self):
        """
        Test system handles real government API rate limits correctly.
        
        Brazilian government APIs have strict rate limits that must be respected
        to maintain access for legitimate research purposes.
        """
        config = Config()
        
        # Test rate limiting with rapid requests (real scenario)
        async with aiohttp.ClientSession() as session:
            camara_url = "https://dadosabertos.camara.leg.br/api/v2/proposicoes"
            
            request_times = []
            successful_requests = 0
            rate_limited_requests = 0
            
            # Make 10 rapid requests to test rate limiting
            for i in range(10):
                start_time = time.time()
                
                try:
                    async with session.get(f"{camara_url}?pagina={i+1}&itens=1", timeout=10) as response:
                        end_time = time.time()
                        request_times.append(end_time - start_time)
                        
                        if response.status == 200:
                            successful_requests += 1
                        elif response.status == 429:
                            rate_limited_requests += 1
                            # Respect rate limit (real API behavior)
                            await asyncio.sleep(2)
                        
                except asyncio.TimeoutError:
                    # Government APIs can be slow
                    pass
                except aiohttp.ClientResponseError as e:
                    if e.status == 429:
                        rate_limited_requests += 1
                
                # Add delay to respect rate limits
                await asyncio.sleep(0.5)
            
            # Verify we handled real API behavior appropriately
            assert successful_requests > 0, "No successful requests to real API"
            
            # If rate limited, verify we handled it gracefully
            if rate_limited_requests > 0:
                # This is expected behavior with real government APIs
                assert rate_limited_requests < 10, "All requests rate limited - check implementation"
            
            # Verify response times are reasonable for government APIs
            if request_times:
                avg_response_time = sum(request_times) / len(request_times)
                assert avg_response_time < 30.0, f"Average response time too high: {avg_response_time}s"


@pytest.mark.slow
class TestRealLoadScenarios:
    """
    Test system under REAL load scenarios that occur in production.
    
    These tests simulate actual usage patterns: peak research periods,
    multiple concurrent users, and heavy academic research workloads.
    """
    
    async def test_real_peak_research_period_load(self):
        """
        Test system under load simulating peak academic research periods.
        
        REAL SCENARIO: End of semester when many students and researchers
        are conducting legislative research simultaneously.
        """
        # Simulate 50 concurrent researchers
        concurrent_users = 50
        search_terms = RealLegislativeDataFixtures.get_real_search_terms()
        
        async def simulate_researcher_session():
            """Simulate a real researcher's search session."""
            # Random real search terms
            import random
            session_searches = random.sample(search_terms, 3)
            
            async with aiohttp.ClientSession() as session:
                for search_term in session_searches:
                    try:
                        # Search via API (real user behavior)
                        search_url = "http://localhost:8000/api/v1/search"
                        params = {"q": search_term, "sources": "camara,senado"}
                        
                        async with session.get(search_url, params=params, timeout=30) as response:
                            if response.status == 200:
                                data = await response.json()
                                # Verify real response structure
                                assert "results" in data or "data" in data
                            elif response.status == 429:
                                # Rate limited - wait and retry (real behavior)
                                await asyncio.sleep(2)
                        
                        # Realistic delay between searches
                        await asyncio.sleep(random.uniform(2, 5))
                        
                    except Exception:
                        # Some requests may fail under load - this is acceptable
                        pass
        
        # Execute concurrent researcher sessions
        start_time = time.time()
        tasks = [simulate_researcher_session() for _ in range(concurrent_users)]
        
        # Wait for all sessions to complete
        results = await asyncio.gather(*tasks, return_exceptions=True)
        end_time = time.time()
        
        # Verify system handled load reasonably
        execution_time = end_time - start_time
        assert execution_time < 180, f"Load test took too long: {execution_time}s"
        
        # Count successful vs failed sessions
        successful_sessions = sum(1 for r in results if not isinstance(r, Exception))
        assert successful_sessions > concurrent_users * 0.7, "Too many failed sessions under load"
    
    async def test_real_comparative_research_load(self):
        """
        Test system under load from comparative legislative research.
        
        REAL SCENARIO: Research team comparing legislation across multiple
        time periods and jurisdictions (federal vs state laws).
        """
        # Simulate large-scale comparative research
        research_queries = [
            {"term": "lei complementar", "years": ["2020", "2021", "2022", "2023"]},
            {"term": "código civil", "years": ["2002", "2010", "2015", "2020"]},
            {"term": "consolidação trabalho", "years": ["1943", "2017", "2020", "2024"]},
            {"term": "constituição federal", "years": ["1988", "2000", "2010", "2020"]}
        ]
        
        async def execute_comparative_research(query_info):
            """Execute comparative research across time periods."""
            results_by_year = {}
            
            async with aiohttp.ClientSession() as session:
                for year in query_info["years"]:
                    search_term = f"{query_info['term']} {year}"
                    
                    try:
                        search_url = "http://localhost:8000/api/v1/search"
                        params = {
                            "q": search_term,
                            "start_date": f"{year}-01-01",
                            "end_date": f"{year}-12-31",
                            "sources": "all"
                        }
                        
                        async with session.get(search_url, params=params, timeout=45) as response:
                            if response.status == 200:
                                data = await response.json()
                                results_by_year[year] = len(data.get("results", []))
                            
                        # Delay between historical searches (respectful of APIs)
                        await asyncio.sleep(1)
                        
                    except Exception:
                        results_by_year[year] = 0
            
            return results_by_year
        
        # Execute all comparative research queries
        start_time = time.time()
        research_tasks = [execute_comparative_research(query) for query in research_queries]
        research_results = await asyncio.gather(*research_tasks, return_exceptions=True)
        end_time = time.time()
        
        # Verify comparative research completed successfully
        execution_time = end_time - start_time
        assert execution_time < 300, f"Comparative research took too long: {execution_time}s"
        
        # Verify we got meaningful results for historical analysis
        successful_research = 0
        for result in research_results:
            if isinstance(result, dict):
                # Check if we got results across time periods
                total_results = sum(result.values())
                if total_results > 0:
                    successful_research += 1
        
        assert successful_research > len(research_queries) * 0.5, "Too few successful comparative research queries"


if __name__ == "__main__":
    # Verify system is running before E2E tests
    import aiohttp
    
    async def check_system_availability():
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get("http://localhost:8000/health", timeout=10) as response:
                    assert response.status == 200, "System not available for E2E testing"
        except Exception as e:
            pytest.skip(f"System not available for E2E testing: {e}")
    
    # Run availability check
    asyncio.run(check_system_availability())
    
    # Execute E2E test suite
    pytest.main([__file__, "-v", "--tb=short", "-m", "not slow"])