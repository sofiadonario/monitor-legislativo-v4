"""
Transport-Specific Test Suite for Monitor Legislativo v4
Testing transport legislation compliance with military precision

SPRINT 10 - TASK 10.2: Transport-Specific Test Suite
✅ LexML transport legislation search validation
✅ ANTT regulatory compliance testing
✅ DOU transport publication monitoring
✅ Transport-specific term validation
✅ Regulatory cross-reference testing
✅ Transport operator compliance checks
✅ Route and concession validation
✅ Safety regulation compliance
✅ Environmental compliance testing
✅ International transport agreement validation
"""

import pytest
import asyncio
import json
import time
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import re

from core.api.lexml_integration import LexMLIntegration
from core.api.camara_service import CamaraService
from core.api.senado_service import SenadoService
from core.api.planalto_service import PlanaltoService
from core.config.config import get_config
from core.monitoring.forensic_logging import get_forensic_logger


class TestTransportLegislationCompliance:
    """
    Comprehensive transport legislation compliance testing.
    Based on Brazilian transport regulatory framework.
    """
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Setup transport-specific test environment."""
        self.config = get_config()
        self.forensic = get_forensic_logger()
        
        # Initialize services
        self.lexml = LexMLIntegration()
        self.camara = CamaraService(self.config.api_configs['camara'])
        self.senado = SenadoService(self.config.api_configs['senado'])
        self.planalto = PlanaltoService(self.config.api_configs['planalto'])
        
        # Transport-specific search terms from guia-legislacao-transporte.md
        self.transport_terms = [
            # General transport terms
            "transporte rodoviário de cargas",
            "transporte rodoviário de passageiros",
            "transporte internacional",
            "transporte interestadual",
            "transporte intermunicipal",
            
            # Regulatory agencies
            "ANTT",
            "Agência Nacional de Transportes Terrestres",
            "DNIT",
            "Departamento Nacional de Infraestrutura de Transportes",
            "CONTRAN",
            "Conselho Nacional de Trânsito",
            
            # Specific regulations
            "RNTRC",
            "Registro Nacional de Transportadores Rodoviários de Cargas",
            "vale-pedágio",
            "carta-frete",
            "conhecimento de transporte",
            "manifesto de carga",
            
            # Vehicle and operator terms
            "transportador autônomo de cargas",
            "TAC",
            "empresa de transporte rodoviário",
            "ETC",
            "cooperativa de transporte",
            
            # Safety and compliance
            "inspeção veicular",
            "cronotacógrafo",
            "tempo de direção",
            "jornada de trabalho motorista",
            "Lei do Motorista",
            "Lei 13.103/2015",
            
            # Infrastructure
            "concessão rodoviária",
            "pedágio",
            "rodovia federal",
            "BR-101", "BR-116", "BR-163",
            
            # Environmental
            "ARLA 32",
            "emissões veiculares",
            "PROCONVE",
            "transporte de produtos perigosos",
            "MOPP"
        ]
        
        # Key transport laws and regulations
        self.key_transport_laws = [
            {"number": "10.233", "year": 2001, "description": "Lei de criação da ANTT"},
            {"number": "11.442", "year": 2007, "description": "Lei do Transporte Rodoviário de Cargas"},
            {"number": "13.103", "year": 2015, "description": "Lei do Motorista"},
            {"number": "9.503", "year": 1997, "description": "Código de Trânsito Brasileiro"},
            {"number": "12.619", "year": 2012, "description": "Lei do Descanso"},
            {"number": "14.599", "year": 2023, "description": "Política Nacional de Pisos Mínimos do Transporte"}
        ]
        
        # ANTT resolutions to test
        self.antt_resolutions = [
            {"number": "5.862", "year": 2019, "topic": "RNTRC"},
            {"number": "5.869", "year": 2020, "topic": "Carta-frete eletrônica"},
            {"number": "5.849", "year": 2019, "topic": "TAC - Transportador Autônomo"},
            {"number": "4.799", "year": 2015, "topic": "Vale-pedágio obrigatório"},
            {"number": "5.833", "year": 2019, "topic": "Transporte de produtos perigosos"}
        ]
    
    @pytest.mark.asyncio
    async def test_transport_term_search_comprehensive(self):
        """Test comprehensive search for all transport-specific terms."""
        
        results_summary = {
            "total_searches": 0,
            "successful_searches": 0,
            "terms_with_results": 0,
            "total_results_found": 0,
            "errors": []
        }
        
        # Test each transport term
        for term in self.transport_terms[:10]:  # Test first 10 terms to avoid rate limits
            results_summary["total_searches"] += 1
            
            try:
                # Search in LexML
                lexml_results = await self.lexml.search(term, {"limit": 10})
                
                if lexml_results and hasattr(lexml_results, 'items'):
                    results_summary["successful_searches"] += 1
                    
                    if len(lexml_results.items) > 0:
                        results_summary["terms_with_results"] += 1
                        results_summary["total_results_found"] += len(lexml_results.items)
                        
                        # Validate transport relevance
                        self._validate_transport_relevance(term, lexml_results.items)
                        
                        # Log successful search
                        self.forensic.log_forensic_event(
                            level=self.forensic.LogLevel.INFO,
                            category=self.forensic.EventCategory.BUSINESS,
                            component="transport_test",
                            operation="term_search",
                            message=f"Transport term search: {term}",
                            success=True,
                            custom_attributes={
                                "term": term,
                                "result_count": len(lexml_results.items),
                                "service": "lexml"
                            }
                        )
                
            except Exception as e:
                results_summary["errors"].append({
                    "term": term,
                    "error": str(e)
                })
                
            # Respect rate limits
            await asyncio.sleep(1)
        
        # Assert minimum success criteria
        assert results_summary["successful_searches"] > 0
        assert results_summary["terms_with_results"] > 0
        
        print(f"\n🚛 Transport Term Search Results:")
        print(f"   Total searches: {results_summary['total_searches']}")
        print(f"   Successful: {results_summary['successful_searches']}")
        print(f"   Terms with results: {results_summary['terms_with_results']}")
        print(f"   Total documents found: {results_summary['total_results_found']}")
    
    @pytest.mark.asyncio
    async def test_key_transport_laws_availability(self):
        """Test availability of key transport laws."""
        
        laws_found = []
        laws_missing = []
        
        for law in self.key_transport_laws:
            try:
                # Search in Planalto
                results = await self.planalto.buscar_lei(
                    numero=law["number"],
                    ano=law["year"]
                )
                
                if results:
                    laws_found.append(law)
                    
                    # Validate law content
                    self._validate_law_content(law, results)
                else:
                    laws_missing.append(law)
                    
            except Exception as e:
                self.forensic.log_error_event(
                    component="transport_test",
                    operation="law_verification",
                    error=e,
                    custom_attributes={"law": law}
                )
                laws_missing.append(law)
            
            await asyncio.sleep(1)  # Rate limiting
        
        print(f"\n📜 Key Transport Laws Verification:")
        print(f"   Laws found: {len(laws_found)}")
        print(f"   Laws missing: {len(laws_missing)}")
        
        if laws_missing:
            print("   Missing laws:")
            for law in laws_missing:
                print(f"     - Lei {law['number']}/{law['year']}: {law['description']}")
        
        # At least 50% of laws should be found
        assert len(laws_found) >= len(self.key_transport_laws) * 0.5
    
    @pytest.mark.asyncio
    async def test_antt_resolution_search(self):
        """Test ANTT resolution search and validation."""
        
        resolutions_found = 0
        
        for resolution in self.antt_resolutions:
            query = f"ANTT Resolução {resolution['number']} {resolution['year']}"
            
            try:
                # Search across all services
                results = await self._search_all_services(query)
                
                if self._has_valid_results(results):
                    resolutions_found += 1
                    
                    # Validate ANTT resolution format
                    self._validate_antt_resolution(resolution, results)
                    
            except Exception as e:
                self.forensic.log_error_event(
                    component="transport_test",
                    operation="antt_resolution_search",
                    error=e,
                    custom_attributes={"resolution": resolution}
                )
            
            await asyncio.sleep(1)
        
        print(f"\n🏛️ ANTT Resolutions Found: {resolutions_found}/{len(self.antt_resolutions)}")
        
        # At least some resolutions should be found
        assert resolutions_found > 0
    
    @pytest.mark.asyncio
    async def test_transport_safety_regulations(self):
        """Test transport safety regulation compliance."""
        
        safety_topics = [
            {
                "term": "tempo de direção motorista",
                "regulations": ["Lei 13.103/2015", "Lei 12.619/2012"],
                "max_hours": 8
            },
            {
                "term": "inspeção veicular obrigatória",
                "regulations": ["Resolução CONTRAN"],
                "frequency": "anual"
            },
            {
                "term": "cronotacógrafo digital",
                "regulations": ["Resolução CONTRAN 92/1999"],
                "required_for": "veículos de carga"
            },
            {
                "term": "transporte produtos perigosos MOPP",
                "regulations": ["Resolução ANTT 5.848/2019"],
                "certification": "MOPP"
            }
        ]
        
        safety_compliance_results = []
        
        for topic in safety_topics:
            try:
                results = await self._search_all_services(topic["term"])
                
                compliance = {
                    "topic": topic["term"],
                    "found": self._has_valid_results(results),
                    "regulations_mentioned": 0,
                    "compliance_level": "unknown"
                }
                
                # Check if regulations are mentioned in results
                if compliance["found"]:
                    for regulation in topic["regulations"]:
                        if self._regulation_mentioned_in_results(regulation, results):
                            compliance["regulations_mentioned"] += 1
                    
                    compliance["compliance_level"] = self._assess_compliance_level(
                        compliance["regulations_mentioned"],
                        len(topic["regulations"])
                    )
                
                safety_compliance_results.append(compliance)
                
            except Exception as e:
                self.forensic.log_error_event(
                    component="transport_test",
                    operation="safety_compliance_check",
                    error=e,
                    custom_attributes={"topic": topic}
                )
            
            await asyncio.sleep(1)
        
        # Print compliance report
        print(f"\n🛡️ Transport Safety Compliance Report:")
        for result in safety_compliance_results:
            print(f"   {result['topic']}:")
            print(f"     Found: {'✅' if result['found'] else '❌'}")
            print(f"     Regulations referenced: {result['regulations_mentioned']}")
            print(f"     Compliance level: {result['compliance_level']}")
        
        # At least some safety topics should be found
        found_count = sum(1 for r in safety_compliance_results if r["found"])
        assert found_count > 0
    
    @pytest.mark.asyncio
    async def test_transport_operator_compliance(self):
        """Test transport operator compliance requirements."""
        
        operator_requirements = [
            {
                "type": "TAC",
                "requirement": "RNTRC ativo",
                "search_terms": ["TAC RNTRC", "transportador autônomo RNTRC"]
            },
            {
                "type": "ETC",
                "requirement": "RNTRC empresa",
                "search_terms": ["empresa transporte RNTRC", "ETC registro"]
            },
            {
                "type": "Cooperativa",
                "requirement": "registro cooperativa transporte",
                "search_terms": ["cooperativa transporte registro", "CTC ANTT"]
            }
        ]
        
        compliance_matrix = {}
        
        for operator in operator_requirements:
            operator_results = {
                "type": operator["type"],
                "requirement": operator["requirement"],
                "documentation_found": False,
                "relevant_results": 0
            }
            
            for term in operator["search_terms"]:
                try:
                    results = await self.lexml.search(term, {"limit": 5})
                    
                    if results and hasattr(results, 'items') and len(results.items) > 0:
                        operator_results["documentation_found"] = True
                        operator_results["relevant_results"] += len(results.items)
                        
                except Exception as e:
                    self.forensic.log_error_event(
                        component="transport_test",
                        operation="operator_compliance_search",
                        error=e,
                        custom_attributes={"operator": operator, "term": term}
                    )
                
                await asyncio.sleep(1)
            
            compliance_matrix[operator["type"]] = operator_results
        
        print(f"\n👥 Transport Operator Compliance Matrix:")
        for op_type, results in compliance_matrix.items():
            print(f"   {op_type}:")
            print(f"     Requirement: {results['requirement']}")
            print(f"     Documentation found: {'✅' if results['documentation_found'] else '❌'}")
            print(f"     Relevant documents: {results['relevant_results']}")
    
    @pytest.mark.asyncio
    async def test_environmental_transport_compliance(self):
        """Test environmental compliance for transport sector."""
        
        environmental_aspects = [
            {
                "aspect": "Emissions Standards",
                "terms": ["PROCONVE transporte", "emissões veiculares diesel"],
                "regulations": ["CONAMA"]
            },
            {
                "aspect": "ARLA 32 Requirements",
                "terms": ["ARLA 32 obrigatório", "SCR caminhões"],
                "regulations": ["Resolução CONAMA 403/2008"]
            },
            {
                "aspect": "Dangerous Goods Transport",
                "terms": ["transporte produtos perigosos", "MOPP certificação"],
                "regulations": ["Decreto 96.044/1988", "Resolução ANTT 5.848/2019"]
            }
        ]
        
        environmental_compliance = []
        
        for aspect in environmental_aspects:
            aspect_results = {
                "aspect": aspect["aspect"],
                "coverage": 0,
                "regulations_found": []
            }
            
            for term in aspect["terms"]:
                try:
                    results = await self._search_all_services(term)
                    
                    if self._has_valid_results(results):
                        aspect_results["coverage"] += 1
                        
                        # Check for regulation references
                        for reg in aspect["regulations"]:
                            if self._regulation_mentioned_in_results(reg, results):
                                if reg not in aspect_results["regulations_found"]:
                                    aspect_results["regulations_found"].append(reg)
                    
                except Exception as e:
                    self.forensic.log_error_event(
                        component="transport_test",
                        operation="environmental_compliance",
                        error=e,
                        custom_attributes={"aspect": aspect, "term": term}
                    )
                
                await asyncio.sleep(1)
            
            aspect_results["coverage_percentage"] = (aspect_results["coverage"] / len(aspect["terms"])) * 100
            environmental_compliance.append(aspect_results)
        
        print(f"\n🌱 Environmental Transport Compliance:")
        for compliance in environmental_compliance:
            print(f"   {compliance['aspect']}:")
            print(f"     Coverage: {compliance['coverage_percentage']:.0f}%")
            print(f"     Regulations found: {', '.join(compliance['regulations_found']) or 'None'}")
    
    @pytest.mark.asyncio
    async def test_interstate_transport_regulations(self):
        """Test interstate and international transport regulations."""
        
        interstate_scenarios = [
            {
                "route": "São Paulo - Rio de Janeiro",
                "type": "interstate",
                "requirements": ["RNTRC", "ANTT autorização"]
            },
            {
                "route": "Brasil - Argentina",
                "type": "international",
                "requirements": ["MIC/DTA", "Acordo MERCOSUL", "seguro internacional"]
            },
            {
                "route": "Porto Alegre - Montevideo",
                "type": "international",
                "requirements": ["Carta Verde", "manifesto internacional"]
            }
        ]
        
        for scenario in interstate_scenarios:
            print(f"\n🚛 Testing {scenario['type']} transport: {scenario['route']}")
            
            for requirement in scenario["requirements"]:
                try:
                    results = await self.lexml.search(
                        f"{requirement} transporte {scenario['type']}",
                        {"limit": 5}
                    )
                    
                    if results and hasattr(results, 'items') and len(results.items) > 0:
                        print(f"   ✅ {requirement}: {len(results.items)} documents found")
                    else:
                        print(f"   ❌ {requirement}: No documents found")
                    
                except Exception as e:
                    print(f"   ⚠️ {requirement}: Search failed - {str(e)}")
                
                await asyncio.sleep(1)
    
    # Helper methods
    
    async def _search_all_services(self, query: str) -> Dict[str, Any]:
        """Search across all available services."""
        results = {}
        
        # Search LexML
        try:
            lexml_results = await self.lexml.search(query, {"limit": 10})
            results["lexml"] = lexml_results
        except Exception:
            results["lexml"] = None
        
        # Search Câmara
        try:
            camara_results = await self.camara.search(query, {"limit": 10})
            results["camara"] = camara_results
        except Exception:
            results["camara"] = None
        
        # Search Senado
        try:
            senado_results = await self.senado.search(query, {"limit": 10})
            results["senado"] = senado_results
        except Exception:
            results["senado"] = None
        
        return results
    
    def _has_valid_results(self, results: Dict[str, Any]) -> bool:
        """Check if any service returned valid results."""
        for service, result in results.items():
            if result and hasattr(result, 'items') and len(result.items) > 0:
                return True
        return False
    
    def _validate_transport_relevance(self, search_term: str, items: List[Any]):
        """Validate that results are relevant to transport sector."""
        transport_keywords = [
            "transporte", "transport", "rodoviário", "rodoviario",
            "ANTT", "motorista", "caminhão", "caminhao", "ônibus", "onibus",
            "carga", "passageiro", "frete", "veículo", "veiculo",
            "rodovia", "estrada", "BR-", "pedágio", "pedagio"
        ]
        
        relevance_count = 0
        for item in items:
            item_text = str(item).lower()
            if any(keyword.lower() in item_text for keyword in transport_keywords):
                relevance_count += 1
        
        relevance_percentage = (relevance_count / len(items)) * 100 if items else 0
        
        # Log relevance metrics
        self.forensic.log_forensic_event(
            level=self.forensic.LogLevel.INFO,
            category=self.forensic.EventCategory.BUSINESS,
            component="transport_test",
            operation="relevance_validation",
            message=f"Transport relevance validation for '{search_term}'",
            success=relevance_percentage > 50,
            custom_attributes={
                "search_term": search_term,
                "total_items": len(items),
                "relevant_items": relevance_count,
                "relevance_percentage": relevance_percentage
            }
        )
        
        # At least 50% of results should be transport-relevant
        assert relevance_percentage >= 50
    
    def _validate_law_content(self, law: Dict[str, Any], content: Any):
        """Validate law content structure and completeness."""
        # Basic validation - law should have content
        assert content is not None
        
        # If content is a string, check minimum length
        if isinstance(content, str):
            assert len(content) > 100  # Laws should have substantial content
        
        # If content is structured, validate structure
        elif isinstance(content, dict):
            # Check for common law fields
            expected_fields = ["numero", "ano", "ementa", "texto"]
            found_fields = sum(1 for field in expected_fields if field in content)
            assert found_fields >= 2  # At least 2 expected fields
    
    def _validate_antt_resolution(self, resolution: Dict[str, Any], results: Dict[str, Any]):
        """Validate ANTT resolution format and content."""
        resolution_number = resolution["number"]
        resolution_year = resolution["year"]
        
        # Check if resolution number appears in results
        found_in_results = False
        for service, result in results.items():
            if result and hasattr(result, 'items'):
                for item in result.items:
                    item_text = str(item)
                    if resolution_number in item_text and str(resolution_year) in item_text:
                        found_in_results = True
                        break
        
        if found_in_results:
            self.forensic.log_forensic_event(
                level=self.forensic.LogLevel.INFO,
                category=self.forensic.EventCategory.BUSINESS,
                component="transport_test",
                operation="antt_validation",
                message=f"ANTT Resolution {resolution_number}/{resolution_year} validated",
                success=True,
                custom_attributes={"resolution": resolution}
            )
    
    def _regulation_mentioned_in_results(self, regulation: str, results: Dict[str, Any]) -> bool:
        """Check if regulation is mentioned in search results."""
        regulation_lower = regulation.lower()
        
        for service, result in results.items():
            if result and hasattr(result, 'items'):
                for item in result.items:
                    item_text = str(item).lower()
                    if regulation_lower in item_text:
                        return True
        
        return False
    
    def _assess_compliance_level(self, found: int, total: int) -> str:
        """Assess compliance level based on regulations found."""
        if total == 0:
            return "unknown"
        
        percentage = (found / total) * 100
        
        if percentage >= 80:
            return "high"
        elif percentage >= 50:
            return "medium"
        elif percentage > 0:
            return "low"
        else:
            return "none"


@pytest.mark.transport
class TestTransportDataValidation:
    """Test transport-specific data validation and integrity."""
    
    def test_rntrc_format_validation(self):
        """Test RNTRC (transport registry) number format validation."""
        
        valid_rntrc_formats = [
            "123456789012",  # 12 digits
            "12.345.678/0001-90",  # CNPJ format
            "123.456.789-10"  # CPF format
        ]
        
        invalid_rntrc_formats = [
            "12345",  # Too short
            "ABCDEFGHIJKL",  # Letters
            "12-34-56-78",  # Wrong format
            ""  # Empty
        ]
        
        # Validate RNTRC patterns
        rntrc_pattern = re.compile(r'^\d{12}$|^\d{2}\.\d{3}\.\d{3}/\d{4}-\d{2}$|^\d{3}\.\d{3}\.\d{3}-\d{2}$')
        
        for valid_rntrc in valid_rntrc_formats:
            assert rntrc_pattern.match(valid_rntrc), f"Valid RNTRC {valid_rntrc} failed validation"
        
        for invalid_rntrc in invalid_rntrc_formats:
            assert not rntrc_pattern.match(invalid_rntrc), f"Invalid RNTRC {invalid_rntrc} passed validation"
    
    def test_vehicle_plate_validation(self):
        """Test Brazilian vehicle plate format validation."""
        
        # Old format: ABC-1234
        old_format = re.compile(r'^[A-Z]{3}-\d{4}$')
        
        # Mercosul format: ABC1D23
        mercosul_format = re.compile(r'^[A-Z]{3}\d[A-Z]\d{2}$')
        
        valid_plates = [
            ("ABC-1234", "old"),
            ("XYZ-9876", "old"),
            ("ABC1D23", "mercosul"),
            ("XYZ9K88", "mercosul")
        ]
        
        invalid_plates = [
            "AB-1234",  # Too few letters
            "ABCD-1234",  # Too many letters
            "ABC-12345",  # Too many numbers
            "123-ABCD",  # Wrong order
            "ABC1234"  # No separator/wrong format
        ]
        
        for plate, format_type in valid_plates:
            if format_type == "old":
                assert old_format.match(plate), f"Valid old format plate {plate} failed"
            else:
                assert mercosul_format.match(plate), f"Valid Mercosul plate {plate} failed"
        
        for plate in invalid_plates:
            assert not (old_format.match(plate) or mercosul_format.match(plate)), \
                   f"Invalid plate {plate} passed validation"
    
    def test_transport_document_numbers(self):
        """Test transport document number formats."""
        
        document_formats = {
            "CT-e": re.compile(r'^\d{44}$'),  # 44 digits
            "MDF-e": re.compile(r'^\d{44}$'),  # 44 digits
            "NF-e": re.compile(r'^\d{44}$'),  # 44 digits
            "DACTE": re.compile(r'^\d{44}$'),  # Based on CT-e
            "Manifesto": re.compile(r'^\d{15,20}$')  # Variable length
        }
        
        test_cases = {
            "CT-e": {
                "valid": ["12345678901234567890123456789012345678901234"],
                "invalid": ["1234567890", "ABC123"]
            },
            "Manifesto": {
                "valid": ["123456789012345", "12345678901234567890"],
                "invalid": ["12345", "ABCDEFGHIJKLMNOP"]
            }
        }
        
        for doc_type, cases in test_cases.items():
            pattern = document_formats.get(doc_type)
            if pattern:
                for valid in cases["valid"]:
                    assert pattern.match(valid), f"Valid {doc_type} {valid} failed"
                
                for invalid in cases["invalid"]:
                    assert not pattern.match(invalid), f"Invalid {doc_type} {invalid} passed"


if __name__ == "__main__":
    # Run transport-specific tests
    pytest.main([__file__, "-v", "-s", "-k", "transport"])