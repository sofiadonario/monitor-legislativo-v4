#!/usr/bin/env python3
"""
Sistema de Classificação Refinado para LexML
Implementa classificação hierárquica em três níveis: Categoria → Tipo → Subtipo
"""

import re
import json
import logging
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime
import pandas as pd

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class RefinedDocumentClassifier:
    """
    Sistema de classificação refinado para documentos LexML
    Implementa classificação hierárquica em três níveis
    """
    
    def __init__(self):
        self.legislation_patterns = self._load_legislation_patterns()
        self.jurisprudence_patterns = self._load_jurisprudence_patterns()
        self.doctrine_patterns = self._load_doctrine_patterns()
        self.thematic_subtypes = self._load_thematic_subtypes()
        
    def classify_document(self, urn: str, title: str, document_summary: str, 
                         document_type_original: str = "") -> Dict:
        """
        Classifica documento em categoria, tipo e subtipo
        """
        
        # Classificação de primeiro nível (categoria principal)
        main_category = self._classify_main_category(urn, title, document_summary)
        
        # Classificação de segundo nível (tipo)
        document_type = self._classify_type(main_category, urn, title, document_summary)
        
        # Classificação de terceiro nível (subtipo)
        document_subtype = self._classify_subtype(main_category, document_type, urn, title, document_summary)
        
        # Calcular confiança
        confidence = self._calculate_confidence(urn, title, document_summary)
        
        return {
            'main_category': main_category,
            'document_type': document_type,
            'document_subtype': document_subtype,
            'classification_confidence': confidence,
            'classification_timestamp': datetime.now().isoformat()
        }
    
    def _classify_main_category(self, urn: str, title: str, document_summary: str) -> str:
        """
        Classifica categoria principal: legislation, jurisprudence, doctrine
        """
        
        urn_lower = urn.lower()
        
        # Padrões de legislação
        legislation_indicators = [
            'lei', 'decreto', 'portaria', 'resolucao', 'instrucao.normativa',
            'medida.provisoria', 'decreto.legislativo', 'emenda.constitucional',
            'lei.complementar', 'lei.ordinaria'
        ]
        
        # Padrões de jurisprudência
        jurisprudence_indicators = [
            'jurisprudencia', 'acordao', 'decisao', 'sentenca', 'sumula',
            'recurso', 'apelacao', 'agravo', 'embargos', 'mandado.seguranca'
        ]
        
        # Padrões de doutrina
        doctrine_indicators = [
            'artigo', 'livro', 'tese', 'dissertacao', 'parecer', 'estudo',
            'relatorio', 'manual', 'capitulo'
        ]
        
        # Verificação por URN (mais confiável)
        for indicator in legislation_indicators:
            if indicator in urn_lower:
                return 'legislation'
        
        for indicator in jurisprudence_indicators:
            if indicator in urn_lower:
                return 'jurisprudence'
        
        for indicator in doctrine_indicators:
            if indicator in urn_lower:
                return 'doctrine'
        
        # Verificação por conteúdo textual
        text_content = f"{title} {document_summary}".lower()
        
        # Contadores de indicadores
        leg_count = sum(1 for indicator in legislation_indicators 
                       if indicator.replace('.', ' ') in text_content)
        jur_count = sum(1 for indicator in jurisprudence_indicators 
                       if indicator.replace('.', ' ') in text_content)
        doc_count = sum(1 for indicator in doctrine_indicators 
                       if indicator.replace('.', ' ') in text_content)
        
        # Decisão baseada no maior score
        scores = {'legislation': leg_count, 'jurisprudence': jur_count, 'doctrine': doc_count}
        max_category = max(scores, key=scores.get)
        
        if scores[max_category] > 0:
            return max_category
        else:
            return 'other'
    
    def _classify_type(self, main_category: str, urn: str, title: str, document_summary: str) -> str:
        """
        Classifica tipo específico baseado na categoria principal
        """
        
        if main_category == 'legislation':
            return self._classify_legislation_type(urn, title, document_summary)
        elif main_category == 'jurisprudence':
            return self._classify_jurisprudence_type(urn, title, document_summary)
        elif main_category == 'doctrine':
            return self._classify_doctrine_type(urn, title, document_summary)
        else:
            return 'other'
    
    def _classify_legislation_type(self, urn: str, title: str, document_summary: str) -> str:
        """
        Classifica tipos específicos de legislação
        """
        
        urn_lower = urn.lower()
        text_content = f"{title} {document_summary}".lower()
        
        # Padrões específicos de legislação
        legislation_types = {
            'lei_ordinaria': ['lei:', 'lei.ordinaria', 'lei.federal'],
            'lei_complementar': ['lei.complementar', 'lc.', 'lei complementar'],
            'medida_provisoria': ['medida.provisoria', 'mp.', 'mp:', 'medida provisória'],
            'decreto_presidencial': ['decreto:', 'decreto.presidencial', 'decreto federal'],
            'decreto_legislativo': ['decreto.legislativo', 'decreto.do.congresso'],
            'portaria_ministerial': ['portaria:', 'portaria.ministerial'],
            'resolucao_agencia': ['resolucao:', 'resolucao.antt', 'resolucao.anp', 'resolucao.aneel'],
            'instrucao_normativa': ['instrucao.normativa', 'in.', 'instrução normativa'],
            'emenda_constitucional': ['emenda.constitucional', 'ec.', 'emenda constitucional'],
            'lei_estadual': ['lei.estadual', 'estado', 'governo.estadual'],
            'lei_municipal': ['lei.municipal', 'municipio', 'prefeitura'],
            'decreto_estadual': ['decreto.estadual', 'governador'],
            'decreto_municipal': ['decreto.municipal', 'prefeito'],
            'portaria_estadual': ['portaria.estadual'],
            'portaria_municipal': ['portaria.municipal']
        }
        
        # Verificação por URN (prioridade)
        for leg_type, patterns in legislation_types.items():
            for pattern in patterns:
                if pattern in urn_lower:
                    return leg_type
        
        # Verificação por conteúdo textual
        for leg_type, patterns in legislation_types.items():
            score = sum(1 for pattern in patterns 
                       if pattern.replace('.', ' ') in text_content)
            if score > 0:
                return leg_type
        
        return 'legislacao_geral'
    
    def _classify_jurisprudence_type(self, urn: str, title: str, document_summary: str) -> str:
        """
        Classifica tipos específicos de jurisprudência
        """
        
        urn_lower = urn.lower()
        text_content = f"{title} {document_summary}".lower()
        
        # Padrões específicos de jurisprudência
        jurisprudence_types = {
            'stf_adi': ['stf', 'adi', 'acao.direta.inconstitucionalidade'],
            'stf_adc': ['stf', 'adc', 'acao.declaratoria.constitucionalidade'],
            'stf_adpf': ['stf', 'adpf', 'arguicao.descumprimento.preceito'],
            'stf_re': ['stf', 're.', 'recurso.extraordinario'],
            'stf_ai': ['stf', 'ai.', 'agravo.instrumento'],
            'stj_resp': ['stj', 'resp', 'recurso.especial'],
            'stj_rms': ['stj', 'rms', 'recurso.ordinario.mandado'],
            'stj_conflito': ['stj', 'conflito.competencia'],
            'trf_apelacao': ['trf', 'apelacao', 'apelacao.civel'],
            'trf_mandado': ['trf', 'mandado.seguranca', 'ms.'],
            'trf_embargos': ['trf', 'embargos'],
            'tj_apelacao': ['tj', 'apelacao', 'tribunal.justica'],
            'tj_agravo': ['tj', 'agravo'],
            'tj_mandado': ['tj', 'mandado.seguranca'],
            'tst_dissidio': ['tst', 'dissidio', 'dissidio.coletivo'],
            'tst_recurso': ['tst', 'recurso.revista'],
            'tse_recurso': ['tse', 'recurso.eleitoral'],
            'stm_apelacao': ['stm', 'apelacao.militar'],
            'sumula': ['sumula', 'sumula.vinculante'],
            'decisao_monocratica': ['decisao.monocratica', 'liminar']
        }
        
        # Verificação por URN e conteúdo
        for jur_type, patterns in jurisprudence_types.items():
            urn_matches = sum(1 for p in patterns if p in urn_lower)
            text_matches = sum(1 for p in patterns if p.replace('.', ' ') in text_content)
            
            if urn_matches >= 2 or text_matches >= 2:
                return jur_type
        
        # Verificação simples
        for jur_type, patterns in jurisprudence_types.items():
            for pattern in patterns:
                if pattern in urn_lower or pattern.replace('.', ' ') in text_content:
                    return jur_type
        
        return 'jurisprudencia_geral'
    
    def _classify_doctrine_type(self, urn: str, title: str, document_summary: str) -> str:
        """
        Classifica tipos específicos de doutrina
        """
        
        text_content = f"{title} {document_summary}".lower()
        
        # Padrões específicos de doutrina
        doctrine_types = {
            'tese_doutorado': ['tese', 'doutorado', 'phd', 'doutor', 'doctorate'],
            'dissertacao_mestrado': ['dissertacao', 'mestrado', 'mestre', 'master'],
            'tcc': ['tcc', 'trabalho.conclusao', 'graduacao', 'bacharelado'],
            'artigo_cientifico': ['artigo', 'paper', 'revista', 'periodico', 'journal'],
            'artigo_nacional': ['revista brasileira', 'periodico nacional'],
            'artigo_internacional': ['international journal', 'revista internacional'],
            'livro': ['livro', 'obra', 'publicacao', 'editora', 'book'],
            'capitulo_livro': ['capitulo', 'cap.', 'secao', 'chapter'],
            'manual_tecnico': ['manual', 'guia', 'handbook', 'orientacao'],
            'relatorio_pesquisa': ['relatorio', 'estudo', 'pesquisa', 'levantamento'],
            'relatorio_tecnico': ['relatorio tecnico', 'technical report'],
            'parecer_tecnico': ['parecer', 'opiniao', 'analise.tecnica'],
            'estudo_impacto': ['estudo.impacto', 'eia', 'rima'],
            'publicacao_associacao': ['cnt', 'antf', 'abcam', 'associacao'],
            'estudo_consultoria': ['consultoria', 'consulting', 'assessoria'],
            'relatorio_organismo': ['oecd', 'banco.mundial', 'iea', 'cepal'],
            'white_paper': ['white paper', 'position paper'],
            'working_paper': ['working paper', 'discussion paper']
        }
        
        # Verificação por conteúdo textual
        scores = {}
        for doc_type, patterns in doctrine_types.items():
            score = sum(1 for p in patterns if p.replace('.', ' ') in text_content)
            if score > 0:
                scores[doc_type] = score
        
        if scores:
            return max(scores, key=scores.get)
        
        # Análise de padrões estruturais
        if any(word in text_content for word in ['universidade', 'faculdade', 'instituto']):
            if 'tese' in text_content or 'doutorado' in text_content:
                return 'tese_doutorado'
            elif 'dissertacao' in text_content or 'mestrado' in text_content:
                return 'dissertacao_mestrado'
            elif 'tcc' in text_content or 'graduacao' in text_content:
                return 'tcc'
        
        return 'doutrina_geral'
    
    def _classify_subtype(self, main_category: str, document_type: str, urn: str, 
                         title: str, document_summary: str) -> str:
        """
        Classifica subtipo específico baseado na categoria e tipo
        """
        
        if main_category == 'legislation':
            return self._classify_legislation_subtype(document_type, urn, title, document_summary)
        elif main_category == 'jurisprudence':
            return self._classify_jurisprudence_subtype(document_type, urn, title, document_summary)
        elif main_category == 'doctrine':
            return self._classify_doctrine_subtype(document_type, urn, title, document_summary)
        
        return 'subtipo_geral'
    
    def _classify_legislation_subtype(self, document_type: str, urn: str, 
                                    title: str, document_summary: str) -> str:
        """
        Classifica subtipos de legislação baseado no conteúdo temático
        """
        
        text_content = f"{title} {document_summary}".lower()
        
        # Contagem de matches por subtipo
        subtype_scores = {}
        for subtype, keywords in self.thematic_subtypes.items():
            score = sum(1 for keyword in keywords if keyword in text_content)
            if score > 0:
                subtype_scores[subtype] = score
        
        # Retorna o subtipo com maior score
        if subtype_scores:
            return max(subtype_scores, key=subtype_scores.get)
        
        return 'legislacao_geral'
    
    def _classify_jurisprudence_subtype(self, document_type: str, urn: str, 
                                      title: str, document_summary: str) -> str:
        """
        Classifica subtipos de jurisprudência baseado no conteúdo
        """
        
        text_content = f"{title} {document_summary}".lower()
        
        # Subtipos jurisprudenciais por matéria
        jurisprudence_subtypes = {
            'direito_administrativo': ['licitacao', 'contrato administrativo', 'servidor publico', 'ato administrativo'],
            'direito_tributario': ['icms', 'ipi', 'tributo', 'imposto', 'taxa'],
            'direito_constitucional': ['constitucional', 'direito fundamental', 'competencia'],
            'direito_ambiental': ['meio ambiente', 'licenca ambiental', 'poluicao'],
            'direito_trabalhista': ['trabalhista', 'emprego', 'sindicato'],
            'direito_civil': ['contrato', 'responsabilidade civil', 'danos'],
            'direito_comercial': ['empresa', 'sociedade', 'comercial'],
            'direito_processual': ['processo', 'recurso', 'procedimento']
        }
        
        # Contar matches
        subtype_scores = {}
        for subtype, keywords in jurisprudence_subtypes.items():
            score = sum(1 for keyword in keywords if keyword in text_content)
            if score > 0:
                subtype_scores[subtype] = score
        
        if subtype_scores:
            return max(subtype_scores, key=subtype_scores.get)
        
        return 'jurisprudencia_geral'
    
    def _classify_doctrine_subtype(self, document_type: str, urn: str, 
                                 title: str, document_summary: str) -> str:
        """
        Classifica subtipos de doutrina baseado no conteúdo
        """
        
        text_content = f"{title} {document_summary}".lower()
        
        # Subtipos doutrinários por área
        doctrine_subtypes = {
            'direito_administrativo': ['administrativo', 'administracao publica'],
            'direito_tributario': ['tributario', 'fiscal', 'tributo'],
            'direito_constitucional': ['constitucional', 'constituicao'],
            'direito_ambiental': ['ambiental', 'meio ambiente', 'sustentabilidade'],
            'direito_trabalhista': ['trabalhista', 'trabalho', 'emprego'],
            'direito_civil': ['civil', 'obrigacoes', 'contratos'],
            'direito_comercial': ['comercial', 'empresarial', 'sociedades'],
            'engenharia_transportes': ['engenharia', 'transporte', 'logistica'],
            'economia_transportes': ['economia', 'custos', 'eficiencia'],
            'gestao_transportes': ['gestao', 'administracao', 'gerenciamento'],
            'tecnologia_transportes': ['tecnologia', 'inovacao', 'digitalizacao']
        }
        
        # Contar matches
        subtype_scores = {}
        for subtype, keywords in doctrine_subtypes.items():
            score = sum(1 for keyword in keywords if keyword in text_content)
            if score > 0:
                subtype_scores[subtype] = score
        
        if subtype_scores:
            return max(subtype_scores, key=subtype_scores.get)
        
        return 'doutrina_geral'
    
    def _calculate_confidence(self, urn: str, title: str, document_summary: str) -> float:
        """
        Calcula confiança da classificação baseada na qualidade dos indicadores
        """
        
        confidence_factors = {
            'urn_clarity': 0.4,  # Clareza da URN
            'title_relevance': 0.3,  # Relevância do título
            'content_indicators': 0.3  # Indicadores no conteúdo
        }
        
        # Avaliação da clareza da URN
        urn_indicators = ['lei', 'decreto', 'portaria', 'resolucao', 'jurisprudencia', 'acordao']
        urn_score = 1.0 if any(indicator in urn.lower() for indicator in urn_indicators) else 0.5
        
        # Avaliação da relevância do título
        transport_keywords = ['transporte', 'carga', 'veiculo', 'combustivel', 'frete', 'caminhao']
        title_score = 1.0 if (len(title) > 20 and 
                            any(word in title.lower() for word in transport_keywords)) else 0.7
        
        # Avaliação dos indicadores de conteúdo
        content_score = 1.0 if len(document_summary) > 50 else 0.6
        
        # Cálculo da confiança ponderada
        confidence = (
            urn_score * confidence_factors['urn_clarity'] +
            title_score * confidence_factors['title_relevance'] +
            content_score * confidence_factors['content_indicators']
        )
        
        return round(confidence, 2)
    
    def _load_legislation_patterns(self) -> Dict:
        """Carrega padrões de legislação"""
        return {
            'federal': ['lei', 'decreto', 'medida.provisoria', 'decreto.legislativo'],
            'estadual': ['lei.estadual', 'decreto.estadual'],
            'municipal': ['lei.municipal', 'decreto.municipal'],
            'regulatory': ['portaria', 'resolucao', 'instrucao.normativa']
        }
    
    def _load_jurisprudence_patterns(self) -> Dict:
        """Carrega padrões de jurisprudência"""
        return {
            'superior': ['stf', 'stj'],
            'regional': ['trf', 'tj'],
            'specialized': ['tst', 'tse', 'stm'],
            'decisions': ['acordao', 'decisao', 'sentenca']
        }
    
    def _load_doctrine_patterns(self) -> Dict:
        """Carrega padrões de doutrina"""
        return {
            'academic': ['tese', 'dissertacao', 'tcc', 'artigo'],
            'technical': ['manual', 'relatorio', 'estudo'],
            'institutional': ['parecer', 'publicacao']
        }
    
    def _load_thematic_subtypes(self) -> Dict:
        """Carrega subtipos temáticos baseados nos novos termos de busca"""
        return {
            'combustiveis_energia': [
                'gas natural', 'biometano', 'diesel', 'biodiesel', 'hidrogênio',
                'etanol', 'combustível', 'energia', 'renovável', 'sustentável'
            ],
            'eficiencia_emissoes': [
                'eficiência energética', 'emissões', 'descarbonização',
                'gases efeito estufa', 'rotulagem veicular', 'consumo combustível'
            ],
            'tecnologia_inovacao': [
                'tecnologias assistivas', 'veículos autônomos', 'telemetria',
                'rastreamento', 'motorização', 'conversão', 'automação'
            ],
            'infraestrutura': [
                'postos abastecimento', 'terminais carga', 'centros distribuição',
                'armazéns', 'infraestrutura', 'logística'
            ],
            'regulamentacao_normas': [
                'contran', 'antt', 'registro', 'habilitação', 'licenciamento',
                'rntrc', 'segurança veicular', 'normas técnicas'
            ],
            'incentivos_tributacao': [
                'ipi', 'icms', 'incentivo fiscal', 'isenção', 'benefício tributário',
                'financiamento', 'crédito', 'subsídio'
            ],
            'programas_governamentais': [
                'rota 2030', 'paten', 'transição energética', 'mobilidade logística',
                'desenvolvimento sustentável', 'programa governo'
            ],
            'maquinas_equipamentos': [
                'máquinas agrícolas', 'implementos rodoviários', 'reboque',
                'semi-reboque', 'carreta', 'bitrem', 'rodotrem'
            ],
            'operacoes_servicos': [
                'transportador autônomo', 'empresa transporte', 'operador logístico',
                'embarcador', 'terceirização', 'contrato frete'
            ]
        }
    
    def classify_batch(self, documents: List[Dict]) -> List[Dict]:
        """
        Classifica um lote de documentos
        """
        
        results = []
        
        for doc in documents:
            try:
                classification = self.classify_document(
                    doc.get('urn', ''),
                    doc.get('title', ''),
                    doc.get('document_summary', ''),
                    doc.get('document_type_original', '')
                )
                
                # Adicionar classificação ao documento
                doc_with_classification = {**doc, **classification}
                results.append(doc_with_classification)
                
            except Exception as e:
                logger.error(f"Erro ao classificar documento {doc.get('urn', 'sem URN')}: {e}")
                # Adicionar classificação padrão em caso de erro
                doc_with_classification = {
                    **doc,
                    'main_category': 'other',
                    'document_type': 'unknown',
                    'document_subtype': 'unknown',
                    'classification_confidence': 0.0
                }
                results.append(doc_with_classification)
        
        return results
    
    def get_classification_statistics(self, classified_documents: List[Dict]) -> Dict:
        """
        Gera estatísticas de classificação
        """
        
        stats = {
            'total_documents': len(classified_documents),
            'main_categories': {},
            'document_types': {},
            'document_subtypes': {},
            'confidence_distribution': {
                'high': 0,  # > 0.8
                'medium': 0,  # 0.6-0.8
                'low': 0  # < 0.6
            }
        }
        
        for doc in classified_documents:
            # Contar categorias principais
            main_cat = doc.get('main_category', 'unknown')
            stats['main_categories'][main_cat] = stats['main_categories'].get(main_cat, 0) + 1
            
            # Contar tipos de documento
            doc_type = doc.get('document_type', 'unknown')
            stats['document_types'][doc_type] = stats['document_types'].get(doc_type, 0) + 1
            
            # Contar subtipos
            doc_subtype = doc.get('document_subtype', 'unknown')
            stats['document_subtypes'][doc_subtype] = stats['document_subtypes'].get(doc_subtype, 0) + 1
            
            # Distribuição de confiança
            confidence = doc.get('classification_confidence', 0.0)
            if confidence > 0.8:
                stats['confidence_distribution']['high'] += 1
            elif confidence > 0.6:
                stats['confidence_distribution']['medium'] += 1
            else:
                stats['confidence_distribution']['low'] += 1
        
        return stats
    
    def export_classification_report(self, classified_documents: List[Dict], 
                                   output_file: str = None) -> str:
        """
        Exporta relatório de classificação
        """
        
        if not output_file:
            output_file = f"classification_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        stats = self.get_classification_statistics(classified_documents)
        
        report = {
            'metadata': {
                'generation_date': datetime.now().isoformat(),
                'total_documents': len(classified_documents),
                'classifier_version': '1.0'
            },
            'statistics': stats,
            'sample_documents': classified_documents[:10]  # Primeiros 10 como exemplo
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        
        logger.info(f"Relatório de classificação salvo em: {output_file}")
        return output_file


def main():
    """Função principal para teste"""
    
    # Exemplo de uso
    classifier = RefinedDocumentClassifier()
    
    # Documento de exemplo
    test_doc = {
        'urn': 'urn:lex:br:federal:lei:2021-12-29;14.267',
        'title': 'Lei sobre uso de biometano em transporte de carga',
        'document_summary': 'Estabelece diretrizes para o uso de biometano como combustível em veículos pesados de transporte de carga, visando reduzir emissões de gases de efeito estufa.',
        'document_type_original': 'Lei Federal'
    }
    
    # Classificar documento
    result = classifier.classify_document(
        test_doc['urn'],
        test_doc['title'],
        test_doc['document_summary'],
        test_doc['document_type_original']
    )
    
    print("Resultado da classificação:")
    print(json.dumps(result, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    main()