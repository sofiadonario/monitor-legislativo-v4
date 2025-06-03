"""
Keyword Analyzer Plugin for Monitor Legislativo v4
Analyzes keyword frequency and trends in legislative documents

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import re
from collections import Counter
from typing import Dict, Any, List, Optional
from datetime import datetime
import logging

from core.plugins.plugin_base import AnalyzerPlugin, PluginMetadata, PluginType

logger = logging.getLogger(__name__)

class KeywordAnalyzerPlugin(AnalyzerPlugin):
    """Plugin for analyzing keyword patterns in legislative data"""
    
    def __init__(self):
        self.config = {}
        self.stop_words = set()
        
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        return PluginMetadata(
            name="keyword_analyzer",
            version="1.0.0",
            author="Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães",
            description="Analyzes keyword frequency and trends in legislative documents",
            plugin_type=PluginType.ANALYZER,
            requires=[],
            config_schema={
                "min_word_length": {
                    "type": "integer",
                    "description": "Minimum word length to consider",
                    "default": 3
                },
                "max_keywords": {
                    "type": "integer",
                    "description": "Maximum number of keywords to return",
                    "default": 50
                },
                "stop_words": {
                    "type": "array",
                    "description": "List of words to ignore",
                    "default": ["de", "da", "do", "para", "com", "sem", "sobre"]
                }
            }
        )
    
    async def initialize(self, config: Dict[str, Any]) -> bool:
        """Initialize the plugin"""
        try:
            self.config = config
            self.stop_words = set(config.get("stop_words", [
                "de", "da", "do", "das", "dos", "para", "com", "sem", 
                "sobre", "em", "no", "na", "nos", "nas", "por", "pelo",
                "pela", "pelos", "pelas", "que", "e", "ou", "mas"
            ]))
            
            # Add common Portuguese articles and prepositions
            self.stop_words.update([
                "o", "a", "os", "as", "um", "uma", "uns", "umas",
                "ao", "aos", "à", "às", "pelo", "pela", "pelos", "pelas"
            ])
            
            logger.info(f"Keyword Analyzer initialized with {len(self.stop_words)} stop words")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Keyword Analyzer: {e}")
            return False
    
    async def shutdown(self) -> None:
        """Shutdown the plugin"""
        logger.info("Keyword Analyzer shutting down")
    
    def validate_config(self, config: Dict[str, Any]) -> tuple[bool, Optional[str]]:
        """Validate plugin configuration"""
        # Check min_word_length
        min_length = config.get("min_word_length", 3)
        if not isinstance(min_length, int) or min_length < 1:
            return False, "min_word_length must be a positive integer"
        
        # Check max_keywords
        max_keywords = config.get("max_keywords", 50)
        if not isinstance(max_keywords, int) or max_keywords < 1:
            return False, "max_keywords must be a positive integer"
        
        # Check stop_words
        stop_words = config.get("stop_words", [])
        if not isinstance(stop_words, list):
            return False, "stop_words must be a list"
        
        return True, None
    
    async def analyze(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze keyword frequency in legislative data"""
        min_length = self.config.get("min_word_length", 3)
        max_keywords = self.config.get("max_keywords", 50)
        
        # Extract text from all documents
        all_text = []
        for item in data:
            # Combine title and summary
            text_parts = []
            if "title" in item:
                text_parts.append(str(item["title"]))
            if "summary" in item:
                text_parts.append(str(item["summary"]))
            if "keywords" in item and isinstance(item["keywords"], list):
                text_parts.extend(item["keywords"])
            
            all_text.append(" ".join(text_parts))
        
        combined_text = " ".join(all_text).lower()
        
        # Extract words
        words = re.findall(r'\b\w+\b', combined_text)
        
        # Filter words
        filtered_words = [
            word for word in words
            if len(word) >= min_length and word not in self.stop_words
        ]
        
        # Count frequencies
        word_counts = Counter(filtered_words)
        
        # Get top keywords
        top_keywords = word_counts.most_common(max_keywords)
        
        # Analyze by source if available
        source_analysis = {}
        for item in data:
            source = item.get("source", "unknown")
            if source not in source_analysis:
                source_analysis[source] = Counter()
            
            text = f"{item.get('title', '')} {item.get('summary', '')}"
            words = re.findall(r'\b\w+\b', text.lower())
            filtered = [w for w in words if len(w) >= min_length and w not in self.stop_words]
            source_analysis[source].update(filtered)
        
        # Get top keywords by source
        source_keywords = {}
        for source, counter in source_analysis.items():
            source_keywords[source] = counter.most_common(10)
        
        # Analyze trends (simple growth calculation)
        # In a real implementation, this would compare with historical data
        trending_keywords = []
        for keyword, count in top_keywords[:20]:
            trending_keywords.append({
                "keyword": keyword,
                "count": count,
                "trend": "stable",  # Would calculate actual trend
                "growth_rate": 0.0
            })
        
        return {
            "total_documents": len(data),
            "total_words": len(filtered_words),
            "unique_words": len(set(filtered_words)),
            "top_keywords": [
                {"keyword": word, "count": count} 
                for word, count in top_keywords
            ],
            "keywords_by_source": {
                source: [{"keyword": word, "count": count} for word, count in keywords]
                for source, keywords in source_keywords.items()
            },
            "trending_keywords": trending_keywords,
            "analysis_timestamp": datetime.now().isoformat()
        }
    
    def get_analysis_types(self) -> List[str]:
        """Return supported analysis types"""
        return ["keyword_frequency", "source_keywords", "trending_keywords"]
    
    async def generate_report(self, analysis: Dict[str, Any], format: str = "json") -> str:
        """Generate analysis report"""
        if format == "json":
            import json
            report = json.dumps(analysis, indent=2, ensure_ascii=False)
            
            # Save to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"keyword_analysis_{timestamp}.json"
            filepath = f"data/reports/{filename}"
            
            import os
            os.makedirs("data/reports", exist_ok=True)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report)
            
            return filepath
            
        elif format == "text":
            lines = [
                "KEYWORD ANALYSIS REPORT",
                "=" * 50,
                f"Generated: {analysis.get('analysis_timestamp', 'N/A')}",
                f"Total Documents: {analysis.get('total_documents', 0)}",
                f"Total Words: {analysis.get('total_words', 0)}",
                f"Unique Words: {analysis.get('unique_words', 0)}",
                "",
                "TOP KEYWORDS:",
                "-" * 30
            ]
            
            for item in analysis.get("top_keywords", [])[:20]:
                lines.append(f"{item['keyword']:20} {item['count']:>10}")
            
            report = "\n".join(lines)
            
            # Save to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"keyword_analysis_{timestamp}.txt"
            filepath = f"data/reports/{filename}"
            
            import os
            os.makedirs("data/reports", exist_ok=True)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(report)
            
            return filepath
            
        else:
            raise ValueError(f"Unsupported format: {format}")

# Make the plugin class discoverable
__plugin__ = KeywordAnalyzerPlugin