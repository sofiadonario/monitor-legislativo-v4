"""Research pattern detection and trend analysis for legislative documents."""
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta
import re
import json
from collections import defaultdict, Counter
import asyncio

from core.config.config import Config
from core.utils.logger import Logger
from core.models.legislative_data import LegislativeDocument
from core.ai.entity_extractor import Entity, EntityType

logger = Logger()


class PatternType(Enum):
    """Types of patterns that can be detected."""
    TEMPORAL = "temporal"
    THEMATIC = "thematic"
    GEOGRAPHIC = "geographic"
    REGULATORY = "regulatory"
    POLICY = "policy"
    LEGISLATIVE_CYCLE = "legislative_cycle"
    AGENCY_ACTIVITY = "agency_activity"
    CROSS_REFERENCE = "cross_reference"


class TrendDirection(Enum):
    """Direction of trend."""
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"
    CYCLICAL = "cyclical"
    EMERGING = "emerging"


@dataclass
class Pattern:
    """Represents a detected pattern."""
    pattern_id: str
    pattern_type: PatternType
    name: str
    description: str
    confidence: float
    evidence: List[str]
    supporting_documents: List[str]
    temporal_range: Tuple[datetime, datetime]
    significance_score: float
    metadata: Dict[str, Any]


@dataclass
class Trend:
    """Represents a detected trend."""
    trend_id: str
    name: str
    direction: TrendDirection
    strength: float
    start_date: datetime
    end_date: Optional[datetime]
    data_points: List[Dict[str, Any]]
    statistical_significance: float
    description: str
    related_patterns: List[str]
    forecast: Dict[str, Any]


@dataclass
class AnalysisResult:
    """Results of pattern and trend analysis."""
    patterns: List[Pattern]
    trends: List[Trend]
    summary: Dict[str, Any]
    time_period: Tuple[datetime, datetime]
    document_count: int
    analysis_timestamp: datetime


class ResearchPatternDetector:
    """Detect research patterns and trends in legislative documents."""
    
    def __init__(self):
        self.config = Config()
        self._load_pattern_definitions()
        
    def _load_pattern_definitions(self):
        """Load pattern detection definitions and rules."""
        self.temporal_patterns = {
            'quarterly_cycles': {
                'description': 'Quarterly legislative activity cycles',
                'detection_rule': self._detect_quarterly_cycles,
                'min_confidence': 0.7
            },
            'election_periods': {
                'description': 'Legislative activity around election periods',
                'detection_rule': self._detect_election_patterns,
                'min_confidence': 0.6
            },
            'regulatory_waves': {
                'description': 'Waves of regulatory activity in specific areas',
                'detection_rule': self._detect_regulatory_waves,
                'min_confidence': 0.8
            }
        }
        
        self.thematic_patterns = {
            'transport_modernization': {
                'keywords': ['modernização', 'digitalização', 'tecnologia', 'inovação'],
                'context': 'transport',
                'min_occurrence': 3
            },
            'environmental_compliance': {
                'keywords': ['meio ambiente', 'sustentabilidade', 'emissões', 'carbono'],
                'context': 'environmental',
                'min_occurrence': 2
            },
            'safety_regulations': {
                'keywords': ['segurança', 'proteção', 'prevenção', 'acidente'],
                'context': 'safety',
                'min_occurrence': 3
            }
        }
        
        # Brazilian election years for pattern detection
        self.election_years = [2018, 2020, 2022, 2024, 2026]
        
        # Regulatory agencies for agency activity patterns
        self.regulatory_agencies = {
            'ANTT': 'Agência Nacional de Transportes Terrestres',
            'ANTAQ': 'Agência Nacional de Transportes Aquaviários',
            'ANAC': 'Agência Nacional de Aviação Civil',
            'ANEEL': 'Agência Nacional de Energia Elétrica',
            'ANP': 'Agência Nacional do Petróleo'
        }
    
    async def analyze_patterns(self, documents: List[LegislativeDocument], 
                             entities: List[Entity] = None) -> AnalysisResult:
        """Analyze patterns and trends in legislative documents."""
        try:
            logger.info(f"Analyzing patterns in {len(documents)} documents")
            
            # Sort documents by date for temporal analysis
            sorted_docs = sorted(documents, key=lambda d: self._extract_date(d))
            
            # Extract time period
            start_date = self._extract_date(sorted_docs[0]) if sorted_docs else datetime.now()
            end_date = self._extract_date(sorted_docs[-1]) if sorted_docs else datetime.now()
            
            # Detect patterns
            patterns = []
            
            # Temporal patterns
            temporal_patterns = await self._detect_temporal_patterns(sorted_docs)
            patterns.extend(temporal_patterns)
            
            # Thematic patterns
            thematic_patterns = await self._detect_thematic_patterns(sorted_docs)
            patterns.extend(thematic_patterns)
            
            # Geographic patterns
            geographic_patterns = await self._detect_geographic_patterns(sorted_docs, entities)
            patterns.extend(geographic_patterns)
            
            # Agency activity patterns
            agency_patterns = await self._detect_agency_patterns(sorted_docs)
            patterns.extend(agency_patterns)
            
            # Detect trends from patterns
            trends = await self._detect_trends(sorted_docs, patterns)
            
            # Generate summary
            summary = self._generate_analysis_summary(patterns, trends, sorted_docs)
            
            result = AnalysisResult(
                patterns=patterns,
                trends=trends,
                summary=summary,
                time_period=(start_date, end_date),
                document_count=len(documents),
                analysis_timestamp=datetime.now()
            )
            
            logger.info(f"Analysis complete: {len(patterns)} patterns, {len(trends)} trends detected")
            return result
            
        except Exception as e:
            logger.error(f"Pattern analysis failed: {str(e)}")
            raise
    
    async def _detect_temporal_patterns(self, documents: List[LegislativeDocument]) -> List[Pattern]:
        """Detect temporal patterns in document publication."""
        patterns = []
        
        # Group documents by time periods
        monthly_counts = defaultdict(int)
        quarterly_counts = defaultdict(int)
        yearly_counts = defaultdict(int)
        
        for doc in documents:
            doc_date = self._extract_date(doc)
            if doc_date:
                month_key = doc_date.strftime('%Y-%m')
                quarter_key = f"{doc_date.year}-Q{(doc_date.month-1)//3 + 1}"
                year_key = str(doc_date.year)
                
                monthly_counts[month_key] += 1
                quarterly_counts[quarter_key] += 1
                yearly_counts[year_key] += 1
        
        # Detect quarterly cycles
        if len(quarterly_counts) >= 4:
            quarterly_pattern = await self._detect_quarterly_cycles(quarterly_counts, documents)
            if quarterly_pattern:
                patterns.append(quarterly_pattern)
        
        # Detect election period patterns
        election_pattern = await self._detect_election_patterns(yearly_counts, documents)
        if election_pattern:
            patterns.append(election_pattern)
        
        # Detect monthly activity spikes
        if monthly_counts:
            spike_pattern = await self._detect_activity_spikes(monthly_counts, documents)
            if spike_pattern:
                patterns.append(spike_pattern)
        
        return patterns
    
    async def _detect_quarterly_cycles(self, quarterly_counts: Dict[str, int], 
                                     documents: List[LegislativeDocument]) -> Optional[Pattern]:
        """Detect quarterly legislative cycles."""
        if len(quarterly_counts) < 4:
            return None
        
        # Calculate quarterly averages
        quarters = ['Q1', 'Q2', 'Q3', 'Q4']
        quarter_sums = {q: 0 for q in quarters}
        quarter_counts = {q: 0 for q in quarters}
        
        for quarter_key, count in quarterly_counts.items():
            if '-Q' in quarter_key:
                quarter = quarter_key.split('-Q')[1]
                if quarter in quarters:
                    quarter_sums[quarter] += count
                    quarter_counts[quarter] += 1
        
        # Calculate averages
        quarter_averages = {}
        for q in quarters:
            if quarter_counts[q] > 0:
                quarter_averages[q] = quarter_sums[q] / quarter_counts[q]
        
        if len(quarter_averages) < 4:
            return None
        
        # Check for significant variation (coefficient of variation > 0.3)
        values = list(quarter_averages.values())
        mean_val = sum(values) / len(values)
        std_dev = (sum((x - mean_val) ** 2 for x in values) / len(values)) ** 0.5
        coeff_var = std_dev / mean_val if mean_val > 0 else 0
        
        if coeff_var > 0.3:
            # Significant quarterly pattern detected
            peak_quarter = max(quarter_averages, key=quarter_averages.get)
            low_quarter = min(quarter_averages, key=quarter_averages.get)
            
            pattern = Pattern(
                pattern_id=f"quarterly_cycle_{datetime.now().strftime('%Y%m%d')}",
                pattern_type=PatternType.TEMPORAL,
                name="Quarterly Legislative Cycle",
                description=f"Peak activity in {peak_quarter}, lowest in {low_quarter}",
                confidence=min(0.9, coeff_var),
                evidence=[
                    f"Q1 average: {quarter_averages.get('Q1', 0):.1f} documents",
                    f"Q2 average: {quarter_averages.get('Q2', 0):.1f} documents",
                    f"Q3 average: {quarter_averages.get('Q3', 0):.1f} documents",
                    f"Q4 average: {quarter_averages.get('Q4', 0):.1f} documents",
                    f"Coefficient of variation: {coeff_var:.2f}"
                ],
                supporting_documents=[doc.id for doc in documents],
                temporal_range=(
                    self._extract_date(documents[0]),
                    self._extract_date(documents[-1])
                ),
                significance_score=coeff_var,
                metadata={
                    'quarterly_averages': quarter_averages,
                    'peak_quarter': peak_quarter,
                    'low_quarter': low_quarter,
                    'coefficient_variation': coeff_var
                }
            )
            
            return pattern
        
        return None
    
    async def _detect_election_patterns(self, yearly_counts: Dict[str, int], 
                                      documents: List[LegislativeDocument]) -> Optional[Pattern]:
        """Detect legislative activity patterns around election years."""
        election_activity = []
        non_election_activity = []
        
        for year_str, count in yearly_counts.items():
            year = int(year_str)
            if year in self.election_years:
                election_activity.append(count)
            else:
                non_election_activity.append(count)
        
        if len(election_activity) < 2 or len(non_election_activity) < 2:
            return None
        
        # Calculate averages
        election_avg = sum(election_activity) / len(election_activity)
        non_election_avg = sum(non_election_activity) / len(non_election_activity)
        
        # Check for significant difference (>20%)
        if abs(election_avg - non_election_avg) / max(election_avg, non_election_avg) > 0.2:
            is_higher_in_election = election_avg > non_election_avg
            confidence = min(0.9, abs(election_avg - non_election_avg) / max(election_avg, non_election_avg))
            
            pattern = Pattern(
                pattern_id=f"election_pattern_{datetime.now().strftime('%Y%m%d')}",
                pattern_type=PatternType.TEMPORAL,
                name="Election Period Activity Pattern",
                description=f"Legislative activity {'increases' if is_higher_in_election else 'decreases'} during election years",
                confidence=confidence,
                evidence=[
                    f"Election years average: {election_avg:.1f} documents",
                    f"Non-election years average: {non_election_avg:.1f} documents",
                    f"Difference: {abs(election_avg - non_election_avg):.1f} documents"
                ],
                supporting_documents=[doc.id for doc in documents],
                temporal_range=(
                    datetime(min(int(y) for y in yearly_counts.keys()), 1, 1),
                    datetime(max(int(y) for y in yearly_counts.keys()), 12, 31)
                ),
                significance_score=confidence,
                metadata={
                    'election_years_activity': election_activity,
                    'non_election_years_activity': non_election_activity,
                    'higher_in_election_years': is_higher_in_election
                }
            )
            
            return pattern
        
        return None
    
    async def _detect_activity_spikes(self, monthly_counts: Dict[str, int], 
                                    documents: List[LegislativeDocument]) -> Optional[Pattern]:
        """Detect monthly activity spikes."""
        if len(monthly_counts) < 6:
            return None
        
        counts = list(monthly_counts.values())
        mean_count = sum(counts) / len(counts)
        std_dev = (sum((x - mean_count) ** 2 for x in counts) / len(counts)) ** 0.5
        
        # Identify spikes (> mean + 2*std_dev)
        spike_threshold = mean_count + 2 * std_dev
        spikes = [(month, count) for month, count in monthly_counts.items() if count > spike_threshold]
        
        if len(spikes) >= 2:
            spike_months = [month for month, _ in spikes]
            spike_counts = [count for _, count in spikes]
            
            pattern = Pattern(
                pattern_id=f"activity_spikes_{datetime.now().strftime('%Y%m%d')}",
                pattern_type=PatternType.TEMPORAL,
                name="Legislative Activity Spikes",
                description=f"Detected {len(spikes)} months with unusually high activity",
                confidence=min(0.9, len(spikes) / len(monthly_counts)),
                evidence=[
                    f"Average monthly activity: {mean_count:.1f} documents",
                    f"Spike threshold: {spike_threshold:.1f} documents",
                    f"Spike months: {', '.join(spike_months)}"
                ],
                supporting_documents=[doc.id for doc in documents],
                temporal_range=(
                    datetime.strptime(min(monthly_counts.keys()), '%Y-%m'),
                    datetime.strptime(max(monthly_counts.keys()), '%Y-%m')
                ),
                significance_score=std_dev / mean_count if mean_count > 0 else 0,
                metadata={
                    'spike_months': spike_months,
                    'spike_counts': spike_counts,
                    'threshold': spike_threshold,
                    'mean_activity': mean_count
                }
            )
            
            return pattern
        
        return None
    
    async def _detect_thematic_patterns(self, documents: List[LegislativeDocument]) -> List[Pattern]:
        """Detect thematic patterns in document content."""
        patterns = []
        
        for theme_name, theme_config in self.thematic_patterns.items():
            theme_docs = []
            theme_evidence = []
            
            for doc in documents:
                doc_text = self._get_document_text(doc).lower()
                matches = []
                
                for keyword in theme_config['keywords']:
                    if keyword.lower() in doc_text:
                        matches.append(keyword)
                
                if len(matches) >= theme_config['min_occurrence']:
                    theme_docs.append(doc)
                    theme_evidence.append(f"Document {doc.id}: matched keywords {', '.join(matches)}")
            
            if len(theme_docs) >= 3:  # Minimum 3 documents for a pattern
                confidence = min(0.9, len(theme_docs) / len(documents))
                
                pattern = Pattern(
                    pattern_id=f"thematic_{theme_name}_{datetime.now().strftime('%Y%m%d')}",
                    pattern_type=PatternType.THEMATIC,
                    name=f"Thematic Pattern: {theme_name.replace('_', ' ').title()}",
                    description=f"Recurring theme in {len(theme_docs)} documents focusing on {theme_config['context']}",
                    confidence=confidence,
                    evidence=theme_evidence[:10],  # Limit evidence to first 10
                    supporting_documents=[doc.id for doc in theme_docs],
                    temporal_range=(
                        self._extract_date(theme_docs[0]),
                        self._extract_date(theme_docs[-1])
                    ),
                    significance_score=len(theme_docs) / len(documents),
                    metadata={
                        'theme_keywords': theme_config['keywords'],
                        'context': theme_config['context'],
                        'document_count': len(theme_docs)
                    }
                )
                
                patterns.append(pattern)
        
        return patterns
    
    async def _detect_geographic_patterns(self, documents: List[LegislativeDocument], 
                                        entities: List[Entity] = None) -> List[Pattern]:
        """Detect geographic patterns in legislative focus."""
        patterns = []
        
        if not entities:
            return patterns
        
        # Group geographic entities
        geographic_entities = [e for e in entities if e.type == EntityType.GEOGRAPHIC_LOCATION]
        location_counts = Counter(entity.name for entity in geographic_entities)
        
        # Identify frequently mentioned locations
        total_locations = sum(location_counts.values())
        frequent_locations = [(loc, count) for loc, count in location_counts.items() 
                            if count / total_locations > 0.1]  # >10% of mentions
        
        if frequent_locations:
            for location, count in frequent_locations:
                # Find documents mentioning this location
                location_docs = []
                for entity in geographic_entities:
                    if entity.name == location:
                        doc_id = entity.metadata.get('document_id')
                        if doc_id:
                            doc = next((d for d in documents if d.id == doc_id), None)
                            if doc and doc not in location_docs:
                                location_docs.append(doc)
                
                if len(location_docs) >= 3:
                    pattern = Pattern(
                        pattern_id=f"geographic_{location.replace(' ', '_')}_{datetime.now().strftime('%Y%m%d')}",
                        pattern_type=PatternType.GEOGRAPHIC,
                        name=f"Geographic Focus: {location}",
                        description=f"Significant legislative focus on {location} ({count} mentions in {len(location_docs)} documents)",
                        confidence=min(0.9, count / total_locations * 10),
                        evidence=[
                            f"Mentioned {count} times across {len(location_docs)} documents",
                            f"Represents {count/total_locations*100:.1f}% of geographic mentions"
                        ],
                        supporting_documents=[doc.id for doc in location_docs],
                        temporal_range=(
                            self._extract_date(location_docs[0]),
                            self._extract_date(location_docs[-1])
                        ),
                        significance_score=count / total_locations,
                        metadata={
                            'location': location,
                            'mention_count': count,
                            'percentage_of_total': count / total_locations * 100
                        }
                    )
                    
                    patterns.append(pattern)
        
        return patterns
    
    async def _detect_agency_patterns(self, documents: List[LegislativeDocument]) -> List[Pattern]:
        """Detect agency activity patterns."""
        patterns = []
        
        agency_activity = defaultdict(list)
        
        for doc in documents:
            doc_text = self._get_document_text(doc)
            
            for agency_abbr, agency_name in self.regulatory_agencies.items():
                if agency_abbr in doc_text or agency_name in doc_text:
                    agency_activity[agency_abbr].append(doc)
        
        # Analyze each agency's activity
        for agency, docs in agency_activity.items():
            if len(docs) >= 5:  # Minimum 5 documents for agency pattern
                # Check for temporal clustering
                dates = [self._extract_date(doc) for doc in docs if self._extract_date(doc)]
                if len(dates) >= 3:
                    dates.sort()
                    
                    # Check for activity clustering (>50% of documents in 6-month period)
                    for i in range(len(dates) - 2):
                        period_end = dates[i] + timedelta(days=180)  # 6 months
                        period_docs = [d for d in dates if dates[i] <= d <= period_end]
                        
                        if len(period_docs) / len(dates) > 0.5:
                            pattern = Pattern(
                                pattern_id=f"agency_{agency}_{datetime.now().strftime('%Y%m%d')}",
                                pattern_type=PatternType.AGENCY_ACTIVITY,
                                name=f"Agency Activity Burst: {agency}",
                                description=f"Concentrated {agency} regulatory activity ({len(period_docs)} documents in 6-month period)",
                                confidence=min(0.9, len(period_docs) / len(dates)),
                                evidence=[
                                    f"Total {agency} documents: {len(docs)}",
                                    f"Clustered period: {dates[i].strftime('%Y-%m')} to {period_end.strftime('%Y-%m')}",
                                    f"Documents in cluster: {len(period_docs)}"
                                ],
                                supporting_documents=[doc.id for doc in docs],
                                temporal_range=(dates[0], dates[-1]),
                                significance_score=len(period_docs) / len(dates),
                                metadata={
                                    'agency': agency,
                                    'total_documents': len(docs),
                                    'cluster_period': (dates[i], period_end),
                                    'cluster_size': len(period_docs)
                                }
                            )
                            
                            patterns.append(pattern)
                            break  # Only detect one cluster per agency
        
        return patterns
    
    async def _detect_trends(self, documents: List[LegislativeDocument], 
                           patterns: List[Pattern]) -> List[Trend]:
        """Detect trends from document analysis and patterns."""
        trends = []
        
        # Temporal trend analysis
        if len(documents) >= 12:  # Need at least 12 documents for trend analysis
            temporal_trend = await self._analyze_temporal_trend(documents)
            if temporal_trend:
                trends.append(temporal_trend)
        
        # Thematic trend analysis
        thematic_trends = await self._analyze_thematic_trends(documents, patterns)
        trends.extend(thematic_trends)
        
        return trends
    
    async def _analyze_temporal_trend(self, documents: List[LegislativeDocument]) -> Optional[Trend]:
        """Analyze temporal trends in document publication."""
        # Group by month
        monthly_counts = defaultdict(int)
        
        for doc in documents:
            doc_date = self._extract_date(doc)
            if doc_date:
                month_key = doc_date.strftime('%Y-%m')
                monthly_counts[month_key] += 1
        
        if len(monthly_counts) < 6:
            return None
        
        # Calculate trend using simple linear regression
        months = sorted(monthly_counts.keys())
        counts = [monthly_counts[month] for month in months]
        
        n = len(months)
        x_vals = list(range(n))
        y_vals = counts
        
        # Linear regression calculations
        x_mean = sum(x_vals) / n
        y_mean = sum(y_vals) / n
        
        numerator = sum((x_vals[i] - x_mean) * (y_vals[i] - y_mean) for i in range(n))
        denominator = sum((x_vals[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return None
        
        slope = numerator / denominator
        
        # Determine trend direction and strength
        if abs(slope) < 0.1:
            direction = TrendDirection.STABLE
            strength = 0.3
        elif slope > 0:
            direction = TrendDirection.INCREASING
            strength = min(0.9, abs(slope) / max(counts) * 10)
        else:
            direction = TrendDirection.DECREASING
            strength = min(0.9, abs(slope) / max(counts) * 10)
        
        # Create data points for visualization
        data_points = [
            {
                'date': month,
                'value': count,
                'type': 'actual'
            }
            for month, count in zip(months, counts)
        ]
        
        # Simple forecast (next 3 months)
        forecast_months = 3
        last_month_val = months[-1]
        last_count = counts[-1]
        
        forecast_data = []
        for i in range(1, forecast_months + 1):
            forecast_val = last_count + slope * i
            forecast_data.append({
                'month_offset': i,
                'predicted_count': max(0, forecast_val),
                'confidence': max(0.3, 0.8 - i * 0.2)
            })
        
        trend = Trend(
            trend_id=f"temporal_trend_{datetime.now().strftime('%Y%m%d')}",
            name="Legislative Activity Trend",
            direction=direction,
            strength=strength,
            start_date=datetime.strptime(months[0], '%Y-%m'),
            end_date=datetime.strptime(months[-1], '%Y-%m'),
            data_points=data_points,
            statistical_significance=min(0.9, abs(slope) * 2),
            description=f"Legislative activity is {direction.value} with strength {strength:.2f}",
            related_patterns=[],
            forecast={
                'method': 'linear_regression',
                'predictions': forecast_data,
                'slope': slope
            }
        )
        
        return trend
    
    async def _analyze_thematic_trends(self, documents: List[LegislativeDocument], 
                                     patterns: List[Pattern]) -> List[Trend]:
        """Analyze trends in thematic patterns."""
        trends = []
        
        thematic_patterns = [p for p in patterns if p.pattern_type == PatternType.THEMATIC]
        
        for pattern in thematic_patterns:
            # Get documents for this pattern
            pattern_docs = [doc for doc in documents if doc.id in pattern.supporting_documents]
            
            if len(pattern_docs) >= 6:
                # Analyze temporal distribution
                monthly_dist = defaultdict(int)
                
                for doc in pattern_docs:
                    doc_date = self._extract_date(doc)
                    if doc_date:
                        month_key = doc_date.strftime('%Y-%m')
                        monthly_dist[month_key] += 1
                
                if len(monthly_dist) >= 3:
                    months = sorted(monthly_dist.keys())
                    counts = [monthly_dist[month] for month in months]
                    
                    # Simple trend detection
                    first_half = counts[:len(counts)//2]
                    second_half = counts[len(counts)//2:]
                    
                    first_avg = sum(first_half) / len(first_half)
                    second_avg = sum(second_half) / len(second_half)
                    
                    if second_avg > first_avg * 1.2:
                        direction = TrendDirection.INCREASING
                        strength = min(0.9, (second_avg - first_avg) / first_avg)
                    elif second_avg < first_avg * 0.8:
                        direction = TrendDirection.DECREASING
                        strength = min(0.9, (first_avg - second_avg) / first_avg)
                    else:
                        direction = TrendDirection.STABLE
                        strength = 0.3
                    
                    data_points = [
                        {
                            'date': month,
                            'value': monthly_dist[month],
                            'type': 'thematic_occurrence'
                        }
                        for month in months
                    ]
                    
                    trend = Trend(
                        trend_id=f"thematic_trend_{pattern.pattern_id}",
                        name=f"Trend: {pattern.name}",
                        direction=direction,
                        strength=strength,
                        start_date=datetime.strptime(months[0], '%Y-%m'),
                        end_date=datetime.strptime(months[-1], '%Y-%m'),
                        data_points=data_points,
                        statistical_significance=strength,
                        description=f"Thematic focus on {pattern.name.lower()} is {direction.value}",
                        related_patterns=[pattern.pattern_id],
                        forecast={'method': 'qualitative', 'direction': direction.value}
                    )
                    
                    trends.append(trend)
        
        return trends
    
    def _extract_date(self, document: LegislativeDocument) -> Optional[datetime]:
        """Extract date from document."""
        # Try different date fields
        date_fields = ['data_evento', 'data_publicacao', 'created_at', 'date']
        
        for field in date_fields:
            date_value = getattr(document, field, None)
            if not date_value:
                continue
            
            if isinstance(date_value, datetime):
                return date_value
            
            if isinstance(date_value, str):
                try:
                    # Try different date formats
                    for fmt in ['%Y-%m-%d', '%d/%m/%Y', '%Y-%m-%d %H:%M:%S']:
                        try:
                            return datetime.strptime(date_value, fmt)
                        except ValueError:
                            continue
                except:
                    continue
        
        return None
    
    def _get_document_text(self, document: LegislativeDocument) -> str:
        """Get text content from document."""
        text_parts = []
        
        if document.title:
            text_parts.append(document.title)
        if document.summary:
            text_parts.append(document.summary)
        if hasattr(document, 'content') and document.content:
            text_parts.append(document.content)
        if hasattr(document, 'full_text') and document.full_text:
            text_parts.append(document.full_text)
            
        return ' '.join(text_parts)
    
    def _generate_analysis_summary(self, patterns: List[Pattern], trends: List[Trend], 
                                 documents: List[LegislativeDocument]) -> Dict[str, Any]:
        """Generate summary of analysis results."""
        pattern_types = Counter(p.pattern_type.value for p in patterns)
        trend_directions = Counter(t.direction.value for t in trends)
        
        # High confidence patterns
        high_conf_patterns = [p for p in patterns if p.confidence > 0.7]
        
        # Significant trends
        significant_trends = [t for t in trends if t.strength > 0.6]
        
        summary = {
            'total_patterns': len(patterns),
            'total_trends': len(trends),
            'high_confidence_patterns': len(high_conf_patterns),
            'significant_trends': len(significant_trends),
            'pattern_types': dict(pattern_types),
            'trend_directions': dict(trend_directions),
            'analysis_period': {
                'start': self._extract_date(documents[0]).isoformat() if documents else None,
                'end': self._extract_date(documents[-1]).isoformat() if documents else None,
                'document_count': len(documents)
            },
            'key_insights': self._generate_key_insights(patterns, trends),
            'recommendations': self._generate_recommendations(patterns, trends)
        }
        
        return summary
    
    def _generate_key_insights(self, patterns: List[Pattern], trends: List[Trend]) -> List[str]:
        """Generate key insights from analysis."""
        insights = []
        
        # Pattern insights
        temporal_patterns = [p for p in patterns if p.pattern_type == PatternType.TEMPORAL]
        if temporal_patterns:
            insights.append(f"Detected {len(temporal_patterns)} temporal patterns in legislative activity")
        
        thematic_patterns = [p for p in patterns if p.pattern_type == PatternType.THEMATIC]
        if thematic_patterns:
            top_theme = max(thematic_patterns, key=lambda p: p.significance_score)
            insights.append(f"Strongest thematic focus: {top_theme.name}")
        
        # Trend insights
        increasing_trends = [t for t in trends if t.direction == TrendDirection.INCREASING]
        if increasing_trends:
            insights.append(f"{len(increasing_trends)} areas showing increasing activity")
        
        decreasing_trends = [t for t in trends if t.direction == TrendDirection.DECREASING]
        if decreasing_trends:
            insights.append(f"{len(decreasing_trends)} areas showing decreasing activity")
        
        return insights
    
    def _generate_recommendations(self, patterns: List[Pattern], trends: List[Trend]) -> List[str]:
        """Generate recommendations based on analysis."""
        recommendations = []
        
        # High-activity pattern recommendations
        high_activity_patterns = [p for p in patterns if p.significance_score > 0.3]
        if high_activity_patterns:
            recommendations.append("Monitor high-activity areas for emerging policy developments")
        
        # Increasing trend recommendations
        increasing_trends = [t for t in trends if t.direction == TrendDirection.INCREASING and t.strength > 0.5]
        if increasing_trends:
            recommendations.append("Investigate drivers of increasing activity in identified areas")
        
        # Geographic pattern recommendations
        geographic_patterns = [p for p in patterns if p.pattern_type == PatternType.GEOGRAPHIC]
        if geographic_patterns:
            recommendations.append("Consider regional policy coordination for geographically concentrated issues")
        
        return recommendations