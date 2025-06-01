"""Smart alerts with ML-based relevance scoring and intelligent filtering."""

import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import defaultdict, Counter
import math
import json

from core.utils.cache_manager import CacheManager
from core.realtime.monitoring_service import MonitoringRule, MonitoringNotification


@dataclass
class RelevanceScore:
    """Relevance score with component breakdown."""
    total_score: float
    content_relevance: float
    user_preference: float
    temporal_relevance: float
    source_credibility: float
    document_importance: float
    confidence: float


@dataclass
class SmartAlert:
    """Enhanced alert with ML-based scoring."""
    id: str
    user_id: int
    document_id: int
    rule_id: str
    title: str
    message: str
    relevance_score: RelevanceScore
    priority: str  # 'high', 'medium', 'low'
    tags: List[str]
    created_at: str
    expires_at: Optional[str] = None
    dismissed: bool = False
    clicked: bool = False
    feedback_score: Optional[int] = None  # User feedback 1-5


@dataclass
class UserProfile:
    """User profile for personalization."""
    user_id: int
    interests: Dict[str, float]  # topic -> weight
    preferred_sources: Dict[str, float]  # source -> weight
    document_type_preferences: Dict[str, float]  # type -> weight
    activity_pattern: Dict[str, float]  # hour -> activity_weight
    feedback_history: List[Dict[str, Any]]
    last_updated: str


class SmartAlertEngine:
    """ML-based smart alert engine with relevance scoring."""
    
    def __init__(self):
        self.cache_manager = CacheManager()
        self.logger = logging.getLogger(__name__)
        
        # User profiles
        self.user_profiles: Dict[int, UserProfile] = {}
        
        # Alert configuration
        self.min_relevance_threshold = 0.3
        self.max_alerts_per_user_per_day = 20
        self.alert_expiry_hours = 72
        
        # ML model weights (simplified - would be learned from data)
        self.feature_weights = {
            'content_match': 0.25,
            'user_preference': 0.20,
            'temporal_relevance': 0.15,
            'source_credibility': 0.15,
            'document_importance': 0.15,
            'social_signals': 0.10
        }
        
        # Topic categories and weights
        self.topic_categories = {
            'proteção_dados': ['dados', 'privacidade', 'lgpd', 'proteção', 'informação'],
            'educação': ['educação', 'ensino', 'escola', 'universidade', 'estudante'],
            'saúde': ['saúde', 'medicina', 'hospital', 'sus', 'paciente'],
            'meio_ambiente': ['ambiente', 'sustentabilidade', 'clima', 'poluição'],
            'tecnologia': ['digital', 'tecnologia', 'internet', 'software', 'inovação'],
            'economia': ['economia', 'financeiro', 'mercado', 'investimento'],
            'segurança': ['segurança', 'crime', 'violência', 'polícia'],
            'infraestrutura': ['transporte', 'energia', 'saneamento', 'obras']
        }
        
        # Source credibility scores
        self.source_credibility = {
            'Planalto': 0.95,
            'Camara': 0.90,
            'Senado': 0.90,
            'STF': 0.95,
            'TCU': 0.85,
            'Ministerio': 0.80
        }
    
    def generate_smart_alert(self, rule: MonitoringRule, document: Dict[str, Any]) -> Optional[SmartAlert]:
        """Generate a smart alert with ML-based relevance scoring."""
        try:
            # Get or create user profile
            user_profile = self._get_user_profile(rule.user_id)
            
            # Calculate relevance score
            relevance_score = self._calculate_relevance_score(document, rule, user_profile)
            
            # Check if alert meets threshold
            if relevance_score.total_score < self.min_relevance_threshold:
                self.logger.debug(f"Alert below threshold: {relevance_score.total_score}")
                return None
            
            # Check daily limit
            if self._exceeds_daily_limit(rule.user_id):
                self.logger.debug(f"Daily alert limit exceeded for user {rule.user_id}")
                return None
            
            # Determine priority
            priority = self._determine_priority(relevance_score.total_score)
            
            # Extract tags
            tags = self._extract_tags(document)
            
            # Generate alert
            alert = SmartAlert(
                id=self._generate_alert_id(),
                user_id=rule.user_id,
                document_id=document.get('id', 0),
                rule_id=rule.id,
                title=self._generate_smart_title(document, rule, relevance_score),
                message=self._generate_smart_message(document, rule, relevance_score),
                relevance_score=relevance_score,
                priority=priority,
                tags=tags,
                created_at=datetime.now().isoformat(),
                expires_at=(datetime.now() + timedelta(hours=self.alert_expiry_hours)).isoformat()
            )
            
            # Update user profile with interaction
            self._update_user_profile_for_alert(user_profile, document, rule)
            
            self.logger.info(f"Generated smart alert {alert.id} with score {relevance_score.total_score:.3f}")
            return alert
            
        except Exception as e:
            self.logger.error(f"Error generating smart alert: {e}")
            return None
    
    def _calculate_relevance_score(self, document: Dict[str, Any], 
                                  rule: MonitoringRule, 
                                  user_profile: UserProfile) -> RelevanceScore:
        """Calculate ML-based relevance score."""
        # Content relevance
        content_relevance = self._calculate_content_relevance(document, rule)
        
        # User preference matching
        user_preference = self._calculate_user_preference_score(document, user_profile)
        
        # Temporal relevance
        temporal_relevance = self._calculate_temporal_relevance(document)
        
        # Source credibility
        source_credibility = self._calculate_source_credibility(document)
        
        # Document importance
        document_importance = self._calculate_document_importance(document)
        
        # Calculate weighted total
        total_score = (
            content_relevance * self.feature_weights['content_match'] +
            user_preference * self.feature_weights['user_preference'] +
            temporal_relevance * self.feature_weights['temporal_relevance'] +
            source_credibility * self.feature_weights['source_credibility'] +
            document_importance * self.feature_weights['document_importance']
        )
        
        # Calculate confidence based on data availability
        confidence = self._calculate_confidence_score(document, user_profile)
        
        return RelevanceScore(
            total_score=min(total_score, 1.0),
            content_relevance=content_relevance,
            user_preference=user_preference,
            temporal_relevance=temporal_relevance,
            source_credibility=source_credibility,
            document_importance=document_importance,
            confidence=confidence
        )
    
    def _calculate_content_relevance(self, document: Dict[str, Any], rule: MonitoringRule) -> float:
        """Calculate content relevance score."""
        content = ' '.join([
            document.get('title', ''),
            document.get('content', ''),
            ' '.join(document.get('keywords', []))
        ]).lower()
        
        if not content or not rule.keywords:
            return 0.0
        
        total_score = 0.0
        content_words = content.split()
        content_length = len(content_words)
        
        for keyword in rule.keywords:
            keyword_lower = keyword.lower()
            
            # Exact matches
            exact_matches = content.count(keyword_lower)
            exact_score = min(exact_matches / 5.0, 1.0)  # Diminishing returns
            
            # Partial matches
            partial_matches = sum(1 for word in content_words if keyword_lower in word)
            partial_score = min(partial_matches / 10.0, 0.5)
            
            # Position boost (keywords in title get higher score)
            title_boost = 1.5 if keyword_lower in document.get('title', '').lower() else 1.0
            
            keyword_score = (exact_score + partial_score) * title_boost
            total_score += keyword_score
        
        # Normalize by number of keywords and content length
        normalized_score = total_score / len(rule.keywords)
        if content_length > 0:
            normalized_score = normalized_score / (math.log(content_length) + 1)
        
        return min(normalized_score, 1.0)
    
    def _calculate_user_preference_score(self, document: Dict[str, Any], 
                                       user_profile: UserProfile) -> float:
        """Calculate user preference matching score."""
        if not user_profile.interests:
            return 0.5  # Neutral score for new users
        
        # Extract document topics
        doc_topics = self._extract_document_topics(document)
        
        # Calculate topic matching score
        topic_score = 0.0
        for topic, weight in doc_topics.items():
            if topic in user_profile.interests:
                topic_score += weight * user_profile.interests[topic]
        
        # Source preference
        doc_source = document.get('source', '')
        source_score = user_profile.preferred_sources.get(doc_source, 0.5)
        
        # Document type preference
        doc_type = document.get('document_type', '')
        type_score = user_profile.document_type_preferences.get(doc_type, 0.5)
        
        # Combine scores
        combined_score = (topic_score * 0.6 + source_score * 0.2 + type_score * 0.2)
        return min(combined_score, 1.0)
    
    def _calculate_temporal_relevance(self, document: Dict[str, Any]) -> float:
        """Calculate temporal relevance based on document recency."""
        pub_date_str = document.get('published_date')
        if not pub_date_str:
            return 0.5
        
        try:
            pub_date = datetime.fromisoformat(pub_date_str.replace('Z', '+00:00'))
            days_old = (datetime.now() - pub_date).days
            
            # Recency decay function
            if days_old <= 1:
                return 1.0
            elif days_old <= 7:
                return 0.9
            elif days_old <= 30:
                return 0.7
            elif days_old <= 90:
                return 0.5
            elif days_old <= 365:
                return 0.3
            else:
                return 0.1
                
        except (ValueError, TypeError):
            return 0.5
    
    def _calculate_source_credibility(self, document: Dict[str, Any]) -> float:
        """Calculate source credibility score."""
        source = document.get('source', '')
        return self.source_credibility.get(source, 0.5)
    
    def _calculate_document_importance(self, document: Dict[str, Any]) -> float:
        """Calculate document importance score."""
        # Document type importance
        doc_type = document.get('document_type', '')
        type_importance = {
            'LEI': 1.0,
            'DECRETO': 0.8,
            'PORTARIA': 0.6,
            'RESOLUCAO': 0.5,
            'INSTRUCAO_NORMATIVA': 0.4
        }.get(doc_type, 0.3)
        
        # Metadata importance
        metadata = document.get('metadata', {})
        metadata_importance = {
            'alta': 1.0,
            'media': 0.7,
            'baixa': 0.4
        }.get(metadata.get('importance', 'baixa'), 0.4)
        
        # Content length indicator (longer documents might be more comprehensive)
        content_length = len(document.get('content', ''))
        length_score = min(content_length / 5000.0, 1.0)  # Normalize to 5000 chars
        
        # Combine factors
        importance_score = (type_importance * 0.5 + metadata_importance * 0.3 + length_score * 0.2)
        return min(importance_score, 1.0)
    
    def _calculate_confidence_score(self, document: Dict[str, Any], 
                                  user_profile: UserProfile) -> float:
        """Calculate confidence in the relevance score."""
        confidence_factors = []
        
        # Data completeness
        required_fields = ['title', 'content', 'source', 'published_date']
        completeness = sum(1 for field in required_fields if document.get(field)) / len(required_fields)
        confidence_factors.append(completeness)
        
        # User profile maturity
        feedback_count = len(user_profile.feedback_history)
        profile_maturity = min(feedback_count / 20.0, 1.0)  # 20 feedbacks for full maturity
        confidence_factors.append(profile_maturity)
        
        # Content richness
        content_richness = min(len(document.get('content', '')) / 1000.0, 1.0)
        confidence_factors.append(content_richness)
        
        return sum(confidence_factors) / len(confidence_factors)
    
    def _extract_document_topics(self, document: Dict[str, Any]) -> Dict[str, float]:
        """Extract topics from document with weights."""
        content = ' '.join([
            document.get('title', ''),
            document.get('content', ''),
            ' '.join(document.get('keywords', []))
        ]).lower()
        
        topic_scores = {}
        
        for topic, keywords in self.topic_categories.items():
            score = 0.0
            for keyword in keywords:
                # Count keyword occurrences
                occurrences = content.count(keyword.lower())
                score += occurrences
            
            # Normalize by topic keyword count
            if keywords:
                topic_scores[topic] = min(score / len(keywords), 1.0)
        
        return topic_scores
    
    def _get_user_profile(self, user_id: int) -> UserProfile:
        """Get or create user profile."""
        if user_id not in self.user_profiles:
            self.user_profiles[user_id] = UserProfile(
                user_id=user_id,
                interests={},
                preferred_sources={},
                document_type_preferences={},
                activity_pattern={},
                feedback_history=[],
                last_updated=datetime.now().isoformat()
            )
            
            # Load from storage if exists
            self._load_user_profile(user_id)
        
        return self.user_profiles[user_id]
    
    def _update_user_profile_for_alert(self, user_profile: UserProfile, 
                                     document: Dict[str, Any], rule: MonitoringRule):
        """Update user profile based on alert generation."""
        # Update document type preferences
        doc_type = document.get('document_type', '')
        if doc_type:
            current_pref = user_profile.document_type_preferences.get(doc_type, 0.5)
            user_profile.document_type_preferences[doc_type] = min(current_pref + 0.01, 1.0)
        
        # Update source preferences
        source = document.get('source', '')
        if source:
            current_pref = user_profile.preferred_sources.get(source, 0.5)
            user_profile.preferred_sources[source] = min(current_pref + 0.01, 1.0)
        
        # Update topic interests
        doc_topics = self._extract_document_topics(document)
        for topic, weight in doc_topics.items():
            current_interest = user_profile.interests.get(topic, 0.5)
            user_profile.interests[topic] = min(current_interest + weight * 0.01, 1.0)
        
        user_profile.last_updated = datetime.now().isoformat()
        self._save_user_profile(user_profile)
    
    def process_user_feedback(self, alert_id: str, feedback_score: int, user_id: int):
        """Process user feedback to improve recommendations."""
        if not 1 <= feedback_score <= 5:
            return
        
        user_profile = self._get_user_profile(user_id)
        
        # Add feedback to history
        feedback = {
            'alert_id': alert_id,
            'score': feedback_score,
            'timestamp': datetime.now().isoformat()
        }
        user_profile.feedback_history.append(feedback)
        
        # Keep only last 100 feedbacks
        user_profile.feedback_history = user_profile.feedback_history[-100:]
        
        # Adjust preferences based on feedback
        # This would involve more sophisticated ML learning
        # For now, simple adjustment based on positive/negative feedback
        
        user_profile.last_updated = datetime.now().isoformat()
        self._save_user_profile(user_profile)
    
    def _determine_priority(self, relevance_score: float) -> str:
        """Determine alert priority based on relevance score."""
        if relevance_score >= 0.8:
            return 'high'
        elif relevance_score >= 0.6:
            return 'medium'
        else:
            return 'low'
    
    def _extract_tags(self, document: Dict[str, Any]) -> List[str]:
        """Extract relevant tags from document."""
        tags = []
        
        # Add document type as tag
        doc_type = document.get('document_type', '')
        if doc_type:
            tags.append(doc_type.lower())
        
        # Add source as tag
        source = document.get('source', '')
        if source:
            tags.append(source.lower())
        
        # Add topic tags
        doc_topics = self._extract_document_topics(document)
        for topic, weight in doc_topics.items():
            if weight > 0.3:  # Only significant topics
                tags.append(topic)
        
        # Add recency tag
        if self._calculate_temporal_relevance(document) > 0.8:
            tags.append('recent')
        
        return tags[:5]  # Limit to 5 tags
    
    def _generate_smart_title(self, document: Dict[str, Any], 
                             rule: MonitoringRule, relevance_score: RelevanceScore) -> str:
        """Generate intelligent alert title."""
        doc_title = document.get('title', 'Documento sem título')
        
        # Truncate long titles
        if len(doc_title) > 60:
            doc_title = doc_title[:57] + '...'
        
        # Add priority indicator
        priority_indicator = {
            'high': '🔥',
            'medium': '⚡',
            'low': '📄'
        }.get(self._determine_priority(relevance_score.total_score), '')
        
        return f"{priority_indicator} {doc_title}"
    
    def _generate_smart_message(self, document: Dict[str, Any], 
                               rule: MonitoringRule, relevance_score: RelevanceScore) -> str:
        """Generate intelligent alert message."""
        doc_title = document.get('title', 'Documento sem título')
        source = document.get('source', 'Fonte desconhecida')
        
        # Identify key relevance factors
        top_factors = []
        if relevance_score.content_relevance > 0.7:
            top_factors.append("alta correspondência de conteúdo")
        if relevance_score.user_preference > 0.7:
            top_factors.append("corresponde às suas preferências")
        if relevance_score.temporal_relevance > 0.8:
            top_factors.append("documento recente")
        
        factor_text = ""
        if top_factors:
            factor_text = f" ({', '.join(top_factors)})"
        
        message = f"Novo documento encontrado para a regra '{rule.name}': {doc_title} - {source}{factor_text}"
        
        # Add confidence indicator
        if relevance_score.confidence < 0.5:
            message += " [Recomendação com baixa confiança]"
        
        return message
    
    def _exceeds_daily_limit(self, user_id: int) -> bool:
        """Check if user has exceeded daily alert limit."""
        # This would check against stored alert counts
        # For now, return False (no limit enforcement)
        return False
    
    def _generate_alert_id(self) -> str:
        """Generate unique alert ID."""
        import hashlib
        content = f"alert_{datetime.now().isoformat()}_{id(self)}"
        return hashlib.md5(content.encode()).hexdigest()[:16]
    
    def _load_user_profile(self, user_id: int):
        """Load user profile from storage."""
        # This would load from database
        pass
    
    def _save_user_profile(self, user_profile: UserProfile):
        """Save user profile to storage."""
        # This would save to database
        pass