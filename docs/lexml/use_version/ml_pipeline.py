#!/usr/bin/env python3
"""
Machine Learning Pipeline for LexML Regulatory Analysis
Implements classification, prediction, and anomaly detection models
"""

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import SVC
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.pipeline import Pipeline
from sklearn.decomposition import PCA, LatentDirichletAllocation
from sklearn.cluster import KMeans, DBSCAN
import joblib
import json
import re
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional
import warnings
warnings.filterwarnings('ignore')

class RegulatoryMLPipeline:
    """Comprehensive ML pipeline for regulatory document analysis"""
    
    def __init__(self):
        self.models = {}
        self.vectorizers = {}
        self.scalers = {}
        self.encoders = {}
        self.performance_metrics = {}
        
    def generate_synthetic_data(self, n_samples: int = 5000) -> pd.DataFrame:
        """Generate synthetic regulatory document data for ML training"""
        
        np.random.seed(42)
        
        # Document types
        doc_types = ['Lei', 'Decreto', 'Portaria', 'Resolução', 'Instrução Normativa']
        urn_types = ['legislacao', 'jurisprudencia', 'doutrina', 'outros']
        authorities = ['ANTT', 'CONTRAN', 'DENATRAN', 'DNIT', 'ANP', 'ANAC', 'ANTAQ']
        transport_modes = ['rodoviario', 'aereo', 'maritimo', 'ferroviario', 'geral']
        states = ['SP', 'RJ', 'MG', 'RS', 'PR', 'BA', 'SC', 'GO', 'PE', 'CE', 'BR']
        
        # Generate features
        data = []
        
        for i in range(n_samples):
            # Basic features
            doc_type = np.random.choice(doc_types)
            urn_type = np.random.choice(urn_types)
            authority = np.random.choice(authorities)
            transport_mode = np.random.choice(transport_modes)
            state = np.random.choice(states)
            
            # Text features (simulated)
            text_length = np.random.randint(100, 2000)
            title_length = np.random.randint(20, 150)
            
            # Temporal features
            year = np.random.randint(1990, 2025)
            month = np.random.randint(1, 13)
            
            # Complexity features
            technical_terms = np.random.randint(0, 20)
            references = np.random.randint(0, 15)
            
            # Impact features (synthetic target)
            impact_score = self._calculate_synthetic_impact(
                authority, transport_mode, state, year, technical_terms
            )
            
            # Compliance difficulty (synthetic target)
            compliance_difficulty = self._calculate_compliance_difficulty(
                doc_type, text_length, technical_terms, references
            )
            
            # Document title (synthetic)
            title = self._generate_synthetic_title(doc_type, authority, transport_mode)
            
            # Document description (synthetic)
            description = self._generate_synthetic_description(
                doc_type, authority, transport_mode, technical_terms
            )
            
            data.append({
                'doc_id': f'DOC_{i:05d}',
                'title': title,
                'description': description,
                'document_type': doc_type,
                'urn_type': urn_type,
                'authority': authority,
                'transport_mode': transport_mode,
                'state': state,
                'year': year,
                'month': month,
                'text_length': text_length,
                'title_length': title_length,
                'technical_terms': technical_terms,
                'references': references,
                'impact_score': impact_score,
                'compliance_difficulty': compliance_difficulty
            })
        
        return pd.DataFrame(data)
    
    def _calculate_synthetic_impact(self, authority: str, mode: str, state: str, 
                                   year: int, technical_terms: int) -> str:
        """Calculate synthetic impact score"""
        
        # Authority weights
        authority_weights = {
            'ANTT': 0.8, 'CONTRAN': 0.7, 'DENATRAN': 0.6,
            'DNIT': 0.5, 'ANP': 0.6, 'ANAC': 0.4, 'ANTAQ': 0.3
        }
        
        # State weights (economic importance)
        state_weights = {
            'SP': 0.9, 'RJ': 0.8, 'MG': 0.7, 'RS': 0.6,
            'PR': 0.5, 'BA': 0.4, 'SC': 0.4, 'GO': 0.3,
            'PE': 0.3, 'CE': 0.2, 'BR': 1.0
        }
        
        # Mode weights
        mode_weights = {
            'rodoviario': 0.9, 'aereo': 0.6, 'maritimo': 0.5,
            'ferroviario': 0.4, 'geral': 0.7
        }
        
        # Calculate base score
        base_score = (
            authority_weights.get(authority, 0.5) * 0.4 +
            state_weights.get(state, 0.5) * 0.3 +
            mode_weights.get(mode, 0.5) * 0.2 +
            min(technical_terms / 20, 1.0) * 0.1
        )
        
        # Add year trend (recent years have higher potential impact)
        year_factor = min((year - 1990) / 35, 1.0)
        final_score = base_score * 0.8 + year_factor * 0.2
        
        # Convert to categories
        if final_score > 0.7:
            return 'Alto'
        elif final_score > 0.4:
            return 'Médio'
        else:
            return 'Baixo'
    
    def _calculate_compliance_difficulty(self, doc_type: str, text_length: int,
                                       technical_terms: int, references: int) -> str:
        """Calculate synthetic compliance difficulty"""
        
        # Document type complexity
        type_complexity = {
            'Lei': 0.8, 'Decreto': 0.7, 'Portaria': 0.5,
            'Resolução': 0.6, 'Instrução Normativa': 0.4
        }
        
        # Normalize features
        length_factor = min(text_length / 2000, 1.0)
        terms_factor = min(technical_terms / 20, 1.0)
        refs_factor = min(references / 15, 1.0)
        
        # Calculate complexity score
        complexity_score = (
            type_complexity.get(doc_type, 0.5) * 0.3 +
            length_factor * 0.25 +
            terms_factor * 0.25 +
            refs_factor * 0.2
        )
        
        # Convert to categories
        if complexity_score > 0.6:
            return 'Difícil'
        elif complexity_score > 0.3:
            return 'Moderado'
        else:
            return 'Fácil'
    
    def _generate_synthetic_title(self, doc_type: str, authority: str, mode: str) -> str:
        """Generate synthetic document title"""
        
        actions = ['Regulamenta', 'Estabelece', 'Dispõe sobre', 'Altera', 'Institui']
        subjects = {
            'rodoviario': ['transporte rodoviário', 'veículos de carga', 'frotas', 'segurança viária'],
            'aereo': ['aviação civil', 'transporte aéreo', 'aeronaves', 'aeroportos'],
            'maritimo': ['navegação', 'portos', 'embarcações', 'transporte aquaviário'],
            'ferroviario': ['transporte ferroviário', 'trens', 'ferrovias', 'estações'],
            'geral': ['transporte', 'mobilidade', 'logística', 'infraestrutura']
        }
        
        action = np.random.choice(actions)
        subject = np.random.choice(subjects.get(mode, subjects['geral']))
        
        return f"{doc_type} que {action.lower()} {subject} no âmbito do {authority}"
    
    def _generate_synthetic_description(self, doc_type: str, authority: str, 
                                       mode: str, technical_terms: int) -> str:
        """Generate synthetic document description"""
        
        base_desc = f"Documento {doc_type.lower()} emitido pelo {authority} "
        
        mode_desc = {
            'rodoviario': 'regulamentando aspectos do transporte rodoviário de cargas',
            'aereo': 'estabelecendo normas para o transporte aéreo',
            'maritimo': 'disciplinando o transporte marítimo e portuário',
            'ferroviario': 'regulando o sistema ferroviário nacional',
            'geral': 'tratando de aspectos gerais do transporte'
        }
        
        technical_desc = ""
        if technical_terms > 10:
            technical_desc = " com alto conteúdo técnico e especificações detalhadas"
        elif technical_terms > 5:
            technical_desc = " contendo especificações técnicas moderadas"
        
        return base_desc + mode_desc.get(mode, mode_desc['geral']) + technical_desc
    
    def build_text_features(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Build text-based features using TF-IDF and other NLP techniques"""
        
        print("📝 Building text features...")
        
        # Combine title and description
        df['combined_text'] = df['title'].fillna('') + ' ' + df['description'].fillna('')
        
        # TF-IDF features
        tfidf_vectorizer = TfidfVectorizer(
            max_features=1000,
            stop_words=None,  # Portuguese stop words would be ideal
            ngram_range=(1, 2),
            min_df=2,
            max_df=0.8
        )
        
        tfidf_features = tfidf_vectorizer.fit_transform(df['combined_text'])
        self.vectorizers['tfidf'] = tfidf_vectorizer
        
        # Count vectorizer for topic modeling
        count_vectorizer = CountVectorizer(
            max_features=500,
            ngram_range=(1, 2),
            min_df=3,
            max_df=0.7
        )
        
        count_features = count_vectorizer.fit_transform(df['combined_text'])
        self.vectorizers['count'] = count_vectorizer
        
        # Topic modeling with LDA
        lda = LatentDirichletAllocation(
            n_components=10,
            random_state=42,
            max_iter=100
        )
        
        topic_features = lda.fit_transform(count_features)
        self.models['lda'] = lda
        
        return {
            'tfidf_features': tfidf_features,
            'topic_features': topic_features,
            'feature_names': tfidf_vectorizer.get_feature_names_out()
        }
    
    def build_categorical_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Build and encode categorical features"""
        
        print("🏷️ Building categorical features...")
        
        # Encode categorical variables
        categorical_cols = ['document_type', 'urn_type', 'authority', 'transport_mode', 'state']
        
        for col in categorical_cols:
            le = LabelEncoder()
            df[f'{col}_encoded'] = le.fit_transform(df[col])
            self.encoders[col] = le
        
        # Create derived features
        df['is_federal'] = (df['state'] == 'BR').astype(int)
        df['is_recent'] = (df['year'] >= 2010).astype(int)
        df['is_high_authority'] = df['authority'].isin(['ANTT', 'CONTRAN', 'DENATRAN']).astype(int)
        df['is_road_transport'] = (df['transport_mode'] == 'rodoviario').astype(int)
        
        # Temporal features
        df['decade'] = (df['year'] // 10) * 10
        df['quarter'] = ((df['month'] - 1) // 3) + 1
        
        return df
    
    def train_document_classifier(self, df: pd.DataFrame, text_features: Dict) -> Dict:
        """Train document type classification model"""
        
        print("🤖 Training document classifier...")
        
        # Prepare features
        X_text = text_features['tfidf_features']
        X_categorical = df[['authority_encoded', 'transport_mode_encoded', 'state_encoded',
                          'year', 'text_length', 'technical_terms', 'references']].values
        
        # Scale numerical features
        scaler = StandardScaler()
        X_categorical_scaled = scaler.fit_transform(X_categorical)
        self.scalers['categorical'] = scaler
        
        # Combine features
        X_combined = np.hstack([X_text.toarray(), X_categorical_scaled])
        y = df['urn_type']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_combined, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train multiple models
        models = {
            'random_forest': RandomForestClassifier(n_estimators=100, random_state=42),
            'gradient_boosting': GradientBoostingClassifier(n_estimators=100, random_state=42),
            'logistic_regression': LogisticRegression(random_state=42, max_iter=1000),
            'naive_bayes': MultinomialNB()
        }
        
        results = {}
        
        for name, model in models.items():
            print(f"  Training {name}...")
            
            # Train model
            if name == 'naive_bayes':
                # Naive Bayes needs non-negative features
                model.fit(X_text, y_train)
                y_pred = model.predict(X_text)
                accuracy = accuracy_score(y_test, y_pred)
            else:
                model.fit(X_train, y_train)
                y_pred = model.predict(X_test)
                accuracy = accuracy_score(y_test, y_pred)
            
            # Cross-validation
            cv_scores = cross_val_score(model, X_train, y_train, cv=5)
            
            results[name] = {
                'model': model,
                'accuracy': accuracy,
                'cv_mean': cv_scores.mean(),
                'cv_std': cv_scores.std(),
                'classification_report': classification_report(y_test, y_pred, output_dict=True)
            }
            
            print(f"    Accuracy: {accuracy:.3f}")
            print(f"    CV Score: {cv_scores.mean():.3f} (+/- {cv_scores.std()*2:.3f})")
        
        # Select best model
        best_model_name = max(results.keys(), key=lambda x: results[x]['accuracy'])
        best_model = results[best_model_name]['model']
        
        self.models['document_classifier'] = best_model
        self.performance_metrics['document_classification'] = results
        
        return results
    
    def train_impact_predictor(self, df: pd.DataFrame, text_features: Dict) -> Dict:
        """Train regulatory impact prediction model"""
        
        print("🎯 Training impact predictor...")
        
        # Prepare features
        X_text = text_features['tfidf_features']
        X_topic = text_features['topic_features']
        X_categorical = df[['authority_encoded', 'transport_mode_encoded', 'state_encoded',
                          'year', 'text_length', 'technical_terms', 'references',
                          'is_federal', 'is_recent', 'is_high_authority']].values
        
        # Scale features
        scaler = StandardScaler()
        X_categorical_scaled = scaler.fit_transform(X_categorical)
        self.scalers['impact'] = scaler
        
        # Combine features
        X_combined = np.hstack([X_text.toarray(), X_topic, X_categorical_scaled])
        y = df['impact_score']
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_combined, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Train model
        model = RandomForestClassifier(n_estimators=150, random_state=42)
        model.fit(X_train, y_train)
        
        # Evaluate
        y_pred = model.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        cv_scores = cross_val_score(model, X_train, y_train, cv=5)
        
        # Feature importance
        feature_importance = model.feature_importances_
        
        self.models['impact_predictor'] = model
        
        results = {
            'accuracy': accuracy,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std(),
            'feature_importance': feature_importance.tolist(),
            'classification_report': classification_report(y_test, y_pred, output_dict=True)
        }
        
        self.performance_metrics['impact_prediction'] = results
        
        print(f"  Impact Predictor Accuracy: {accuracy:.3f}")
        print(f"  CV Score: {cv_scores.mean():.3f} (+/- {cv_scores.std()*2:.3f})")
        
        return results
    
    def train_anomaly_detector(self, df: pd.DataFrame, text_features: Dict) -> Dict:
        """Train anomaly detection model"""
        
        print("🔍 Training anomaly detector...")
        
        # Prepare features for anomaly detection
        X_text = text_features['tfidf_features']
        X_topic = text_features['topic_features']
        X_categorical = df[['authority_encoded', 'transport_mode_encoded', 'state_encoded',
                          'year', 'text_length', 'technical_terms', 'references']].values
        
        # Scale features
        scaler = StandardScaler()
        X_categorical_scaled = scaler.fit_transform(X_categorical)
        self.scalers['anomaly'] = scaler
        
        # Use PCA for dimensionality reduction
        pca = PCA(n_components=50)
        X_text_reduced = pca.fit_transform(X_text.toarray())
        
        # Combine features
        X_combined = np.hstack([X_text_reduced, X_topic, X_categorical_scaled])
        
        # Train clustering model for anomaly detection
        kmeans = KMeans(n_clusters=10, random_state=42)
        clusters = kmeans.fit_predict(X_combined)
        
        # Calculate distances to cluster centers
        distances = []
        for i, point in enumerate(X_combined):
            cluster_center = kmeans.cluster_centers_[clusters[i]]
            distance = np.linalg.norm(point - cluster_center)
            distances.append(distance)
        
        # Define anomaly threshold (95th percentile)
        anomaly_threshold = np.percentile(distances, 95)
        
        # DBSCAN for additional anomaly detection
        dbscan = DBSCAN(eps=0.5, min_samples=5)
        dbscan_labels = dbscan.fit_predict(X_combined)
        
        # Points labeled as -1 are anomalies in DBSCAN
        dbscan_anomalies = (dbscan_labels == -1)
        
        self.models['anomaly_detector'] = {
            'kmeans': kmeans,
            'dbscan': dbscan,
            'pca': pca,
            'threshold': anomaly_threshold
        }
        
        results = {
            'kmeans_anomalies': np.sum(np.array(distances) > anomaly_threshold),
            'dbscan_anomalies': np.sum(dbscan_anomalies),
            'total_documents': len(df),
            'anomaly_rate_kmeans': np.sum(np.array(distances) > anomaly_threshold) / len(df),
            'anomaly_rate_dbscan': np.sum(dbscan_anomalies) / len(df)
        }
        
        self.performance_metrics['anomaly_detection'] = results
        
        print(f"  K-means anomalies: {results['kmeans_anomalies']} ({results['anomaly_rate_kmeans']:.2%})")
        print(f"  DBSCAN anomalies: {results['dbscan_anomalies']} ({results['anomaly_rate_dbscan']:.2%})")
        
        return results
    
    def run_complete_pipeline(self, df: pd.DataFrame = None) -> Dict:
        """Run the complete ML pipeline"""
        
        print("🚀 Running Complete ML Pipeline")
        print("=" * 60)
        
        # Generate or use provided data
        if df is None:
            print("📊 Generating synthetic training data...")
            df = self.generate_synthetic_data(n_samples=5000)
        
        # Build features
        df = self.build_categorical_features(df)
        text_features = self.build_text_features(df)
        
        # Train models
        classification_results = self.train_document_classifier(df, text_features)
        impact_results = self.train_impact_predictor(df, text_features)
        anomaly_results = self.train_anomaly_detector(df, text_features)
        
        # Compile results
        pipeline_results = {
            'timestamp': datetime.now().isoformat(),
            'data_summary': {
                'total_samples': len(df),
                'features_built': len(text_features['feature_names']),
                'models_trained': len(self.models)
            },
            'performance_metrics': self.performance_metrics,
            'model_summary': {
                'document_classifier': 'Multi-class classification of document types',
                'impact_predictor': 'Regulatory impact level prediction',
                'anomaly_detector': 'Outlier detection for unusual documents'
            }
        }
        
        # Save results
        output_file = f"ml_pipeline_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(pipeline_results, f, indent=2, ensure_ascii=False, default=str)
        
        # Save models
        models_file = f"ml_models_{datetime.now().strftime('%Y%m%d_%H%M%S')}.joblib"
        joblib.dump({
            'models': self.models,
            'vectorizers': self.vectorizers,
            'scalers': self.scalers,
            'encoders': self.encoders
        }, models_file)
        
        print(f"\n✅ Pipeline completed successfully!")
        print(f"📄 Results saved to: {output_file}")
        print(f"🤖 Models saved to: {models_file}")
        
        return pipeline_results
    
    def predict_new_document(self, title: str, description: str, 
                           metadata: Dict) -> Dict:
        """Predict attributes for a new document"""
        
        if not self.models:
            raise ValueError("Models not trained. Run pipeline first.")
        
        # Prepare features
        combined_text = f"{title} {description}"
        
        # Text features
        tfidf_features = self.vectorizers['tfidf'].transform([combined_text])
        
        # Categorical features
        categorical_features = np.array([[
            metadata.get('authority_encoded', 0),
            metadata.get('transport_mode_encoded', 0),
            metadata.get('state_encoded', 0),
            metadata.get('year', 2024),
            len(combined_text),
            metadata.get('technical_terms', 0),
            metadata.get('references', 0)
        ]])
        
        # Scale categorical features
        categorical_scaled = self.scalers['categorical'].transform(categorical_features)
        
        # Combine features
        X_combined = np.hstack([tfidf_features.toarray(), categorical_scaled])
        
        # Make predictions
        predictions = {}
        
        if 'document_classifier' in self.models:
            doc_pred = self.models['document_classifier'].predict(X_combined)[0]
            doc_proba = self.models['document_classifier'].predict_proba(X_combined)[0]
            predictions['document_type'] = {
                'predicted_class': doc_pred,
                'confidence': float(max(doc_proba))
            }
        
        if 'impact_predictor' in self.models:
            impact_pred = self.models['impact_predictor'].predict(X_combined)[0]
            impact_proba = self.models['impact_predictor'].predict_proba(X_combined)[0]
            predictions['impact_level'] = {
                'predicted_class': impact_pred,
                'confidence': float(max(impact_proba))
            }
        
        return predictions


def main():
    """Main execution function"""
    print("🤖 LexML Machine Learning Pipeline")
    print("=" * 50)
    
    # Initialize pipeline
    pipeline = RegulatoryMLPipeline()
    
    # Run complete pipeline
    results = pipeline.run_complete_pipeline()
    
    # Display summary
    print(f"\n📊 Pipeline Summary:")
    print(f"  • Total samples processed: {results['data_summary']['total_samples']:,}")
    print(f"  • Features extracted: {results['data_summary']['features_built']:,}")
    print(f"  • Models trained: {results['data_summary']['models_trained']}")
    
    print(f"\n🎯 Model Performance:")
    for model_name, metrics in results['performance_metrics'].items():
        if isinstance(metrics, dict) and 'accuracy' in metrics:
            print(f"  • {model_name}: {metrics['accuracy']:.3f} accuracy")
    
    print(f"\n✅ ML Pipeline completed successfully!")
    
    return results


if __name__ == "__main__":
    main()