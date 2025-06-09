#!/usr/bin/env python3
"""
Production data seeding script for Monitor Legislativo
Seeds the database with realistic production data
"""

import os
import sys
import json
import logging
import random
from datetime import datetime, timedelta
from typing import List, Dict, Any

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from core.config.config import get_config
from core.database.migrations import DatabaseMigrationManager
from core.models.models import Document, Alert, User, SearchQuery, ExportRequest
from core.utils.production_logger import get_logger

class ProductionDataSeeder:
    """Seeds production database with realistic data"""
    
    def __init__(self):
        self.config = get_config()
        self.logger = get_logger()
        self.db_manager = DatabaseMigrationManager()
        
        # Sample data templates
        self.document_types = [
            "projeto_lei", "decreto", "portaria", "resolucao", 
            "medida_provisoria", "pec", "lei_complementar"
        ]
        
        self.sources = ["camara", "senado", "planalto", "ministerios", "agencias"]
        
        self.statuses = ["tramitando", "aprovado", "rejeitado", "arquivado", "sancionado"]
        
        # Sample content for different types
        self.sample_documents = self._load_sample_documents()
        
    def _load_sample_documents(self) -> List[Dict[str, Any]]:
        """Load sample document templates"""
        return [
            {
                "title": "Projeto de Lei nº {number}/2024 - Lei Geral de Proteção de Dados Pessoais",
                "type": "projeto_lei",
                "source": "camara",
                "content": "Estabelece diretrizes nacionais para a proteção de dados pessoais e cria a Autoridade Nacional de Proteção de Dados...",
                "summary": "Regulamenta a proteção de dados pessoais no âmbito da administração pública federal",
                "keywords": ["proteção de dados", "privacidade", "LGPD", "dados pessoais"]
            },
            {
                "title": "Decreto nº {number}/2024 - Transparência de Dados Governamentais",
                "type": "decreto",
                "source": "planalto",
                "content": "Estabelece diretrizes para a transparência e abertura de dados governamentais...",
                "summary": "Normas para transparência ativa de dados do governo federal",
                "keywords": ["transparência", "dados abertos", "governo digital", "acesso à informação"]
            },
            {
                "title": "Proposta de Emenda Constitucional nº {number}/2024 - Reforma Tributária",
                "type": "pec",
                "source": "senado",
                "content": "Altera a Constituição Federal para estabelecer novo sistema tributário nacional...",
                "summary": "Proposta de simplificação do sistema tributário brasileiro",
                "keywords": ["reforma tributária", "impostos", "simplificação", "federalismo"]
            },
            {
                "title": "Portaria nº {number}/2024 - Regulamentação de Serviços Digitais",
                "type": "portaria",
                "source": "ministerios",
                "content": "Estabelece procedimentos para a prestação de serviços públicos digitais...",
                "summary": "Normas para digitalização de serviços públicos",
                "keywords": ["serviços digitais", "governo eletrônico", "atendimento", "digitalização"]
            },
            {
                "title": "Resolução nº {number}/2024 - Normas de Sustentabilidade Ambiental",
                "type": "resolucao",
                "source": "agencias",
                "content": "Estabelece diretrizes para sustentabilidade ambiental em órgãos públicos...",
                "summary": "Normas ambientais para a administração pública federal",
                "keywords": ["sustentabilidade", "meio ambiente", "gestão ambiental", "responsabilidade"]
            },
            {
                "title": "Medida Provisória nº {number}/2024 - Programa de Digitalização",
                "type": "medida_provisoria",
                "source": "planalto",
                "content": "Institui programa nacional de digitalização de serviços públicos...",
                "summary": "Aceleração da transformação digital do setor público",
                "keywords": ["digitalização", "transformação digital", "modernização", "eficiência"]
            }
        ]
    
    def seed_users(self, count: int = 50) -> List[int]:
        """Seed users table with sample users"""
        self.logger.logger.info(f"Seeding {count} users...")
        
        from werkzeug.security import generate_password_hash
        
        user_templates = [
            {"role": "admin", "department": "TI", "count": 2},
            {"role": "manager", "department": "Juridico", "count": 8},
            {"role": "user", "department": "Analise", "count": 35},
            {"role": "viewer", "department": "Consultoria", "count": 5}
        ]
        
        users_sql = """
        INSERT INTO users (username, email, password_hash, role, active, created_at, department)
        VALUES (%(username)s, %(email)s, %(password_hash)s, %(role)s, %(active)s, %(created_at)s, %(department)s)
        RETURNING id
        """
        
        user_ids = []
        
        with self.db_manager.engine.connect() as conn:
            user_counter = 1
            
            for template in user_templates:
                for i in range(template["count"]):
                    username = f"user{user_counter:03d}"
                    email = f"{username}@monitor-legislativo.gov.br"
                    password_hash = generate_password_hash("password123")
                    
                    result = conn.execute(text(users_sql), {
                        "username": username,
                        "email": email,
                        "password_hash": password_hash,
                        "role": template["role"],
                        "active": True,
                        "created_at": datetime.utcnow() - timedelta(days=random.randint(1, 90)),
                        "department": template["department"]
                    })
                    
                    user_id = result.fetchone()[0]
                    user_ids.append(user_id)
                    user_counter += 1
            
            conn.commit()
        
        self.logger.logger.info(f"Created {len(user_ids)} users")
        return user_ids
    
    def seed_documents(self, count: int = 10000) -> List[int]:
        """Seed documents table with sample documents"""
        self.logger.logger.info(f"Seeding {count} documents...")
        
        documents_sql = """
        INSERT INTO documents (
            title, content, summary, type, source, status, 
            created_at, updated_at, metadata, url, keywords
        ) VALUES (
            %(title)s, %(content)s, %(summary)s, %(type)s, %(source)s, %(status)s,
            %(created_at)s, %(updated_at)s, %(metadata)s, %(url)s, %(keywords)s
        ) RETURNING id
        """
        
        document_ids = []
        
        with self.db_manager.engine.connect() as conn:
            for i in range(count):
                # Select random template
                template = random.choice(self.sample_documents)
                doc_number = f"{2024000 + i + 1}"
                
                # Generate document data
                title = template["title"].format(number=doc_number)
                content = template["content"] + f" Documento número {doc_number} com conteúdo específico..."
                summary = template["summary"]
                doc_type = template["type"]
                source = template["source"]
                status = random.choice(self.statuses)
                
                # Random timestamps within last year
                created_at = datetime.utcnow() - timedelta(
                    days=random.randint(1, 365),
                    hours=random.randint(0, 23),
                    minutes=random.randint(0, 59)
                )
                updated_at = created_at + timedelta(days=random.randint(0, 30))
                
                # Metadata
                metadata = {
                    "document_number": doc_number,
                    "year": 2024,
                    "classification": random.choice(["publico", "restrito", "confidencial"]),
                    "author": f"Autor {random.randint(1, 100)}",
                    "pages": random.randint(1, 50)
                }
                
                # URL
                url = f"https://{source}.gov.br/documentos/{doc_number}"
                
                # Keywords
                keywords = json.dumps(template["keywords"] + [f"doc{doc_number}", str(2024)])
                
                result = conn.execute(text(documents_sql), {
                    "title": title,
                    "content": content,
                    "summary": summary,
                    "type": doc_type,
                    "source": source,
                    "status": status,
                    "created_at": created_at,
                    "updated_at": updated_at,
                    "metadata": json.dumps(metadata),
                    "url": url,
                    "keywords": keywords
                })
                
                document_id = result.fetchone()[0]
                document_ids.append(document_id)
                
                if (i + 1) % 1000 == 0:
                    self.logger.logger.info(f"Created {i + 1} documents...")
            
            conn.commit()
        
        self.logger.logger.info(f"Created {len(document_ids)} documents")
        return document_ids
    
    def seed_alerts(self, user_ids: List[int], count: int = 200) -> List[int]:
        """Seed alerts table"""
        self.logger.logger.info(f"Seeding {count} alerts...")
        
        alerts_sql = """
        INSERT INTO alerts (
            user_id, name, description, query, filters, active, 
            created_at, last_triggered, trigger_count
        ) VALUES (
            %(user_id)s, %(name)s, %(description)s, %(query)s, %(filters)s, %(active)s,
            %(created_at)s, %(last_triggered)s, %(trigger_count)s
        ) RETURNING id
        """
        
        alert_templates = [
            {
                "name": "Leis de Proteção de Dados",
                "description": "Monitora documentos relacionados à proteção de dados pessoais",
                "query": "proteção dados pessoais LGPD",
                "filters": {"type": ["projeto_lei", "decreto"], "source": ["camara", "senado"]}
            },
            {
                "name": "Reforma Tributária",
                "description": "Acompanha propostas de reforma do sistema tributário",
                "query": "reforma tributária impostos",
                "filters": {"type": ["pec", "projeto_lei"], "source": ["camara", "senado"]}
            },
            {
                "name": "Digitalização Governo",
                "description": "Monitora iniciativas de digitalização do governo",
                "query": "digitalização governo eletrônico serviços digitais",
                "filters": {"type": ["decreto", "portaria"], "source": ["planalto", "ministerios"]}
            },
            {
                "name": "Sustentabilidade Ambiental",
                "description": "Acompanha normas de sustentabilidade ambiental",
                "query": "sustentabilidade meio ambiente",
                "filters": {"type": ["resolucao", "portaria"], "source": ["agencias", "ministerios"]}
            },
            {
                "name": "Transparência Pública",
                "description": "Monitora documentos sobre transparência e dados abertos",
                "query": "transparência dados abertos acesso informação",
                "filters": {"source": ["planalto", "ministerios"]}
            }
        ]
        
        alert_ids = []
        
        with self.db_manager.engine.connect() as conn:
            for i in range(count):
                template = random.choice(alert_templates)
                user_id = random.choice(user_ids)
                
                # Add variation to alerts
                name = f"{template['name']} - {i + 1}"
                description = template['description']
                query = template['query']
                filters = json.dumps(template['filters'])
                active = random.choice([True, True, True, False])  # 75% active
                
                created_at = datetime.utcnow() - timedelta(days=random.randint(1, 180))
                last_triggered = created_at + timedelta(days=random.randint(1, 30)) if active else None
                trigger_count = random.randint(0, 50) if active else 0
                
                result = conn.execute(text(alerts_sql), {
                    "user_id": user_id,
                    "name": name,
                    "description": description,
                    "query": query,
                    "filters": filters,
                    "active": active,
                    "created_at": created_at,
                    "last_triggered": last_triggered,
                    "trigger_count": trigger_count
                })
                
                alert_id = result.fetchone()[0]
                alert_ids.append(alert_id)
            
            conn.commit()
        
        self.logger.logger.info(f"Created {len(alert_ids)} alerts")
        return alert_ids
    
    def seed_search_queries(self, user_ids: List[int], count: int = 5000):
        """Seed search queries table"""
        self.logger.logger.info(f"Seeding {count} search queries...")
        
        search_sql = """
        INSERT INTO search_queries (
            user_id, query, filters, results_count, execution_time,
            created_at
        ) VALUES (
            %(user_id)s, %(query)s, %(filters)s, %(results_count)s, %(execution_time)s,
            %(created_at)s
        )
        """
        
        common_queries = [
            "lei proteção dados",
            "reforma tributária",
            "governo digital",
            "sustentabilidade",
            "transparência",
            "decreto 2024",
            "projeto lei educação",
            "portaria saúde",
            "resolução ambiental",
            "medida provisória economia"
        ]
        
        with self.db_manager.engine.connect() as conn:
            for i in range(count):
                user_id = random.choice(user_ids)
                query = random.choice(common_queries)
                
                # Add some variation
                if random.random() < 0.3:
                    query += f" {random.randint(2020, 2024)}"
                
                filters = json.dumps({
                    "type": random.sample(self.document_types, random.randint(1, 3)),
                    "source": random.sample(self.sources, random.randint(1, 2))
                } if random.random() < 0.4 else {})
                
                results_count = random.randint(0, 500)
                execution_time = round(random.uniform(0.1, 5.0), 3)
                created_at = datetime.utcnow() - timedelta(
                    days=random.randint(1, 90),
                    hours=random.randint(0, 23),
                    minutes=random.randint(0, 59)
                )
                
                conn.execute(text(search_sql), {
                    "user_id": user_id,
                    "query": query,
                    "filters": filters,
                    "results_count": results_count,
                    "execution_time": execution_time,
                    "created_at": created_at
                })
            
            conn.commit()
        
        self.logger.logger.info(f"Created {count} search queries")
    
    def seed_export_requests(self, user_ids: List[int], count: int = 500):
        """Seed export requests table"""
        self.logger.logger.info(f"Seeding {count} export requests...")
        
        export_sql = """
        INSERT INTO export_requests (
            user_id, format, query, filters, status, file_path,
            created_at, completed_at, records_count, file_size
        ) VALUES (
            %(user_id)s, %(format)s, %(query)s, %(filters)s, %(status)s, %(file_path)s,
            %(created_at)s, %(completed_at)s, %(records_count)s, %(file_size)s
        )
        """
        
        formats = ["csv", "json", "excel", "pdf"]
        statuses = ["completed", "completed", "completed", "failed", "pending"]
        
        with self.db_manager.engine.connect() as conn:
            for i in range(count):
                user_id = random.choice(user_ids)
                format_type = random.choice(formats)
                query = random.choice([
                    "proteção dados",
                    "reforma tributária",
                    "sustentabilidade",
                    "transparência governo",
                    ""  # Empty query for full export
                ])
                
                filters = json.dumps({
                    "date_range": {
                        "start": "2024-01-01",
                        "end": "2024-12-31"
                    },
                    "type": random.sample(self.document_types, random.randint(1, 2))
                } if random.random() < 0.6 else {})
                
                status = random.choice(statuses)
                created_at = datetime.utcnow() - timedelta(days=random.randint(1, 60))
                
                if status == "completed":
                    completed_at = created_at + timedelta(minutes=random.randint(1, 30))
                    records_count = random.randint(10, 10000)
                    file_size = random.randint(1024, 50*1024*1024)  # 1KB to 50MB
                    file_path = f"exports/export_{i+1}_{user_id}.{format_type}"
                elif status == "failed":
                    completed_at = created_at + timedelta(minutes=random.randint(1, 10))
                    records_count = 0
                    file_size = 0
                    file_path = None
                else:  # pending
                    completed_at = None
                    records_count = None
                    file_size = None
                    file_path = None
                
                conn.execute(text(export_sql), {
                    "user_id": user_id,
                    "format": format_type,
                    "query": query,
                    "filters": filters,
                    "status": status,
                    "file_path": file_path,
                    "created_at": created_at,
                    "completed_at": completed_at,
                    "records_count": records_count,
                    "file_size": file_size
                })
            
            conn.commit()
        
        self.logger.logger.info(f"Created {count} export requests")
    
    def create_sample_exports(self, count: int = 20):
        """Create sample export files"""
        self.logger.logger.info(f"Creating {count} sample export files...")
        
        export_dir = "data/exports"
        os.makedirs(export_dir, exist_ok=True)
        
        for i in range(count):
            # Create sample CSV
            csv_file = os.path.join(export_dir, f"sample_export_{i+1}.csv")
            with open(csv_file, 'w', encoding='utf-8') as f:
                f.write("title,type,source,status,created_at\n")
                for j in range(random.randint(10, 100)):
                    template = random.choice(self.sample_documents)
                    f.write(f'"{template["title"].format(number=j+1)}",')
                    f.write(f'"{template["type"]}",')
                    f.write(f'"{template["source"]}",')
                    f.write(f'"{random.choice(self.statuses)}",')
                    f.write(f'"{datetime.utcnow().isoformat()}"\n')
        
        self.logger.logger.info(f"Created {count} sample export files")
    
    def run_full_seed(self):
        """Run complete data seeding process"""
        self.logger.logger.info("Starting full production data seeding...")
        
        try:
            # Ensure database is initialized
            if not self.db_manager.get_applied_migrations():
                self.logger.logger.info("Initializing database...")
                self.db_manager.initialize_database()
            
            # Apply any pending migrations
            self.db_manager.apply_migrations()
            
            # Seed data
            user_ids = self.seed_users(50)
            document_ids = self.seed_documents(10000)
            alert_ids = self.seed_alerts(user_ids, 200)
            self.seed_search_queries(user_ids, 5000)
            self.seed_export_requests(user_ids, 500)
            self.create_sample_exports(20)
            
            # Update search vectors for documents
            self.logger.logger.info("Updating search vectors...")
            with self.db_manager.engine.connect() as conn:
                conn.execute(text("""
                    UPDATE documents 
                    SET search_vector = to_tsvector('portuguese', 
                        COALESCE(title, '') || ' ' || 
                        COALESCE(content, '') || ' ' ||
                        COALESCE(summary, '')
                    )
                    WHERE search_vector IS NULL
                """))
                conn.commit()
            
            self.logger.logger.info("Production data seeding completed successfully!")
            
            # Generate summary report
            self._generate_seeding_report()
            
        except Exception as e:
            self.logger.logger.error(f"Data seeding failed: {e}")
            raise
    
    def _generate_seeding_report(self):
        """Generate seeding summary report"""
        report = {
            "seeding_completed_at": datetime.utcnow().isoformat(),
            "environment": self.config.ENVIRONMENT,
            "database_url": self.config.DATABASE_URL.split('@')[0] + '@***',  # Hide credentials
            "summary": {}
        }
        
        # Count records
        with self.db_manager.engine.connect() as conn:
            tables = ['users', 'documents', 'alerts', 'search_queries', 'export_requests']
            
            for table in tables:
                result = conn.execute(text(f"SELECT COUNT(*) FROM {table}"))
                count = result.fetchone()[0]
                report["summary"][table] = count
        
        # Save report
        report_file = f"data/reports/seeding_report_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
        os.makedirs("data/reports", exist_ok=True)
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        self.logger.logger.info(f"Seeding report saved to: {report_file}")
        
        # Print summary
        print("\n=== Production Data Seeding Summary ===")
        for table, count in report["summary"].items():
            print(f"{table.replace('_', ' ').title()}: {count:,}")
        print(f"\nReport saved to: {report_file}")

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Seed production data for Monitor Legislativo")
    parser.add_argument("--users", type=int, default=50, help="Number of users to create")
    parser.add_argument("--documents", type=int, default=10000, help="Number of documents to create")
    parser.add_argument("--alerts", type=int, default=200, help="Number of alerts to create")
    parser.add_argument("--searches", type=int, default=5000, help="Number of search queries to create")
    parser.add_argument("--exports", type=int, default=500, help="Number of export requests to create")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be done without executing")
    
    args = parser.parse_args()
    
    if args.dry_run:
        print("Dry run mode - showing what would be created:")
        print(f"Users: {args.users}")
        print(f"Documents: {args.documents}")
        print(f"Alerts: {args.alerts}")
        print(f"Search Queries: {args.searches}")
        print(f"Export Requests: {args.exports}")
        print("\nRun without --dry-run to execute seeding.")
        return
    
    seeder = ProductionDataSeeder()
    
    if args.users or args.documents or args.alerts or args.searches or args.exports:
        # Custom seeding
        if args.users:
            user_ids = seeder.seed_users(args.users)
        else:
            # Get existing user IDs
            with seeder.db_manager.engine.connect() as conn:
                result = conn.execute(text("SELECT id FROM users WHERE active = true"))
                user_ids = [row[0] for row in result]
        
        if args.documents:
            seeder.seed_documents(args.documents)
        
        if args.alerts and user_ids:
            seeder.seed_alerts(user_ids, args.alerts)
        
        if args.searches and user_ids:
            seeder.seed_search_queries(user_ids, args.searches)
        
        if args.exports and user_ids:
            seeder.seed_export_requests(user_ids, args.exports)
    else:
        # Full seeding
        seeder.run_full_seed()

if __name__ == "__main__":
    # Fix import issue
    from sqlalchemy import text
    logging.basicConfig(level=logging.INFO)
    main()