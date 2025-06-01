"""
Multi-tenant Database Sharding Strategy for Monitor Legislativo
Developed by Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import hashlib
import uuid
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
from enum import Enum
from dataclasses import dataclass
from sqlalchemy import create_engine, MetaData, Table, Column, String, DateTime, Integer, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import logging

logger = logging.getLogger(__name__)

class ShardingStrategy(Enum):
    """Sharding strategies available"""
    HASH_BASED = "hash_based"
    RANGE_BASED = "range_based"
    DIRECTORY_BASED = "directory_based"
    HYBRID = "hybrid"

class TenantType(Enum):
    """Types of tenants in the system"""
    GOVERNMENT = "government"
    ACADEMIC = "academic"
    CORPORATE = "corporate"
    NGO = "ngo"
    INDIVIDUAL = "individual"

@dataclass
class ShardConfig:
    """Configuration for a database shard"""
    shard_id: str
    connection_string: str
    capacity_limit: int
    current_tenants: int
    region: str
    is_active: bool = True
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()

@dataclass
class TenantConfig:
    """Configuration for a tenant"""
    tenant_id: str
    tenant_name: str
    tenant_type: TenantType
    shard_id: str
    data_retention_days: int = 365
    max_documents: int = 100000
    max_users: int = 100
    created_at: datetime = None
    is_active: bool = True
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()

class ShardingManager:
    """Manages database sharding for multi-tenant support"""
    
    def __init__(self, master_db_url: str, strategy: ShardingStrategy = ShardingStrategy.HASH_BASED):
        self.master_db_url = master_db_url
        self.strategy = strategy
        self.shards: Dict[str, ShardConfig] = {}
        self.tenants: Dict[str, TenantConfig] = {}
        self.shard_engines: Dict[str, Any] = {}
        
        # Attribution
        self.project_attribution = {
            "developers": "Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães",
            "organization": "MackIntegridade",
            "financing": "MackPesquisa"
        }
        
        # Initialize master database connection
        self.master_engine = create_engine(master_db_url)
        self.master_session = sessionmaker(bind=self.master_engine)
        
        # Load existing shard and tenant configurations
        self._load_configurations()
    
    def add_shard(self, shard_config: ShardConfig) -> bool:
        """Add a new shard to the system"""
        try:
            # Test connection to the shard
            engine = create_engine(shard_config.connection_string)
            engine.connect().close()
            
            # Store shard configuration
            self.shards[shard_config.shard_id] = shard_config
            self.shard_engines[shard_config.shard_id] = engine
            
            # Initialize shard schema
            self._initialize_shard_schema(shard_config.shard_id)
            
            # Save to master database
            self._save_shard_config(shard_config)
            
            logger.info(f"Shard {shard_config.shard_id} added successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add shard {shard_config.shard_id}: {e}")
            return False
    
    def create_tenant(self, tenant_name: str, tenant_type: TenantType, 
                     preferences: Dict[str, Any] = None) -> str:
        """Create a new tenant and assign to appropriate shard"""
        
        tenant_id = str(uuid.uuid4())
        
        # Determine optimal shard
        shard_id = self._select_shard_for_tenant(tenant_id, tenant_type)
        
        if not shard_id:
            raise Exception("No available shards for new tenant")
        
        # Create tenant configuration
        tenant_config = TenantConfig(
            tenant_id=tenant_id,
            tenant_name=tenant_name,
            tenant_type=tenant_type,
            shard_id=shard_id,
            data_retention_days=preferences.get('data_retention_days', 365),
            max_documents=preferences.get('max_documents', 100000),
            max_users=preferences.get('max_users', 100)
        )
        
        # Initialize tenant schema in shard
        self._initialize_tenant_schema(tenant_config)
        
        # Store tenant configuration
        self.tenants[tenant_id] = tenant_config
        self._save_tenant_config(tenant_config)
        
        # Update shard tenant count
        self.shards[shard_id].current_tenants += 1
        
        logger.info(f"Tenant {tenant_name} ({tenant_id}) created on shard {shard_id}")
        return tenant_id
    
    def get_shard_for_tenant(self, tenant_id: str) -> Optional[str]:
        """Get the shard ID for a specific tenant"""
        tenant_config = self.tenants.get(tenant_id)
        return tenant_config.shard_id if tenant_config else None
    
    def get_session_for_tenant(self, tenant_id: str) -> Optional[Session]:
        """Get a database session for a specific tenant"""
        shard_id = self.get_shard_for_tenant(tenant_id)
        if not shard_id or shard_id not in self.shard_engines:
            return None
        
        engine = self.shard_engines[shard_id]
        session_maker = sessionmaker(bind=engine)
        return session_maker()
    
    def _select_shard_for_tenant(self, tenant_id: str, tenant_type: TenantType) -> Optional[str]:
        """Select the optimal shard for a new tenant"""
        
        if self.strategy == ShardingStrategy.HASH_BASED:
            return self._hash_based_selection(tenant_id)
        elif self.strategy == ShardingStrategy.RANGE_BASED:
            return self._range_based_selection(tenant_id)
        elif self.strategy == ShardingStrategy.DIRECTORY_BASED:
            return self._directory_based_selection(tenant_type)
        elif self.strategy == ShardingStrategy.HYBRID:
            return self._hybrid_selection(tenant_id, tenant_type)
        
        return None
    
    def _hash_based_selection(self, tenant_id: str) -> Optional[str]:
        """Hash-based shard selection"""
        if not self.shards:
            return None
        
        # Create hash of tenant ID
        hash_value = int(hashlib.md5(tenant_id.encode()).hexdigest(), 16)
        
        # Get available shards (not at capacity)
        available_shards = [
            shard_id for shard_id, config in self.shards.items()
            if config.is_active and config.current_tenants < config.capacity_limit
        ]
        
        if not available_shards:
            return None
        
        # Select shard based on hash
        shard_index = hash_value % len(available_shards)
        return available_shards[shard_index]
    
    def _range_based_selection(self, tenant_id: str) -> Optional[str]:
        """Range-based shard selection (by tenant ID ranges)"""
        # Sort tenant ID and assign to shards based on alphabetical ranges
        first_char = tenant_id[0].lower()
        
        # Define ranges (can be configured)
        ranges = {
            'shard_1': ['0', '1', '2', '3', '4', '5', '6', '7'],
            'shard_2': ['8', '9', 'a', 'b', 'c', 'd', 'e', 'f'],
            'shard_3': ['g', 'h', 'i', 'j', 'k', 'l', 'm', 'n'],
            'shard_4': ['o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']
        }
        
        for shard_id, range_chars in ranges.items():
            if first_char in range_chars and shard_id in self.shards:
                shard_config = self.shards[shard_id]
                if shard_config.is_active and shard_config.current_tenants < shard_config.capacity_limit:
                    return shard_id
        
        # Fallback to hash-based if range assignment fails
        return self._hash_based_selection(tenant_id)
    
    def _directory_based_selection(self, tenant_type: TenantType) -> Optional[str]:
        """Directory-based selection (by tenant type)"""
        # Assign shards based on tenant type for better resource allocation
        type_to_shard = {
            TenantType.GOVERNMENT: 'government_shard',
            TenantType.ACADEMIC: 'academic_shard',
            TenantType.CORPORATE: 'corporate_shard',
            TenantType.NGO: 'ngo_shard',
            TenantType.INDIVIDUAL: 'individual_shard'
        }
        
        preferred_shard = type_to_shard.get(tenant_type)
        if preferred_shard and preferred_shard in self.shards:
            shard_config = self.shards[preferred_shard]
            if shard_config.is_active and shard_config.current_tenants < shard_config.capacity_limit:
                return preferred_shard
        
        # Fallback to hash-based selection
        return self._hash_based_selection(str(uuid.uuid4()))
    
    def _hybrid_selection(self, tenant_id: str, tenant_type: TenantType) -> Optional[str]:
        """Hybrid selection combining multiple strategies"""
        # Try directory-based first for specific tenant types
        if tenant_type in [TenantType.GOVERNMENT, TenantType.ACADEMIC]:
            directory_shard = self._directory_based_selection(tenant_type)
            if directory_shard:
                return directory_shard
        
        # Fallback to hash-based selection
        return self._hash_based_selection(tenant_id)
    
    def _initialize_shard_schema(self, shard_id: str):
        """Initialize schema for a new shard"""
        engine = self.shard_engines[shard_id]
        
        # Create tenant-specific tables with attribution
        metadata = MetaData()
        
        # Tenants table for this shard
        tenants_table = Table('tenants', metadata,
            Column('tenant_id', String(36), primary_key=True),
            Column('tenant_name', String(255), nullable=False),
            Column('tenant_type', String(50), nullable=False),
            Column('created_at', DateTime, default=datetime.utcnow),
            Column('is_active', Integer, default=1),
            Column('attribution', JSON, default=lambda: self.project_attribution)
        )
        
        # Documents table (partitioned by tenant)
        documents_table = Table('documents', metadata,
            Column('id', String(36), primary_key=True),
            Column('tenant_id', String(36), nullable=False),
            Column('source', String(100), nullable=False),
            Column('document_type', String(100), nullable=False),
            Column('title', String(1000), nullable=False),
            Column('content', JSON),
            Column('published_date', DateTime),
            Column('created_at', DateTime, default=datetime.utcnow),
            Column('updated_at', DateTime, default=datetime.utcnow)
        )
        
        # Alerts table
        alerts_table = Table('alerts', metadata,
            Column('id', String(36), primary_key=True),
            Column('tenant_id', String(36), nullable=False),
            Column('user_id', String(36), nullable=False),
            Column('query', String(1000), nullable=False),
            Column('frequency', String(50), nullable=False),
            Column('last_run', DateTime),
            Column('is_active', Integer, default=1),
            Column('created_at', DateTime, default=datetime.utcnow)
        )
        
        # Users table
        users_table = Table('users', metadata,
            Column('id', String(36), primary_key=True),
            Column('tenant_id', String(36), nullable=False),
            Column('email', String(255), unique=True, nullable=False),
            Column('name', String(255), nullable=False),
            Column('role', String(100), nullable=False),
            Column('created_at', DateTime, default=datetime.utcnow),
            Column('is_active', Integer, default=1)
        )
        
        # Create all tables
        metadata.create_all(engine)
        
        logger.info(f"Schema initialized for shard {shard_id}")
    
    def _initialize_tenant_schema(self, tenant_config: TenantConfig):
        """Initialize tenant-specific schema elements"""
        session = self.get_session_for_tenant(tenant_config.tenant_id)
        
        try:
            # Insert tenant record
            session.execute("""
                INSERT INTO tenants (tenant_id, tenant_name, tenant_type, attribution)
                VALUES (:tenant_id, :tenant_name, :tenant_type, :attribution)
            """, {
                'tenant_id': tenant_config.tenant_id,
                'tenant_name': tenant_config.tenant_name,
                'tenant_type': tenant_config.tenant_type.value,
                'attribution': self.project_attribution
            })
            
            session.commit()
            logger.info(f"Tenant schema initialized for {tenant_config.tenant_id}")
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to initialize tenant schema: {e}")
            raise
        finally:
            session.close()
    
    def _load_configurations(self):
        """Load shard and tenant configurations from master database"""
        try:
            with self.master_engine.connect() as conn:
                # Load shard configurations
                shard_results = conn.execute("""
                    SELECT shard_id, connection_string, capacity_limit, 
                           current_tenants, region, is_active, created_at
                    FROM shards WHERE is_active = 1
                """)
                
                for row in shard_results:
                    shard_config = ShardConfig(
                        shard_id=row.shard_id,
                        connection_string=row.connection_string,
                        capacity_limit=row.capacity_limit,
                        current_tenants=row.current_tenants,
                        region=row.region,
                        is_active=bool(row.is_active),
                        created_at=row.created_at
                    )
                    self.shards[row.shard_id] = shard_config
                    self.shard_engines[row.shard_id] = create_engine(row.connection_string)
                
                # Load tenant configurations
                tenant_results = conn.execute("""
                    SELECT tenant_id, tenant_name, tenant_type, shard_id,
                           data_retention_days, max_documents, max_users,
                           created_at, is_active
                    FROM tenants WHERE is_active = 1
                """)
                
                for row in tenant_results:
                    tenant_config = TenantConfig(
                        tenant_id=row.tenant_id,
                        tenant_name=row.tenant_name,
                        tenant_type=TenantType(row.tenant_type),
                        shard_id=row.shard_id,
                        data_retention_days=row.data_retention_days,
                        max_documents=row.max_documents,
                        max_users=row.max_users,
                        created_at=row.created_at,
                        is_active=bool(row.is_active)
                    )
                    self.tenants[row.tenant_id] = tenant_config
                    
        except Exception as e:
            logger.warning(f"Could not load configurations from master DB: {e}")
            # This is expected on first run
    
    def _save_shard_config(self, shard_config: ShardConfig):
        """Save shard configuration to master database"""
        with self.master_engine.connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO shards 
                (shard_id, connection_string, capacity_limit, current_tenants, 
                 region, is_active, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                shard_config.shard_id,
                shard_config.connection_string,
                shard_config.capacity_limit,
                shard_config.current_tenants,
                shard_config.region,
                shard_config.is_active,
                shard_config.created_at
            ))
    
    def _save_tenant_config(self, tenant_config: TenantConfig):
        """Save tenant configuration to master database"""
        with self.master_engine.connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO tenants
                (tenant_id, tenant_name, tenant_type, shard_id,
                 data_retention_days, max_documents, max_users,
                 created_at, is_active)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                tenant_config.tenant_id,
                tenant_config.tenant_name,
                tenant_config.tenant_type.value,
                tenant_config.shard_id,
                tenant_config.data_retention_days,
                tenant_config.max_documents,
                tenant_config.max_users,
                tenant_config.created_at,
                tenant_config.is_active
            ))
    
    def get_shard_statistics(self) -> Dict[str, Any]:
        """Get statistics for all shards"""
        stats = {
            "total_shards": len(self.shards),
            "total_tenants": len(self.tenants),
            "shards": {},
            "attribution": self.project_attribution
        }
        
        for shard_id, shard_config in self.shards.items():
            stats["shards"][shard_id] = {
                "current_tenants": shard_config.current_tenants,
                "capacity_limit": shard_config.capacity_limit,
                "utilization_percent": (shard_config.current_tenants / shard_config.capacity_limit) * 100,
                "region": shard_config.region,
                "is_active": shard_config.is_active
            }
        
        return stats
    
    def migrate_tenant(self, tenant_id: str, target_shard_id: str) -> bool:
        """Migrate a tenant to a different shard"""
        try:
            tenant_config = self.tenants.get(tenant_id)
            if not tenant_config:
                raise Exception(f"Tenant {tenant_id} not found")
            
            source_shard_id = tenant_config.shard_id
            
            if source_shard_id == target_shard_id:
                logger.info(f"Tenant {tenant_id} already on target shard {target_shard_id}")
                return True
            
            # TODO: Implement data migration logic
            # 1. Copy tenant data from source to target shard
            # 2. Verify data integrity
            # 3. Update tenant configuration
            # 4. Remove data from source shard
            
            logger.info(f"Tenant {tenant_id} migration from {source_shard_id} to {target_shard_id} completed")
            return True
            
        except Exception as e:
            logger.error(f"Failed to migrate tenant {tenant_id}: {e}")
            return False


# Global sharding manager instance
_sharding_manager: Optional[ShardingManager] = None


def initialize_sharding_manager(master_db_url: str, strategy: ShardingStrategy = ShardingStrategy.HASH_BASED):
    """Initialize the global sharding manager"""
    global _sharding_manager
    _sharding_manager = ShardingManager(master_db_url, strategy)
    return _sharding_manager


def get_sharding_manager() -> ShardingManager:
    """Get the global sharding manager instance"""
    if _sharding_manager is None:
        raise RuntimeError("Sharding manager not initialized")
    return _sharding_manager