import logging
from typing import Optional, Dict, Any

from .supabase_config import DatabaseManager as BaseManager, get_database_manager


class TwoTierManager:
    """Manages two-tier database access (primary and fallback)"""
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(TwoTierManager, cls).__new__(cls)
            cls._instance.primary_manager = None
            cls._instance.fallback_manager = None  # Placeholder for future use
        return cls._instance

    async def initialize_managers(self):
        """Initialize both primary and fallback database managers"""
        try:
            self.primary_manager = await get_database_manager()
            if self.primary_manager:
                logger.info("Primary database manager initialized successfully.")
            else:
                logger.warning("Primary database manager failed to initialize.")
        except Exception as e:
            logger.error(f"Error initializing primary database manager: {e}", exc_info=True)
            
        # Initialize fallback manager here if implemented
        # self.fallback_manager = await get_fallback_manager()

    @property
    def primary(self) -> Optional[BaseManager]:
        return self.primary_manager


async def get_two_tier_manager() -> TwoTierManager:
    """Dependency to get the two-tier manager instance"""
    manager = TwoTierManager()
    if not manager.primary:
        await manager.initialize_managers()
    return manager
