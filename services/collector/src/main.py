"""
Monitor Legislativo v4 - Collector Service
Automated data collection with Prefect orchestration
"""

import asyncio
import logging
import os
from pathlib import Path

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/app/data/logs/collector.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)


async def main():
    """Main entry point for collector service"""
    logger.info("🚀 Starting Monitor Legislativo Collector Service")
    
    # Ensure data directories exist
    for directory in ['raw', 'processed', 'exports', 'logs']:
        Path(f'/app/data/{directory}').mkdir(parents=True, exist_ok=True)
    
    logger.info("📁 Data directories initialized")
    
    # For Phase 1, just keep the service running
    # In later phases, this will start Prefect deployments
    logger.info("🔄 Collector service is running (Phase 1 - Infrastructure setup)")
    
    try:
        while True:
            await asyncio.sleep(60)  # Keep service alive
            logger.debug("Collector service heartbeat")
    except KeyboardInterrupt:
        logger.info("🛑 Collector service shutdown requested")
    except Exception as e:
        logger.error(f"❌ Collector service error: {e}")
        raise


if __name__ == "__main__":
    asyncio.run(main())