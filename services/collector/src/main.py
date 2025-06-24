"""
Monitor Legislativo v4 - Collector Service
Automated data collection with Prefect orchestration
"""

import asyncio
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Optional

from prefect import serve
from prefect.logging import get_run_logger

# Import our flows
from flows.lexml_collection import daily_collection_flow, manual_collection_flow, health_check_flow
from utils.monitoring import start_monitoring_loop, collection_metrics, alert_manager
from services.database_service import CollectionDatabaseService

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


class CollectorService:
    """Main collector service with Prefect integration"""
    
    def __init__(self):
        self.monitoring_task: Optional[asyncio.Task] = None
        self.shutdown_event = asyncio.Event()
        self.running = False
    
    async def initialize(self):
        """Initialize service components"""
        logger.info("🚀 Starting Monitor Legislativo Collector Service")
        
        # Ensure data directories exist
        for directory in ['raw', 'processed', 'exports', 'logs']:
            Path(f'/app/data/{directory}').mkdir(parents=True, exist_ok=True)
        
        logger.info("📁 Data directories initialized")
        
        # Test database connectivity
        try:
            db_service = CollectionDatabaseService()
            await db_service.initialize()
            health = await db_service.health_check()
            await db_service.close()
            
            if health.get('status') == 'healthy':
                logger.info("✅ Database connectivity verified")
            else:
                logger.warning(f"⚠️ Database health check: {health}")
                
        except Exception as e:
            logger.error(f"❌ Database connectivity failed: {e}")
            # Don't fail startup - service can still run in monitoring mode
        
        # Start monitoring loop
        logger.info("🔍 Starting monitoring loop")
        self.monitoring_task = asyncio.create_task(start_monitoring_loop())
        
        logger.info("✅ Collector service initialized")
    
    async def run_prefect_server(self):
        """Run Prefect flows as a server"""
        logger.info("🔄 Starting Prefect flow server")
        
        try:
            # Create flow deployments
            deployments = [
                daily_collection_flow.to_deployment(
                    name="daily-collection",
                    tags=["production", "automated", "daily"],
                    description="Daily automated collection of legislative documents",
                    version="1.0.0"
                ),
                manual_collection_flow.to_deployment(
                    name="manual-collection", 
                    tags=["production", "manual", "on-demand"],
                    description="Manual collection flow for specific search terms",
                    version="1.0.0"
                ),
                health_check_flow.to_deployment(
                    name="health-check",
                    tags=["monitoring", "health-check", "automated"],
                    description="Health check flow to monitor system components",
                    version="1.0.0"
                )
            ]
            
            # Start serving flows
            await serve(
                *deployments,
                limit=10,  # Max concurrent flow runs
                webserver=True,
                port=4200
            )
            
        except Exception as e:
            logger.error(f"❌ Prefect server error: {e}")
            raise
    
    async def run_standalone_mode(self):
        """Run in standalone mode without Prefect server"""
        logger.info("🔄 Running in standalone mode")
        
        # Periodically run health checks
        while not self.shutdown_event.is_set():
            try:
                # Run health check every 15 minutes
                health_result = await health_check_flow()
                logger.info(f"Health check result: {health_result.get('overall_status', 'unknown')}")
                
                # Check if we should trigger a manual collection
                # This could be based on external signals, files, or API calls
                
                # Wait 15 minutes or until shutdown
                try:
                    await asyncio.wait_for(self.shutdown_event.wait(), timeout=900)  # 15 minutes
                    break
                except asyncio.TimeoutError:
                    continue
                    
            except Exception as e:
                logger.error(f"Standalone mode error: {e}")
                await asyncio.sleep(60)  # Wait 1 minute on error
    
    async def shutdown(self):
        """Graceful shutdown"""
        logger.info("🛑 Collector service shutdown requested")
        self.shutdown_event.set()
        
        # Cancel monitoring task
        if self.monitoring_task and not self.monitoring_task.done():
            self.monitoring_task.cancel()
            try:
                await self.monitoring_task
            except asyncio.CancelledError:
                pass
        
        # Generate final health report
        try:
            from utils.monitoring import generate_health_report
            final_report = await generate_health_report()
            logger.info(f"Final health report: {final_report}")
        except Exception as e:
            logger.error(f"Failed to generate final health report: {e}")
        
        logger.info("✅ Collector service shutdown complete")
    
    def setup_signal_handlers(self):
        """Setup signal handlers for graceful shutdown"""
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}")
            asyncio.create_task(self.shutdown())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)


async def main():
    """Main entry point for collector service"""
    service = CollectorService()
    
    try:
        # Setup signal handlers
        service.setup_signal_handlers()
        
        # Initialize service
        await service.initialize()
        
        # Determine run mode
        run_mode = os.getenv('COLLECTOR_RUN_MODE', 'standalone')  # prefect or standalone
        
        if run_mode == 'prefect':
            # Run with Prefect server
            await service.run_prefect_server()
        else:
            # Run in standalone mode
            await service.run_standalone_mode()
            
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt")
    except Exception as e:
        logger.error(f"❌ Service error: {e}")
        sys.exit(1)
    finally:
        await service.shutdown()


if __name__ == "__main__":
    asyncio.run(main())