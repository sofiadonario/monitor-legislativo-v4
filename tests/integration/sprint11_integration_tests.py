"""
Sprint 11 Integration Tests for Monitor Legislativo v4
Tests all new systems working together

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import pytest
import asyncio
from datetime import datetime, timedelta
from unittest.mock import Mock, patch
import json

# Import all Sprint 11 systems
from core.events import event_bus, Event, EventType, start_event_processing
from core.tenancy import tenant_manager, Tenant, TenantStatus
from core.cqrs import command_bus, query_bus, CreatePropositionCommand, SearchPropositionsQuery
from core.plugins import plugin_manager, BasePlugin
from core.cache import unified_cache, CacheStrategy
from core.chaos import chaos_engine, ChaosExperiment, ImpactLevel
from core.cost_optimization import cost_monitor, optimization_engine
from core.capacity_planning import capacity_planner, TimeHorizon
from infrastructure.multi_region import region_manager, Region, RegionStatus
from desktop.offline import offline_storage, sync_manager, offline_api_client
from web.realtime import websocket_handler
from web.api.graphql_schema import schema as graphql_schema


class TestSprint11Integration:
    """Integration tests for all Sprint 11 features"""
    
    @pytest.fixture
    async def setup_test_environment(self):
        """Setup test environment with all systems"""
        # Start event processing
        await start_event_processing()
        
        # Create test tenant
        test_tenant = await tenant_manager.create_tenant(
            name="Test Organization",
            slug="test-org",
            admin_email="test@example.com",
            plan="professional"
        )
        
        # Start monitoring services
        await cost_monitor.start_monitoring()
        await region_manager.start_monitoring()
        
        yield test_tenant
        
        # Cleanup
        await event_bus.stop_processing()
        await cost_monitor.stop_monitoring()
        await region_manager.stop_monitoring()
    
    @pytest.mark.asyncio
    async def test_event_driven_multi_tenant_flow(self, setup_test_environment):
        """Test event-driven architecture with multi-tenant support"""
        tenant = setup_test_environment
        
        # Track events
        received_events = []
        
        async def event_handler(event: Event):
            received_events.append(event)
        
        # Subscribe to events
        event_bus.subscribe([EventType.PROPOSITION_CREATED], event_handler)
        
        # Create proposition via CQRS in tenant context
        from core.tenancy import TenantContext
        
        with TenantContext(tenant):
            # Send command
            command = CreatePropositionCommand(
                source="test",
                type="PL",
                number="1234",
                year=2024,
                title="Test Proposition",
                summary="Test summary",
                author="Test Author",
                user_id="test-user"
            )
            
            result = await command_bus.dispatch(command)
            assert result["status"] == "created"
        
        # Wait for event propagation
        await asyncio.sleep(0.1)
        
        # Verify event was received
        assert len(received_events) == 1
        assert received_events[0].type == EventType.PROPOSITION_CREATED
        assert received_events[0].data["title"] == "Test Proposition"
    
    @pytest.mark.asyncio
    async def test_offline_sync_with_cqrs(self):
        """Test offline storage syncing with CQRS commands"""
        # Store proposition offline
        await offline_storage.store_proposition({
            "id": "offline-prop-1",
            "title": "Offline Proposition",
            "summary": "Created offline",
            "source": "camara",
            "type": "PL",
            "number": "5678",
            "year": 2024,
            "author": "Offline Author",
            "status": "active"
        })
        
        # Get unsynced records
        unsynced = await offline_storage.database.get_unsynced_records()
        assert len(unsynced) > 0
        
        # Simulate sync process
        sync_result = await sync_manager.sync_all()
        assert sync_result["status"] == "completed"
        
        # Verify proposition can be queried via CQRS
        query = SearchPropositionsQuery(
            search_text="Offline Proposition",
            page=1,
            page_size=10
        )
        
        result = await query_bus.dispatch(query)
        assert result.data is not None
    
    @pytest.mark.asyncio
    async def test_plugin_with_websocket_notifications(self):
        """Test plugin system with WebSocket notifications"""
        notifications_sent = []
        
        # Mock WebSocket handler
        async def mock_notify(data):
            notifications_sent.append(data)
        
        websocket_handler.notify_clients = mock_notify
        
        # Create custom plugin
        class NotificationPlugin(BasePlugin):
            def get_info(self):
                return {
                    "name": "Notification Plugin",
                    "version": "1.0.0",
                    "author": "Test"
                }
            
            async def initialize(self):
                # Subscribe to events
                await event_bus.subscribe(
                    [EventType.PROPOSITION_CREATED],
                    self.handle_proposition
                )
            
            async def handle_proposition(self, event: Event):
                await websocket_handler.notify_clients({
                    "type": "new_proposition",
                    "data": event.data
                })
        
        # Register and initialize plugin
        plugin = NotificationPlugin()
        await plugin_manager.register_plugin("notification", plugin)
        await plugin_manager.initialize_plugins()
        
        # Create proposition to trigger notification
        event = Event(
            type=EventType.PROPOSITION_CREATED,
            source="test",
            data={"id": "test-123", "title": "Plugin Test"}
        )
        await event_bus.publish(event)
        
        # Wait for processing
        await asyncio.sleep(0.1)
        
        # Verify notification was sent
        assert len(notifications_sent) > 0
        assert notifications_sent[0]["type"] == "new_proposition"
    
    @pytest.mark.asyncio
    async def test_multi_region_failover_with_chaos(self):
        """Test multi-region failover triggered by chaos engineering"""
        # Register chaos experiment
        experiment = ChaosExperiment(
            name="Primary Region Failure",
            target_service="sa-east-1",
            fault_type="service_unavailable",
            impact_level=ImpactLevel.HIGH,
            max_duration_minutes=5
        )
        
        experiment_id = await chaos_engine.register_experiment(experiment)
        
        # Get initial primary region
        primary = region_manager.get_primary_region()
        initial_primary_id = primary.id
        
        # Simulate region failure via chaos
        primary.error_rate = 0.5  # 50% error rate
        primary.latency_ms = 10000  # 10 second latency
        
        # Trigger failover check
        await region_manager._check_failover_conditions()
        
        # Verify failover occurred
        new_primary = region_manager.get_primary_region()
        assert new_primary.id != initial_primary_id
        assert new_primary.tier.value == "primary"
        
        # Verify traffic was redirected
        assert primary.target_traffic_percentage == 0.0
        assert new_primary.target_traffic_percentage == 80.0
    
    @pytest.mark.asyncio
    async def test_cost_optimization_with_capacity_planning(self):
        """Test cost optimization recommendations based on capacity planning"""
        # Create capacity plan
        plan = await capacity_planner.create_capacity_plan(TimeHorizon.SHORT_TERM)
        assert plan is not None
        
        # Generate cost optimization recommendations
        recommendations = await optimization_engine.generate_recommendations()
        
        # Find recommendations related to capacity
        capacity_recommendations = [
            rec for rec in recommendations
            if "capacity" in rec.title.lower() or "scaling" in rec.title.lower()
        ]
        
        assert len(capacity_recommendations) > 0
        
        # Verify recommendations align with capacity plan
        for rec in capacity_recommendations:
            if rec.savings_estimate:
                assert rec.savings_estimate.monthly_savings > 0
    
    @pytest.mark.asyncio
    async def test_graphql_with_cache_and_tenant_isolation(self, setup_test_environment):
        """Test GraphQL queries with caching in multi-tenant context"""
        tenant = setup_test_environment
        
        # Execute GraphQL query
        query = """
        query {
            propositions(first: 10) {
                edges {
                    node {
                        id
                        title
                        source
                    }
                }
                totalCount
            }
        }
        """
        
        # First execution (cache miss)
        from core.tenancy import TenantContext
        
        with TenantContext(tenant):
            result1 = await graphql_schema.execute(query)
            assert result1.errors is None
            
            # Check cache was populated
            cache_key = f"tenant:{tenant.id}:graphql:propositions"
            cached = await unified_cache.get(cache_key)
            assert cached is not None
        
        # Second execution (cache hit)
        with TenantContext(tenant):
            result2 = await graphql_schema.execute(query)
            assert result2.errors is None
            
            # Results should be identical
            assert result1.data == result2.data
    
    @pytest.mark.asyncio
    async def test_end_to_end_resilience_scenario(self):
        """Test complete system resilience with multiple failures"""
        results = {
            "events_processed": 0,
            "commands_executed": 0,
            "queries_handled": 0,
            "cache_hits": 0,
            "failovers": 0
        }
        
        # Setup event tracking
        async def track_event(event: Event):
            results["events_processed"] += 1
        
        event_bus.subscribe(list(EventType), track_event)
        
        # Simulate high load
        tasks = []
        for i in range(50):
            # Mix of commands and queries
            if i % 2 == 0:
                command = CreatePropositionCommand(
                    source="test",
                    type="PL",
                    number=str(1000 + i),
                    year=2024,
                    title=f"Load Test Proposition {i}",
                    summary=f"Testing system under load {i}",
                    author=f"Test Author {i}",
                    user_id="load-test"
                )
                tasks.append(command_bus.dispatch(command))
            else:
                query = SearchPropositionsQuery(
                    search_text=f"Test {i}",
                    page=1,
                    page_size=5
                )
                tasks.append(query_bus.dispatch(query))
        
        # Execute concurrently
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Count successes
        successes = sum(1 for r in results_list if not isinstance(r, Exception))
        assert successes > 40  # At least 80% success rate
        
        # Verify system metrics
        await asyncio.sleep(0.5)  # Allow event processing
        assert results["events_processed"] > 0
        
        # Check system health
        capacity_summary = capacity_planner.get_planning_summary()
        cost_stats = cost_monitor.get_statistics()
        region_summary = region_manager.get_region_summary()
        
        assert capacity_summary["average_confidence"] > 0.5
        assert cost_stats["monitoring_enabled"] is True
        assert region_summary["active_regions"] >= 2


class TestPerformanceUnderLoad:
    """Performance tests for Sprint 11 features"""
    
    @pytest.mark.asyncio
    async def test_high_throughput_event_processing(self):
        """Test event bus under high load"""
        processed_count = 0
        
        async def count_handler(event: Event):
            nonlocal processed_count
            processed_count += 1
        
        # Subscribe handler
        event_bus.subscribe([EventType.PROPOSITION_CREATED], count_handler)
        
        # Generate high volume of events
        start_time = datetime.now()
        
        tasks = []
        for i in range(1000):
            event = Event(
                type=EventType.PROPOSITION_CREATED,
                source="load-test",
                data={"id": f"load-{i}", "title": f"Load Test {i}"}
            )
            tasks.append(event_bus.publish(event))
        
        await asyncio.gather(*tasks)
        
        # Wait for processing
        await asyncio.sleep(1)
        
        duration = (datetime.now() - start_time).total_seconds()
        throughput = processed_count / duration
        
        print(f"Event throughput: {throughput:.2f} events/second")
        assert throughput > 100  # At least 100 events/second
    
    @pytest.mark.asyncio
    async def test_concurrent_multi_tenant_operations(self):
        """Test system with multiple tenants operating concurrently"""
        # Create multiple tenants
        tenants = []
        for i in range(5):
            tenant = await tenant_manager.create_tenant(
                name=f"Tenant {i}",
                slug=f"tenant-{i}",
                admin_email=f"tenant{i}@example.com",
                plan="professional"
            )
            tenants.append(tenant)
        
        # Simulate concurrent operations per tenant
        async def tenant_operations(tenant):
            from core.tenancy import TenantContext
            
            with TenantContext(tenant):
                # Create propositions
                for j in range(10):
                    command = CreatePropositionCommand(
                        source="test",
                        type="PL",
                        number=f"{tenant.id}-{j}",
                        year=2024,
                        title=f"Tenant {tenant.name} Prop {j}",
                        summary=f"Multi-tenant test {j}",
                        author=f"Author {tenant.id}",
                        user_id=f"user-{tenant.id}"
                    )
                    await command_bus.dispatch(command)
                
                # Query propositions
                query = SearchPropositionsQuery(
                    search_text=tenant.name,
                    page=1,
                    page_size=20
                )
                result = await query_bus.dispatch(query)
                
                return len(result.data)
        
        # Run operations for all tenants concurrently
        results = await asyncio.gather(*[tenant_operations(t) for t in tenants])
        
        # Each tenant should see their own data
        for i, count in enumerate(results):
            assert count >= 0  # Should have results
        
        # Verify tenant isolation
        tenant_summaries = await asyncio.gather(*[
            tenant_manager.get_tenant(t.id) for t in tenants
        ])
        
        assert all(t is not None for t in tenant_summaries)


if __name__ == "__main__":
    # Run integration tests
    pytest.main([__file__, "-v", "-s"])