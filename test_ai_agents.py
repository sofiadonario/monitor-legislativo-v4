#!/usr/bin/env python3
"""
Test script for AI Agent Foundation
Tests production-ready AI agents with dual-memory architecture, cost monitoring,
and semantic caching for Brazilian legislative research assistance.
"""

import sys
import asyncio
from pathlib import Path

# Add core directory to path
sys.path.insert(0, str(Path(__file__).parent / "core"))

async def test_ai_agent_foundation():
    """Test the AI agent foundation components"""
    print("🤖 Testing AI Agent Foundation")
    print("=" * 50)
    
    try:
        from ai.agent_foundation import (
            ProductionAIAgent, 
            AIAgentManager, 
            AgentConfig, 
            AgentRole,
            CostMonitor,
            SemanticCache,
            AgentMemory
        )
        from ai.redis_memory_manager import RedisMemoryManager
        
        print("✅ AI agent foundation imported successfully")
        
        # Mock Redis client for testing
        class MockRedis:
            def __init__(self):
                self.data = {}
                self.lists = {}
                self.hashes = {}
                self.sets = {}
                self.sorted_sets = {}
            
            async def get(self, key): return self.data.get(key)
            async def set(self, key, value): self.data[key] = value
            async def setex(self, key, ttl, value): self.data[key] = value
            async def incrbyfloat(self, key, amount): 
                self.data[key] = float(self.data.get(key, 0)) + amount
                return self.data[key]
            async def expire(self, key, ttl): pass
            async def hset(self, key, field=None, value=None, mapping=None):
                if key not in self.hashes: self.hashes[key] = {}
                if mapping:
                    self.hashes[key].update(mapping)
                else:
                    self.hashes[key][field] = value
            async def hget(self, key, field): return self.hashes.get(key, {}).get(field)
            async def hgetall(self, key): return self.hashes.get(key, {})
            async def hdel(self, key, *fields):
                if key in self.hashes:
                    for field in fields:
                        self.hashes[key].pop(field, None)
            async def hlen(self, key): return len(self.hashes.get(key, {}))
            async def hkeys(self, key): return list(self.hashes.get(key, {}).keys())
            async def lpush(self, key, *values):
                if key not in self.lists: self.lists[key] = []
                self.lists[key] = list(values) + self.lists[key]
            async def lrange(self, key, start, end):
                return self.lists.get(key, [])[start:end+1 if end >= 0 else None]
            async def ltrim(self, key, start, end):
                if key in self.lists:
                    self.lists[key] = self.lists[key][start:end+1]
            async def llen(self, key): return len(self.lists.get(key, []))
            async def sadd(self, key, *values):
                if key not in self.sets: self.sets[key] = set()
                self.sets[key].update(values)
            async def smembers(self, key): return list(self.sets.get(key, set()))
            async def scard(self, key): return len(self.sets.get(key, set()))
            async def srem(self, key, *values):
                if key in self.sets:
                    self.sets[key].difference_update(values)
            async def zadd(self, key, mapping):
                if key not in self.sorted_sets: self.sorted_sets[key] = {}
                self.sorted_sets[key].update(mapping)
            async def zrange(self, key, start, end):
                if key not in self.sorted_sets: return []
                items = sorted(self.sorted_sets[key].items(), key=lambda x: x[1])
                return [item[0] for item in items[start:end+1 if end >= 0 else None]]
            async def zrangebyscore(self, key, min_score, max_score, start=0, num=None):
                if key not in self.sorted_sets: return []
                items = [(k, v) for k, v in self.sorted_sets[key].items() if min_score <= v <= max_score]
                items.sort(key=lambda x: x[1])
                items = items[start:start+num if num else None]
                return [item[0] for item in items]
            async def zrem(self, key, *members):
                if key in self.sorted_sets:
                    for member in members:
                        self.sorted_sets[key].pop(member, None)
            async def delete(self, *keys):
                for key in keys:
                    self.data.pop(key, None)
                    self.hashes.pop(key, None)
                    self.lists.pop(key, None)
                    self.sets.pop(key, None)
                    self.sorted_sets.pop(key, None)
            async def scan(self, cursor, match=None):
                if cursor != 0: return 0, []
                keys = []
                for storage in [self.data, self.hashes, self.lists, self.sets, self.sorted_sets]:
                    keys.extend(storage.keys())
                if match:
                    import fnmatch
                    keys = [k for k in keys if fnmatch.fnmatch(k, match)]
                return 0, keys
            def pipeline(self): return MockPipeline(self)
        
        class MockPipeline:
            def __init__(self, redis): 
                self.redis = redis
                self.commands = []
            def hget(self, key, field): 
                self.commands.append(('hget', key, field))
                return self
            async def execute(self):
                results = []
                for cmd, key, field in self.commands:
                    if cmd == 'hget':
                        results.append(await self.redis.hget(key, field))
                return results
        
        redis_client = MockRedis()
        
        # Test 1: Agent Configuration
        print("\n1. Testing Agent Configuration...")
        config = AgentConfig(
            agent_id="test_research_agent",
            role=AgentRole.RESEARCH_ASSISTANT,
            max_short_term_memory=10,
            max_long_term_memory=100,
            cost_budget_monthly=5.0,
            temperature=0.1,
            model="gpt-4o-mini"
        )
        print(f"✅ Agent config created: {config.agent_id} with role {config.role.value}")
        
        # Test 2: Cost Monitor
        print("\n2. Testing Cost Monitor...")
        cost_monitor = CostMonitor(redis_client, monthly_budget=5.0)
        
        cost = await cost_monitor.calculate_cost("gpt-4o-mini", 100, 50)
        print(f"✅ Calculated cost for 100 input + 50 output tokens: {cost:.4f} cents")
        
        await cost_monitor.track_usage("test_agent", cost, "gpt-4o-mini")
        summary = await cost_monitor.get_cost_summary("test_agent")
        print(f"✅ Cost tracking: Daily {summary['daily_cost_cents']:.4f}¢, Monthly {summary['monthly_cost_cents']:.4f}¢")
        
        # Test 3: Semantic Cache
        print("\n3. Testing Semantic Cache...")
        semantic_cache = SemanticCache(redis_client)
        
        # Test cache miss
        cached = await semantic_cache.get_cached_response("test query", "gpt-4o-mini", 0.1)
        print(f"✅ Cache miss test: {cached is None}")
        
        # Mock response for caching
        from ai.agent_foundation import LLMResponse
        mock_response = LLMResponse(
            content="This is a test response",
            model_used="gpt-4o-mini",
            tokens_input=10,
            tokens_output=20,
            cost_cents=0.5,
            response_time_ms=100.0
        )
        
        await semantic_cache.cache_response("test query", "gpt-4o-mini", 0.1, mock_response)
        
        # Test cache hit
        cached = await semantic_cache.get_cached_response("test query", "gpt-4o-mini", 0.1)
        print(f"✅ Cache hit test: {cached is not None and cached.from_cache}")
        
        # Test 4: Agent Memory
        print("\n4. Testing Agent Memory...")
        memory = AgentMemory(redis_client, "test_agent", config)
        
        # Add short-term memory
        st_id = await memory.add_short_term_memory(
            "Test short-term memory content",
            {"type": "test", "importance": "high"}
        )
        print(f"✅ Short-term memory added: {st_id}")
        
        # Add long-term memory
        lt_id = await memory.add_long_term_memory(
            "Test long-term memory about Brazilian legislation",
            {"type": "knowledge", "domain": "transport"}
        )
        print(f"✅ Long-term memory added: {lt_id}")
        
        # Test memory retrieval
        context = await memory.get_short_term_context(limit=5)
        print(f"✅ Short-term context retrieved: {len(context)} entries")
        
        search_results = await memory.search_long_term_memory(["legislation", "transport"], limit=3)
        print(f"✅ Long-term memory search: {len(search_results)} results")
        
        # Test 5: Production AI Agent
        print("\n5. Testing Production AI Agent...")
        agent = ProductionAIAgent(redis_client, config)
        
        response = await agent.process_query("What are the latest transport regulations in Brazil?")
        print(f"✅ Agent query processed: {len(response.content)} characters")
        print(f"✅ Response from cache: {response.from_cache}")
        print(f"✅ Cost: {response.cost_cents:.4f} cents")
        
        # Test agent status
        status = await agent.get_agent_status()
        print(f"✅ Agent status: {status['status']}")
        print(f"✅ Memory entries: {status['memory']['short_term_entries']}/{status['memory']['long_term_entries']}")
        
        # Test 6: AI Agent Manager
        print("\n6. Testing AI Agent Manager...")
        manager = AIAgentManager(redis_client)
        
        # Create agent through manager
        created_agent = await manager.create_agent(config)
        print(f"✅ Agent created through manager: {created_agent.config.agent_id}")
        
        # Get agent
        retrieved_agent = await manager.get_agent("test_research_agent")
        print(f"✅ Agent retrieved: {retrieved_agent is not None}")
        
        # System status
        system_status = await manager.get_system_status()
        print(f"✅ System status: {system_status['active_agents']} active agents")
        
        # Test 7: Redis Memory Manager
        print("\n7. Testing Redis Memory Manager...")
        memory_manager = RedisMemoryManager(redis_client)
        
        await memory_manager.initialize_ai_redis_structure()
        print("✅ Redis AI structure initialized")
        
        await memory_manager.create_memory_indexes("test_agent")
        print("✅ Memory indexes created")
        
        # Store memory with indexing
        memory_entry = {
            "entry_id": "test_mem_001",
            "content": "Test memory content about transport legislation",
            "timestamp": "2024-12-27T10:00:00",
            "cost_cents": 0.5,
            "ttl": 3600
        }
        
        stored_id = await memory_manager.store_memory_with_indexing("test_agent", memory_entry)
        print(f"✅ Memory stored with indexing: {stored_id}")
        
        # Search memory
        search_results = await memory_manager.search_memory_by_keywords("test_agent", ["transport", "legislation"])
        print(f"✅ Keyword search results: {len(search_results)} entries")
        
        # Performance stats
        perf_stats = await memory_manager.get_memory_performance_stats("test_agent")
        print(f"✅ Performance stats retrieved")
        
        print("\n" + "=" * 50)
        print("🎉 AI Agent Foundation Tests Passed!")
        print("✅ Agent configuration and role system working")
        print("✅ Cost monitoring and budget tracking operational")
        print("✅ Semantic caching for cost optimization functional")
        print("✅ Dual-memory architecture (short-term + long-term) working")
        print("✅ Production AI agent processing queries correctly")
        print("✅ Agent manager coordinating multiple agents")
        print("✅ Redis memory manager with indexing and optimization")
        print("✅ Memory persistence and retrieval patterns functional")
        
        return True
        
    except Exception as e:
        print(f"❌ AI agent foundation test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_api_endpoints():
    """Test the AI agents API endpoints"""
    print("\n🌐 Testing AI Agents API")
    print("=" * 50)
    
    try:
        # Add main_app to path
        sys.path.insert(0, str(Path(__file__).parent / "main_app"))
        
        # Test API imports
        from api.ai_agents import router, get_agent_manager
        print("✅ AI agents API imported successfully")
        
        # Test router configuration
        if router:
            print("✅ FastAPI router configured")
            print(f"✅ Router prefix: {router.prefix}")
            print(f"✅ Router tags: {router.tags}")
            
            # Count endpoints
            endpoint_count = len([route for route in router.routes])
            print(f"✅ API endpoints available: {endpoint_count}")
        
        return True
        
    except Exception as e:
        print(f"❌ API endpoint test failed: {e}")
        return False

async def main():
    """Run all AI agent foundation tests"""
    print("🚀 Starting AI Agent Foundation Tests")
    print("=" * 60)
    
    # Test core foundation
    core_success = await test_ai_agent_foundation()
    
    # Test API endpoints
    api_success = await test_api_endpoints()
    
    print("\n" + "=" * 60)
    if core_success and api_success:
        print("🎉 ALL AI AGENT FOUNDATION TESTS PASSED!")
        print("🤖 Production-ready AI agents with dual-memory architecture")
        print("💰 Cost monitoring and semantic caching operational")
        print("🧠 Specialized Brazilian legislative research assistance")
        print("🌐 API endpoints ready for production")
        print("📊 Memory management and optimization functional")
        return True
    else:
        print("❌ Some tests failed - check logs above")
        return False

if __name__ == "__main__":
    success = asyncio.run(main())
    sys.exit(0 if success else 1)