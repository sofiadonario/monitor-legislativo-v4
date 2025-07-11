#!/usr/bin/env python3
"""
Test Redis Connection for Monitor Legislativo v4
"""
import asyncio
import redis.asyncio as redis
import os
from datetime import datetime

async def test_redis_connection():
    """Test Redis connection using the Railway Redis URL"""
    redis_url = "redis://default:UewdfsyhNXtwRdNfyKCzOowoiCdhPSGu@redis.railway.internal:6379"
    
    print("🔍 Testing Redis Connection...")
    print(f"Redis URL: {redis_url}")
    
    client = None
    try:
        # Create Redis client
        client = redis.from_url(redis_url, decode_responses=True)
        
        # Test basic connectivity
        start_time = datetime.now()
        await client.ping()
        latency = (datetime.now() - start_time).total_seconds() * 1000
        
        print(f"✅ Redis PING successful! Latency: {latency:.2f}ms")
        
        # Test basic operations
        test_key = "monitor_legislativo_test"
        test_value = f"Test value at {datetime.now()}"
        
        # Set a value
        await client.set(test_key, test_value, ex=60)  # Expire in 60 seconds
        print(f"✅ SET operation successful")
        
        # Get the value
        retrieved_value = await client.get(test_key)
        print(f"✅ GET operation successful: {retrieved_value}")
        
        # Test cache performance
        cache_key = "performance_test"
        cache_data = {"timestamp": datetime.now().isoformat(), "test": "performance"}
        
        # Set JSON data
        await client.set(cache_key, str(cache_data), ex=300)
        cached_data = await client.get(cache_key)
        print(f"✅ Cache performance test successful: {cached_data}")
        
        # Clean up test keys
        await client.delete(test_key, cache_key)
        print(f"✅ Cleanup successful")
        
        print("\n🎉 Redis connection test PASSED!")
        print("Redis is properly configured and ready for production use.")
        
        return True
        
    except Exception as e:
        print(f"❌ Redis connection test FAILED: {e}")
        print("This is expected if running locally - Redis URL is for Railway internal network")
        return False
    
    finally:
        if client:
            await client.close()

if __name__ == "__main__":
    asyncio.run(test_redis_connection())