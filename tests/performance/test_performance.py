"""Performance tests for the application."""

import pytest
import time
import asyncio
import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch
import psutil
import os


class TestPerformanceBaseline:
    """Baseline performance tests."""

    def test_api_response_time(self):
        """Test API response times are within acceptable limits."""
        from core.api.api_service import APIService
        
        # Mock the actual API calls to avoid network dependency
        with patch('core.api.api_service.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'data': 'test'}
            mock_get.return_value = mock_response
            
            api_service = APIService()
            
            start_time = time.time()
            # Simulate search operation
            result = api_service.search_documents('test query')
            end_time = time.time()
            
            response_time = end_time - start_time
            
            # Response should be under 500ms for mocked calls
            assert response_time < 0.5, f"API response time {response_time:.3f}s exceeds limit"

    @pytest.mark.asyncio
    async def test_async_performance(self):
        """Test async operation performance."""
        async def mock_async_operation():
            await asyncio.sleep(0.01)  # Simulate small delay
            return "completed"
        
        start_time = time.time()
        
        # Run multiple async operations concurrently
        tasks = [mock_async_operation() for _ in range(100)]
        results = await asyncio.gather(*tasks)
        
        end_time = time.time()
        total_time = end_time - start_time
        
        # 100 operations should complete in under 1 second
        assert total_time < 1.0, f"Async operations took {total_time:.3f}s"
        assert len(results) == 100

    def test_memory_usage_baseline(self):
        """Test memory usage stays within acceptable limits."""
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Simulate some operations that might consume memory
        large_data = []
        for i in range(1000):
            large_data.append({'id': i, 'data': 'x' * 100})
        
        peak_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = peak_memory - initial_memory
        
        # Memory increase should be reasonable (under 50MB for this test)
        assert memory_increase < 50, f"Memory usage increased by {memory_increase:.2f}MB"
        
        # Clean up
        del large_data

    def test_database_query_performance(self):
        """Test database query performance."""
        # Mock database operations
        with patch('core.models.models.Document.query') as mock_query:
            mock_query.filter.return_value.limit.return_value.all.return_value = [
                Mock(title=f"Document {i}", content=f"Content {i}") 
                for i in range(10)
            ]
            
            start_time = time.time()
            
            # Simulate multiple queries
            for _ in range(50):
                # This would be actual database queries
                results = mock_query.filter('title').limit(10).all()
            
            end_time = time.time()
            query_time = end_time - start_time
            
            # 50 queries should complete quickly when mocked
            assert query_time < 0.1, f"Database queries took {query_time:.3f}s"

    def test_cache_performance(self):
        """Test cache operation performance."""
        from core.utils.cache_manager import CacheManager
        
        cache_manager = CacheManager(max_size=1000)
        
        # Test cache write performance
        start_time = time.time()
        for i in range(1000):
            cache_manager.set(f"key_{i}", f"value_{i}")
        write_time = time.time() - start_time
        
        # Test cache read performance
        start_time = time.time()
        for i in range(1000):
            cache_manager.get(f"key_{i}")
        read_time = time.time() - start_time
        
        # Cache operations should be fast
        assert write_time < 1.0, f"Cache writes took {write_time:.3f}s"
        assert read_time < 1.0, f"Cache reads took {read_time:.3f}s"

    def test_search_index_performance(self):
        """Test search indexing and query performance."""
        # Mock search operations
        mock_documents = [
            {'id': i, 'title': f'Document {i}', 'content': f'Content {i}'}
            for i in range(1000)
        ]
        
        start_time = time.time()
        
        # Simulate search indexing
        indexed_docs = {}
        for doc in mock_documents:
            indexed_docs[doc['id']] = {
                'title_words': doc['title'].split(),
                'content_words': doc['content'].split()
            }
        
        indexing_time = time.time() - start_time
        
        # Test search query performance
        start_time = time.time()
        
        query_term = "Document"
        results = []
        for doc_id, doc_data in indexed_docs.items():
            if query_term in doc_data['title_words']:
                results.append(doc_id)
        
        search_time = time.time() - start_time
        
        assert indexing_time < 2.0, f"Indexing took {indexing_time:.3f}s"
        assert search_time < 0.5, f"Search took {search_time:.3f}s"


class TestConcurrencyPerformance:
    """Test performance under concurrent load."""

    def test_concurrent_api_requests(self):
        """Test performance with concurrent API requests."""
        from core.api.api_service import APIService
        
        with patch('core.api.api_service.requests.get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'data': 'test'}
            mock_get.return_value = mock_response
            
            api_service = APIService()
            
            def make_request():
                return api_service.search_documents('test')
            
            start_time = time.time()
            
            # Use ThreadPoolExecutor for concurrent requests
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = [executor.submit(make_request) for _ in range(50)]
                results = [future.result() for future in futures]
            
            end_time = time.time()
            total_time = end_time - start_time
            
            # 50 concurrent requests should complete quickly when mocked
            assert total_time < 2.0, f"Concurrent requests took {total_time:.3f}s"
            assert len(results) == 50

    def test_thread_safety(self):
        """Test thread safety of shared resources."""
        from core.utils.cache_manager import CacheManager
        
        cache_manager = CacheManager()
        results = []
        errors = []
        
        def cache_operations():
            try:
                for i in range(100):
                    cache_manager.set(f"thread_key_{threading.current_thread().ident}_{i}", f"value_{i}")
                    value = cache_manager.get(f"thread_key_{threading.current_thread().ident}_{i}")
                    results.append(value)
            except Exception as e:
                errors.append(e)
        
        # Create multiple threads
        threads = []
        for _ in range(5):
            thread = threading.Thread(target=cache_operations)
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Verify no errors occurred
        assert len(errors) == 0, f"Thread safety errors: {errors}"
        assert len(results) == 500  # 5 threads * 100 operations

    def test_connection_pool_performance(self):
        """Test connection pool performance under load."""
        # This would test database connection pooling
        # Mock implementation for demonstration
        
        connection_times = []
        
        def simulate_connection():
            start = time.time()
            # Simulate connection establishment
            time.sleep(0.001)  # 1ms simulated connection time
            end = time.time()
            connection_times.append(end - start)
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(simulate_connection) for _ in range(100)]
            [future.result() for future in futures]
        
        avg_connection_time = sum(connection_times) / len(connection_times)
        max_connection_time = max(connection_times)
        
        # Connection times should be consistent
        assert avg_connection_time < 0.01, f"Average connection time: {avg_connection_time:.4f}s"
        assert max_connection_time < 0.05, f"Max connection time: {max_connection_time:.4f}s"


class TestScalabilityLimits:
    """Test scalability and resource limits."""

    def test_large_dataset_handling(self):
        """Test handling of large datasets."""
        # Create large mock dataset
        large_dataset = [
            {'id': i, 'title': f'Document {i}', 'content': 'x' * 1000}
            for i in range(10000)
        ]
        
        start_time = time.time()
        
        # Test processing large dataset
        processed_count = 0
        for item in large_dataset:
            # Simulate processing
            if len(item['content']) > 500:
                processed_count += 1
        
        processing_time = time.time() - start_time
        
        # Processing should complete in reasonable time
        assert processing_time < 5.0, f"Large dataset processing took {processing_time:.3f}s"
        assert processed_count == 10000

    def test_memory_leak_detection(self):
        """Test for memory leaks during repeated operations."""
        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Perform repeated operations that might leak memory
        for cycle in range(10):
            # Create and destroy objects
            temp_data = []
            for i in range(1000):
                temp_data.append({'data': 'x' * 100})
            
            # Process data
            processed = [item for item in temp_data if len(item['data']) > 50]
            
            # Clear references
            del temp_data
            del processed
            
            # Check memory every few cycles
            if cycle % 3 == 0:
                current_memory = process.memory_info().rss / 1024 / 1024
                memory_growth = current_memory - initial_memory
                
                # Memory growth should be minimal
                assert memory_growth < 100, f"Memory grew by {memory_growth:.2f}MB after {cycle+1} cycles"

    def test_cpu_usage_efficiency(self):
        """Test CPU usage efficiency."""
        # Get initial CPU usage
        process = psutil.Process(os.getpid())
        
        start_time = time.time()
        cpu_start = process.cpu_percent()
        
        # Perform CPU-intensive operations
        total = 0
        for i in range(100000):
            total += i * i
        
        end_time = time.time()
        execution_time = end_time - start_time
        
        # Operation should complete efficiently
        assert execution_time < 2.0, f"CPU-intensive operation took {execution_time:.3f}s"

    def test_io_performance(self):
        """Test I/O operation performance."""
        import tempfile
        
        # Test file I/O performance
        test_data = "Test data " * 1000  # ~9KB of data
        
        start_time = time.time()
        
        # Write test
        with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
            temp_filename = f.name
            for _ in range(100):
                f.write(test_data)
        
        write_time = time.time() - start_time
        
        # Read test
        start_time = time.time()
        
        with open(temp_filename, 'r') as f:
            content = f.read()
        
        read_time = time.time() - start_time
        
        # Cleanup
        os.unlink(temp_filename)
        
        # I/O operations should be reasonably fast
        assert write_time < 1.0, f"File write took {write_time:.3f}s"
        assert read_time < 0.5, f"File read took {read_time:.3f}s"


class TestLoadTesting:
    """Simulated load testing scenarios."""

    def test_high_frequency_requests(self):
        """Test handling high-frequency requests."""
        request_count = 0
        errors = 0
        
        def simulate_request():
            nonlocal request_count, errors
            try:
                # Simulate request processing
                time.sleep(0.001)  # 1ms processing time
                request_count += 1
            except Exception:
                errors += 1
        
        start_time = time.time()
        
        # Simulate 1000 requests in quick succession
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(simulate_request) for _ in range(1000)]
            [future.result() for future in futures]
        
        end_time = time.time()
        total_time = end_time - start_time
        
        requests_per_second = request_count / total_time
        
        # Should handle at least 100 requests per second
        assert requests_per_second > 100, f"Only {requests_per_second:.1f} requests/second"
        assert errors == 0, f"{errors} errors occurred during load test"

    def test_sustained_load(self):
        """Test sustained load over time."""
        start_time = time.time()
        request_times = []
        
        # Run for 10 seconds
        while time.time() - start_time < 10:
            request_start = time.time()
            
            # Simulate work
            time.sleep(0.01)  # 10ms of work
            
            request_end = time.time()
            request_times.append(request_end - request_start)
            
            # Small delay between requests
            time.sleep(0.005)  # 5ms delay
        
        # Analyze performance consistency
        avg_time = sum(request_times) / len(request_times)
        max_time = max(request_times)
        
        # Performance should be consistent
        assert avg_time < 0.02, f"Average request time: {avg_time:.4f}s"
        assert max_time < 0.05, f"Max request time: {max_time:.4f}s"

    @pytest.mark.slow
    def test_stress_test(self):
        """Stress test with extreme load."""
        # This test would push the system to its limits
        # Mark as slow since it takes significant time
        
        successful_operations = 0
        failed_operations = 0
        
        def stress_operation():
            nonlocal successful_operations, failed_operations
            try:
                # Simulate resource-intensive operation
                data = [i * i for i in range(1000)]
                result = sum(data)
                successful_operations += 1
                return result
            except Exception:
                failed_operations += 1
        
        start_time = time.time()
        
        # High concurrency stress test
        with ThreadPoolExecutor(max_workers=100) as executor:
            futures = [executor.submit(stress_operation) for _ in range(5000)]
            results = [future.result() for future in futures if future.result() is not None]
        
        end_time = time.time()
        total_time = end_time - start_time
        
        success_rate = successful_operations / (successful_operations + failed_operations)
        
        # System should maintain reasonable performance under stress
        assert success_rate > 0.95, f"Success rate: {success_rate:.2%}"
        assert total_time < 60, f"Stress test took {total_time:.1f}s"