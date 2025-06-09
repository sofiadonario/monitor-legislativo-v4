"""
Session Factory for async HTTP session management
Implements recommendations from technical analysis
"""

import aiohttp
import asyncio
import ssl
import certifi
import random
from typing import Optional


class SessionFactory:
    """Factory for managing HTTP sessions with proper lifecycle"""
    
    _session: Optional[aiohttp.ClientSession] = None
    _session_lock = asyncio.Lock()
    
    # User-Agent rotation for anti-automation bypass
    USER_AGENTS = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    ]
    
    @classmethod
    async def get_session(cls) -> aiohttp.ClientSession:
        """Get or create HTTP session with proper configuration"""
        async with cls._session_lock:
            if not hasattr(cls, '_session') or cls._session is None or cls._session.closed:
                # Create SSL context that handles government sites
                ssl_context = ssl.create_default_context(cafile=certifi.where())
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                
                # Configure connector
                connector = aiohttp.TCPConnector(
                    ssl=ssl_context,
                    limit=500,  # FIXED: Increased total pool size from 100 to 500
                    limit_per_host=100,  # FIXED: Increased per-host from 30 to 100 (for government APIs)
                    ttl_dns_cache=300,  # DNS cache TTL
                    use_dns_cache=True,
                    enable_cleanup_closed=True,  # ADDED: Clean up closed connections
                    keepalive_timeout=30,  # ADDED: Keep connections alive for reuse
                    limit_per_host_default=100  # ADDED: Default per-host limit
                )
                
                # Default headers with User-Agent rotation
                headers = {
                    'User-Agent': random.choice(cls.USER_AGENTS),
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                    'Accept-Language': 'pt-BR,pt;q=0.9,en;q=0.8',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                }
                
                # Create session with timeout
                timeout = aiohttp.ClientTimeout(total=30, connect=10)
                cls._session = aiohttp.ClientSession(
                    connector=connector,
                    headers=headers,
                    timeout=timeout
                )
                
            return cls._session
    
    @classmethod
    async def close_all(cls):
        """Close all sessions and cleanup resources"""
        async with cls._session_lock:
            if hasattr(cls, '_session') and cls._session and not cls._session.closed:
                await cls._session.close()
                cls._session = None
    
    @classmethod
    async def get_fresh_session(cls) -> aiohttp.ClientSession:
        """Get a fresh session with new User-Agent"""
        await cls.close_all()
        return await cls.get_session()


async def fetch_with_retry(url: str, max_retries: int = 3, backoff_factor: float = 1.5, **kwargs):
    """
    Fetch URL with retry logic and exponential backoff
    """
    retry_count = 0
    
    while retry_count < max_retries:
        try:
            session = await SessionFactory.get_session()
            
            # Add random delay to avoid rate limiting
            if retry_count > 0:
                delay = random.uniform(1.0, 3.0)
                await asyncio.sleep(delay)
            
            async with session.get(url, **kwargs) as response:
                if response.status == 200:
                    return await response.text()
                elif response.status in [429, 503, 504]:  # Rate limited or server errors
                    raise aiohttp.ClientResponseError(
                        request_info=response.request_info,
                        history=response.history,
                        status=response.status
                    )
                else:
                    response.raise_for_status()
                    
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            retry_count += 1
            if retry_count >= max_retries:
                raise
            
            # Exponential backoff
            wait_time = backoff_factor ** retry_count
            await asyncio.sleep(wait_time)
            
            # Try fresh session on retry
            if retry_count > 1:
                await SessionFactory.get_fresh_session()
    
    raise Exception(f"Failed to fetch {url} after {max_retries} retries")