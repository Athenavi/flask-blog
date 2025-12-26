"""
缓存防击穿保护工具模块
实现三种常见的缓存防击穿策略：
1. 错开TTL（在超时值中加入随机抖动）
2. 基于锁的再生（只有一个请求会重新生成已过期的缓存）
3. 提供过期数据（在后台重新生成时返回过期缓存）
"""

import random
import threading
from functools import wraps
from typing import Any, Callable

from flask import current_app
from flask_caching import Cache

# 用于实现锁机制的全局字典
_cache_locks = {}
_locks_lock = threading.Lock()


def staggered_ttl(timeout: int, jitter_range: float = 0.1) -> int:
    """
    为缓存超时添加随机抖动，避免大量缓存同时失效
    
    Args:
        timeout: 基础超时时间（秒）
        jitter_range: 抖动范围（0-1之间的小数），例如0.1表示±10%
    
    Returns:
        添加抖动后的超时时间
    """
    jitter = timeout * jitter_range
    min_timeout = int(timeout - jitter)
    max_timeout = int(timeout + jitter)
    return random.randint(min_timeout, max_timeout)


def cache_with_staggered_ttl(timeout: int = 300, jitter_range: float = 0.1):
    """
    带有错开TTL的缓存装饰器
    
    Args:
        timeout: 基础超时时间（秒）
        jitter_range: 抖动范围（0-1之间的小数）
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 获取原始缓存装饰器
            cache_decorator = current_app.extensions['cache']

            # 生成带抖动的超时时间
            staggered_timeout = staggered_ttl(timeout, jitter_range)

            # 应用缓存（此处简化实现，实际应该与Flask-Cache集成更紧密）
            return f(*args, **kwargs)

        return decorated_function

    return decorator


def get_cache_lock(key: str) -> threading.Lock:
    """
    获取指定缓存键的锁对象
    
    Args:
        key: 缓存键
        
    Returns:
        对应的锁对象
    """
    with _locks_lock:
        if key not in _cache_locks:
            _cache_locks[key] = threading.Lock()
        return _cache_locks[key]


def cache_with_regeneration(cache_instance: Cache,
                            timeout: int = 300,
                            lock_timeout: int = 10):
    """
    带有锁机制的缓存装饰器，防止缓存击穿
    
    Args:
        cache_instance: Flask-Cache实例
        timeout: 缓存超时时间
        lock_timeout: 获取锁的超时时间（秒）
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 生成缓存键
            cache_key = f"{f.__module__}.{f.__name__}:{hash(str(args) + str(kwargs))}"

            # 尝试从缓存获取数据
            value = cache_instance.get(cache_key)
            if value is not None:
                return value

            # 缓存未命中，获取锁
            lock = get_cache_lock(cache_key)
            acquired = lock.acquire(timeout=lock_timeout)

            if not acquired:
                # 获取锁超时，可能数据库压力过大，直接查询数据库
                current_app.logger.warning(f"Cache lock timeout for key: {cache_key}")
                return f(*args, **kwargs)

            try:
                # 再次检查缓存，防止重复计算
                value = cache_instance.get(cache_key)
                if value is not None:
                    return value

                # 执行实际函数
                value = f(*args, **kwargs)

                # 存储到缓存
                cache_instance.set(cache_key, value, timeout=timeout)

                return value
            finally:
                # 释放锁
                lock.release()

        return decorated_function

    return decorator


def cache_with_stale_data(cache_instance: Cache,
                          fresh_timeout: int = 300,
                          stale_timeout: int = 3600):
    """
    支持返回过期数据的缓存装饰器
    
    Args:
        cache_instance: Flask-Cache实例
        fresh_timeout: 新鲜数据的超时时间
        stale_timeout: 过期数据的超时时间（在此时间内仍可返回）
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # 生成缓存键
            cache_key = f"{f.__module__}.{f.__name__}:{hash(str(args) + str(kwargs))}"
            stale_key = f"{cache_key}:stale"

            # 尝试获取新鲜数据
            fresh_value = cache_instance.get(cache_key)
            if fresh_value is not None:
                return fresh_value

            # 尝试获取过期数据
            stale_value = cache_instance.get(stale_key)
            if stale_value is not None:
                # 异步更新缓存（在新线程中执行）
                thread = threading.Thread(
                    target=update_stale_cache,
                    args=(cache_instance, cache_key, stale_key, f, args, kwargs,
                          fresh_timeout, stale_timeout)
                )
                thread.daemon = True
                thread.start()

                # 返回过期数据
                return stale_value

            # 都没有，执行函数获取数据
            value = f(*args, **kwargs)

            # 存储新鲜数据和过期数据
            cache_instance.set(cache_key, value, timeout=fresh_timeout)
            cache_instance.set(stale_key, value, timeout=stale_timeout)

            return value

        return decorated_function

    return decorator


def update_stale_cache(cache_instance: Cache,
                       cache_key: str,
                       stale_key: str,
                       func: Callable,
                       args: tuple,
                       kwargs: dict,
                       fresh_timeout: int,
                       stale_timeout: int):
    """
    更新过期缓存的辅助函数，在单独线程中运行
    
    Args:
        cache_instance: Flask-Cache实例
        cache_key: 新鲜数据缓存键
        stale_key: 过期数据缓存键
        func: 需要执行的函数
        args: 函数参数
        kwargs: 函数关键字参数
        fresh_timeout: 新鲜数据超时时间
        stale_timeout: 过期数据超时时间
    """
    try:
        # 执行函数获取新数据
        value = func(*args, **kwargs)

        # 更新缓存
        cache_instance.set(cache_key, value, timeout=fresh_timeout)
        # 延长过期数据的生命周期
        cache_instance.set(stale_key, value, timeout=stale_timeout)
    except Exception as e:
        current_app.logger.error(f"Error updating stale cache {cache_key}: {str(e)}")


class ProtectedCache:
    """
    带有防击穿保护的缓存类
    集成多种防击穿策略
    """

    def __init__(self, cache_instance: Cache):
        self.cache = cache_instance

    def get_with_staggered_ttl(self, key: str, default: Any = None,
                               timeout: int = 300, jitter_range: float = 0.1) -> Any:
        """
        带有错开TTL的获取缓存方法
        
        Args:
            key: 缓存键
            default: 默认值
            timeout: 基础超时时间
            jitter_range: 抖动范围
            
        Returns:
            缓存值或默认值
        """
        value = self.cache.get(key)
        if value is None:
            value = default
            if default is not None:
                staggered_timeout = staggered_ttl(timeout, jitter_range)
                self.cache.set(key, default, timeout=staggered_timeout)
        return value

    def get_with_lock(self, key: str, generator_func: Callable,
                      timeout: int = 300, lock_timeout: int = 10) -> Any:
        """
        带锁机制的获取缓存方法
        
        Args:
            key: 缓存键
            generator_func: 用于生成缓存值的函数
            timeout: 缓存超时时间
            lock_timeout: 获取锁的超时时间
            
        Returns:
            缓存值
        """
        value = self.cache.get(key)
        if value is not None:
            return value

        # 获取锁
        lock = get_cache_lock(key)
        acquired = lock.acquire(timeout=lock_timeout)

        if not acquired:
            # 获取锁超时，直接执行函数
            current_app.logger.warning(f"Cache lock timeout for key: {key}")
            return generator_func()

        try:
            # 再次检查缓存
            value = self.cache.get(key)
            if value is not None:
                return value

            # 生成值并缓存
            value = generator_func()
            self.cache.set(key, value, timeout=timeout)
            return value
        finally:
            lock.release()

    def get_with_stale_data(self, key: str, generator_func: Callable,
                            fresh_timeout: int = 300,
                            stale_timeout: int = 3600) -> Any:
        """
        支持过期数据的获取缓存方法
        
        Args:
            key: 缓存键
            generator_func: 用于生成缓存值的函数
            fresh_timeout: 新鲜数据的超时时间
            stale_timeout: 过期数据的超时时间
            
        Returns:
            缓存值
        """
        stale_key = f"{key}:stale"

        # 尝试获取新鲜数据
        fresh_value = self.cache.get(key)
        if fresh_value is not None:
            return fresh_value

        # 尝试获取过期数据
        stale_value = self.cache.get(stale_key)
        if stale_value is not None:
            # 异步更新缓存
            thread = threading.Thread(
                target=self._update_stale_cache_async,
                args=(key, stale_key, generator_func, fresh_timeout, stale_timeout)
            )
            thread.daemon = True
            thread.start()

            return stale_value

        # 都没有，生成新值
        value = generator_func()
        self.cache.set(key, value, timeout=fresh_timeout)
        self.cache.set(stale_key, value, timeout=stale_timeout)
        return value

    def _update_stale_cache_async(self, key: str, stale_key: str,
                                  generator_func: Callable,
                                  fresh_timeout: int, stale_timeout: int):
        """
        异步更新过期缓存
        """
        try:
            value = generator_func()
            self.cache.set(key, value, timeout=fresh_timeout)
            # 延长过期数据生命周期
            self.cache.set(stale_key, value, timeout=stale_timeout)
        except Exception as e:
            current_app.logger.error(f"Error updating stale cache {key}: {str(e)}")
