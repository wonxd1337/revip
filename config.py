# config.py
import os
import tempfile

# Konfigurasi Scanner
class Config:
    # Thread settings
    MAX_THREADS_REVERSE = 30  # Thread untuk reverse IP (pakai proxy)
    MAX_THREADS_SCAN = 100     # Thread untuk scan domain (tanpa proxy)
    
    # Proxy settings
    PREFER_SOCKS5 = True
    SOCKS5_PRIORITY = 0.7
    PROXY_REFRESH_INTERVAL = 1800  # 30 menit dalam detik
    PROXY_URL = "https://raw.githubusercontent.com/proxifly/free-proxy-list/refs/heads/main/proxies/all/data.txt"
    
    # RNG settings
    MAX_VALID_RNG = 50
    MAX_VALID_RNG_LIMIT = 200  # Batas maksimal
    
    # Cache settings
    MAX_CACHE_SIZE = 10000  # Maksimal entries di cache
    CACHE_CLEANUP_INTERVAL = 3600  # Bersihkan cache setiap 1 jam
    
    # Memory management
    TEMP_DIR = tempfile.gettempdir() + "/mt_scanner/"
    MAX_MEMORY_ITEMS = 5000  # Maksimal item dalam memory
    
    # File output
    OUTPUT_FILES = {
        'movable_type': 'movable_type.txt',
        'movable_type_v4': 'movable_type_v4.txt',
        'processed_ips': 'processed_ips.txt',  # Track IP sudah diproses
        'cache': 'cache.db'  # Database cache
    }
    
    # Retry settings
    MAX_RETRIES = 3
    RETRY_DELAY = 2
    
    # Timeout settings
    TIMEOUT_REVERSE = 30
    TIMEOUT_SCAN = 10
    
    @staticmethod
    def ensure_temp_dir():
        """Pastikan direktori temporary ada"""
        if not os.path.exists(Config.TEMP_DIR):
            os.makedirs(Config.TEMP_DIR)
