# cache_manager.py
import sqlite3
import json
import time
import os
import threading
from config import Config

class CacheManager:
    def __init__(self):
        self.db_path = Config.TEMP_DIR + Config.OUTPUT_FILES['cache']
        self.processed_ips_path = Config.TEMP_DIR + Config.OUTPUT_FILES['processed_ips']
        self.lock = threading.Lock()
        
        # Inisialisasi database
        self.init_database()
        
        # Mulai thread cleanup
        self.start_cleanup_thread()
    
    def init_database(self):
        """Inisialisasi database SQLite"""
        Config.ensure_temp_dir()
        
        conn = sqlite3.connect(self.db_path, timeout=10)
        cursor = conn.cursor()
        
        # Tabel untuk cache reverse IP
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reverse_ip_cache (
                ip TEXT PRIMARY KEY,
                domains TEXT,
                timestamp REAL,
                source TEXT
            )
        ''')
        
        # Tabel untuk hasil scan
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                domain TEXT PRIMARY KEY,
                result TEXT,
                timestamp REAL
            )
        ''')
        
        # Tabel untuk tracking IP diproses
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS processed_ips (
                ip TEXT PRIMARY KEY,
                timestamp REAL,
                status TEXT
            )
        ''')
        
        # Index untuk performance
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON reverse_ip_cache(timestamp)')
        
        conn.commit()
        conn.close()
    
    def get_reverse_cache(self, ip):
        """Ambil cache reverse IP"""
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path, timeout=10)
                cursor = conn.cursor()
                cursor.execute(
                    'SELECT domains, timestamp FROM reverse_ip_cache WHERE ip = ?',
                    (ip,)
                )
                row = cursor.fetchone()
                conn.close()
                
                if row:
                    domains, timestamp = row
                    # Cache valid untuk 24 jam
                    if time.time() - timestamp < 86400:
                        return json.loads(domains)
            except:
                pass
            return None
    
    def save_reverse_cache(self, ip, domains, source):
        """Simpan cache reverse IP"""
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path, timeout=10)
                cursor = conn.cursor()
                cursor.execute(
                    '''INSERT OR REPLACE INTO reverse_ip_cache 
                       (ip, domains, timestamp, source) VALUES (?, ?, ?, ?)''',
                    (ip, json.dumps(domains), time.time(), source)
                )
                conn.commit()
                conn.close()
            except:
                pass
    
    def is_ip_processed(self, ip):
        """Cek apakah IP sudah diproses"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            cursor = conn.cursor()
            cursor.execute(
                'SELECT timestamp FROM processed_ips WHERE ip = ?',
                (ip,)
            )
            row = cursor.fetchone()
            conn.close()
            
            if row:
                # IP valid untuk 7 hari
                return time.time() - row[0] < 604800
        except:
            pass
        return False
    
    def mark_ip_processed(self, ip, status='success'):
        """Tandai IP sudah diproses"""
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path, timeout=10)
                cursor = conn.cursor()
                cursor.execute(
                    '''INSERT OR REPLACE INTO processed_ips 
                       (ip, timestamp, status) VALUES (?, ?, ?)''',
                    (ip, time.time(), status)
                )
                conn.commit()
                conn.close()
            except:
                pass
    
def cleanup_old_cache(self):
    """Bersihkan cache lama"""
    while True:
        time.sleep(Config.CACHE_CLEANUP_INTERVAL)
        
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            cursor = conn.cursor()
            
            # Hapus cache reverse IP > 7 hari
            cursor.execute(
                'DELETE FROM reverse_ip_cache WHERE timestamp < ?',
                (time.time() - 604800,)
            )
            rev_count = cursor.rowcount
            
            # Hapus processed IP > 30 hari
            cursor.execute(
                'DELETE FROM processed_ips WHERE timestamp < ?',
                (time.time() - 2592000,)
            )
            proc_count = cursor.rowcount
            
            # Commit perubahan
            conn.commit()
            print(f"[✓] Cache cleaned: {rev_count + proc_count} entries removed")
            
            # Vacuum database untuk compact (di luar transaksi)
            if rev_count + proc_count > 100:  # Only vacuum if significant cleanup
                cursor.execute('VACUUM')
                print("[✓] Database vacuum completed")
            
            conn.close()
            
        except Exception as e:
            print(f"[-] Cache cleanup error: {e}")
    
    def start_cleanup_thread(self):
        """Mulai thread cleanup cache"""
        cleanup_thread = threading.Thread(target=self.cleanup_old_cache, daemon=True)
        cleanup_thread.start()
    
    def get_stats(self):
        """Dapatkan statistik cache"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            cursor = conn.cursor()
            
            stats = {}
            for table in ['reverse_ip_cache', 'scan_results', 'processed_ips']:
                cursor.execute(f'SELECT COUNT(*) FROM {table}')
                stats[table] = cursor.fetchone()[0]
            
            conn.close()
            return stats
        except:
            return {}