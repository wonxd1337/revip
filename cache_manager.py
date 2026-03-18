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
        
        # Enable foreign keys and auto_vacuum
        cursor.execute('PRAGMA foreign_keys = ON')
        cursor.execute('PRAGMA auto_vacuum = 1')  # FULL auto_vacuum
        
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
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_proc_timestamp ON processed_ips(timestamp)')
        
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
            except Exception as e:
                print(f"[-] Error reading cache: {e}")
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
            except Exception as e:
                print(f"[-] Error saving cache: {e}")
    
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
        except Exception as e:
            print(f"[-] Error checking processed IP: {e}")
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
            except Exception as e:
                print(f"[-] Error marking IP processed: {e}")
    
    def cleanup_old_cache(self):
        """Bersihkan cache lama (running di background thread)"""
        while True:
            try:
                # Tunggu sesuai interval
                time.sleep(Config.CACHE_CLEANUP_INTERVAL)
                
                # Cek database size
                if os.path.exists(self.db_path):
                    db_size = os.path.getsize(self.db_path) / (1024 * 1024)  # MB
                else:
                    db_size = 0
                
                # Koneksi ke database
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
                
                # Hapus scan results > 30 hari (jika ada)
                cursor.execute(
                    'DELETE FROM scan_results WHERE timestamp < ?',
                    (time.time() - 2592000,)
                )
                scan_count = cursor.rowcount
                
                # Commit perubahan
                conn.commit()
                
                total_removed = rev_count + proc_count + scan_count
                if total_removed > 0:
                    print(f"[✓] Cache cleaned: {total_removed} entries removed")
                
                # Vacuum database jika perlu (significant cleanup atau db terlalu besar)
                if total_removed > 100 or db_size > 100:  # >100MB
                    cursor.execute('VACUUM')
                    new_size = os.path.getsize(self.db_path) / (1024 * 1024)
                    print(f"[✓] Database vacuum completed: {db_size:.1f}MB → {new_size:.1f}MB")
                
                conn.close()
                
            except Exception as e:
                print(f"[-] Cache cleanup error: {e}")
                try:
                    conn.close()
                except:
                    pass
    
    def start_cleanup_thread(self):
        """Mulai thread cleanup cache"""
        cleanup_thread = threading.Thread(target=self.cleanup_old_cache, daemon=True)
        cleanup_thread.start()
        print("[*] Cache cleanup thread started")
    
    def get_stats(self):
        """Dapatkan statistik cache"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            cursor = conn.cursor()
            
            stats = {}
            tables = ['reverse_ip_cache', 'scan_results', 'processed_ips']
            
            for table in tables:
                cursor.execute(f'SELECT COUNT(*) FROM {table}')
                stats[table] = cursor.fetchone()[0]
            
            # Dapatkan ukuran database
            if os.path.exists(self.db_path):
                stats['db_size_mb'] = os.path.getsize(self.db_path) / (1024 * 1024)
            else:
                stats['db_size_mb'] = 0
            
            conn.close()
            return stats
        except Exception as e:
            print(f"[-] Error getting stats: {e}")
            return {}
    
    def clear_all_cache(self):
        """Bersihkan semua cache (manual)"""
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path, timeout=10)
                cursor = conn.cursor()
                
                # Hapus semua data
                cursor.execute('DELETE FROM reverse_ip_cache')
                cursor.execute('DELETE FROM scan_results')
                cursor.execute('DELETE FROM processed_ips')
                
                conn.commit()
                cursor.execute('VACUUM')
                conn.close()
                
                print("[✓] All cache cleared")
                return True
            except Exception as e:
                print(f"[-] Error clearing cache: {e}")
                return False
    
    def optimize_database(self):
        """Optimasi database manual"""
        try:
            conn = sqlite3.connect(self.db_path, timeout=10)
            cursor = conn.cursor()
            
            # Rebuild indexes
            cursor.execute('REINDEX')
            
            # Vacuum database
            cursor.execute('VACUUM')
            
            # Analyze untuk query optimizer
            cursor.execute('ANALYZE')
            
            conn.close()
            print("[✓] Database optimized")
            return True
        except Exception as e:
            print(f"[-] Error optimizing database: {e}")
            return False
