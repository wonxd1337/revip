# main.py
import os
import sys
import signal
import atexit
from config import Config
from proxy_manager import ProxyManager
from cache_manager import CacheManager
from scanner import MovableTypeScanner
from ip_generator import IPGenerator

class MovableTypeMassScanner:
    def __init__(self):
        self.proxy_manager = None
        self.cache_manager = None
        self.scanner = None
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Register cleanup
        atexit.register(self.cleanup)
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C"""
        print("\n\n[!] Received interrupt signal. Cleaning up...")
        self.running = False
        self.cleanup()
        sys.exit(0)
    
    def cleanup(self):
        """Bersihkan resources"""
        print("[*] Cleaning up resources...")
        
        # Bersihkan cache lama
        if self.cache_manager:
            stats = self.cache_manager.get_stats()
            print(f"[*] Cache stats: {stats}")
        
        # Tampilkan statistik proxy
        if self.proxy_manager:
            self.proxy_manager.print_stats()
        
        print("[✓] Cleanup completed")
    
    def print_header(self):
        """Tampilkan header"""
        print("""
    ╔════════════════════════════════════════════════════════════╗
    ║         Movable Type Mass Scanner v2.0 (Enterprise)        ║
    ║  - Auto Proxy Refresh (5 menit)                            ║
    ║  - SQLite Cache System                                     ║
    ║  - Memory Efficient                                        ║
    ║  - Run for Days Without Issues                             ║
    ╚════════════════════════════════════════════════════════════╝
        """)
    
    def run(self):
        """Main execution"""
        self.print_header()
        
        # Inisialisasi komponen
        print("[*] Initializing components...")
        
        # Proxy Manager (auto-refresh)
        print("[*] Starting Proxy Manager...")
        self.proxy_manager = ProxyManager()
        
        # Cache Manager
        print("[*] Starting Cache Manager...")
        self.cache_manager = CacheManager()
        
        # Scanner
        self.scanner = MovableTypeScanner(self.proxy_manager, self.cache_manager)
        
        # IP Generator
        self.ip_generator = IPGenerator(self.cache_manager)
        
        # Pilih metode
        print("\n" + "="*50)
        print("SELECT INPUT METHOD")
        print("="*50)
        print("1. Scan from IP list file")
        print("2. Scan with RNG IP (auto-generate)")
        print("3. Continuous scan (run forever)")
        print("4. Show statistics")
        
        choice = input("\nChoice (1-4): ").strip()
        
        if choice == '1':
            self.scan_from_file()
        elif choice == '2':
            self.scan_with_rng()
        elif choice == '3':
            self.continuous_scan()
        elif choice == '4':
            self.show_stats()
        else:
            print("[!] Invalid choice!")
    
    def scan_from_file(self):
        """Scan dari file"""
        filename = input("IP list file: ").strip()
        
        try:
            with open(filename, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            
            print(f"[*] Loaded {len(ips)} IPs")
            
            from concurrent.futures import ThreadPoolExecutor, as_completed
            
            with ThreadPoolExecutor(max_workers=Config.MAX_THREADS_REVERSE) as executor:
                futures = []
                for ip in ips:
                    if not self.running:
                        break
                    
                    # Skip jika sudah diproses
                    if not self.cache_manager.is_ip_processed(ip):
                        futures.append(executor.submit(self.scanner.process_ip, ip))
                    else:
                        print(f"[↺] Skipping cached IP: {ip}")
                
                for future in as_completed(futures):
                    if not self.running:
                        break
                    try:
                        future.result()
                    except Exception as e:
                        print(f"[-] Error: {e}")
                        
        except Exception as e:
            print(f"[!] Error: {e}")
    
    def scan_with_rng(self):
        """Scan dengan RNG IP"""
        base_ip = input("Base IP (e.g., 157.7.44): ").strip()
        
        # Format IP
        if base_ip.count('.') == 2:
            base_ip = base_ip + '.1'
        
        # Jumlah IP
        try:
            max_valid = input(f"Number of IPs (default {Config.MAX_VALID_RNG}): ").strip()
            if max_valid:
                max_valid = min(int(max_valid), Config.MAX_VALID_RNG_LIMIT)
            else:
                max_valid = Config.MAX_VALID_RNG
        except:
            max_valid = Config.MAX_VALID_RNG
        
        print(f"[*] Will generate up to {max_valid} valid IPs")
        
        # Stream dan proses
        self.ip_generator.stream_ips(
            base_ip, 
            self.scanner.process_ip,
            max_valid
        )
    
    def continuous_scan(self):
        """Continuous scan mode"""
        print("\n[*] Continuous Scan Mode")
        print("[*] Press Ctrl+C to stop\n")
        
        base_ip = input("Base IP for generation: ").strip()
        
        if base_ip.count('.') == 2:
            base_ip = base_ip + '.1'
        
        cycle = 0
        while self.running:
            cycle += 1
            print(f"\n{'='*60}")
            print(f"CYCLE #{cycle} - {time.strftime('%Y-%m-%d %H:%M:%S')}")
            print('='*60)
            
            # Generate dan proses IP
            self.ip_generator.stream_ips(
                base_ip,
                self.scanner.process_ip,
                Config.MAX_VALID_RNG
            )
            
            # Tampilkan statistik
            self.show_stats(quiet=True)
            
            # Istirahat antar cycle
            print(f"\n[*] Cycle #{cycle} completed. Waiting 60 seconds...")
            for i in range(60):
                if not self.running:
                    break
                time.sleep(1)
                if i % 10 == 0:
                    print(f"[*] Next cycle in {60-i}s...", end='\r')
    
    def show_stats(self, quiet=False):
        """Tampilkan statistik"""
        if not quiet:
            print("\n" + "="*60)
            print("SYSTEM STATISTICS")
            print("="*60)
        
        # Cache stats
        cache_stats = self.cache_manager.get_stats()
        print(f"\n📦 Cache Database:")
        for table, count in cache_stats.items():
            print(f"  - {table}: {count} entries")
        
        # Proxy stats
        self.proxy_manager.print_stats()
        
        # File stats
        print("\n📁 Output Files:")
        for name, filename in Config.OUTPUT_FILES.items():
            if os.path.exists(filename):
                size = os.path.getsize(filename) / 1024  # KB
                print(f"  - {filename}: {size:.2f} KB")
            elif os.path.exists(Config.TEMP_DIR + filename):
                size = os.path.getsize(Config.TEMP_DIR + filename) / 1024
                print(f"  - {filename} (temp): {size:.2f} KB")

def main():
    scanner = MovableTypeMassScanner()
    scanner.run()

if __name__ == "__main__":
    main()