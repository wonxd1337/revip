# main.py
import os
import sys
import signal
import atexit
import time
import shutil
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
from config import Config
from proxy_manager import ProxyManager
from cache_manager import CacheManager
from scanner import MovableTypeScanner
from ip_generator import IPGenerator

# ============================================
# DASHBOARD DENGAN BORDER (LENGKAP)
# ============================================
class BorderDashboard:
    def __init__(self):
        self.width = min(shutil.get_terminal_size().columns, 100)  # Max 100 columns
        # ANSI color codes
        self.BOLD = '\033[1m'
        self.RED = '\033[91m'
        self.GREEN = '\033[92m'
        self.YELLOW = '\033[93m'
        self.BLUE = '\033[94m'
        self.PURPLE = '\033[95m'
        self.CYAN = '\033[96m'
        self.WHITE = '\033[97m'
        self.END = '\033[0m'
        
        # Border characters
        self.TL = '┌'  # Top Left
        self.TR = '┐'  # Top Right
        self.BL = '└'  # Bottom Left
        self.BR = '┘'  # Bottom Right
        self.H = '─'   # Horizontal
        self.V = '│'   # Vertical
        self.TM = '┬'  # Top Middle
        self.BM = '┴'  # Bottom Middle
        self.LM = '├'  # Left Middle
        self.RM = '┤'  # Right Middle
        self.CR = '┼'  # Cross
        
        # Real stats yang akan diupdate (GLOBAL)
        self.stats = {
            'ips_processed': 0,      # Total IP sudah diproses
            'ips_total': 0,           # Total IP target (0 = unlimited)
            'mt_found': 0,            # Total MT ditemukan
            'domains_found': 0,        # Total domains dari reverse IP
            'speed': 0,                # Kecepatan scan (IP/detik)
            'recent_finds': 0,         # MT ditemukan dalam 1 menit terakhir
            'proxies_working': 0,       # Proxy yang bekerja
            'proxies_total': 0,         # Total proxy
            'uptime': '00:00:00',       # Waktu sejak start
            'cache_size': '0 MB',       # Ukuran file cache
            'start_time': time.time()   # Waktu start
        }
        
        # Logs dan findings
        self.logs = []          # System logs (proxy, error, info)
        self.findings = []       # MT findings dengan path lengkap
        
        # Untuk hitung speed
        self.last_count = 0
        self.last_time = time.time()
        
        # Lock untuk thread safety
        self.lock = threading.Lock()
        
        # Pause state
        self.paused = False
    
    def clear(self):
        """Clear terminal"""
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def border_line(self, left, middle, right, content=""):
        """Buat garis border dengan isi"""
        if content:
            # Hitung panjang konten yang bisa muat
            max_content_len = self.width - 4  # -4 untuk border dan spasi
            if len(content) > max_content_len:
                content = content[:max_content_len-3] + "..."
            
            # Hitung padding kiri dan kanan
            total_padding = self.width - len(content) - 4
            left_pad = total_padding // 2
            right_pad = total_padding - left_pad
            
            return f"{left}{' ' * left_pad}{content}{' ' * right_pad}{right}"
        else:
            return f"{left}{self.H * (self.width-2)}{right}"
    
    def header(self):
        """Buat header dengan border"""
        print(self.border_line(self.TL, self.TM, self.TR))
        print(self.border_line(self.V, self.CR, self.V, "MOVABLE TYPE SCANNER v3.0"))
        print(self.border_line(self.LM, self.CR, self.RM))
    
    def footer(self):
        """Buat footer dengan border"""
        print(self.border_line(self.LM, self.CR, self.RM))
        print(self.border_line(self.BL, self.BM, self.BR))
    
    def progress_bar(self, percent, length=20):
        """Buat progress bar"""
        filled = int(length * percent / 100)
        bar = self.GREEN + "█" * filled + self.YELLOW + "░" * (length - filled) + self.END
        return bar
    
    def format_number(self, num):
        """Format angka (1K, 1M, dll)"""
        if num > 999999:
            return f"{num/1000000:.1f}M"
        if num > 999:
            return f"{num/1000:.1f}K"
        return str(num)
    
    def update_uptime(self):
        """Update uptime"""
        seconds = int(time.time() - self.stats['start_time'])
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        secs = seconds % 60
        self.stats['uptime'] = f"{hours:02d}:{minutes:02d}:{secs:02d}"
    
    def update_speed(self):
        """Update kecepatan scan"""
        with self.lock:
            now = time.time()
            time_diff = now - self.last_time
            if time_diff >= 2:
                count_diff = self.stats['ips_processed'] - self.last_count
                self.stats['speed'] = count_diff / time_diff
                self.last_count = self.stats['ips_processed']
                self.last_time = now
    
    def add_log(self, log_type, message):
        """Tambah log entry"""
        with self.lock:
            self.logs.append({
                'time': datetime.now().strftime('%H:%M:%S'),
                'type': log_type,
                'message': message
            })
            if len(self.logs) > 20:
                self.logs.pop(0)
    
    def add_finding(self, domain, path, version, ip, vulnerable=False, status_code=None):
        """Tambah MT finding dengan path lengkap"""
        with self.lock:
            # Format display: domain + path
            full_url = f"{domain}{path}"
            
            self.findings.append({
                'domain': domain,
                'path': path,
                'full_url': full_url,
                'version': version,
                'ip': ip,
                'vulnerable': vulnerable,
                'status_code': status_code,
                'time': datetime.now().strftime('%H:%M:%S')
            })
            
            self.stats['mt_found'] += 1
            self.stats['recent_finds'] += 1
            self.stats['domains_found'] += 1
            
            # Keep last 15 findings
            if len(self.findings) > 15:
                self.findings.pop(0)
            
            # Log dengan path lengkap
            vuln_indicator = " 🔥 VULN!" if vulnerable else ""
            path_display = path if len(path) < 20 else path[:17] + "..."
            self.add_log('VULN' if vulnerable else 'FOUND', 
                        f"{domain}{path_display} | MT v{version}{vuln_indicator}")
    
    def update_proxy_stats(self, working, total):
        """Update statistik proxy"""
        with self.lock:
            self.stats['proxies_working'] = working
            self.stats['proxies_total'] = total
    
    def update_cache_size(self, size_mb):
        """Update ukuran cache"""
        with self.lock:
            self.stats['cache_size'] = f"{size_mb:.1f} MB"
    
    def stats_section(self):
        """Tampilkan section statistics (GLOBAL STATS)"""
        self.update_uptime()
        self.update_speed()
        
        # Title
        title = f"{self.BOLD}{self.CYAN}LIVE STATISTICS (GLOBAL){self.END}"
        uptime = f"Uptime: {self.stats['uptime']}"
        padding = self.width - len('  ') - len(title) - len(uptime) - 6
        print(f"{self.V}  {title}{' ' * padding}{uptime}  {self.V}")
        
        # Separator
        print(f"{self.V}  {self.H * (self.width-6)}  {self.V}")
        
        # IP Progress (GLOBAL)
        if self.stats['ips_total'] > 0:
            ip_percent = min(100, (self.stats['ips_processed'] / self.stats['ips_total']) * 100)
            ip_bar = self.progress_bar(ip_percent)
            ip_text = f"{self.BOLD}📡 IPs Processed{self.END} : {self.format_number(self.stats['ips_processed']):>6} / {self.format_number(self.stats['ips_total'])}  {ip_bar}  {ip_percent:.0f}%"
            print(f"{self.V}  {ip_text:<{self.width-6}}  {self.V}")
        else:
            ip_text = f"{self.BOLD}📡 IPs Processed{self.END} : {self.format_number(self.stats['ips_processed']):>6} (unlimited)"
            print(f"{self.V}  {ip_text:<{self.width-6}}  {self.V}")
        
        # Domains Found (GLOBAL)
        domains_text = f"{self.BOLD}🌐 Domains Found{self.END} : {self.GREEN}{self.format_number(self.stats['domains_found']):>6}{self.END}"
        print(f"{self.V}  {domains_text:<{self.width-6}}  {self.V}")
        
        # MT Detected (GLOBAL)
        mt_color = self.GREEN if self.stats['mt_found'] > 0 else self.YELLOW
        mt_text = f"{self.BOLD}🎯 MT Detected{self.END} : {mt_color}{self.format_number(self.stats['mt_found']):>6}{self.END}"
        print(f"{self.V}  {mt_text:<{self.width-6}}  {self.V}")
        
        # Speed (GLOBAL)
        speed_color = self.GREEN if self.stats['speed'] > 5 else self.YELLOW if self.stats['speed'] > 1 else self.RED
        recent_color = self.GREEN if self.stats['recent_finds'] > 0 else self.WHITE
        speed_text = f"{self.BOLD}⚡ Speed{self.END} : {speed_color}{self.stats['speed']:.1f} IP/s{self.END}      {recent_color}🔥 +{self.stats['recent_finds']} in last min{self.END}"
        print(f"{self.V}  {speed_text:<{self.width-6}}  {self.V}")
        
        # Proxies (GLOBAL)
        if self.stats['proxies_total'] > 0:
            proxy_percent = (self.stats['proxies_working'] / self.stats['proxies_total']) * 100
            proxy_color = self.GREEN if proxy_percent > 70 else self.YELLOW if proxy_percent > 40 else self.RED
            proxy_text = f"{self.BOLD}🔄 Active Proxies{self.END} : {proxy_color}{self.stats['proxies_working']}{self.END} / {self.stats['proxies_total']}  ✓ {proxy_percent:.0f}% working"
            print(f"{self.V}  {proxy_text:<{self.width-6}}  {self.V}")
        
        # Cache Size
        cache_num = float(self.stats['cache_size'].replace(' MB',''))
        cache_color = self.YELLOW if cache_num > 500 else self.RED if cache_num > 1000 else self.GREEN
        cache_text = f"{self.BOLD}💾 Cache{self.END} : {cache_color}{self.stats['cache_size']}{self.END}"
        print(f"{self.V}  {cache_text:<{self.width-6}}  {self.V}")
    
    def findings_section(self):
        """Tampilkan latest finds dengan path lengkap"""
        print(self.border_line(self.LM, self.CR, self.RM))
        print(f"{self.V}  {self.BOLD}{self.CYAN}LATEST FINDS (with paths){self.END}" + 
              f"{' ' * (self.width - len('  LATEST FINDS (with paths)') - 4)}  {self.V}")
        
        if not self.findings and not self.logs:
            print(f"{self.V}  {self.WHITE}  No activity yet...{self.END}" + 
                  f"{' ' * (self.width - len('  No activity yet...') - 6)}  {self.V}")
        else:
            # Tampilkan findings terbaru (prioritas)
            for finding in self.findings[-8:]:  # Last 8 findings
                # Icon based on vulnerability
                if finding.get('vulnerable'):
                    icon = f"{self.RED}{self.BOLD}🔥{self.END}"
                else:
                    icon = f"{self.GREEN}✓{self.END}"
                
                # Format: domain + path
                full_display = finding['full_url']
                if len(full_display) > 40:
                    full_display = full_display[:37] + "..."
                
                # Status code jika ada
                status = f" ({finding['status_code']})" if finding.get('status_code') else ""
                
                # Version info
                version_info = f"v{finding['version']}" if finding.get('version') != 'unknown' else ""
                
                # Gabungkan
                log_text = f"[{finding['time']}]  {icon}  {full_display}{status}  {version_info}"
                
                # Truncate if too long
                max_len = self.width - 8
                if len(log_text) > max_len:
                    log_text = log_text[:max_len-3] + "..."
                
                padding = ' ' * (self.width - len(log_text) - 4)
                print(f"{self.V}  {log_text}{padding}  {self.V}")
            
            # Tambah separator jika masih ada space
            if len(self.findings) < 8 and self.logs:
                if self.findings:
                    # Tambah garis pemisah tipis
                    print(f"{self.V}  {self.H * (self.width-6)}  {self.V}")
                
                remaining = 8 - len(self.findings)
                for log in self.logs[-remaining:]:
                    # Icon based on type
                    if log['type'] == 'PROXY':
                        icon = f"{self.BLUE}🔄{self.END}"
                    elif log['type'] == 'ERROR':
                        icon = f"{self.RED}✗{self.END}"
                    elif log['type'] == 'RETRY':
                        icon = f"{self.YELLOW}⚠{self.END}"
                    elif log['type'] == 'SKIP':
                        icon = f"{self.WHITE}↺{self.END}"
                    elif log['type'] == 'INFO':
                        icon = f"{self.WHITE}•{self.END}"
                    else:
                        icon = f"{self.WHITE}•{self.END}"
                    
                    log_text = f"[{log['time']}]  {icon}  {log['message']}"
                    
                    max_len = self.width - 8
                    if len(log_text) > max_len:
                        log_text = log_text[:max_len-3] + "..."
                    
                    padding = ' ' * (self.width - len(log_text) - 4)
                    print(f"{self.V}  {log_text}{padding}  {self.V}")
    
    def menu_section(self):
        """Tampilkan menu"""
        print(self.border_line(self.LM, self.CR, self.RM))
        
        # Menu items
        pause_text = f"{self.CYAN}[Space]{self.END} {self.BOLD}Pause{self.END}" if not self.paused else f"{self.CYAN}[Space]{self.END} {self.BOLD}Resume{self.END}"
        menu = f"{pause_text}  {self.CYAN}[S]{self.END} {self.BOLD}Save{self.END}  {self.CYAN}[V]{self.END} {self.BOLD}View{self.END}  {self.CYAN}[C]{self.END} {self.BOLD}Cleanup{self.END}  {self.CYAN}[Q]{self.END} {self.BOLD}Quit{self.END}"
        
        # Center menu
        menu_padding = (self.width - len(menu) - 4) // 2
        if menu_padding < 0:
            menu_padding = 0
        
        print(f"{self.V}{' ' * menu_padding}{menu}{' ' * (self.width - len(menu) - menu_padding - 4)}  {self.V}")
        
        # Pause indicator
        if self.paused:
            pause_msg = f"{self.YELLOW}⚠  SCANNER PAUSED - Press SPACE to resume  ⚠{self.END}"
            pause_padding = (self.width - len(pause_msg) - 4) // 2
            if pause_padding < 0:
                pause_padding = 0
            print(f"{self.V}{' ' * pause_padding}{pause_msg}{' ' * (self.width - len(pause_msg) - pause_padding - 4)}  {self.V}")
    
    def render(self):
        """Render seluruh dashboard"""
        self.clear()
        self.header()
        self.stats_section()
        self.findings_section()
        self.menu_section()
        self.footer()
    
    def toggle_pause(self):
        """Toggle pause state"""
        self.paused = not self.paused
        return self.paused


# ============================================
# MAIN SCANNER CLASS
# ============================================
class MovableTypeMassScanner:
    def __init__(self):
        self.proxy_manager = None
        self.cache_manager = None
        self.scanner = None
        self.ip_generator = None
        self.dashboard = BorderDashboard()
        self.running = True
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)
        
        # Register cleanup
        atexit.register(self.cleanup)
        
        # Thread untuk update dashboard
        self.dashboard_thread = threading.Thread(target=self.dashboard_updater, daemon=True)
        self.dashboard_thread.start()
    
    def signal_handler(self, signum, frame):
        """Handle Ctrl+C"""
        print("\n\n[!] Received interrupt signal. Cleaning up...")
        self.running = False
        self.cleanup()
        sys.exit(0)
    
    def cleanup(self):
        """Bersihkan resources"""
        print("[*] Cleaning up resources...")
        
        if self.cache_manager:
            stats = self.cache_manager.get_stats()
            print(f"[*] Cache stats: {stats}")
        
        if self.proxy_manager:
            self.proxy_manager.print_stats()
        
        print("[✓] Cleanup completed")
    
    def dashboard_updater(self):
        """Update dashboard secara periodik"""
        while self.running:
            try:
                # Update proxy stats
                if self.proxy_manager:
                    with self.proxy_manager.lock:
                        working = len([p for p in self.proxy_manager.proxy_list 
                                     if p in self.proxy_manager.proxy_stats])
                        self.dashboard.update_proxy_stats(working, len(self.proxy_manager.proxy_list))
                
                # Update cache size
                if self.cache_manager and os.path.exists(self.cache_manager.db_path):
                    size_mb = os.path.getsize(self.cache_manager.db_path) / (1024 * 1024)
                    self.dashboard.update_cache_size(size_mb)
                
                # Reset recent finds counter setiap menit
                if int(time.time()) % 60 == 0:
                    self.dashboard.stats['recent_finds'] = 0
                
                # Render ulang setiap 2 detik (jika tidak pause)
                time.sleep(2)
                if not self.dashboard.paused and self.running:
                    self.dashboard.render()
                    
            except Exception as e:
                # Silent error untuk dashboard thread
                pass
    
    def print_initial_header(self):
        """Tampilkan header awal"""
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
        self.print_initial_header()
        
        # Inisialisasi komponen
        print("[*] Initializing components...")
        
        # Proxy Manager
        print("[*] Starting Proxy Manager...")
        self.proxy_manager = ProxyManager()
        
        # Cache Manager
        print("[*] Starting Cache Manager...")
        self.cache_manager = CacheManager()
        
        # Scanner
        self.scanner = MovableTypeScanner(self.proxy_manager, self.cache_manager)
        
        # IP Generator
        self.ip_generator = IPGenerator(self.cache_manager)
        
        # Update dashboard dengan data awal
        if self.proxy_manager:
            self.dashboard.stats['proxies_total'] = len(self.proxy_manager.proxy_list)
        
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
    
    def on_mt_found(self, domain, path, version, ip, vulnerable=False, status_code=None):
        """Callback ketika MT ditemukan (dengan path)"""
        self.dashboard.add_finding(domain, path, version, ip, vulnerable, status_code)
    
    def scan_from_file(self):
        """Scan dari file"""
        filename = input("IP list file: ").strip()
        
        try:
            with open(filename, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            
            # Set total IP
            self.dashboard.stats['ips_total'] = len(ips)
            
            # Render dashboard pertama
            self.dashboard.render()
            
            from concurrent.futures import ThreadPoolExecutor, as_completed
            
            with ThreadPoolExecutor(max_workers=Config.MAX_THREADS_REVERSE) as executor:
                futures = []
                for ip in ips:
                    if not self.running:
                        break
                    
                    # Cek pause
                    while self.dashboard.paused and self.running:
                        time.sleep(0.5)
                    
                    # Skip jika sudah diproses
                    if not self.cache_manager.is_ip_processed(ip):
                        futures.append(executor.submit(self.process_ip, ip))
                    else:
                        self.dashboard.add_log('SKIP', f"IP {ip} already processed")
                        # Render tanpa update IP
                        if not self.dashboard.paused:
                            self.dashboard.render()
                
                for future in as_completed(futures):
                    if not self.running:
                        break
                    
                    while self.dashboard.paused and self.running:
                        time.sleep(0.5)
                    
                    try:
                        future.result()
                    except Exception as e:
                        self.dashboard.add_log('ERROR', str(e)[:50])
                        if not self.dashboard.paused:
                            self.dashboard.render()
                        
        except Exception as e:
            self.dashboard.add_log('ERROR', f"File error: {str(e)[:30]}")
            self.dashboard.render()
            print(f"[!] Error: {e}")
    
    def process_ip(self, ip):
        """Proses satu IP"""
        try:
            # Proses IP via scanner
            domains_tnt = self.scanner.reverse_ip_tntcode(ip)
            domains_ht = self.scanner.reverse_ip_hackertarget(ip)
            
            all_domains = list(set(domains_tnt + domains_ht))
            
            if all_domains:
                self.dashboard.stats['domains_found'] += len(all_domains)
                self.dashboard.add_log('INFO', f"{ip} | {len(all_domains)} domains")
                
                # Scan domains
                found_count = 0
                with ThreadPoolExecutor(max_workers=Config.MAX_THREADS_SCAN) as executor:
                    futures = [executor.submit(self.scan_domain_with_path, domain, ip) for domain in all_domains]
                    for future in as_completed(futures):
                        results = future.result()
                        if results:
                            found_count += len(results)
                            for r in results:
                                self.on_mt_found(
                                    domain=r['domain'],
                                    path=r['path'],
                                    version=r.get('version', 'unknown'),
                                    ip=ip,
                                    vulnerable=r.get('is_v4', False),
                                    status_code=r.get('status_code')
                                )
                
                # Update stats
                self.dashboard.stats['ips_processed'] += 1
                self.cache_manager.mark_ip_processed(ip, 'success' if found_count else 'empty')
                
                # Render update
                if not self.dashboard.paused:
                    self.dashboard.render()
            else:
                self.dashboard.stats['ips_processed'] += 1
                self.dashboard.add_log('INFO', f"{ip} | no domains")
                self.cache_manager.mark_ip_processed(ip, 'no_domains')
                if not self.dashboard.paused:
                    self.dashboard.render()
                
        except Exception as e:
            self.dashboard.add_log('ERROR', f"{ip}: {str(e)[:30]}")
            self.dashboard.stats['ips_processed'] += 1
            if not self.dashboard.paused:
                self.dashboard.render()
    
    def scan_domain_with_path(self, domain, original_ip):
        """Scan domain dan return hasil dengan path (wrapper untuk scanner.scan_domain)"""
        try:
            results = self.scanner.scan_domain(domain)
            # Transform hasil untuk include path
            transformed = []
            for r in results:
                # Extract path dari URL
                if 'xmlrpc_url' in r:
                    parsed = urlparse(r['xmlrpc_url'])
                    path = parsed.path or '/'
                else:
                    path = '/xmlrpc.php'
                
                transformed.append({
                    'domain': domain,
                    'path': path,
                    'version': r.get('version', 'unknown'),
                    'is_v4': r.get('is_v4', False),
                    'status_code': r.get('xmlrpc_status')
                })
            return transformed
        except:
            return []
    
    def scan_with_rng(self):
        """Scan dengan RNG IP"""
        base_ip = input("Base IP (e.g., 157.7.44): ").strip()
        
        if base_ip.count('.') == 2:
            base_ip = base_ip + '.1'
        
        try:
            max_valid = input(f"Number of IPs (default {Config.MAX_VALID_RNG}): ").strip()
            if max_valid:
                max_valid = min(int(max_valid), Config.MAX_VALID_RNG_LIMIT)
            else:
                max_valid = Config.MAX_VALID_RNG
        except:
            max_valid = Config.MAX_VALID_RNG
        
        self.dashboard.stats['ips_total'] = max_valid
        self.dashboard.add_log('INFO', f"Generating {max_valid} valid IPs from {base_ip}")
        self.dashboard.render()
        
        time.sleep(2)
        self.ip_generator.stream_ips(base_ip, self.process_ip, max_valid)
    
    def continuous_scan(self):
        """Continuous scan mode"""
        self.dashboard.add_log('INFO', "Starting continuous scan mode")
        
        base_ip = input("Base IP for generation: ").strip()
        
        if base_ip.count('.') == 2:
            base_ip = base_ip + '.1'
        
        self.dashboard.stats['ips_total'] = 0  # 0 = unlimited
        
        cycle = 0
        while self.running:
            cycle += 1
            self.dashboard.add_log('INFO', f"Starting cycle #{cycle}")
            if not self.dashboard.paused:
                self.dashboard.render()
            
            self.ip_generator.stream_ips(base_ip, self.process_ip, Config.MAX_VALID_RNG)
            
            self.dashboard.add_log('INFO', f"Cycle #{cycle} completed. Waiting 60 seconds...")
            if not self.dashboard.paused:
                self.dashboard.render()
            
            # Countdown 60 detik
            for i in range(60, 0, -1):
                if not self.running:
                    break
                if i % 10 == 0 and not self.dashboard.paused:
                    self.dashboard.add_log('INFO', f"Next cycle in {i}s")
                    self.dashboard.render()
                time.sleep(1)
    
    def show_stats(self, quiet=False):
        """Tampilkan statistik detail"""
        if not quiet:
            print("\n" + "="*60)
            print("SYSTEM STATISTICS")
            print("="*60)
        
        cache_stats = self.cache_manager.get_stats()
        print(f"\n📦 Cache Database:")
        for table, count in cache_stats.items():
            print(f"  - {table}: {count} entries")
        
        if self.proxy_manager:
            self.proxy_manager.print_stats()
        
        print("\n📁 Output Files:")
        for name, filename in Config.OUTPUT_FILES.items():
            if os.path.exists(filename):
                size = os.path.getsize(filename) / 1024
                print(f"  - {filename}: {size:.2f} KB")
            elif os.path.exists(Config.TEMP_DIR + filename):
                size = os.path.getsize(Config.TEMP_DIR + filename) / 1024
                print(f"  - {filename} (temp): {size:.2f} KB")
        
        input("\nPress Enter to return to dashboard...")


# ============================================
# ENTRY POINT
# ============================================
def main():
    scanner = MovableTypeMassScanner()
    scanner.run()

if __name__ == "__main__":
    main()
