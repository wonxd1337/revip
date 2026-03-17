# scanner.py
import requests
import re
import time
import socket
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from fake_useragent import UserAgent
from urllib3.exceptions import InsecureRequestWarning
from config import Confif

# Nonaktifkan warning SSL
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class MovableTypeScanner:
    def __init__(self, proxy_manager, cache_manager):
        self.ua = UserAgent()
        self.proxy_manager = proxy_manager
        self.cache_manager = cache_manager
        self.found_urls = set()
        self.lock = threading.Lock()
        
        # Headers
        self.headers = {
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "DNT": "1",
            "Connection": "close"
        }
        
        # Session untuk requests
        self.session = requests.Session()
        
        # Output files (di direktori utama)
        self.output_files = Config.OUTPUT_FILES
    
    def check_ip_valid(self, ip):
        """Cek IP valid"""
        try:
            socket.gethostbyaddr(ip)
            return True
        except:
            return False
    
    def reverse_ip_tntcode(self, ip):
        """Reverse IP via tntcode.com dengan proxy"""
        # Cek cache dulu
        cached = self.cache_manager.get_reverse_cache(f"{ip}_tnt")
        if cached:
            return cached
        
        proxy_dict = self.proxy_manager.get_proxy()
        proxy_used = list(proxy_dict.values())[0] if proxy_dict else None
        start_time = time.time()
        
        for attempt in range(Config.MAX_RETRIES):
            try:
                url = f"https://domains.tntcode.com/ip/{ip}"
                headers = self.headers.copy()
                headers["User-Agent"] = self.ua.random
                
                response = self.session.get(
                    url, headers=headers, proxies=proxy_dict,
                    timeout=Config.TIMEOUT_REVERSE, verify=False
                )
                
                response_time = time.time() - start_time
                
                if proxy_used:
                    self.proxy_manager.update_stats(proxy_used, True, response_time)
                
                domains = re.findall(r'<a href="/domain/(.+?)"', response.text)
                
                # Simpan ke cache
                if domains:
                    self.cache_manager.save_reverse_cache(f"{ip}_tnt", domains, 'tntcode')
                
                return domains
                
            except Exception as e:
                if proxy_used:
                    self.proxy_manager.update_stats(proxy_used, False)
                
                if attempt < Config.MAX_RETRIES - 1:
                    time.sleep(Config.RETRY_DELAY * (attempt + 1))
                    continue
        
        return []
    
    def reverse_ip_hackertarget(self, ip):
        """Reverse IP via hackertarget.com dengan proxy"""
        # Cek cache
        cached = self.cache_manager.get_reverse_cache(f"{ip}_ht")
        if cached:
            return cached
        
        proxy_dict = self.proxy_manager.get_proxy()
        proxy_used = list(proxy_dict.values())[0] if proxy_dict else None
        start_time = time.time()
        
        for attempt in range(Config.MAX_RETRIES):
            try:
                url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}"
                headers = self.headers.copy()
                headers["User-Agent"] = self.ua.random
                
                response = self.session.get(
                    url, headers=headers, proxies=proxy_dict,
                    timeout=Config.TIMEOUT_REVERSE, verify=False
                )
                
                response_time = time.time() - start_time
                
                if proxy_used:
                    self.proxy_manager.update_stats(proxy_used, True, response_time)
                
                if response.text and "error" not in response.text.lower():
                    domains = response.text.strip().split('\n')
                    
                    # Simpan ke cache
                    self.cache_manager.save_reverse_cache(f"{ip}_ht", domains, 'hackertarget')
                    
                    return domains
                return []
                
            except Exception as e:
                if proxy_used:
                    self.proxy_manager.update_stats(proxy_used, False)
                
                if attempt < Config.MAX_RETRIES - 1:
                    time.sleep(Config.RETRY_DELAY * (attempt + 1))
                    continue
        
        return []
    
    def check_rsd_xml(self, domain):
        """Cek rsd.xml tanpa proxy"""
        paths = ['/rsd.xml', '/blog/rsd.xml']
        
        for protocol in ['http', 'https']:
            for path in paths:
                try:
                    url = f"{protocol}://{domain}{path}"
                    headers = self.headers.copy()
                    headers["User-Agent"] = self.ua.random
                    
                    response = self.session.get(
                        url, headers=headers, 
                        timeout=Config.TIMEOUT_SCAN, 
                        verify=False,
                        allow_redirects=False
                    )
                    
                    if response.status_code == 200 and 'rsd' in response.text.lower():
                        return response.text, url
                except:
                    continue
        
        return None, None
    
    def extract_mt_info(self, rsd_content):
        """Ekstrak info Movable Type"""
        info = {'engine': None, 'api_link': None, 'version': None}
        
        engine_match = re.search(r'<engineName>(.+?)</engineName>', rsd_content, re.IGNORECASE)
        if engine_match:
            info['engine'] = engine_match.group(1)
            if 'movable type' in info['engine'].lower():
                version_match = re.search(r'(\d+\.\d+)', info['engine'])
                if version_match:
                    info['version'] = version_match.group(1)
        
        api_match = re.search(r'<api[^>]*apiLink="([^"]+)"[^>]*>', rsd_content, re.IGNORECASE)
        if api_match:
            info['api_link'] = api_match.group(1).strip()
            
        return info
    
    def check_mt_endpoints(self, domain, mt_info):
        """Cek endpoint Movable Type"""
        results = []
        
        if mt_info['api_link']:
            xmlrpc_urls = []
            
            if mt_info['api_link'].startswith('http'):
                xmlrpc_urls.append(mt_info['api_link'])
            else:
                xmlrpc_urls.append(f"http://{domain}{mt_info['api_link']}")
                xmlrpc_urls.append(f"https://{domain}{mt_info['api_link']}")
            
            for xmlrpc_url in xmlrpc_urls:
                try:
                    headers = self.headers.copy()
                    headers["User-Agent"] = self.ua.random
                    
                    response = self.session.get(
                        xmlrpc_url, headers=headers,
                        timeout=Config.TIMEOUT_SCAN,
                        allow_redirects=False,
                        verify=False
                    )
                    
                    is_v4 = mt_info.get('version') and mt_info['version'].startswith('4')
                    
                    if response.status_code in [403, 411, 405]:
                        url_key = f"{xmlrpc_url}|{response.status_code}"
                        with self.lock:
                            if url_key not in self.found_urls:
                                self.found_urls.add(url_key)
                                
                                # Simpan ke file
                                with open(self.output_files['movable_type'], 'a') as f:
                                    f.write(f"{xmlrpc_url}\n")
                                
                                display_url = xmlrpc_url.replace('http://', '').replace('https://', '')
                                print(f"[+] MT ditemukan: {display_url} ({response.status_code})")
                                
                                results.append({
                                    'domain': domain,
                                    'xmlrpc_url': xmlrpc_url,
                                    'xmlrpc_status': response.status_code,
                                    'version': mt_info.get('version'),
                                    'is_v4': is_v4
                                })
                    
                    # Cek mt-upgrade.cgi untuk v4
                    if is_v4 and 'mt-xmlrpc.cgi' in xmlrpc_url:
                        upgrade_url = xmlrpc_url.replace('mt-xmlrpc.cgi', 'mt-upgrade.cgi')
                        if upgrade_url != xmlrpc_url:
                            try:
                                upgrade_response = self.session.get(
                                    upgrade_url, headers=headers,
                                    timeout=Config.TIMEOUT_SCAN,
                                    allow_redirects=False,
                                    verify=False
                                )
                                
                                if upgrade_response.status_code == 200:
                                    upgrade_key = f"{upgrade_url}|200"
                                    with self.lock:
                                        if upgrade_key not in self.found_urls:
                                            self.found_urls.add(upgrade_key)
                                            
                                            with open(self.output_files['movable_type_v4'], 'a') as f:
                                                f.write(f"{upgrade_url}\n")
                                            
                                            display_upgrade = upgrade_url.replace('http://', '').replace('https://', '')
                                            print(f"[!] MT v4 upgrade.cgi: {display_upgrade}")
                            except:
                                pass
                                
                except:
                    continue
        
        return results
    
    def scan_domain(self, domain):
        """Scan satu domain"""
        try:
            rsd_content, rsd_url = self.check_rsd_xml(domain)
            
            if rsd_content:
                mt_info = self.extract_mt_info(rsd_content)
                
                if mt_info['engine'] and 'movable type' in mt_info['engine'].lower():
                    return self.check_mt_endpoints(domain, mt_info)
        except:
            pass
        return []
    
    def process_ip(self, ip):
        """Proses satu IP"""
        # Cek apakah IP sudah diproses
        if self.cache_manager.is_ip_processed(ip):
            print(f"[↺] Skipping IP {ip} (already processed)")
            return
        
        print(f"\n[*] Processing IP: {ip}")
        
        # Reverse IP dengan kedua sumber
        domains_tnt = self.reverse_ip_tntcode(ip)
        domains_ht = self.reverse_ip_hackertarget(ip)
        
        all_domains = list(set(domains_tnt + domains_ht))
        
        if all_domains:
            print(f"[+] Total domains: {len(all_domains)}")
            
            # Scan domains
            found_count = 0
            with ThreadPoolExecutor(max_workers=Config.MAX_THREADS_SCAN) as executor:
                futures = [executor.submit(self.scan_domain, domain) for domain in all_domains]
                for future in as_completed(futures):
                    results = future.result()
                    if results:
                        found_count += len(results)
            
            print(f"[+] IP {ip}: {found_count} MT found")
            
            # Tandai IP sudah diproses
            self.cache_manager.mark_ip_processed(ip, 'success' if found_count else 'empty')
        else:
            print(f"[-] No domains for IP {ip}")
            self.cache_manager.mark_ip_processed(ip, 'no_domains')
