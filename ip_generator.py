# ip_generator.py
import random
import socket
import time
from queue import Queue
from threading import Thread
from config import Config

class IPGenerator:
    def __init__(self, cache_manager):
        self.cache_manager = cache_manager
        self.valid_ips = Queue()
        self.running = True
    
    def check_ip_valid(self, ip):
        """Cek validitas IP dengan timeout"""
        try:
            socket.gethostbyaddr(ip)
            return True
        except:
            return False
    
    def generate_ips(self, base_ip, max_valid=None):
        """Generate IP random secara streaming"""
        if max_valid is None:
            max_valid = Config.MAX_VALID_RNG
        
        base_parts = base_ip.split('.')
        if len(base_parts) != 4:
            print("[!] Invalid IP format!")
            return []
        
        base = '.'.join(base_parts[:3]) + '.'
        valid_count = 0
        attempted = set()
        
        print(f"[*] Generating {max_valid} valid IPs from {base}[1-254]...")
        
        # Generator pattern
        while valid_count < max_valid and len(attempted) < 254:
            last_octet = random.randint(1, 254)
            ip = base + str(last_octet)
            
            if ip in attempted:
                continue
                
            attempted.add(ip)
            
            # Cek validitas
            if self.check_ip_valid(ip):
                valid_count += 1
                yield ip
                print(f"[+] Valid IP: {ip} ({valid_count}/{max_valid})")
            
            # Small delay to prevent overwhelming
            if valid_count % 10 == 0:
                time.sleep(0.1)
        
        print(f"[*] Generated {valid_count} valid IPs")
    
    def stream_ips(self, base_ip, callback, max_valid=None):
        """Stream IP dan proses dengan callback"""
        for ip in self.generate_ips(base_ip, max_valid):
            # Cek cache dulu
            if not self.cache_manager.is_ip_processed(ip):
                callback(ip)
            else:
                print(f"[↺] Skipping cached IP: {ip}")