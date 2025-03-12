import asyncio
import aiohttp
import aiodns
import whois  # Correct import statement
from urllib.parse import urlparse, urljoin
from datetime import datetime, timezone
from weasyprint import HTML
import socket
import ssl
import OpenSSL
import logging
from typing import List, Dict, Any, Optional, Union
import os
from dotenv import load_dotenv
from jinja2 import Environment, FileSystemLoader
from bs4 import BeautifulSoup
import re
from textblob import TextBlob
from ipwhois import IPWhois
import aiofiles
import json
from pathlib import Path

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
logger = logging.getLogger(__name__)

# Configuration
MAX_REDIRECTS = int(os.getenv('MAX_REDIRECTS', 10))
MAX_CONTENT_SIZE = int(os.getenv('MAX_CONTENT_SIZE', 1_000_000))  # 1 MB
DOWNLOAD_PATH = os.getenv('DOWNLOAD_PATH', 'downloaded_sites')
GITHUB_PAGES_PATH = os.getenv('GITHUB_PAGES_PATH', 'docs')

class URLTracer:
    def __init__(self):
        self.session = None
        self.dns_resolver = None
        self.visited_urls = set()
        self.download_path = Path(DOWNLOAD_PATH)
        self.github_pages_path = Path(GITHUB_PAGES_PATH)
        
        # Create necessary directories
        self.download_path.mkdir(parents=True, exist_ok=True)
        self.github_pages_path.mkdir(parents=True, exist_ok=True)

    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        self.dns_resolver = aiodns.DNSResolver()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()

    @staticmethod
    def ensure_scheme(url: str) -> str:
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            return f"https://{url}"
        return url

    @staticmethod
    def extract_domain(url: str) -> str:
        parsed_url = urlparse(url)
        if parsed_url.netloc:
            domain = parsed_url.netloc.split(':')[0].replace('www.', '')
        else:
            domain = parsed_url.path.split('/')[0].replace('www.', '')
        return domain

    async def follow_redirects(self, url: str) -> List[str]:
        redirects = [url]
        try:
            async with self.session.get(url, allow_redirects=True, max_redirects=MAX_REDIRECTS) as response:
                for history in response.history:
                    if str(history.url) != redirects[-1]:
                        redirects.append(str(history.url))
                if str(response.url) != redirects[-1]:
                    redirects.append(str(response.url))
        except aiohttp.ClientError as e:
            logger.error(f"Error following redirects for {url}: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error while following redirects for {url}: {e}")
        return redirects

    async def get_whois_info(self, url: str) -> Optional[Dict[str, Any]]:
        domain = self.extract_domain(url)
        try:
            whois_info = await asyncio.to_thread(whois.whois, domain)
            return whois_info
        except Exception as e:
            logger.error(f"WHOIS lookup failed for {domain}: {e}")
            return None

    async def get_dns_info(self, url: str) -> Dict[str, Any]:
        domain = self.extract_domain(url)
        dns_info = {'domain': domain, 'A': [], 'NS': [], 'CNAME': []}

        for record_type in ['A', 'NS', 'CNAME']:
            try:
                if record_type == 'CNAME':
                    result = await self.dns_resolver.query(domain, 'CNAME')
                    dns_info['CNAME'] = [{'target': result.cname}]
                else:
                    result = await self.dns_resolver.query(domain, record_type)
                    if record_type == 'A':
                        dns_info['A'] = [{'ip': r.host} for r in result]
                    elif record_type == 'NS':
                        dns_info['NS'] = [{'name': r.host} for r in result]
            except aiodns.error.DNSError as e:
                logger.warning(f"DNS lookup failed for {domain} ({record_type}): {e}")
            except Exception as e:
                logger.error(f"Unexpected error during DNS lookup for {domain} ({record_type}): {e}")

        return dns_info

    async def get_ip_address(self, url: str) -> Optional[str]:
        domain = self.extract_domain(url)
        try:
            ip_address = await asyncio.to_thread(socket.gethostbyname, domain)
            return ip_address
        except Exception as e:
            logger.error(f"IP lookup failed for {domain}: {e}")
            return None

    async def reverse_dns_lookup(self, ip_address: str) -> Optional[List[str]]:
        try:
            hostnames = await asyncio.to_thread(socket.gethostbyaddr, ip_address)
            return hostnames[1]
        except Exception as e:
            logger.error(f"Reverse DNS lookup failed for {ip_address}: {e}")
            return None

    @staticmethod
    def calculate_domain_age(creation_date: Optional[Union[datetime, List[datetime]]]) -> str:
        if not creation_date:
            return "Unknown"

        if isinstance(creation_date, list):
            # Filter out None values
            creation_date = [date for date in creation_date if date is not None]
            if not creation_date:
                return "Unknown"
            creation_date = min(creation_date)

        if not isinstance(creation_date, datetime):
            return "Unknown"

        now = datetime.now(timezone.utc)

        # Ensure creation_date is timezone-aware
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        delta = now - creation_date
        years, remaining_days = divmod(delta.days, 365)
        months, days = divmod(remaining_days, 30)

        return f"{years} years, {months} months, {days} days"

    async def get_ip_geolocation(self, ip_address: str) -> str:
        try:
            obj = IPWhois(ip_address)
            result = await asyncio.to_thread(obj.lookup_rdap)
            country = result.get('asn_country_code', 'Unknown')
            return country
        except Exception as e:
            logger.error(f"Geolocation lookup failed for {ip_address}: {e}")
            return "Unknown"

    async def is_cloudflare_domain(self, domain: str) -> bool:
        try:
            ns_records = await self.dns_resolver.query(domain, 'NS')
            cloudflare_ns_suffixes = ['cloudflare.com', '.cloudflare.com']
            for ns in ns_records:
                ns_text = ns.host.lower().rstrip('.')
                if any(ns_text.endswith(suffix) for suffix in cloudflare_ns_suffixes):
                    return True
            return False
        except aiodns.error.DNSError as e:
            logger.warning(f"DNS lookup failed for {domain} when checking Cloudflare usage: {e}")
            return False
        except Exception as e:
            logger.error(f"Error checking Cloudflare usage for {domain}: {e}")
            return False

    async def analyze_content(self, url: str) -> Dict[str, Any]:
        # Initialize indicators with default values
        indicators = {
            'password_field': False,
            'login_form': False,
            'suspicious_keywords': [],
            'external_links': 0,
            'images': 0,
            'scripts': 0,
            'language_analysis': {
                'sentiment': None,
                'subjectivity': None,
                'keywords': []
            },
            'server_software': 'Unknown',
        }
        try:
            async with self.session.get(url, allow_redirects=True, timeout=10) as response:
                headers = response.headers
                indicators['server_software'] = headers.get('Server', 'Unknown')
                if response.status == 200:
                    content = await response.text()
                    if len(content) > MAX_CONTENT_SIZE:
                        logger.warning(f"Content size exceeds limit for {url}")
                        return indicators
                    soup = BeautifulSoup(content, 'html.parser')

                    # Update indicators with actual values
                    indicators['password_field'] = bool(soup.find('input', {'type': 'password'}))
                    indicators['login_form'] = bool(soup.find('form'))
                    indicators['suspicious_keywords'] = self.check_suspicious_keywords(content)
                    indicators['external_links'] = len(soup.find_all('a', href=re.compile('^https?://')))
                    indicators['images'] = len(soup.find_all('img'))
                    indicators['scripts'] = len(soup.find_all('script'))
                    # Advanced content analysis using TextBlob
                    indicators['language_analysis'] = self.analyze_language(content)
                else:
                    logger.warning(f"Failed to fetch content from {url}. Status code: {response.status}")
                    return indicators
        except Exception as e:
            logger.exception(f"Error analyzing content for {url}: {e}")
        return indicators

    @staticmethod
    def check_suspicious_keywords(content: str) -> List[str]:
        suspicious_keywords = [
            'login', 'password', 'credit card', 'social security',
            'bank account', 'urgent', 'verify', 'suspended', 'limited time'
        ]
        return [keyword for keyword in suspicious_keywords if keyword.lower() in content.lower()]

    def analyze_language(self, content: str) -> Dict[str, Any]:
        analysis = {
            'sentiment': None,
            'subjectivity': None,
            'keywords': []
        }
        try:
            blob = TextBlob(content)
            analysis['sentiment'] = blob.sentiment.polarity
            analysis['subjectivity'] = blob.sentiment.subjectivity
            analysis['keywords'] = list(blob.noun_phrases)
        except Exception as e:
            logger.error(f"Language analysis failed: {e}")
        return analysis

    async def get_ssl_info(self, url: str) -> Dict[str, Any]:
        ssl_info = {}
        try:
            parsed_url = urlparse(url)
            hostname = parsed_url.hostname
            context = ssl.create_default_context()
            # Disable certificate verification
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.open_connection(hostname, 443, ssl=context)
            cert_bin = writer.get_extra_info('ssl_object').getpeercert(True)
            x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert_bin)
            ssl_info['issuer'] = dict(x509.get_issuer().get_components())
            ssl_info['subject'] = dict(x509.get_subject().get_components())
            ssl_info['notBefore'] = x509.get_notBefore().decode()
            ssl_info['notAfter'] = x509.get_notAfter().decode()
            ssl_info['serialNumber'] = x509.get_serial_number()
            ssl_info['version'] = x509.get_version()
        except Exception as e:
            logger.error(f"SSL info retrieval failed for {url}: {e}")
        return ssl_info

    async def detect_whois_privacy(self, whois_info: Dict[str, Any]) -> bool:
        privacy_keywords = ['Privacy', 'Protected', 'WhoisGuard', 'Contact Privacy', 'Domains By Proxy']
        registrant = whois_info.get('registrant_name', '') or ''
        if not registrant:
            registrant = whois_info.get('org', '') or ''
        return any(keyword.lower() in registrant.lower() for keyword in privacy_keywords)

    async def get_email_auth_records(self, domain: str) -> Dict[str, Any]:
        records = {'SPF': [], 'DMARC': []}
        try:
            # SPF Record
            try:
                txt_records = await self.dns_resolver.query(domain, 'TXT')
                spf_records = [r.text for r in txt_records if 'v=spf1' in r.text]
                records['SPF'] = spf_records
            except aiodns.error.DNSError as e:
                logger.warning(f"SPF record lookup failed for {domain}: {e}")

            # DMARC Record
            try:
                dmarc_domain = f"_dmarc.{domain}"
                dmarc_records = await self.dns_resolver.query(dmarc_domain, 'TXT')
                records['DMARC'] = [r.text for r in dmarc_records]
            except aiodns.error.DNSError as e:
                logger.warning(f"DMARC record lookup failed for {domain}: {e}")

            # DKIM is more complex because it requires knowing the selector
            records['DKIM'] = 'DKIM check not performed (selector unknown)'
        except Exception as e:
            logger.error(f"Email auth records lookup failed for {domain}: {e}")
        return records

    async def check_dnssec(self, domain: str) -> bool:
        try:
            result = await self.dns_resolver.query(domain, 'DNSKEY')
            return bool(result)
        except aiodns.error.DNSError:
            return False
        except Exception as e:
            logger.error(f"DNSSEC check failed for {domain}: {e}")
            return False

    async def check_blacklists(self, url: str) -> Dict[str, Any]:
        results = {}
        domain = self.extract_domain(url)
        try:
            # OpenPhish blacklist
            async with self.session.get('https://openphish.com/feed.txt') as response:
                if response.status == 200:
                    content = await response.text()
                    blacklist = content.splitlines()
                    results['OpenPhish'] = url in blacklist or domain in blacklist
                else:
                    logger.warning(f"Failed to fetch OpenPhish feed: {response.status}")
                    results['OpenPhish'] = False
        except Exception as e:
            logger.error(f"Blacklist check failed for {url}: {e}")
            results['OpenPhish'] = False
        return results

    async def check_server_vulnerabilities(self, server_header: str) -> List[str]:
        vulnerabilities = []
        try:
            # For demonstration, we'll check for outdated Apache versions
            if 'Apache' in server_header:
                version_match = re.search(r'Apache/([0-9\.]+)', server_header)
                if version_match:
                    version = version_match.group(1)
                    # Assume versions below 2.4.49 are vulnerable (example)
                    if float(version[:3]) < 2.4:
                        vulnerabilities.append(f"Apache version {version} is outdated and may have vulnerabilities.")
        except Exception as e:
            logger.error(f"Server vulnerability check failed: {e}")
        return vulnerabilities

    async def get_hosting_provider(self, ip_address: str) -> str:
        try:
            obj = IPWhois(ip_address)
            result = await asyncio.to_thread(obj.lookup_rdap)
            org = result.get('network', {}).get('name', 'Unknown')
            return org
        except Exception as e:
            logger.error(f"Hosting provider lookup failed for {ip_address}: {e}")
            return 'Unknown'

    async def get_dns_history(self, domain: str) -> List[Dict[str, Any]]:
        # Since we cannot use APIs that require API keys, this feature is limited
        # We can check for historical NS records if possible
        history = []
        # Placeholder for actual implementation
        logger.info(f"DNS history check not implemented for {domain} due to lack of openly available sources.")
        return history

    async def get_real_ip_behind_cloudflare(self, domain: str) -> Optional[str]:
        """Attempt to find the real IP address behind Cloudflare using multiple methods."""
        try:
            # Method 1: Check historical DNS records
            historical_ips = await self.check_historical_dns(domain)
            if historical_ips:
                return historical_ips[0]  # Return the most recent historical IP

            # Method 2: Check for common subdomains that might bypass Cloudflare
            subdomains = ['ftp', 'cpanel', 'webmail', 'mail', 'direct', 'direct-connect']
            for subdomain in subdomains:
                try:
                    subdomain_full = f"{subdomain}.{domain}"
                    result = await self.dns_resolver.query(subdomain_full, 'A')
                    if result:
                        return result[0].host
                except:
                    continue

            # Method 3: Check for SPF records which might reveal real IPs
            try:
                txt_records = await self.dns_resolver.query(domain, 'TXT')
                for record in txt_records:
                    if 'v=spf1' in record.text:
                        ip_matches = re.findall(r'ip4:(\d+\.\d+\.\d+\.\d+)', record.text)
                        if ip_matches:
                            return ip_matches[0]
            except:
                pass

            return None
        except Exception as e:
            logger.error(f"Error finding real IP behind Cloudflare for {domain}: {e}")
            return None

    async def check_historical_dns(self, domain: str) -> List[str]:
        """Check historical DNS records using various sources."""
        historical_ips = []
        
        # You might want to add API keys for these services in your .env file
        api_sources = [
            f"https://securitytrails.com/domain/{domain}/history/a",
            f"https://viewdns.info/iphistory/?domain={domain}",
            f"https://dns.google/resolve?name={domain}&type=A"
        ]

        for api_url in api_sources:
            try:
                async with self.session.get(api_url) as response:
                    if response.status == 200:
                        data = await response.text()
                        # Extract IPs from the response (implementation depends on the API response format)
                        ips = re.findall(r'\d+\.\d+\.\d+\.\d+', data)
                        historical_ips.extend(ips)
            except Exception as e:
                logger.warning(f"Failed to get historical DNS from {api_url}: {e}")

        return list(set(historical_ips))  # Remove duplicates

    async def crawl_and_download_site(self, url: str, max_depth: int = 3) -> Dict[str, Any]:
        """Crawl the website and download all accessible content."""
        base_url = url
        domain = self.extract_domain(url)
        domain_dir = self.download_path / domain
        domain_dir.mkdir(exist_ok=True)

        crawl_info = {
            'pages': [],
            'assets': [],
            'errors': []
        }

        async def download_asset(asset_url: str, asset_path: Path):
            try:
                async with self.session.get(asset_url) as response:
                    if response.status == 200:
                        async with aiofiles.open(asset_path, 'wb') as f:
                            await f.write(await response.read())
                        return True
            except Exception as e:
                logger.error(f"Failed to download asset {asset_url}: {e}")
                crawl_info['errors'].append(f"Asset download failed: {asset_url}")
                return False

        async def process_page(page_url: str, depth: int):
            if depth > max_depth or page_url in self.visited_urls:
                return

            self.visited_urls.add(page_url)
            try:
                async with self.session.get(page_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        soup = BeautifulSoup(content, 'html.parser')

                        # Create relative path for the page
                        page_path = domain_dir / f"{len(crawl_info['pages'])}.html"
                        
                        # Download assets (images, css, js, etc.)
                        for tag, attr in [('img', 'src'), ('link', 'href'), ('script', 'src')]:
                            for element in soup.find_all(tag):
                                if element.get(attr):
                                    asset_url = urljoin(page_url, element[attr])
                                    if asset_url.startswith(('http://', 'https://')):
                                        asset_filename = f"{len(crawl_info['assets'])}_{Path(asset_url).name}"
                                        asset_path = domain_dir / 'assets' / asset_filename
                                        asset_path.parent.mkdir(exist_ok=True)
                                        
                                        if await download_asset(asset_url, asset_path):
                                            # Update the element's source to the local path
                                            element[attr] = f'assets/{asset_filename}'
                                            crawl_info['assets'].append({
                                                'url': asset_url,
                                                'local_path': str(asset_path)
                                            })

                        # Save the modified HTML
                        async with aiofiles.open(page_path, 'w', encoding='utf-8') as f:
                            await f.write(str(soup))
                        
                        crawl_info['pages'].append({
                            'url': page_url,
                            'local_path': str(page_path),
                            'title': soup.title.string if soup.title else 'No title'
                        })

                        # Find and process links
                        if depth < max_depth:
                            for link in soup.find_all('a'):
                                href = link.get('href')
                                if href:
                                    next_url = urljoin(page_url, href)
                                    if next_url.startswith(base_url) and next_url not in self.visited_urls:
                                        await process_page(next_url, depth + 1)

            except Exception as e:
                logger.error(f"Failed to process page {page_url}: {e}")
                crawl_info['errors'].append(f"Page processing failed: {page_url}")

        # Start crawling from the base URL
        await process_page(url, 0)

        # Generate index.html for GitHub Pages
        await self.generate_github_pages(domain, crawl_info)
        
        return crawl_info

    async def generate_github_pages(self, domain: str, crawl_info: Dict[str, Any]):
        """Generate GitHub Pages website with the crawled content."""
        try:
            # Create domain directory in GitHub Pages path
            domain_pages_dir = self.github_pages_path / domain
            domain_pages_dir.mkdir(exist_ok=True)

            # Copy all downloaded content to GitHub Pages directory
            source_dir = self.download_path / domain
            if source_dir.exists():
                # Use robocopy on Windows or cp on Unix
                if os.name == 'nt':
                    os.system(f'robocopy "{source_dir}" "{domain_pages_dir}" /E')
                else:
                    os.system(f'cp -r "{source_dir}"/* "{domain_pages_dir}"/')

            # Generate index.html with links to all pages
            index_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Archived content of {domain}</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; }}
                    .container {{ max-width: 800px; margin: 0 auto; }}
                    .page-list {{ list-style: none; padding: 0; }}
                    .page-item {{ margin: 10px 0; padding: 10px; border: 1px solid #ddd; }}
                    .error-list {{ color: red; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Archived content of {domain}</h1>
                    <p>Archived on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                    
                    <h2>Pages:</h2>
                    <ul class="page-list">
                        {''.join(f'<li class="page-item"><a href="{page["local_path"]}">{page["title"]}</a></li>' for page in crawl_info['pages'])}
                    </ul>

                    <h2>Assets:</h2>
                    <ul>
                        {''.join(f'<li>{asset["url"]}</li>' for asset in crawl_info['assets'])}
                    </ul>

                    {'<h2>Errors:</h2><ul class="error-list">' + ''.join(f'<li>{error}</li>' for error in crawl_info['errors']) + '</ul>' if crawl_info['errors'] else ''}
                </div>
            </body>
            </html>
            """

            async with aiofiles.open(domain_pages_dir / 'index.html', 'w', encoding='utf-8') as f:
                await f.write(index_content)

            # Generate metadata file
            metadata = {
                'domain': domain,
                'archive_date': datetime.now().isoformat(),
                'pages_count': len(crawl_info['pages']),
                'assets_count': len(crawl_info['assets']),
                'errors_count': len(crawl_info['errors'])
            }

            async with aiofiles.open(domain_pages_dir / 'metadata.json', 'w', encoding='utf-8') as f:
                await f.write(json.dumps(metadata, indent=2))

        except Exception as e:
            logger.error(f"Failed to generate GitHub Pages for {domain}: {e}")

    async def analyze_url(self, url: str) -> Dict[str, Any]:
        """Main method to analyze a URL."""
        url = self.ensure_scheme(url)
        domain = self.extract_domain(url)
        
        analysis_results = {
            'url': url,
            'domain': domain,
            'redirects': [],
            'whois_info': None,
            'dns_info': None,
            'ip_info': {
                'address': None,
                'geolocation': None,
                'reverse_dns': None,
                'real_ip': None  # For Cloudflare-protected sites
            },
            'domain_age': None,
            'cloudflare_protected': False,
            'content_analysis': None,
            'ssl_info': None,
            'crawl_info': None
        }

        try:
            # Follow redirects
            analysis_results['redirects'] = await self.follow_redirects(url)
            final_url = analysis_results['redirects'][-1] if analysis_results['redirects'] else url

            # Get WHOIS information
            whois_info = await self.get_whois_info(final_url)
            analysis_results['whois_info'] = whois_info
            if whois_info and whois_info.creation_date:
                analysis_results['domain_age'] = self.calculate_domain_age(whois_info.creation_date)

            # Get DNS information
            analysis_results['dns_info'] = await self.get_dns_info(final_url)

            # Check if site is behind Cloudflare
            analysis_results['cloudflare_protected'] = await self.is_cloudflare_domain(domain)

            # Get IP information
            ip_address = await self.get_ip_address(final_url)
            if ip_address:
                analysis_results['ip_info']['address'] = ip_address
                analysis_results['ip_info']['geolocation'] = await self.get_ip_geolocation(ip_address)
                analysis_results['ip_info']['reverse_dns'] = await self.reverse_dns_lookup(ip_address)

                # If behind Cloudflare, try to find real IP
                if analysis_results['cloudflare_protected']:
                    real_ip = await self.get_real_ip_behind_cloudflare(domain)
                    if real_ip:
                        analysis_results['ip_info']['real_ip'] = real_ip
                        # Get additional information about the real IP
                        analysis_results['ip_info']['real_ip_info'] = {
                            'geolocation': await self.get_ip_geolocation(real_ip),
                            'reverse_dns': await self.reverse_dns_lookup(real_ip)
                        }

            # Analyze content
            analysis_results['content_analysis'] = await self.analyze_content(final_url)

            # Get SSL certificate information
            analysis_results['ssl_info'] = await self.get_ssl_info(final_url)

            # Crawl and download the site
            analysis_results['crawl_info'] = await self.crawl_and_download_site(final_url)

        except Exception as e:
            logger.error(f"Error during URL analysis: {e}")
            analysis_results['error'] = str(e)

        return analysis_results

    async def batch_analyze(self, urls: List[str]) -> List[Dict[str, Any]]:
        """Analyze multiple URLs in parallel."""
        tasks = [self.analyze_url(url) for url in urls]
        return await asyncio.gather(*tasks)

class ReportGenerator:
    def __init__(self):
        self.env = Environment(loader=FileSystemLoader('templates'))
        self.template = self.env.get_template('report_template.html')

    async def generate_report(self, data: Dict[str, Any], output_file: str) -> None:
        try:
            html_content = self.template.render(data)
            # Generate PDF directly from the HTML content string
            HTML(string=html_content).write_pdf(output_file)
            logger.info(f"Report saved to {output_file}")
        except Exception as e:
            logger.error(f"Report generation failed: {e}")

async def analyze_single_url(url: str, tracer: URLTracer) -> Dict[str, Any]:
    url = URLTracer.ensure_scheme(url)
    original_url = url  # Keep the URL after ensuring the scheme
    redirects = await tracer.follow_redirects(url)
    final_url = redirects[-1]

    tasks = []
    redirects_set = list(set(redirects))
    for redirect in redirects_set:
        tasks.append(tracer.get_whois_info(redirect))
        tasks.append(tracer.get_dns_info(redirect))
        tasks.append(tracer.get_ip_address(redirect))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Deduplicate and prepare results
    unique_whois_infos = {}
    unique_dns_infos = {}
    unique_ip_addresses = []

    for idx, redirect in enumerate(redirects_set):
        if not isinstance(results[idx * 3], Exception) and results[idx * 3] is not None:
            domain = URLTracer.extract_domain(redirect)
            unique_whois_infos[domain] = results[idx * 3]
        if not isinstance(results[idx * 3 + 1], Exception) and results[idx * 3 + 1] is not None:
            domain = URLTracer.extract_domain(redirect)
            unique_dns_infos[domain] = results[idx * 3 + 1]
        if not isinstance(results[idx * 3 + 2], Exception) and results[idx * 3 + 2] is not None:
            ip_address = results[idx * 3 + 2]
            if ip_address not in unique_ip_addresses:
                unique_ip_addresses.append(ip_address)

    # Process results
    reverse_dns_info = {}
    ip_geolocations = {}
    hosting_providers = {}
    ssl_info = {}
    email_auth_records = {}
    blacklist_checks = {}
    server_vulnerabilities = []

    tasks = []
    ip_list = unique_ip_addresses
    for ip in ip_list:
        tasks.append(tracer.get_ip_geolocation(ip))
        tasks.append(tracer.get_hosting_provider(ip))
        tasks.append(tracer.reverse_dns_lookup(ip))

    ip_results = await asyncio.gather(*tasks, return_exceptions=True)

    for idx, ip in enumerate(ip_list):
        geolocation = ip_results[idx * 3]
        hosting_provider = ip_results[idx * 3 + 1]
        reverse_dns = ip_results[idx * 3 + 2]
        ip_geolocations[ip] = geolocation if not isinstance(geolocation, Exception) else "Unknown"
        hosting_providers[ip] = hosting_provider if not isinstance(hosting_provider, Exception) else "Unknown"
        reverse_dns_info[ip] = reverse_dns if reverse_dns else []

    domain = URLTracer.extract_domain(final_url)
    uses_cloudflare = await tracer.is_cloudflare_domain(domain)
    ssl_info = await tracer.get_ssl_info(final_url)
    email_auth_records = await tracer.get_email_auth_records(domain)
    dnssec_status = await tracer.check_dnssec(domain)
    blacklist_checks = await tracer.check_blacklists(final_url)
    content_analysis = await tracer.analyze_content(final_url)
    whois_info = unique_whois_infos.get(domain, {})
    whois_privacy_detected = await tracer.detect_whois_privacy(whois_info) if whois_info else False
    server_vulnerabilities = await tracer.check_server_vulnerabilities(content_analysis.get('server_software', ''))

    # Prepare data for report
    creation_date = whois_info.get('creation_date') if whois_info else None
    domain_age = URLTracer.calculate_domain_age(creation_date)

    report_data = {
        'original_url': url,
        'redirects': redirects,
        'whois_infos': [{'domain': k, 'info': v} for k, v in unique_whois_infos.items()],
        'dns_infos': [{'domain': k, 'info': v} for k, v in unique_dns_infos.items()],
        'ip_addresses': unique_ip_addresses,
        'final_url': final_url,
        'cloudflare_info': uses_cloudflare,
        'reverse_dns_info': reverse_dns_info,
        'ip_geolocations': ip_geolocations,
        'hosting_providers': hosting_providers,
        'ssl_info': ssl_info,
        'email_auth_records': email_auth_records,
        'dnssec_status': dnssec_status,
        'blacklist_checks': blacklist_checks,
        'whois_privacy_detected': whois_privacy_detected,
        'timestamp': datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'domain_age': domain_age,
        'uses_cloudflare': uses_cloudflare,
        'content_analysis': content_analysis,
        'server_vulnerabilities': server_vulnerabilities,
    }

    return report_data

async def main():
    print("Welcome to the enhanced ScamTrail script!")
    print("1. Analyze a single URL")
    print("2. Perform bulk analysis")
    choice = input("Enter your choice (1 or 2): ").strip()

    async with URLTracer() as tracer:
        if choice == '1':
            url = input("Enter the URL to trace: ").strip()
            report_data = await analyze_single_url(url, tracer)

            # Generate report
            report_generator = ReportGenerator()
            output_file = f"scamtrail_report_{URLTracer.extract_domain(url)}.pdf"
            await report_generator.generate_report(report_data, output_file)

            # Print out the key information
            print(f"\nAnalysis Results for {url}:")
            print(f"Report saved to: {output_file}")
            print(f"Final Destination: {report_data['final_url']}")
            print(f"Number of Redirects: {len(report_data['redirects']) - 1}")
            print(f"Domain age: {report_data['domain_age']}")

            final_ip = report_data['ip_addresses'][-1] if report_data['ip_addresses'] else None
            if final_ip and final_ip in report_data['ip_geolocations']:
                print(f"Geographical location: {report_data['ip_geolocations'][final_ip]}")
            else:
                print("Unable to determine the geographical location.")

            print(f"Hosting Provider: {report_data['hosting_providers'].get(final_ip, 'Unknown')}")

            print(f"Uses CloudFlare: {'Yes' if report_data['uses_cloudflare'] else 'No'}")
            print(f"DNSSEC Enabled: {'Yes' if report_data['dnssec_status'] else 'No'}")
            print(f"WHOIS Privacy Detected: {'Yes' if report_data['whois_privacy_detected'] else 'No'}")
            print(f"Blacklisted by OpenPhish: {'Yes' if report_data['blacklist_checks'].get('OpenPhish') else 'No'}")

            print("\nContent Analysis:")
            for key, value in report_data['content_analysis'].items():
                if key == 'suspicious_keywords':
                    print(f"- Suspicious Keywords: {', '.join(value) if value else 'None found'}")
                elif key == 'language_analysis':
                    if value['sentiment'] is not None and value['subjectivity'] is not None:
                        print(f"- Sentiment Polarity: {value.get('sentiment')}")
                        print(f"- Subjectivity: {value.get('subjectivity')}")
                        print(f"- Extracted Keywords: {', '.join(value.get('keywords', []))}")
                    else:
                        print("- Language Analysis: Not available.")
                else:
                    print(f"- {key.replace('_', ' ').title()}: {value}")

            if report_data['server_vulnerabilities']:
                print("\nServer Vulnerabilities Detected:")
                for vulnerability in report_data['server_vulnerabilities']:
                    print(f"- {vulnerability}")
            else:
                print("\nNo server vulnerabilities detected based on available data.")

        elif choice == '2':
            urls = []
            print("Enter URLs for bulk analysis (one per line, enter a blank line to finish):")
            while True:
                url = input().strip()
                if not url:
                    break
                urls.append(url)

            report_generator = ReportGenerator()
            for url in urls:
                report_data = await analyze_single_url(url, tracer)
                output_file = f"scamtrail_report_{URLTracer.extract_domain(url)}.pdf"
                await report_generator.generate_report(report_data, output_file)
                print(f"Analysis completed for {url}. Report saved to {output_file}")

            print(f"\nBulk analysis completed. Individual reports have been generated for each URL.")

        else:
            print("Invalid choice. Please run the script again and choose 1 or 2.")

if __name__ == "__main__":
    asyncio.run(main())
