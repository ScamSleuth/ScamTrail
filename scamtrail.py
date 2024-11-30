import asyncio
import aiohttp
import aiodns
import whois
from urllib.parse import urlparse
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
import aiofiles
from bs4 import BeautifulSoup
import re
import tempfile
from textblob import TextBlob

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configuration
MAX_REDIRECTS = int(os.getenv('MAX_REDIRECTS', 10))
MAX_CONTENT_SIZE = int(os.getenv('MAX_CONTENT_SIZE', 1_000_000))  # 1 MB

class URLTracer:
    def __init__(self):
        self.session = None
        self.dns_resolver = None

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
        domain = parsed_url.netloc.split(':')[0].replace('www.', '')
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
            creation_date = min(creation_date)

        now = datetime.now(timezone.utc)

        # Ensure creation_date is timezone-aware
        if creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        delta = now - creation_date
        years, remaining_days = divmod(delta.days, 365)
        months, days = divmod(remaining_days, 30)

        return f"{years} years, {months} months, {days} days"

    async def get_ip_geolocation(self, ip_address: str) -> str:
        # Since we cannot use APIs that require API keys, we'll perform a basic WHOIS lookup on the IP
        try:
            result = await asyncio.to_thread(whois.whois, ip_address)
            country = result.get('country', 'Unknown')
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

    async def get_hosting_provider(self, ip_address: str) -> str:
        try:
            # Perform WHOIS lookup on the IP address
            whois_info = await asyncio.to_thread(whois.whois, ip_address)
            org = whois_info.get('org', 'Unknown')
            return org
        except Exception as e:
            logger.error(f"Hosting provider lookup failed for {ip_address}: {e}")
            return 'Unknown'

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

    async def get_dns_history(self, domain: str) -> List[Dict[str, Any]]:
        # Since we cannot use APIs that require API keys, this feature is limited
        # We can check for historical NS records if possible
        history = []
        # Placeholder for actual implementation
        logger.info(f"DNS history check not implemented for {domain} due to lack of openly available sources.")
        return history

class ReportGenerator:
    def __init__(self):
        self.env = Environment(loader=FileSystemLoader('templates'))
        self.template = self.env.get_template('report_template.html')

    async def generate_report(self, data: Dict[str, Any], output_file: str) -> None:
        html_content = self.template.render(data)

        # Use a temporary file
        with tempfile.NamedTemporaryFile('w', delete=False, suffix='.html') as tmp_file:
            temp_html_file = tmp_file.name
            async with aiofiles.open(temp_html_file, 'w') as f:
                await f.write(html_content)

        # Convert HTML to PDF using WeasyPrint
        HTML(temp_html_file).write_pdf(output_file)
        logger.info(f"Report saved to {output_file}")

        # Clean up temporary HTML file
        os.remove(temp_html_file)

async def analyze_single_url(url: str, tracer: URLTracer) -> Dict[str, Any]:
    url = URLTracer.ensure_scheme(url)
    redirects = await tracer.follow_redirects(url)
    final_url = redirects[-1]

    tasks = []
    for redirect in set(redirects):  # Use `set` to remove duplicates
        tasks.append(tracer.get_whois_info(redirect))
        tasks.append(tracer.get_dns_info(redirect))
        tasks.append(tracer.get_ip_address(redirect))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Deduplicate and prepare results
    unique_whois_infos = {}
    unique_dns_infos = {}
    unique_ip_addresses = set()

    for idx, redirect in enumerate(set(redirects)):
        if not isinstance(results[idx * 3], Exception):
            domain = URLTracer.extract_domain(redirect)
            unique_whois_infos[domain] = results[idx * 3]
        if not isinstance(results[idx * 3 + 1], Exception):
            domain = URLTracer.extract_domain(redirect)
            unique_dns_infos[domain] = results[idx * 3 + 1]
        if not isinstance(results[idx * 3 + 2], Exception):
            unique_ip_addresses.add(results[idx * 3 + 2])

    # Process results
    cloudflare_info = {}
    reverse_dns_info = {}
    ip_geolocations = {}
    hosting_providers = {}
    ssl_info = {}
    email_auth_records = {}
    dnssec_status = {}
    blacklist_checks = {}
    whois_privacy = {}
    server_vulnerabilities = []

    for ip in unique_ip_addresses:
        geolocation = await tracer.get_ip_geolocation(ip)
        ip_geolocations[ip] = geolocation
        hosting_provider = await tracer.get_hosting_provider(ip)
        hosting_providers[ip] = hosting_provider
        reverse_dns = await tracer.reverse_dns_lookup(ip)
        reverse_dns_info[ip] = reverse_dns if reverse_dns else []

    domain = URLTracer.extract_domain(final_url)
    uses_cloudflare = await tracer.is_cloudflare_domain(domain)
    ssl_info = await tracer.get_ssl_info(final_url)
    email_auth_records = await tracer.get_email_auth_records(domain)
    dnssec_status = await tracer.check_dnssec(domain)
    blacklist_checks = await tracer.check_blacklists(final_url)
    content_analysis = await tracer.analyze_content(final_url)
    whois_info = unique_whois_infos.get(domain, {})
    whois_privacy_detected = await tracer.detect_whois_privacy(whois_info)
    server_vulnerabilities = await tracer.check_server_vulnerabilities(content_analysis.get('server_software', ''))

    # Prepare data for report
    creation_date = whois_info.get('creation_date')
    domain_age = URLTracer.calculate_domain_age(creation_date)

    report_data = {
        'original_url': url,
        'redirects': redirects,
        'whois_infos': [{'domain': k, 'info': v} for k, v in unique_whois_infos.items()],
        'dns_infos': [{'domain': k, 'info': v} for k, v in unique_dns_infos.items()],
        'ip_addresses': list(unique_ip_addresses),
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
