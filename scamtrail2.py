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
from bs4 import BeautifulSoup
import re
from textblob import TextBlob
from ipwhois import IPWhois
import ipaddress
import hashlib

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s:%(name)s:%(message)s')
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
            }
        
    async def extract_ioc(self, data: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Extraheert Indicators of Compromise (IOCs) uit de geanalyseerde data.
        """
        iocs = {
            'domains': [],
            'ips': [],
            'urls': [],
            'emails': []
        }
        
        # Domeinen
        for redirect in data.get('redirects', []):
            domain = self.extract_domain(redirect)
            if domain and domain not in iocs['domains']:
                iocs['domains'].append(domain)
        
        # IPs
        for ip in data.get('ip_addresses', []):
            if ip and ip not in iocs['ips']:
                iocs['ips'].append(ip)
        
        # URLs
        for redirect in data.get('redirects', []):
            if redirect and redirect not in iocs['urls']:
                iocs['urls'].append(redirect)
        
        # E-mails
        whois_infos = data.get('whois_infos', [])
        for whois_item in whois_infos:
            info = whois_item.get('info', {})
            emails = []
            
            # Extract emails from various WHOIS fields
            for field in ['emails', 'email', 'registrant_email', 'admin_email', 'tech_email']:
                if field in info:
                    email_value = info[field]
                    if isinstance(email_value, list):
                        emails.extend(email_value)
                    elif isinstance(email_value, str):
                        emails.append(email_value)
            
            # Filter and add valid emails
            email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
            for email in emails:
                if email and re.match(email_pattern, email) and email not in iocs['emails']:
                    iocs['emails'].append(email)
        
        return iocs
        
    async def detect_cloaking(self, url: str) -> Dict[str, Any]:
        """
        Detecteert cloaking technieken die scammers vaak gebruiken om detectie te vermijden.
        """
        result = {
            'cloaking_detected': False,
            'techniques': [],
            'details': {}
        }
        
        try:
            # Test 1: Verschillende user-agents
            headers_normal = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36'
            }
            
            headers_bot = {
                'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)'
            }
            
            # Fetch met normale browser user-agent
            async with self.session.get(url, headers=headers_normal) as normal_response:
                normal_content = await normal_response.text()
                normal_status = normal_response.status
            
            # Fetch met bot user-agent
            async with self.session.get(url, headers=headers_bot) as bot_response:
                bot_content = await bot_response.text()
                bot_status = bot_response.status
            
            # Vergelijk resultaten
            if normal_status != bot_status:
                result['cloaking_detected'] = True
                result['techniques'].append('Verschillende HTTP statuscodes voor verschillende user-agents')
                result['details']['status_normal'] = normal_status
                result['details']['status_bot'] = bot_status
            
            # Vergelijk contentlengte en checksum
            normal_hash = hashlib.md5(normal_content.encode()).hexdigest()
            bot_hash = hashlib.md5(bot_content.encode()).hexdigest()
            
            if abs(len(normal_content) - len(bot_content)) > 5000:  # Grote verschillen
                result['cloaking_detected'] = True
                result['techniques'].append('Significant verschil in contentlengte voor verschillende user-agents')
                result['details']['content_length_diff'] = abs(len(normal_content) - len(bot_content))
            
            if normal_hash != bot_hash:
                # Verder onderzoek naar de verschillen
                # Analyseer verdwenen of toegevoegde formulieren
                normal_soup = BeautifulSoup(normal_content, 'html.parser')
                bot_soup = BeautifulSoup(bot_content, 'html.parser')
                
                normal_forms = normal_soup.find_all('form')
                bot_forms = bot_soup.find_all('form')
                
                if len(normal_forms) != len(bot_forms):
                    result['cloaking_detected'] = True
                    result['techniques'].append('Formulieren worden verborgen voor bots')
                    result['details']['forms_normal'] = len(normal_forms)
                    result['details']['forms_bot'] = len(bot_forms)
            
            # Test 2: IP-gebaseerde cloaking (moeilijker te detecteren)
            # Dit zou proxies vereisen om adequaat te testen
            
            # Test 3: JavaScript-gebaseerde cloaking (partial detection)
            js_pattern = r'navigator\.userAgent|document\.referrer'
            if re.search(js_pattern, normal_content):
                result['techniques'].append('Mogelijke JS user-agent detectie gevonden')
                result['details']['js_ua_check'] = True
            
            # Geolocation cloaking check
            geo_pattern = r'geoip|geolocation|country_code'
            if re.search(geo_pattern, normal_content, re.IGNORECASE):
                result['techniques'].append('Mogelijke geografische filtering gevonden')
                result['details']['geo_check'] = True
        
        except Exception as e:
            logger.error(f"Fout bij cloaking detectie voor {url}: {e}")
        
        return result
        
    async def generate_reporting_templates(self, domain: str, data: Dict[str, Any]) -> Dict[str, str]:
        """
        Genereert sjablonen voor het melden van de scam bij verschillende instanties.
        """
        templates = {}
        
        # Basisinformatie
        scam_url = data.get('original_url', '')
        final_url = data.get('final_url', '')
        
        # Haal IOCs op
        iocs = await self.extract_ioc(data)
        
        # Threat score berekening
        threat_assessment = await self.calculate_threat_score(data)
        
        # 1. Sjabloon voor registrar
        whois_infos = data.get('whois_infos', [])
        registrar = None
        
        for whois_item in whois_infos:
            info = whois_item.get('info', {})
            if info and 'registrar' in info:
                registrar = info['registrar']
                break
        
        if registrar:
            templates['registrar'] = f"""
Onderwerp: Rapport van frauduleuze website: {domain}

Geachte {registrar},

Ik wil een frauduleuze website melden die geregistreerd is via uw dienst:

Domein: {domain}
URL: {scam_url}
Waargenomen op: {data.get('timestamp', 'recent')}

Dreigingsscore: {threat_assessment.get('score')}/{threat_assessment.get('max_score')} ({threat_assessment.get('risk_level')})
Redenen voor dit rapport:
{chr(10).join('- ' + reason for reason in threat_assessment.get('reasons', []))}

Deze website vertoont sterke indicaties van frauduleuze activiteit en vormt een risico voor uw klanten. Ik verzoek u vriendelijk om dit domein te onderzoeken en passende maatregelen te nemen in overeenstemming met uw beleid voor acceptabel gebruik.

Gerelateerde IOCs:
- Domeinen: {', '.join(iocs.get('domains', []))}
- IP-adressen: {', '.join(iocs.get('ips', []))}

Met vriendelijke groet,
[Uw naam]
"""
        
        # 2. Sjabloon voor CloudFlare
        if data.get('uses_cloudflare', False):
            templates['cloudflare'] = f"""
Onderwerp: Abuse Report - Phishing/Scam Website Behind Cloudflare: {domain}

Beste Cloudflare Trust & Safety Team,

Ik wil een frauduleuze website melden die momenteel wordt beschermd door Cloudflare:

Domein: {domain}
URL: {scam_url}
Waargenomen op: {data.get('timestamp', 'recent')}

Dreigingsscore: {threat_assessment.get('score')}/{threat_assessment.get('max_score')} ({threat_assessment.get('risk_level')})
Redenen voor dit rapport:
{chr(10).join('- ' + reason for reason in threat_assessment.get('reasons', []))}

Deze site overtreedt uw acceptabel gebruiksbeleid met betrekking tot frauduleuze content. De site probeert gebruikers te misleiden om [korte beschrijving van de scam].

Gerelateerde IOCs:
- Domeinen: {', '.join(iocs.get('domains', []))}
- IP-adressen: {', '.join(iocs.get('ips', []))}

Met vriendelijke groet,
[Uw naam]
"""
        
        # 3. Sjabloon voor hoster
        ip_addresses = data.get('ip_addresses', [])
        hosting_providers = data.get('hosting_providers', {})
        
        if ip_addresses and hosting_providers:
            primary_ip = ip_addresses[0]
            hoster = hosting_providers.get(primary_ip, 'Unknown')
            
            if hoster != 'Unknown':
                templates['hoster'] = f"""
Onderwerp: Abuse Report - Fraudulent Website: {domain}

Beste {hoster} Abuse Team,

Ik wil een frauduleuze website melden die wordt gehost op uw infrastructuur:

Domein: {domain}
URL: {scam_url}
IP-adres: {primary_ip}
Waargenomen op: {data.get('timestamp', 'recent')}

Dreigingsscore: {threat_assessment.get('score')}/{threat_assessment.get('max_score')} ({threat_assessment.get('risk_level')})
Redenen voor dit rapport:
{chr(10).join('- ' + reason for reason in threat_assessment.get('reasons', []))}

Deze site overtreedt uw acceptabel gebruiksbeleid met betrekking tot frauduleuze content. De site probeert gebruikers te misleiden om [korte beschrijving van de scam].

Gerelateerde IOCs:
- Domeinen: {', '.join(iocs.get('domains', []))}
- IP-adressen: {', '.join(iocs.get('ips', []))}

Met vriendelijke groet,
[Uw naam]
"""
        
        # 4. Sjabloon voor Google Safe Browsing
        templates['google_safebrowsing'] = f"""
Onderwerp: Phishing/Malicious Website Report: {domain}

Beste Google Safe Browsing Team,

Ik wil de volgende URL melden als een frauduleuze/phishing site:

URL: {scam_url}
Eindbestemming: {final_url}
Waargenomen op: {data.get('timestamp', 'recent')}

Dreigingsscore: {threat_assessment.get('score')}/{threat_assessment.get('max_score')} ({threat_assessment.get('risk_level')})
Redenen voor deze melding:
{chr(10).join('- ' + reason for reason in threat_assessment.get('reasons', []))}

Deze site lijkt een phishing/scam website te zijn die probeert gebruikers te misleiden. Zou u deze URL kunnen toevoegen aan uw Safe Browsing database om gebruikers te beschermen?

Met vriendelijke groet,
[Uw naam]
"""
        
        return templates


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
    """
    Voert een volledige analyse uit van een URL en geeft een uitgebreid rapport terug.
    """
    url = URLTracer.ensure_scheme(url)
    original_url = url  # Bewaar de URL na het toevoegen van het schema
    redirects = await tracer.follow_redirects(url)
    final_url = redirects[-1]

    # Basis analyse-taken
    tasks = []
    redirects_set = list(set(redirects))
    for redirect in redirects_set:
        tasks.append(tracer.get_whois_info(redirect))
        tasks.append(tracer.get_dns_info(redirect))
        tasks.append(tracer.get_ip_address(redirect))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Ontdubbel en bereid resultaten voor
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

    # Verwerk resultaten
    reverse_dns_info = {}
    ip_geolocations = {}
    hosting_providers = {}
    ssl_info = {}
    email_auth_records = {}
    blacklist_checks = {}
    server_vulnerabilities = []

    # IP gerelateerde taken
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

    # Domein en URL gerelateerde checks
    domain = URLTracer.extract_domain(final_url)
    
    # Basis domein analyse
    uses_cloudflare = await tracer.is_cloudflare_domain(domain)
    ssl_info = await tracer.get_ssl_info(final_url)
    email_auth_records = await tracer.get_email_auth_records(domain)
    dnssec_status = await tracer.check_dnssec(domain)
    content_analysis = await tracer.analyze_content(final_url)
    whois_info = unique_whois_infos.get(domain, {})
    whois_privacy_detected = await tracer.detect_whois_privacy(whois_info) if whois_info else False
    server_vulnerabilities = await tracer.check_server_vulnerabilities(content_analysis.get('server_software', ''))

    # Nieuwe analyses
    cloudflare_bypass_result = None
    if uses_cloudflare:
        cloudflare_bypass_result = await tracer.bypass_cloudflare(domain)
    
    # Technologie fingerprinting
    tech_fingerprint = await tracer.get_technology_fingerprint(final_url)
    
    # Scam/phishing databases
    blacklist_checks = await tracer.check_known_scam_databases(final_url)
    
    # Cloaking detectie
    cloaking_info = await tracer.detect_cloaking(final_url)

    # Bereid data voor rapport voor
    creation_date = whois_info.get('creation_date') if whois_info else None
    domain_age = URLTracer.calculate_domain_age(creation_date)

    # Bereken threat score
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
        # Voeg nieuwe velden toe
        'cloudflare_bypass_result': cloudflare_bypass_result,
        'technology_fingerprint': tech_fingerprint,
        'cloaking_detection': cloaking_info
    }
    
    # Bereken threat score en IoCs
    report_data['threat_assessment'] = await tracer.calculate_threat_score(report_data)
    report_data['indicators_of_compromise'] = await tracer.extract_ioc(report_data)
    
    # Genereer rapportage templates
    report_data['reporting_templates'] = await tracer.generate_reporting_templates(domain, report_data)
    
    return report_data


async def main():
    print("Welkom bij de verbeterde ScamTrail Tool!")
    print("1. Analyseer een enkele URL")
    print("2. Voer een bulk-analyse uit")
    choice = input("Maak je keuze (1 of 2): ").strip()

    async with URLTracer() as tracer:
        if choice == '1':
            url = input("Voer de URL in die je wilt analyseren: ").strip()
            print(f"Analyse van {url} wordt gestart...")
            
            report_data = await analyze_single_url(url, tracer)

            # Genereer rapport
            report_generator = ReportGenerator()
            output_file = f"scamtrail_report_{URLTracer.extract_domain(url)}.pdf"
            await report_generator.generate_report(report_data, output_file)

            # Print de belangrijkste informatie
            print(f"\n=== Analyse resultaten voor {url} ===")
            print(f"Rapport opgeslagen in: {output_file}")
            print(f"Eindbestemming: {report_data['final_url']}")
            print(f"Aantal redirects: {len(report_data['redirects']) - 1}")
            print(f"Domeinleeftijd: {report_data['domain_age']}")

            # Threat assessment
            threat = report_data.get('threat_assessment', {})
            print(f"\n=== Dreigingsbeoordeling ===")
            print(f"Score: {threat.get('score', 'N/A')}/{threat.get('max_score', 100)} - {threat.get('risk_level', 'Onbekend')}")
            if 'reasons' in threat and threat['reasons']:
                print("Redenen:")
                for reason in threat['reasons']:
                    print(f"- {reason}")

            # IP en hosting informatie
            print(f"\n=== IP & Hosting Informatie ===")
            final_ip = report_data['ip_addresses'][-1] if report_data['ip_addresses'] else None
            if final_ip:
                print(f"Primair IP-adres: {final_ip}")
                if final_ip in report_data['ip_geolocations']:
                    print(f"Geografische locatie: {report_data['ip_geolocations'][final_ip]}")
                print(f"Hosting Provider: {report_data['hosting_providers'].get(final_ip, 'Onbekend')}")
            else:
                print("Geen IP-adres gevonden.")

            # CloudFlare bypass resultaten
            if report_data.get('uses_cloudflare', False):
                print(f"\n=== CloudFlare Bescherming ===")
                print(f"De website gebruikt CloudFlare: Ja")
                
                bypass_result = report_data.get('cloudflare_bypass_result', {})
                if bypass_result and bypass_result.get('success', False):
                    print(f"CloudFlare Bypass Succesvol: Ja")
                    print(f"Methode: {bypass_result.get('bypass_method', 'Onbekend')}")
                    print(f"Origineel IP: {bypass_result.get('origin_ip', 'Onbekend')}")
                    print(f"Originele hosting provider: {bypass_result.get('origin_hosting', 'Onbekend')}")
                else:
                    print("CloudFlare Bypass: Mislukt - Kon geen origin server identificeren")
            
            # Technologie fingerprint
            tech = report_data.get('technology_fingerprint', {})
            if tech:
                print(f"\n=== Technologie Profiel ===")
                print(f"CMS: {tech.get('cms', 'Onbekend')}")
                print(f"Server: {tech.get('server', 'Onbekend')}")
                if tech.get('js_frameworks'):
                    print(f"JS Frameworks: {', '.join(tech.get('js_frameworks', []))}")
                if tech.get('analytics'):
                    print(f"Analytics: {', '.join(tech.get('analytics', []))}")
                if tech.get('payment_systems'):
                    print(f"Betaalsystemen: {', '.join(tech.get('payment_systems', []))}")
            
            # Cloaking detectie
            cloaking = report_data.get('cloaking_detection', {})
            if cloaking and cloaking.get('cloaking_detected', False):
                print(f"\n=== Cloaking Gedetecteerd ===")
                print(f"Gedetecteerde technieken:")
                for technique in cloaking.get('techniques', []):
                    print(f"- {technique}")
            
            # Security checks
            print(f"\n=== Security Checks ===")
            print(f"CloudFlare Gebruikt: {'Ja' if report_data.get('uses_cloudflare', False) else 'Nee'}")
            print(f"DNSSEC Ingeschakeld: {'Ja' if report_data.get('dnssec_status', False) else 'Nee'}")
            print(f"WHOIS Privacy Gedetecteerd: {'Ja' if report_data.get('whois_privacy_detected', False) else 'Nee'}")
            
            blacklist = report_data.get('blacklist_checks', {})
            print(f"OpenPhish Blacklist: {'Ja' if blacklist.get('OpenPhish', False) else 'Nee'}")
            print(f"PhishTank Blacklist: {'Ja' if blacklist.get('PhishTank', False) else 'Nee'}")

            # Content analyse
            print(f"\n=== Content Analyse ===")
            content = report_data.get('content_analysis', {})
            for key, value in content.items():
                if key == 'suspicious_keywords':
                    print(f"- Verdachte keywords: {', '.join(value) if value else 'Geen gevonden'}")
                elif key == 'language_analysis':
                    if value.get('sentiment') is not None and value.get('subjectivity') is not None:
                        print(f"- Sentiment polariteit: {value.get('sentiment', 'N/A')}")
                        print(f"- Subjectiviteit: {value.get('subjectivity', 'N/A')}")
                    else:
                        print("- Taalanalyse: Niet beschikbaar.")
                else:
                    print(f"- {key.replace('_', ' ').title()}: {value}")

            # Server kwetsbaarheden
            if report_data.get('server_vulnerabilities'):
                print("\n=== Server Kwetsbaarheden ===")
                for vuln in report_data.get('server_vulnerabilities', []):
                    print(f"- {vuln}")

            # E-mail beveiliging
            email_auth = report_data.get('email_auth_records', {})
            print(f"\n=== E-mail Beveiliging ===")
            print(f"SPF Records: {'Ja' if email_auth.get('SPF') else 'Nee'}")
            print(f"DMARC Records: {'Ja' if email_auth.get('DMARC') else 'Nee'}")
            
            # Rapport templates
            print(f"\n=== Rapport Templates ===")
            templates = report_data.get('reporting_templates', {})
            if templates:
                print(f"Beschikbare templates:")
                for template_name in templates.keys():
                    print(f"- {template_name}")
                
                # Vraag of gebruiker een specifieke template wil zien
                template_choice = input("\nWelke template wil je bekijken? (of druk Enter om door te gaan): ").strip().lower()
                if template_choice and template_choice in templates:
                    print(f"\n{templates[template_choice]}")

        elif choice == '2':
            urls = []
            print("Voer URLs in voor bulk-analyse (één per regel, voer een lege regel in om te eindigen):")
            while True:
                url = input().strip()
                if not url:
                    break
                urls.append(url)

            report_generator = ReportGenerator()
            for url in urls:
                print(f"Analyse van {url} wordt gestart...")
                report_data = await analyze_single_url(url, tracer)
                output_file = f"scamtrail_report_{URLTracer.extract_domain(url)}.pdf"
                await report_generator.generate_report(report_data, output_file)
                
                # Print samenvatting
                threat = report_data.get('threat_assessment', {})
                print(f"Analyse voltooid voor {url}:")
                print(f"- Dreigingsscore: {threat.get('score', 'N/A')}/{threat.get('max_score', 100)} - {threat.get('risk_level', 'Onbekend')}")
                print(f"- Rapport opgeslagen in {output_file}")
                print("---")

            print(f"\nBulk-analyse voltooid. Individuele rapporten zijn gegenereerd voor elke URL.")

        else:
            print("Ongeldige keuze. Start het script opnieuw en kies 1 of 2.")


if __name__ == "__main__":
    asyncio.run(main()),
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
        
    async def get_technology_fingerprint(self, url: str) -> Dict[str, Any]:
        """
        Analyseert welke technologieën een website gebruikt.
        """
        tech_info = {
            'cms': 'Unknown',
            'server': 'Unknown',
            'js_frameworks': [],
            'analytics': [],
            'payment_systems': [],
        }
        
        try:
            async with self.session.get(url, allow_redirects=True) as response:
                if response.status == 200:
                    # Server technologie uit headers
                    headers = response.headers
                    tech_info['server'] = headers.get('Server', 'Unknown')
                    
                    # Controleer X-Powered-By header
                    if 'X-Powered-By' in headers:
                        powered_by = headers.get('X-Powered-By')
                        if 'PHP' in powered_by:
                            tech_info['cms'] += f" (PHP: {powered_by})"
                        elif 'ASP.NET' in powered_by:
                            tech_info['cms'] += f" (ASP.NET: {powered_by})"
                    
                    # Controleer content
                    content = await response.text()
                    soup = BeautifulSoup(content, 'html.parser')
                    
                    # CMS detectie
                    if 'wp-content' in content:
                        tech_info['cms'] = 'WordPress'
                    elif 'joomla' in content:
                        tech_info['cms'] = 'Joomla'
                    elif 'drupal' in content:
                        tech_info['cms'] = 'Drupal'
                    elif 'shopify' in content.lower():
                        tech_info['cms'] = 'Shopify'
                    elif 'magento' in content.lower():
                        tech_info['cms'] = 'Magento'
                    
                    # JS Frameworks detectie
                    if 'react' in content.lower() or 'reactjs' in content.lower():
                        tech_info['js_frameworks'].append('React')
                    if 'vue' in content.lower() or 'vuejs' in content.lower():
                        tech_info['js_frameworks'].append('Vue.js')
                    if 'angular' in content.lower():
                        tech_info['js_frameworks'].append('Angular')
                    if 'jquery' in content.lower():
                        tech_info['js_frameworks'].append('jQuery')
                    
                    # Analytics detectie
                    if 'google-analytics' in content or 'googletagmanager' in content:
                        tech_info['analytics'].append('Google Analytics')
                    if 'facebook.com/tr?' in content or 'connect.facebook.net' in content:
                        tech_info['analytics'].append('Facebook Pixel')
                    
                    # Betaalsystemen detectie
                    if 'paypal' in content.lower():
                        tech_info['payment_systems'].append('PayPal')
                    if 'stripe' in content.lower():
                        tech_info['payment_systems'].append('Stripe')
                    if 'adyen' in content.lower():
                        tech_info['payment_systems'].append('Adyen')
                    if 'mollie' in content.lower():
                        tech_info['payment_systems'].append('Mollie')
                        
                    # Controleer meta tags voor meer informatie
                    meta_generator = soup.find('meta', attrs={'name': 'generator'})
                    if meta_generator and 'content' in meta_generator.attrs:
                        tech_info['cms'] = meta_generator['content']
        except Exception as e:
            logger.error(f"Technologie fingerprinting mislukt voor {url}: {e}")
        
        return tech_info
        
    async def calculate_threat_score(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Berekent een dreigingsscore op basis van verschillende factoren.
        Hoe hoger de score, hoe groter de kans dat het een scam is.
        """
        score = 0
        max_score = 100
        reasons = []
        
        # 1. Domeinleeftijd
        domain_age_str = data.get('domain_age', 'Unknown')
        if domain_age_str != 'Unknown':
            try:
                years = int(domain_age_str.split(' ')[0])
                if years < 1:
                    score += 20
                    reasons.append("Domein is minder dan 1 jaar oud")
                elif years < 2:
                    score += 10
                    reasons.append("Domein is minder dan 2 jaar oud")
            except:
                pass
        
        # 2. WHOIS privacy
        if data.get('whois_privacy_detected', False):
            score += 5
            reasons.append("WHOIS privacy is ingeschakeld")
        
        # 3. Redirects
        redirects = data.get('redirects', [])
        if len(redirects) > 2:
            score += 5 * (len(redirects) - 2)  # 5 punten per redirect boven 2
            reasons.append(f"{len(redirects) - 1} redirects gedetecteerd")
        
        # 4. Content analyse
        content_analysis = data.get('content_analysis', {})
        if content_analysis.get('password_field', False):
            score += 15
            reasons.append("Bevat wachtwoordveld (mogelijk phishing)")
        
        suspicious_keywords = content_analysis.get('suspicious_keywords', [])
        if suspicious_keywords:
            score += min(15, 3 * len(suspicious_keywords))
            reasons.append(f"Verdachte woorden gevonden: {', '.join(suspicious_keywords)}")
        
        # 5. Blacklist controle
        blacklist_checks = data.get('blacklist_checks', {})
        if blacklist_checks.get('OpenPhish', False):
            score += 25
            reasons.append("Gevonden in OpenPhish database")
        if blacklist_checks.get('PhishTank', False):
            score += 25
            reasons.append("Gevonden in PhishTank database")
        
        # 6. SSL certificaat ontbreekt of is zelf-ondertekend
        ssl_info = data.get('ssl_info', {})
        if not ssl_info:
            score += 10
            reasons.append("Geen SSL/TLS certificaat")
        elif 'issuer' in ssl_info:
            issuer = ssl_info['issuer']
            # Check of het een zelf-ondertekend certificaat is
            if isinstance(issuer, dict) and issuer.get(b'CN') == issuer.get(b'O'):
                score += 15
                reasons.append("Zelf-ondertekend SSL certificaat")
        
        # 7. Email beveiliging
        email_auth = data.get('email_auth_records', {})
        if not email_auth.get('SPF', []):
            score += 5
            reasons.append("Geen SPF records")
        if not email_auth.get('DMARC', []):
            score += 5
            reasons.append("Geen DMARC records")
        
        # 8. Server kwetsbaarheden
        vulnerabilities = data.get('server_vulnerabilities', [])
        if vulnerabilities:
            score += min(15, 5 * len(vulnerabilities))
            reasons.append(f"{len(vulnerabilities)} server kwetsbaarheden gevonden")
        
        # 9. Geografische locatie (bepaalde locaties worden vaker gebruikt voor scams)
        high_risk_countries = ['RU', 'CN', 'UA', 'RO', 'BG', 'NG', 'ZA']
        ip_addresses = data.get('ip_addresses', [])
        ip_geolocations = data.get('ip_geolocations', {})
        
        for ip in ip_addresses:
            country = ip_geolocations.get(ip, 'Unknown')
            if country in high_risk_countries:
                score += 10
                reasons.append(f"Hosting in hoog-risico land: {country}")
                break
        
        # Begrens de score op max_score
        score = min(score, max_score)
        
        return {
            'score': score,
            'max_score': max_score,
            'risk_level': 'Hoog' if score > 70 else 'Gemiddeld' if score > 40 else 'Laag',
            'reasons': reasons
        }

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
        
    # Nieuwe functies voor CloudFlare bypass en andere verbeteringen
    
    async def bypass_cloudflare(self, domain: str) -> Dict[str, Any]:
        """
        Probeert de oorspronkelijke IP/hoster achter CloudFlare-beschermde sites te vinden.
        """
        results = {
            'origin_ip': None,
            'origin_hosting': 'Unknown',
            'bypass_method': None,
            'success': False
        }

        # Methode 1: Controleer subdomains
        # Veel voorkomende subdomeinen die mogelijk niet achter CloudFlare zitten
        common_subdomains = [
            'direct', 'direct-connect', 'origin', 'origin-www', 
            'cpanel', 'webmail', 'mail', 'smtp', 'ftp', 'sftp', 
            'webdisk', 'ns1', 'ns2', 'admin', 'api', 'dev'
        ]
        
        for subdomain in common_subdomains:
            try:
                full_domain = f"{subdomain}.{domain}"
                logger.info(f"Proberen subdomain bypass via {full_domain}")
                try:
                    ip_address = await asyncio.to_thread(socket.gethostbyname, full_domain)
                    # Verifieer dat het geen CloudFlare IP is
                    if not await self.is_cloudflare_ip(ip_address):
                        results['origin_ip'] = ip_address
                        results['bypass_method'] = f"Subdomain leak via {full_domain}"
                        results['success'] = True
                        # Haal hosting provider op
                        results['origin_hosting'] = await self.get_hosting_provider(ip_address)
                        return results
                except socket.gaierror:
                    continue
            except Exception as e:
                logger.error(f"Fout bij subdomain bypass voor {subdomain}.{domain}: {e}")
        
        # Methode 2: Historische DNS-gegevens
        # Deze functie is beperkt zonder externe API, maar we kunnen proberen SecurityTrails of VirusTotal data op te vragen
        # (Opmerking: voor volledige implementatie zou je een betaalde API nodig hebben)
        logger.info(f"Proberen historische DNS-gegevens voor {domain}")
        try:
            # Simuleer een basic DNS history check
            # Voor productie zou je hier een API integratie gebruiken
            # Aangezien dit alleen een voorbeeld is, werkt dit niet daadwerkelijk
            pass
        except Exception as e:
            logger.error(f"Fout bij het ophalen van historische DNS gegevens: {e}")
        
        # Methode 3: Controleer SSL certificaat informatie
        logger.info(f"Proberen SSL certificaat analyse voor {domain}")
        try:
            ssl_info = await self.get_ssl_info(f"https://{domain}")
            # Sommige SSL certs bevatten het originele IP in Subject Alternative Name
            if ssl_info and 'subject' in ssl_info:
                subject_info = ssl_info['subject']
                for key, value in subject_info.items():
                    # Convert bytes to string if needed
                    if isinstance(key, bytes):
                        key = key.decode('utf-8', errors='ignore')
                    if isinstance(value, bytes):
                        value = value.decode('utf-8', errors='ignore')
                    # Zoek naar IP-adressen in certificaat
                    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
                    if isinstance(value, str):
                        ips = re.findall(ip_pattern, value)
                        for ip in ips:
                            if not await self.is_cloudflare_ip(ip):
                                results['origin_ip'] = ip
                                results['bypass_method'] = "SSL certificate leak"
                                results['success'] = True
                                results['origin_hosting'] = await self.get_hosting_provider(ip)
                                return results
        except Exception as e:
            logger.error(f"Fout bij SSL certificaat analyse: {e}")
        
        # Methode 4: MX records
        # Mail servers staan vaak op dezelfde infrastructuur
        logger.info(f"Proberen MX records voor {domain}")
        try:
            mx_records = await self.dns_resolver.query(domain, 'MX')
            for mx in mx_records:
                mx_hostname = mx.host.rstrip('.')
                try:
                    mx_ip = await asyncio.to_thread(socket.gethostbyname, mx_hostname)
                    if not await self.is_cloudflare_ip(mx_ip):
                        # Vergelijk IP-blokken (eerste twee octetten)
                        mx_subnet = '.'.join(mx_ip.split('.')[:2])
                        
                        # Controleren of we andere IPs in hetzelfde subnet kunnen vinden
                        try:
                            www_domain = f"www.{domain}"
                            www_ip = await asyncio.to_thread(socket.gethostbyname, www_domain)
                            www_subnet = '.'.join(www_ip.split('.')[:2])
                            
                            if mx_subnet == www_subnet:
                                results['origin_ip'] = mx_ip
                                results['bypass_method'] = f"MX record in hetzelfde subnet als {www_domain}"
                                results['success'] = True
                                results['origin_hosting'] = await self.get_hosting_provider(mx_ip)
                                return results
                        except:
                            pass
                except:
                    continue
        except Exception as e:
            logger.error(f"Fout bij MX records controle: {e}")

        logger.warning(f"Geen CloudFlare bypass gevonden voor {domain}")
        return results

    async def is_cloudflare_ip(self, ip_address: str) -> bool:
        """
        Controleert of een IP-adres tot CloudFlare behoort.
        """
        try:
            # CloudFlare IPv4 ranges (vereenvoudigd voor voorbeeld)
            # In een volledige implementatie zou je de actuele ranges van CloudFlare API halen
            cloudflare_ranges = [
                "173.245.48.0/20",
                "103.21.244.0/22",
                "103.22.200.0/22",
                "103.31.4.0/22",
                "141.101.64.0/18",
                "108.162.192.0/18",
                "190.93.240.0/20",
                "188.114.96.0/20",
                "197.234.240.0/22",
                "198.41.128.0/17",
                "162.158.0.0/15",
                "104.16.0.0/13",
                "104.24.0.0/14",
                "172.64.0.0/13",
                "131.0.72.0/22"
            ]
            
            ip_obj = ipaddress.ip_address(ip_address)
            
            for cidr in cloudflare_ranges:
                network = ipaddress.ip_network(cidr)
                if ip_obj in network:
                    return True
                    
            return False
        except Exception as e:
            logger.error(f"Fout bij het controleren van CloudFlare IP range: {e}")
            return False
            
    async def check_known_scam_databases(self, url: str) -> Dict[str, bool]:
        """
        Controleert de URL in meerdere publieke scam/phishing databases.
        """
        results = {
            'OpenPhish': False,
            'PhishTank': False,
            'Google Safe Browsing': 'Unknown'  # Voor Google Safe Browsing heb je een API-sleutel nodig
        }
        
        domain = self.extract_domain(url)
        
        # OpenPhish check (al aanwezig in je code, hier uitgebreid)
        try:
            async with self.session.get('https://openphish.com/feed.txt') as response:
                if response.status == 200:
                    content = await response.text()
                    blacklist = content.splitlines()
                    results['OpenPhish'] = any(
                        item in url or item in domain for item in blacklist
                    )
                else:
                    logger.warning(f"OpenPhish feed ophalen mislukt: {response.status}")
        except Exception as e:
            logger.error(f"OpenPhish check mislukt voor {url}: {e}")
        
        # PhishTank check
        try:
            # PhishTank vereist eigenlijk een API-sleutel, dit is een vereenvoudigde implementatie
            phishtank_url = f"http://checkurl.phishtank.com/checkurl/?url={url}"
            async with self.session.get(phishtank_url) as response:
                if response.status == 200:
                    content = await response.text()
                    results['PhishTank'] = "phish_id" in content
                else:
                    logger.warning(f"PhishTank check mislukt: {response.status}")
        except Exception as e:
            logger.error(f"PhishTank check mislukt voor {url}: {e}")
        
        return results
