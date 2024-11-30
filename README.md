## ScamTrail
ScamTrail is a Python-based tool designed to analyze URLs for potential scams or phishing activity. It performs a comprehensive check by following redirects, retrieving WHOIS and DNS information, analyzing content for suspicious indicators, and generating detailed PDF reports.

## Features

- **Follow URL Redirects:** Track and display all redirects from the initial URL to the final destination.
- **WHOIS Lookup:** Retrieve domain registration data, including the domain's creation date, registrar, and detect WHOIS privacy protection.
- **DNS Lookup:** Fetch A, NS, and CNAME records for the domain.
- **IP Address and Geolocation:** Resolve the IP address of the domain and determine its geographical location.
- **Reverse DNS Lookup:** Identify associated hostnames for resolved IP addresses.
- **Domain Age Calculation:** Estimate the age of the domain based on its WHOIS registration data.
- **Cloudflare Detection:** Identify whether the domain is using Cloudflare services.
- **SSL Certificate Analysis:** Retrieve and display SSL certificate details, including issuer, validity dates, and serial number.
- **Hosting Provider Identification:** Determine the hosting provider by performing WHOIS lookups on IP addresses.
- **Content Analysis**:
   - Detect suspicious indicators such as password fields, login forms, and phishing-related keywords.
   - Perform advanced language analysis to assess sentiment polarity, subjectivity, and extract keywords.
   - Identify server software from HTTP headers and check for known server vulnerabilities.
- **Email Authentication Records:** Retrieve SPF, DKIM, and DMARC records to assess email authentication measures.
- **DNSSEC Validation:** Check if DNSSEC is enabled for the domain.
- **Blacklist Checks:** Verify if the domain or URL is listed on known phishing blacklists like OpenPhish.
- **Server Vulnerabilities Check:** Analyze server software versions to identify potential vulnerabilities.
- **PDF Report Generation:** Create a detailed PDF report of the URL analysis, containing all collected data and insights.

## Installation
Prerequisites
- **Python 3.7+**
- **pip (Python package manager)**

### Install the Required Dependencies
Run the following command to install all required Python packages:

```
pip install aiohttp aiodns python-whois weasyprint pyOpenSSL jinja2 beautifulsoup4 aiofiles python-dotenv textblob ipwhois
```

### Download TextBlob Corpora

TextBlob requires certain corpora for language analysis. Run the following command to download them:

```
python -m textblob.download_corpora
```

### Additional System Dependencies for WeasyPrint
WeasyPrint may require additional system libraries to function properly, especially for PDF generation:

### On Debian/Ubuntu:

```
sudo apt-get install libpango-1.0-0 libpangocairo-1.0-0 libcairo2
```

### On macOS:

```
brew install cairo pango gdk-pixbuf libffi
```

## Usage
### Command-Line Interface
ScamTrail supports the analysis of a single URL or multiple URLs in bulk. Here's how to use it via the command line.

1. **Run the Script:** Navigate to the directory containing scamtrail.py and run:
```
python scamtrail.py
```
2. **Choose an Option:** After starting the script, you'll be prompted to choose between two options:
   - Option 1: Analyze a single URL.
   - Option 2: Perform a bulk analysis of multiple URLs.
3. **Analyze a Single URL:** After selecting option 1, you will be prompted to enter a URL. For example:

```
Enter the URL to trace: https://example.com
```
The tool will:

- Follow any redirects.
- Retrieve WHOIS and DNS information.
- Resolve the IP address and perform reverse DNS lookups.
- Detect if the domain uses Cloudflare.
- Analyze the page content for suspicious indicators and perform language analysis.
- Retrieve SSL certificate details.
- Check for WHOIS privacy protection.
- Retrieve email authentication records (SPF, DKIM, DMARC).
- Validate DNSSEC status.
- Perform blacklist checks.
- Identify hosting provider and server vulnerabilities.
- Generate a PDF report with the results.
4. **Perform Bulk Analysis:** After selecting option 2, you can enter multiple URLs (one per line). To finish inputting URLs, press Enter on a blank line. Example:
```
Enter URLs for bulk analysis (one per line, enter a blank line to finish):
https://example1.com
https://example2.com
```
The tool will analyze each URL in sequence, generating individual reports for each one.

## Report Details
The generated PDF report includes the following information:

- **Redirect Chain:** A list of all redirects encountered while tracing the URL.
- **WHOIS Information:** Registration data for each domain in the redirect chain, including registrar, creation and expiration dates, and name servers.
- **WHOIS Privacy Detection:** Indicates if WHOIS privacy protection services are used.
- **DNS Records:** A, NS, and CNAME records for the domain.
- **IP Information:** Resolved IP addresses and reverse DNS lookup results.
- **Geolocation:** The estimated geographical location of each IP address.
- **Hosting Provider Identification:** Hosting provider details based on IP WHOIS lookups.
- **SSL Certificate Information:** Details about the SSL certificate, including issuer, subject, validity period, and serial number.
- **Email Authentication Records:** Retrieved SPF, DKIM, and DMARC records for the domain.
- **DNSSEC Validation:** Indicates whether DNSSEC is enabled for the domain.
- **Blacklist Checks:** Results of checks against known phishing blacklists like OpenPhish.
- **Domain Age:** The calculated age of the domain.
- **Cloudflare Usage:** Whether the domain uses Cloudflare services.
- **Content Analysis:**
   - Presence of password fields and login forms.
   - Detection of suspicious keywords commonly used in phishing sites.
   - Counts of external links, images, and scripts.
   - Advanced language analysis (sentiment polarity, subjectivity, extracted keywords).
   - Server software identification from HTTP headers.
- **Server Vulnerabilities:** Information on potential vulnerabilities based on server software versions.

## Use Cases
ScamTrail is ideal for:

- **Security Researchers:** Investigating suspicious URLs and identifying potential phishing or scam sites.
- **Incident Response Teams:** Generating detailed reports on malicious links for further action.
- **Domain Owners:** Checking how their domain is being used or if it’s potentially compromised.
- **Law Enforcement:** Tracking suspicious domains and documenting malicious activities.

##Example Output (Command-Line Summary)
After running the analysis, ScamTrail will display a summary like this in the terminal:

```
Analysis Results for https://example.com:
Report saved to: scamtrail_report_example.com.pdf
Final Destination: https://final.example.com
Number of Redirects: 2
Domain Age: 5 years, 2 months, 15 days
Geographical Location: United States
Hosting Provider: Example Hosting Provider
Uses CloudFlare: Yes
DNSSEC Enabled: No
WHOIS Privacy Detected: Yes
Blacklisted by OpenPhish: No

Content Analysis:
- Password Field Present: True
- Login Form Present: True
- Suspicious Keywords: login, password, verify
- External Links: 15
- Images: 8
- Scripts: 5
- Sentiment Polarity: -0.1
- Subjectivity: 0.6
- Extracted Keywords: account, security, update
- Server Software: Apache/2.4.41 (Ubuntu)

No server vulnerabilities detected based on available data.
```

## Intended Use
ScamTrail is designed to be used by:

- **Security Analysts:** To investigate URLs and identify scam or phishing sites.
- **Penetration Testers:** As part of a toolkit to assess the security of URLs.
- **Law Enforcement:** For tracking suspicious domains and documenting malicious activities.
Make sure to comply with all relevant laws and ethical guidelines when using ScamTrail for investigations.

## License
This project is licensed under the MIT License.
