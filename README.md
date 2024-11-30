## ScamTrail
ScamTrail is a Python-based tool designed to analyze URLs for potential scams or phishing activity. It performs a comprehensive check by following redirects, retrieving WHOIS and DNS information, analyzing content for suspicious indicators, and generating detailed PDF reports.

## Features
- **Follow URL Redirects:** Track and display all redirects from the initial URL to the final destination.
- **WHOIS Lookup:** Retrieve domain registration data, including the domain's creation date and registrar.
- **DNS Lookup:** Fetch A, NS, and CNAME records for the domain.
- **IP Address and Geolocation:** Resolve the IP address of the domain and attempt to locate its geographical position.
- **Reverse DNS Lookup:** Identify associated hostnames for resolved IP addresses.
- **Domain Age Calculation:** Estimate the age of the domain based on its WHOIS registration data.
- **Cloudflare Detection:** Identify whether the domain is using Cloudflare for DNS services.
- **Content Analysis:** Detect suspicious indicators, such as password fields, login forms, and keywords commonly used in phishing sites.
- **PDF Report Generation:** Create a detailed PDF report of the URL analysis, containing all collected data and insights.

## Installation
Prerequisites
- **Python 3.7+**
- **pip (Python package manager)**

### Install the Required Dependencies
Run the following command to install all required Python packages:

```
pip install aiohttp aiodns whois weasyprint jinja2 beautifulsoup4 aiofiles python-dotenv
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
- Analyze the page content for suspicious indicators.
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

- Redirect Chain: A list of all redirects encountered while tracing the URL.
- WHOIS Information: Registration data for each domain in the redirect chain.
- DNS Records: A, NS, and CNAME records for the domain.
- IP Information: Resolved IP address and reverse DNS lookup results.
- Geolocation: The estimated geographical location of the IP address.
- Domain Age: The calculated age of the domain.
- Cloudflare Usage: Whether the domain uses Cloudflare services.
- Content Analysis: Details on suspicious keywords, login forms, password fields, and more.

## Use Cases
ScamTrail is ideal for:
- Security Researchers: Investigating suspicious URLs and identifying potential phishing sites.
- Incident Response Teams: Generating reports on malicious links for further action.
- Domain Owners: Checking how their domain is being used or if it’s potentially compromised.
- Example Output (Command-Line Summary)
- After running the analysis, ScamTrail will display a summary like this in the terminal:

```
Analysis Results for https://example.com:
Report saved to: scamtrail_report_example.com.pdf
Final destination: https://final.example.com
Number of redirects: 2
Domain age: 5 years, 2 months, 15 days
Geographical location: San Francisco, California, United States
Uses CloudFlare: Yes

Content Analysis:
- Password Field: False
- Login Form: True
- Suspicious Keywords: login, password, credit card
- External Links: 15
- Images: 8
- Scripts: 5
```

## Intended Use
ScamTrail is designed to be used by:

- Security Analysts: To investigate URLs and identify scam or phishing sites.
- Penetration Testers: As part of a toolkit to assess the security of URLs.
- Law Enforcement: For tracking suspicious domains and documenting malicious activities.
Make sure to comply with all relevant laws and ethical guidelines when using ScamTrail for investigations.

## License
This project is licensed under the MIT License.
