import requests
import xml.etree.ElementTree as ET
import argparse
import sys
import json
import logging
import time
import os
import getpass
from pathlib import Path
from typing import Optional, Dict, List, Union, Set
from urllib.parse import urlparse
import ipaddress
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# Configuration
CONFIG = {
    'API_BASE_URL': 'https://www.namesilo.com/api',
    'IP_CHECK_URL': 'https://ifconfig.me',
    'DEFAULT_TTL': 3603,
    'REQUEST_TIMEOUT': 30,
    'MAX_RETRIES': 3,
    'BACKOFF_FACTOR': 0.3,
    'SPF_TEMPLATE': 'v=spf1 a mx a:{domain} ip4:***CHANGEME*** ip4:{ip} ?all'
}

def get_api_key() -> str:
    """
    Securely prompt for the NameSilo API key.
    The API key is only stored in memory during runtime.
    """
    print("\nNameSilo API Key Required")
    print("------------------------")
    print("Please enter your NameSilo API key.")
    print("The key will not be stored and you'll need to enter it each time you run the script.")
    print("You can find your API key in your NameSilo account settings.")
    
    api_key = getpass.getpass("API Key: ").strip()
    
    if not api_key:
        print("Error: API key is required")
        sys.exit(1)
    
    return api_key

class NameSiloDDNS:
    def __init__(self, api_key: str, domains_file: Optional[str], record_types: Set[str], update_spf: bool, log_level: str = 'INFO'):
        """
        Initialize the NameSilo DDNS updater.
        
        Args:
            api_key: NameSilo API key
            domains_file: Path to the JSON file containing domains configuration, or None to fetch all domains
            record_types: Set of record types to update ('A' and/or 'AAAA')
            update_spf: Whether to update SPF records
            log_level: Logging level (default: INFO)
        """
        self.api_key = api_key
        self.domains_file = domains_file
        self.record_types = record_types
        self.update_spf = update_spf
        self.setup_logging(log_level)
        self.session = self.setup_requests_session()

    def setup_logging(self, log_level: str) -> None:
        """Configure logging with both file and console handlers."""
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('namesilo_ddns.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def setup_requests_session(self) -> requests.Session:
        """Configure requests session with retry mechanism."""
        session = requests.Session()
        retry_strategy = Retry(
            total=CONFIG['MAX_RETRIES'],
            backoff_factor=CONFIG['BACKOFF_FACTOR'],
            status_forcelist=[429, 500, 502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def validate_domain(self, domain: str) -> bool:
        """Validate domain name format."""
        try:
            result = urlparse("//" + domain)
            return all([result.netloc, "." in result.netloc])
        except Exception:
            return False

    def validate_ip(self, ip: str) -> bool:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def get_wan_ip(self) -> Optional[str]:
        """Fetch current WAN IP address."""
        try:
            response = self.session.get(CONFIG['IP_CHECK_URL'], timeout=CONFIG['REQUEST_TIMEOUT'])
            response.raise_for_status()
            ip = response.text.strip()
            if self.validate_ip(ip):
                return ip
            self.logger.error(f"Invalid IP address received: {ip}")
            return None
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Failed to fetch WAN IP: {str(e)}")
            return None

    def get_all_domains(self) -> Optional[List[str]]:
        """Fetch all domains from NameSilo account."""
        url = f"{CONFIG['API_BASE_URL']}/listDomains"
        params = {
            'version': '1',
            'type': 'xml',
            'key': self.api_key
        }

        try:
            response = self.session.get(url, params=params, timeout=CONFIG['REQUEST_TIMEOUT'])
            response.raise_for_status()
            
            # Log the raw response for debugging
            self.logger.debug(f"Raw API response: {response.text}")
            
            root = ET.fromstring(response.text)
            
            # Check if the API request was successful (code 300 means success)
            code = root.find('.//code')
            detail = root.find('.//detail')
            
            if code is not None and code.text == '300' and detail is not None and detail.text == 'success':
                domains = []
                domains_elem = root.find('.//domains')
                if domains_elem is not None:
                    for domain in domains_elem.findall('domain'):
                        if domain.text:
                            domains.append(domain.text)
                
                if domains:
                    self.logger.info(f"Found {len(domains)} domains in your account: {', '.join(domains)}")
                    return domains
                else:
                    self.logger.error("No domains found in the account")
                    return None
            else:
                error_code = code.text if code is not None else "unknown"
                error_detail = detail.text if detail is not None else "unknown error"
                self.logger.error(f"API request failed with code {error_code}: {error_detail}")
                return None
                
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error retrieving domain list: {str(e)}")
            return None
        except ET.ParseError as e:
            self.logger.error(f"Error parsing domain list response: {str(e)}")
            return None

    def get_domain_records(self, domain: str) -> Optional[str]:
        """Fetch DNS records for a domain."""
        if not self.validate_domain(domain):
            self.logger.error(f"Invalid domain name: {domain}")
            return None

        url = f"{CONFIG['API_BASE_URL']}/dnsListRecords"
        params = {
            'version': '1',
            'type': 'xml',
            'key': self.api_key,
            'domain': domain
        }

        try:
            response = self.session.get(url, params=params, timeout=CONFIG['REQUEST_TIMEOUT'])
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error retrieving domain records for {domain}: {str(e)}")
            return None

    def update_dns_record(self, domain: str, record_id: str, rrhost: str, rrvalue: str, rrttl: int = CONFIG['DEFAULT_TTL']) -> Optional[str]:
        """Update a DNS record."""
        rrhost = '' if rrhost == '@' else rrhost
        url = f"{CONFIG['API_BASE_URL']}/dnsUpdateRecord"
        params = {
            'version': '1',
            'type': 'xml',
            'key': self.api_key,
            'domain': domain,
            'rrid': record_id,
            'rrhost': rrhost,
            'rrvalue': rrvalue,
            'rrttl': rrttl
        }

        try:
            response = self.session.get(url, params=params, timeout=CONFIG['REQUEST_TIMEOUT'])
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Error updating DNS record: {str(e)}")
            return None

    def update_spf_record(self, domain: str, record_id: str, current_ip: str) -> Optional[str]:
        """Update SPF record with current IP."""
        spf_record = CONFIG['SPF_TEMPLATE'].format(domain=domain, ip=current_ip)
        return self.update_dns_record(domain, record_id, '@', spf_record)

    def process_domain_records(self, domain: str, subdomains: List[str], xml_data: Optional[str], current_ip: str) -> None:
        """Process and update domain records as needed."""
        if xml_data is None:
            return

        try:
            root = ET.fromstring(xml_data)
            records = root.findall(".//resource_record")
            spf_updated = False

            for record in records:
                record_type = record.find('type').text
                record_id = record.find('record_id').text
                value = record.find('value').text
                ttl = record.find('ttl').text
                host = record.find('host').text

                if self.update_spf and record_type == 'TXT' and host == domain and 'v=spf1' in value:
                    self.logger.info(f"Updating SPF record for {domain}")
                    response = self.update_spf_record(domain, record_id, current_ip)
                    self.logger.info(f"SPF update response: {response}")
                    spf_updated = True
                elif record_type in self.record_types:
                    if '*' in subdomains or any(host == domain or host.endswith('.' + domain) for sd in subdomains):
                        if value != current_ip or ttl != str(CONFIG['DEFAULT_TTL']):
                            self.logger.info(f"Updating {record_type} record for {host} to {current_ip}")
                            rrhost = '@' if host == domain else host.replace('.' + domain, '')
                            response = self.update_dns_record(domain, record_id, rrhost, current_ip)
                            self.logger.info(f"DNS update response: {response}")
                        else:
                            self.logger.info(f"No update needed for {host}")

            if self.update_spf and not spf_updated:
                self.logger.warning(f"SPF record not found for {domain}. You may need to create it manually.")

        except ET.ParseError as e:
            self.logger.error(f"Error parsing XML response for {domain}: {str(e)}")

    def load_domains(self) -> Dict[str, List[str]]:
        """Load domains configuration from JSON file or fetch all domains."""
        if self.domains_file:
            try:
                with open(self.domains_file, 'r') as f:
                    return json.load(f)
            except FileNotFoundError:
                self.logger.error(f"Domains file '{self.domains_file}' not found.")
                sys.exit(1)
            except json.JSONDecodeError:
                self.logger.error(f"Invalid JSON in domains file '{self.domains_file}'.")
                sys.exit(1)
        else:
            domains = self.get_all_domains()
            if domains:
                # Create a dictionary with all domains using wildcard for subdomains
                return {domain: ["*"] for domain in domains}
            else:
                self.logger.error("Failed to fetch domains from NameSilo.")
                sys.exit(1)

    def run(self, check_ip_only: bool = False) -> None:
        """Main execution method."""
        current_wan_ip = self.get_wan_ip()
        if not current_wan_ip:
            self.logger.error("Failed to fetch current WAN IP.")
            return

        self.logger.info(f"Current WAN IP: {current_wan_ip}")
        if check_ip_only:
            return

        domains = self.load_domains()
        for domain, subdomains in domains.items():
            self.logger.info(f"Processing domain: {domain}")
            xml_records = self.get_domain_records(domain)
            self.process_domain_records(domain, subdomains, xml_records, current_ip=current_wan_ip)

def main():
    """Entry point of the script."""
    parser = argparse.ArgumentParser(description="NameSilo Dynamic DNS Updater")
    parser.add_argument("-d", "--domains-file", help="JSON file containing domains and subdomains (optional, if not provided will update all domains)")
    parser.add_argument("-c", "--check-ip-only", action="store_true", help="Only check and display the current WAN IP")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                      help="Set the logging level")
    parser.add_argument("--record-types", default="A,AAAA", help="Comma-separated list of record types to update (A,AAAA)")
    parser.add_argument("--no-spf", action="store_true", help="Skip updating SPF records")

    args = parser.parse_args()
    
    # Get API key securely through user input
    api_key = get_api_key()
    
    # Parse record types
    record_types = set(args.record_types.upper().split(','))
    valid_types = {'A', 'AAAA'}
    if not record_types.issubset(valid_types):
        print(f"Error: Invalid record types. Valid types are: {', '.join(valid_types)}")
        sys.exit(1)
    
    updater = NameSiloDDNS(api_key, args.domains_file, record_types, not args.no_spf, args.log_level)
    updater.run(args.check_ip_only)

if __name__ == "__main__":
    main()