# NameSilo Dynamic DNS Updater

This Python script is designed to update DNS records for domains hosted on NameSilo, a popular domain registrar and DNS management platform. It allows you to dynamically update the IP addresses associated with your domains and subdomains whenever your WAN IP changes.

## Features

- Fetches the current WAN IP address using the `ifconfig.me` service
- Retrieves and updates DNS records for specified domains from NameSilo's API
- Can automatically update all domains in your NameSilo account
- Selectively update A and/or AAAA records
- Optional SPF record updates
- Support for wildcard subdomain updates
- Robust error handling with retry mechanism
- Comprehensive logging system
- Input validation for domains and IP addresses
- Configurable through command-line arguments
- JSON-based domain configuration (optional)
- Secure API key handling through interactive prompt

## Prerequisites

Before using this script, make sure you have the following:

- Python 3.x installed on your system
- A NameSilo account with API access enabled
- Your NameSilo API key (you'll be prompted to enter it when running the script)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/boredchilada/NamesiloDDNS.git
cd NamesiloDDNS
```

2. Create and activate a virtual environment:

### Windows
```cmd
python -m venv venv
venv\Scripts\activate
```

### Linux/macOS
```bash
python3 -m venv venv
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## API Key Security

For enhanced security, the script prompts for your NameSilo API key each time it runs. This ensures that:
- Your API key is never stored in plaintext
- The key only exists in memory during script execution
- There's no risk of accidental exposure through environment variables or config files
- You maintain full control over when and how your API key is used

## Usage

### Basic Usage (Update All Domains)

To update all domains in your NameSilo account:
```bash
python NamesiloDDNS.py
```

This will:
- Prompt you for your NameSilo API key
- Fetch all domains from your NameSilo account
- Update all subdomains for each domain
- Update both A and AAAA records by default

### Advanced Usage (Specific Domains)

If you want to update only specific domains, create a JSON file (e.g., `domains.json`) with your domain configuration:

```json
{
    "example.com": ["*"],
    "example2.com": ["www", "mail", "dev"]
}
```

Then run:
```bash
python NamesiloDDNS.py -d domains.json
```

### Command-line Arguments

- `-d, --domains-file`: JSON file containing domains and subdomains (optional)
- `-c, --check-ip-only`: Only check and display the current WAN IP
- `--log-level`: Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
- `--record-types`: Comma-separated list of record types to update (default: "A,AAAA")
- `--no-spf`: Skip updating SPF records

### Examples

1. Update A records for all domains in your account:
```bash
python NamesiloDDNS.py --record-types A
```

2. Update A records for all domains, skip SPF:
```bash
python NamesiloDDNS.py --record-types A --no-spf
```

3. Update specific domains only:
```bash
python NamesiloDDNS.py -d domains.json --record-types A
```

4. Check current WAN IP:
```bash
python NamesiloDDNS.py -c
```

5. Run with debug logging:
```bash
python NamesiloDDNS.py --log-level DEBUG
```

## Logging

The script maintains a log file (`namesilo_ddns.log`) containing detailed information about:
- DNS record updates
- API responses
- Errors and warnings
- IP address changes

## Important Note About Automation

Due to security considerations, automated/unattended operation (e.g., via cron jobs or Task Scheduler) is currently not supported. This is a deliberate design choice to prevent the storage of API keys in plaintext and reduce the risk of unauthorized access. The script requires manual input of the API key each time it runs.

If you need automated updates, consider using NameSilo's built-in DDNS service or implementing your own secure key management system.

## Error Handling

The script includes robust error handling for:
- Network connectivity issues
- API rate limiting
- Invalid domain names
- Invalid IP addresses
- Configuration file errors
- API authentication failures

## Troubleshooting

1. Check the log file (`namesilo_ddns.log`) for detailed error messages
2. Verify your API key is valid
3. Ensure your domains.json file is properly formatted (if using one)
4. Check your internet connection
5. Verify the domains in your configuration are active in your NameSilo account

Common issues:
- "Invalid API Key": Verify your NameSilo API key
- "Invalid Domain": Check domain format in domains.json
- "Connection Error": Check internet connectivity
- "Rate Limit": Wait before retrying (automatic retry implemented)
- "Invalid Record Type": Ensure --record-types contains only A and/or AAAA

## Security Considerations

- API key is never stored in plaintext
- The key only exists in memory during script execution
- Input is masked when entering the API key
- The script validates all inputs before processing
- HTTPS is used for all API communications
- Request timeouts prevent hanging operations

## License

This script is released under the [MIT License](https://opensource.org/licenses/MIT).

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This script is provided as-is without any warranty. Use it at your own risk. Make sure to comply with NameSilo's API usage terms and conditions.

---
