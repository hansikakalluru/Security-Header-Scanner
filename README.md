# Security-Header-Scanner
This tool scans a url that the user provides and displays any possible vulnerabilities and the respective mitigations.

## Purpose

This tool helps identify whether a website is sending important security headers such as:

- Content-Security-Policy
- X-Frame-Options
- Strict-Transport-Security
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy

It reports which headers are present, which are missing, and explains the vulnerability each header helps mitigate.

## Requirements

Python 3.8 or newer

Install the required dependency:

```powershell
pip install requests
```

## Installation

1. Clone or download the project folder.
2. Open PowerShell in the project directory.
3. Install the dependency if needed:

```powershell
pip install requests
```

## Usage

Run the script with a target URL:

```powershell
python windows_header_checker.py https://example.com
```

You can also use a domain without the protocol:

```powershell
python windows_header_checker.py example.com
```

### Help command

```powershell
python windows_header_checker.py -h
```

## Example Output

The tool prints a report showing:

- whether each header is present or missing
- the header value if present
- the vulnerability it helps reduce
- the mitigation it provides

## Notes

- The script automatically adds https:// if the URL does not start with http or https.
- Network access is required to scan the target website.
