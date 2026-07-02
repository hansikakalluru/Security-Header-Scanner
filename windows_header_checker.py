import requests 
import sys
import argparse

SECURITY_HEADERS = {
    "Content-Security-Policy": {
        "vulnerability": "Cross-site scripting (XSS) and injection attacks",
        "mitigation": "Restricts the sources of scripts, styles, and other resources the browser can load."
    },

    "X-Frame-Options": {
        "vulnerability": "Clickjacking attacks",
        "mitigation": "Prevents the page from being embedded inside a frame or iframe by an attacker."
    },

    "Strict-Transport-Security": {
        "vulnerability": "Protocol downgrade and man-in-the-middle attacks",
        "mitigation": "Forces browsers to use HTTPS for the site and its subdomains."
    },

    "X-Content-Type-Options": {
        "vulnerability": "MIME type sniffing attacks",
        "mitigation": "Stops browsers from interpreting files as a different content type than declared."
    },

    "Referrer-Policy": {
        "vulnerability": "Unwanted leakage of sensitive URL information",
        "mitigation": "Controls how much referrer information is sent to other sites."
    },

    "Permissions-Policy": {
        "vulnerability": "Abuse of browser features and APIs",
        "mitigation": "Restricts which browser features and APIs can be used by the website."
    }
}


def analyze_headers(url):
    response = requests.get(
        url,
        timeout=10,
        allow_redirects=True
    )

    headers = response.headers
    results = []
    found = 0
    missing = 0

    for header, details in SECURITY_HEADERS.items():
        vulnerability = details["vulnerability"]
        mitigation = details["mitigation"]
        present = header in headers

        if present:
            found += 1
        else:
            missing += 1

        results.append({
            "header": header,
            "present": present,
            "value": headers.get(header, ""),
            "vulnerability": vulnerability,
            "mitigation": mitigation,
        })

    return {
        "url": url,
        "found": found,
        "missing": missing,
        "results": results,
    }


def check_headers(url):
    try:
        analysis = analyze_headers(url)

        print("\n" + "=" * 60)
        print(f"Security Header Analysis: {analysis['url']}")
        print("=" * 60)

        for result in analysis["results"]:
            if result["present"]:
                print(f"[+] {result['header']}")
                print(f"    Value: {result['value']}")
                print(f"    Vulnerability: {result['vulnerability']}")
                print(f"    Mitigation: {result['mitigation']}\n")
            else:
                print(f"[-] {result['header']} MISSING")
                print(f"    Vulnerability: {result['vulnerability']}")
                print(f"    Mitigation: {result['mitigation']}\n")

        print("=" * 60)
        print(f"Headers Found   : {analysis['found']}")
        print(f"Headers Missing : {analysis['missing']}")
        print("=" * 60)

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Check common security headers for a given URL."
    )
    parser.add_argument("url", nargs="?", help="URL to check (e.g. https://example.com)")

    args = parser.parse_args()

    if not args.url:
        parser.print_help()
        sys.exit(1)

    url = args.url
    if not url.startswith("http"):
        url = "https://" + url

    check_headers(url)


if __name__ == "__main__":
    main()