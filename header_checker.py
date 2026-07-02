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


def check_headers(url):
    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        headers = response.headers

        print("\n" + "=" * 60)
        print(f"Security Header Analysis: {url}")
        print("=" * 60)

        found = 0
        missing = 0

        for header, details in SECURITY_HEADERS.items():
            vulnerability = details["vulnerability"]
            mitigation = details["mitigation"]

            if header in headers:
                found += 1
                print(f"[+] {header}")
                print(f"    Value: {headers[header]}")
                print(f"    Vulnerability: {vulnerability}")
                print(f"    Mitigation: {mitigation}\n")

            else:
                missing += 1
                print(f"[-] {header} MISSING")
                print(f"    Vulnerability: {vulnerability}")
                print(f"    Mitigation: {mitigation}\n")

        print("=" * 60)
        print(f"Headers Found   : {found}")
        print(f"Headers Missing : {missing}")
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