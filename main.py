import argparse
from scanner import Scanner

def main():
    parser = argparse.ArgumentParser(description="GitCodeSentry: Scan code for GitHub rendering vulnerabilities")
    parser.add_argument("--url", help="GitHub URL to scan (e.g., https://github.com/org/repo)")
    parser.add_argument("--dir", help="Local directory path to scan")
    args = parser.parse_args()

    if not (args.url or args.dir):
        parser.error("Please provide either a --url or --dir argument")

    scanner = Scanner()
    if args.url:
        print(f"Scanning GitHub URL: {args.url}")
        scanner.scan_from_url(args.url)
    elif args.dir:
        print(f"Scanning local directory: {args.dir}")
        scanner.scan_from_directory(args.dir)

    scanner.report()

if __name__ == "__main__":
    main()