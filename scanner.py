from fetcher import GitHubFetcher
from analyzer import CodeAnalyzer
from utils import read_files_in_directory
from colorama import init, Fore, Style  # For colored output

init()  # Initialize colorama for cross-platform color support

class Scanner:
    def __init__(self):
        self.analyzer = CodeAnalyzer()
        self.vulnerabilities = []

    def scan_from_url(self, url):
        fetcher = GitHubFetcher(url)
        files = fetcher.fetch_files()
        for file_path, content in files.items():
            issues = self.analyzer.analyze(file_path, content)
            self.vulnerabilities.extend(issues)

    def scan_from_directory(self, directory):
        files = read_files_in_directory(directory)
        for file_path, content in files.items():
            issues = self.analyzer.analyze(file_path, content)
            self.vulnerabilities.extend(issues)

    def report(self):
        if not self.vulnerabilities:
            print(f"{Fore.GREEN}No vulnerabilities found. Your code looks clean!{Style.RESET_ALL}")
            return

        # Categorize by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        for vuln in self.vulnerabilities:
            severity_counts[vuln['severity']] += 1

        # Summary
        print(f"\n{Fore.YELLOW}Scan Summary:{Style.RESET_ALL}")
        print(f"Total issues found: {len(self.vulnerabilities)}")
        for sev, count in severity_counts.items():
            color = Fore.RED if sev == 'Critical' else Fore.MAGENTA if sev == 'High' else Fore.YELLOW if sev == 'Medium' else Fore.CYAN
            print(f"{color}{sev}: {count}{Style.RESET_ALL}")

        # Detailed report
        print(f"\n{Fore.YELLOW}Detailed Findings:{Style.RESET_ALL}")
        for vuln in sorted(self.vulnerabilities, key=lambda x: x['severity'], reverse=True):
            color = Fore.RED if vuln['severity'] == 'Critical' else Fore.MAGENTA if vuln['severity'] == 'High' else Fore.YELLOW if vuln['severity'] == 'Medium' else Fore.CYAN
            print(f"{color}- {vuln['file']} (Line {vuln['line']}): {vuln['issue']} [{vuln['severity']}]{Style.RESET_ALL}")