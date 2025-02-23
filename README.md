# GitCodeSentry

![GitCodeSentry Logo](logo.png)

**GitCodeSentry** is a powerful terminal-based tool designed to scan GitHub repositories or local directories for code vulnerabilities, with a focus on GitHub rendering exploits and obfuscated malicious patterns. Whether you're auditing a public repo or checking your local codebase, GitCodeSentry helps uncover hidden threats like self-replicating worms, encoded payloads, and suspicious scripts.

Inspired by real-world examples (e.g., [GitHub Community Discussion #151605](https://github.com/orgs/community/discussions/151605) and [infected code samples](https://pastebin.com/raw/M8cps9iB)), this tool is built to keep your code safe.

## Features

- **GitHub URL Scanning**: Analyzes public repositories directly via GitHub's API.
- **Local Directory Scanning**: Inspects files in any local folder.
- **Advanced Vulnerability Detection**:
  - Obfuscated code (Base64, hex, Unicode tricks).
  - Suspicious keywords (`eval`, `exec`, `subprocess`, `infect`, etc.).
  - Markdown rendering risks (hidden scripts, executable code blocks).
  - Dynamic execution and import patterns.
- **Color-Coded Reports**: Prioritizes findings by severity (Critical, High, Medium, Low).
- **Extensible**: Easily add new patterns or refine detection logic.

## Installation

1. Clone or download this repository:
   ```bash
   git clone https://github.com/makalin/GitCodeSentry.git
   cd GitCodeSentry
   ```
2. Install dependencies:
   ```bash
   pip install requests colorama
   ```
3. Run the tool with Python 3.x:
   ```bash
   python main.py --help
   ```

## Usage

Scan a GitHub repository:
```bash
python main.py --url https://github.com/org/repo
```

Scan a local directory:
```bash
python main.py --dir /path/to/code
```

### Example Output
```
Scan Summary:
Total issues found: 5
Critical: 1
High: 2
Medium: 1
Low: 0

Detailed Findings:
- test.py (Line 15): Decoded Base64 contains suspicious content: import os... [Critical]
- test.py (Line 6): Suspicious keyword "os.walk" detected [High]
- test.py (Line 15): Potential obfuscation via "base64.b64decode" [High]
- test.py (Line 6): Suspicious keyword "infect" detected [Medium]
```

## How It Works

1. **Input**: Provide a GitHub URL or local directory path.
2. **Fetching**: Pulls files from GitHub or reads local files.
3. **Analysis**: Scans for:
   - Encoded payloads (Base64, hex, compression libraries).
   - Malware-like patterns (`os.walk`, `subprocess`, `pickle.loads`).
   - Markdown exploits (`<script>`, executable code blocks).
   - Unicode obfuscation (e.g., RTL overrides).
4. **Reporting**: Outputs a detailed, color-coded report.

## Detected Threats

- **Self-Replicating Worms**: Like the [Pastebin example](https://pastebin.com/raw/M8cps9iB).
- **GitHub Rendering Exploits**: Hidden code that executes when viewed or cloned.
- **Obfuscated Backdoors**: Encoded strings or dynamic imports.

## To-Do

- Add support for private repos (GitHub token authentication).
- Export reports to JSON or CSV.
- Fine-tune detection to reduce false positives.
- Expand pattern library (e.g., `requests`, `socket` for network-based threats).

## Contributing

Contributions are welcome! To add new detection patterns or improve the tool:
1. Fork the repo.
2. Create a feature branch (`git checkout -b feature/new-pattern`).
3. Commit changes (`git commit -m "Add X detection"`).
4. Push to your fork (`git push origin feature/new-pattern`).
5. Open a pull request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Built with inspiration from GitHub community discussions and real-world malware samples.
- Powered by Python, `requests`, and `colorama`.

---

Keep your code safe with GitCodeSentry!
