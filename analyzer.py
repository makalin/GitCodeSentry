import base64
import re
import unicodedata
import binascii

class CodeAnalyzer:
    def analyze(self, file_path, content):
        vulnerabilities = []
        lines = content.splitlines()

        # Suspicious keywords and patterns
        suspicious_keywords = [
            'infect', 'os.walk', 'os.system', 'subprocess', 'eval', 'exec',
            'pickle.loads', 'marshal.loads', 'codeop', 'sys.executable',
            '__import__', 'builtins'
        ]
        encoding_methods = [
            'base64.b64decode', 'binascii.unhexlify', 'zlib.decompress',
            'gzip.decompress', 'bz2.decompress'
        ]

        for i, line in enumerate(lines, 1):
            line_lower = line.lower()

            # Markdown-specific checks
            if file_path.endswith('.md'):
                if '<script' in line_lower or 'javascript:' in line_lower:
                    vulnerabilities.append({
                        'file': file_path,
                        'line': i,
                        'issue': 'Embedded script or JS link in Markdown',
                        'severity': 'Critical'
                    })
                if re.search(r'```.*(eval|exec|os\.|subprocess)', line, re.IGNORECASE):
                    vulnerabilities.append({
                        'file': file_path,
                        'line': i,
                        'issue': 'Suspicious code block with execution risk',
                        'severity': 'High'
                    })

            # Code-specific checks (Python assumed for .py, but extensible)
            if file_path.endswith(('.py', '.pyw')):
                # Suspicious keywords
                for kw in suspicious_keywords:
                    if kw in line:
                        vulnerabilities.append({
                            'file': file_path,
                            'line': i,
                            'issue': f'Suspicious keyword "{kw}" detected',
                            'severity': 'High' if kw in ['eval', 'exec', 'subprocess'] else 'Medium'
                        })

                # Encoding/decoding methods
                for enc in encoding_methods:
                    if enc in line:
                        vulnerabilities.append({
                            'file': file_path,
                            'line': i,
                            'issue': f'Potential obfuscation via "{enc}"',
                            'severity': 'High'
                        })
                        # Try to decode base64 as an example
                        if enc == 'base64.b64decode':
                            base64_match = re.search(r'base64\.b64decode$$ [\'"]([A-Za-z0-9+/=]+)[\'"] $$', line)
                            if base64_match:
                                try:
                                    decoded = base64.b64decode(base64_match.group(1)).decode('utf-8', errors='ignore')
                                    if any(kw in decoded for kw in suspicious_keywords):
                                        vulnerabilities.append({
                                            'file': file_path,
                                            'line': i,
                                            'issue': f'Decoded Base64 contains suspicious content: {decoded[:50]}...',
                                            'severity': 'Critical'
                                        })
                                except:
                                    pass  # Invalid base64, skip

                # Dynamic imports or string-based execution
                if re.search(r'__import__$$ [\'"].+[\'"] $$', line):
                    vulnerabilities.append({
                        'file': file_path,
                        'line': i,
                        'issue': 'Dynamic import detected - potential obfuscation',
                        'severity': 'Medium'
                    })

            # General checks across all files
            # Unusual Unicode (obfuscation or RTL tricks)
            if any(ord(char) > 127 for char in line):
                unicode_chars = [char for char in line if ord(char) > 127]
                if any(ord(char) in [8234, 8235, 8236, 8237, 8238] for char in line):  # RTL/LTR controls
                    severity = 'High'
                    issue = 'Suspicious Unicode control characters (e.g., RTL override)'
                else:
                    severity = 'Low'
                    issue = f'Unusual Unicode characters: {unicode_chars[:5]}...'
                vulnerabilities.append({
                    'file': file_path,
                    'line': i,
                    'issue': issue,
                    'severity': severity
                })

            # Encoded string literals (e.g., hex or escaped sequences)
            if re.search(r'\\x[0-9a-fA-F]{2}', line) or re.search(r'0x[0-9a-fA-F]+', line):
                vulnerabilities.append({
                    'file': file_path,
                    'line': i,
                    'issue': 'Encoded string literal detected - possible obfuscation',
                    'severity': 'Medium'
                })

        return vulnerabilities