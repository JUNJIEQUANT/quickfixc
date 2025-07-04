#!/usr/bin/env python3
"""
Enhanced Legacy Crypto Scanner for QuickFIX C++ Codebase
Improved accuracy with context analysis, config externalization, and advanced filtering
"""

import os
import re
import yaml
import json
from dataclasses import dataclass, asdict
from typing import List, Dict, Set, Optional, Tuple
from pathlib import Path
from enum import Enum

class ConfidenceLevel(Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM" 
    LOW = "LOW"

@dataclass
class CryptoFinding:
    file_path: str
    line_number: int
    line_content: str
    crypto_type: str
    algorithm: str
    severity: str
    confidence: str
    context_lines: List[str]
    description: str
    recommendation: str
    usage_type: str

class EnhancedLegacyCryptoScanner:
    def __init__(self, config_path: Optional[str] = None):
        self.findings: List[CryptoFinding] = []
        self.config = self.load_config(config_path)
        
        # Context analysis settings
        self.context_window = 3  # Lines before/after to analyze
        
        # Exclusion patterns (to reduce false positives)
        self.exclusion_patterns = [
            r'^\s*//',           # C++ line comments
            r'^\s*/\*',          # C++ block comment start
            r'\*/\s*$',          # C++ block comment end
            r'#define\s+\w+',    # Macro definitions (unless specifically crypto)
            r'enum\s+\w*',       # Enum definitions
            r'typedef\s+',       # Type definitions
            r'namespace\s+',     # Namespace declarations
            r'^\s*\*',           # Doxygen/comment continuation
            r'printf\s*\(',      # Debug/logging output
            r'std::cout\s*<<',   # Console output
            r'LOG\w*\s*\(',      # Logging statements
            r'const\s+int\s+\w*(?:DES|TRADES?|SIDES?)\w*\s*=',  # FIX protocol constants
            r'EncryptMethod_\w+\s*=',     # FIX protocol encryption method fields
            r'TrdType_\w+\s*=',           # FIX trade type fields  
            r'NoSides?\w*\s*=',           # FIX sides-related fields
            r'select_nodes?\(',           # XML library functions
        ]
        
        # High-confidence indicators (reduce false positives)
        self.high_confidence_indicators = {
            'function_calls': [
                r'\w+\s*\(',         # Function call pattern
                r'->\s*\w+\s*\(',    # Member function call
                r'::\s*\w+\s*\(',    # Namespace function call
            ],
            'assignments': [
                r'=\s*\w+',          # Assignment
                r'\w+\s*=',          # Variable assignment
            ],
            'declarations': [
                r'\w+\s+\*?\s*\w+',  # Variable declaration
                r'new\s+\w+',        # Object instantiation
            ]
        }

    def load_config(self, config_path: Optional[str] = None) -> Dict:
        """Load crypto patterns from external config file or use defaults"""
        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    if config_path.endswith('.yaml') or config_path.endswith('.yml'):
                        return yaml.safe_load(f)
                    else:
                        return json.load(f)
            except Exception as e:
                print(f"Warning: Could not load config {config_path}: {e}")
        
        # Default configuration (can be exported to YAML/JSON)
        return {
            'crypto_patterns': {
                'RSA': {
                    'patterns': [
                        r'SSL_CTX_use_RSAPrivateKey\s*\(',
                        r'EVP_PKEY_RSA\b',
                        r'RSA_\w+\s*\(',
                        r'PEM_read.*RSA\w*\s*\(',
                        r'RSA\s*\*\s*\w+',
                        r'RSA_new\s*\(',
                        r'RSA_free\s*\(',
                    ],
                    'severity': 'HIGH',
                    'description': 'RSA algorithm usage - not quantum resistant',
                    'recommendation': 'Replace with ML-DSA (NIST Dilithium) for signatures'
                },
                
                'DSA': {
                    'patterns': [
                        r'EVP_PKEY_DSA\b',
                        r'DSA_\w+\s*\(',
                        r'DSA\s*\*\s*\w+',
                        r'PEM_read.*DSA\w*\s*\(',
                    ],
                    'severity': 'HIGH',
                    'description': 'DSA algorithm usage - not quantum resistant',
                    'recommendation': 'Replace with ML-DSA (NIST Dilithium) for signatures'
                },
                
                'ECDSA_EC': {
                    'patterns': [
                        r'EVP_PKEY_EC\b',
                        r'EC_KEY_\w+\s*\(',
                        r'ECDH_\w+\s*\(',
                        r'SSL_CTX_set_tmp_ecdh\s*\(',
                        r'EC_KEY\s*\*\s*\w+',
                        r'NID_X9_62_prime256v1\b',
                        r'NID_secp\w+\b',
                    ],
                    'severity': 'HIGH', 
                    'description': 'ECDSA/EC algorithm usage - not quantum resistant',
                    'recommendation': 'Replace ECDSA with ML-DSA, ECDH with ML-KEM (Kyber)'
                },
                
                'DH': {
                    'patterns': [
                        r'DH_new\s*\(',
                        r'DH_free\s*\(',
                        r'SSL_CTX_set_tmp_dh\s*\(',
                        r'DH\s*\*\s*\w+',
                        r'DH_generate_\w+\s*\(',
                        r'ssl_callback_TmpDH\b',
                    ],
                    'severity': 'HIGH',
                    'description': 'Diffie-Hellman key exchange - not quantum resistant', 
                    'recommendation': 'Replace with ML-KEM (NIST Kyber) for key exchange'
                },
                
                'Legacy_TLS': {
                    'patterns': [
                        r'SSLv2_\w+_method\s*\(',
                        r'SSLv3_\w+_method\s*\(',
                        r'TLSv1_\w+_method\s*\(',
                        r'TLSv1_1_\w+_method\s*\(',
                        r'TLSv1_2_\w+_method\s*\(',
                        r'SSL_PROTOCOL_SSLV[23]\b',
                        r'SSL_PROTOCOL_TLSV1[^_3]\b',
                    ],
                    'severity': 'MEDIUM',
                    'description': 'Legacy SSL/TLS protocol versions',
                    'recommendation': 'Upgrade to TLS 1.3 with post-quantum cipher suites'
                },
                
                'Weak_Cipher': {
                    'patterns': [
                        r'RC4\b',
                        r'(?<![A-Za-z_])DES\b(?!C)',  # Must be word boundary on both sides
                        r'(?<![A-Za-z_])3DES\b',
                        r'MD5\b',
                        r'SHA1\b(?!6|28|384|512)',  # Avoid matching SHA-2 variants
                    ],
                    'severity': 'MEDIUM',
                    'description': 'Weak cipher or hash algorithm',
                    'recommendation': 'Use AES-256 and SHA-256/SHA-3 minimum'
                },
                
                'Weak_Key_Size': {
                    'patterns': [
                        r'(?:keylen|key_size|bits?)\s*[=<]\s*(?:512|1024)\b',
                        r'(?:512|1024).*(?:bit|key)',
                        r'get_rfc2409_prime_1024\b',
                    ],
                    'severity': 'MEDIUM', 
                    'description': 'Weak key size detected (≤1024 bits)',
                    'recommendation': 'Use minimum 2048-bit keys, preferably 3072+'
                }
            },
            
            'file_types': ['.cpp', '.h', '.hpp', '.cc', '.cxx', '.c'],
            'exclude_dirs': ['test', 'tests', 'examples', 'docs', '.git'],
            'exclude_files': ['*_test.cpp', '*_example.cpp', 'pugixml*', 'double-conversion*']
        }

    def export_config(self, output_path: str) -> None:
        """Export current configuration to YAML file"""
        try:
            with open(output_path, 'w') as f:
                yaml.dump(self.config, f, default_flow_style=False, indent=2)
            print(f"Configuration exported to {output_path}")
        except Exception as e:
            print(f"Error exporting config: {e}")

    def is_excluded_line(self, line: str) -> bool:
        """Check if line should be excluded from analysis"""
        line_stripped = line.strip()
        if not line_stripped:
            return True
            
        for pattern in self.exclusion_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return True
        return False

    def get_context_lines(self, lines: List[str], line_num: int) -> List[str]:
        """Get context lines around the target line"""
        start = max(0, line_num - self.context_window - 1)
        end = min(len(lines), line_num + self.context_window)
        return lines[start:end]

    def calculate_confidence(self, line: str, context_lines: List[str], algorithm: str) -> ConfidenceLevel:
        """Calculate confidence level for the finding"""
        confidence_score = 0
        
        if re.search(r'const\s+\w+\s+\w+(?:Method|Type)_\w+\s*=', line):
            return ConfidenceLevel.LOW
        
        # Check for enum/constant definitions (lower confidence) 
        if re.search(r'const\s+(?:int|char)\s+\w+\s*=', line):
            confidence_score -= 2
        
        # Check for function calls (higher confidence)
        for pattern in self.high_confidence_indicators['function_calls']:
            if re.search(pattern, line):
                confidence_score += 3
                
        # Check for assignments/declarations
        for pattern in self.high_confidence_indicators['assignments']:
            if re.search(pattern, line):
                confidence_score += 2
                
        # Context analysis - look for related crypto operations nearby
        context_text = ' '.join(context_lines)
        crypto_context_patterns = [
            r'SSL_CTX_\w+',
            r'certificate',
            r'private.*key',
            r'handshake',
            r'encrypt',
            r'decrypt',
            r'sign',
            r'verify'
        ]
        
        for pattern in crypto_context_patterns:
            if re.search(pattern, context_text, re.IGNORECASE):
                confidence_score += 1
                
        # Determine confidence level
        if confidence_score >= 4:
            return ConfidenceLevel.HIGH
        elif confidence_score >= 2:
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW

    def scan_file(self, file_path: str) -> None:
        """Scan a single file with enhanced accuracy"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                if self.is_excluded_line(line):
                    continue
                    
                for crypto_type, config in self.config['crypto_patterns'].items():
                    for pattern in config['patterns']:
                        match = re.search(pattern, line, re.IGNORECASE)
                        if match:
                            context_lines = self.get_context_lines(lines, line_num)
                            confidence = self.calculate_confidence(line, context_lines, crypto_type)
                            usage_type = self.determine_usage_type(line, context_lines, crypto_type)
                            
                            # Only include medium/high confidence findings
                            if confidence != ConfidenceLevel.LOW:
                                finding = CryptoFinding(
                                    file_path=file_path,
                                    line_number=line_num,
                                    line_content=line.rstrip(),
                                    crypto_type='Legacy Cryptography',
                                    algorithm=crypto_type,
                                    severity=config['severity'],
                                    confidence=confidence.value,
                                    context_lines=[l.rstrip() for l in context_lines],
                                    description=config['description'],
                                    recommendation=config['recommendation'],
                                    usage_type=usage_type
                                )
                                self.findings.append(finding)
                                
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")

    def scan_directory(self, directory: str) -> None:
        """Scan directory with file filtering"""
        allowed_extensions = set(self.config.get('file_types', ['.cpp', '.h']))
        exclude_dirs = set(self.config.get('exclude_dirs', []))
        
        for root, dirs, files in os.walk(directory):
            # Filter out excluded directories
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if any(file.endswith(ext) for ext in allowed_extensions):
                    file_path = os.path.join(root, file)
                    self.scan_file(file_path)

    def generate_detailed_report(self) -> str:
        """Generate enhanced report with confidence levels and recommendations"""
        if not self.findings:
            return "✅ No high-confidence legacy cryptography usage found."
        
        # Filter and sort findings
        high_conf_findings = [f for f in self.findings if f.confidence == 'HIGH']
        medium_conf_findings = [f for f in self.findings if f.confidence == 'MEDIUM']
        
        report = []
        report.append("=" * 90)
        report.append("🔍 ENHANCED QUICKFIX LEGACY CRYPTOGRAPHY SCAN REPORT")
        report.append("=" * 90)
        
        report.append(f"🎯 HIGH CONFIDENCE FINDINGS: {len(high_conf_findings)}")
        report.append(f"⚠️  MEDIUM CONFIDENCE FINDINGS: {len(medium_conf_findings)}")
        report.append(f"📊 TOTAL VERIFIED FINDINGS: {len(self.findings)}")
        report.append("")
        
        # Group by algorithm and confidence
        def report_findings_group(findings: List[CryptoFinding], confidence_label: str):
            if not findings:
                return
                
            by_algorithm = {}
            for finding in findings:
                if finding.algorithm not in by_algorithm:
                    by_algorithm[finding.algorithm] = []
                by_algorithm[finding.algorithm].append(finding)
            
            report.append(f"🔴 {confidence_label} FINDINGS")
            report.append("-" * 60)
            
            for algorithm in sorted(by_algorithm.keys()):
                alg_findings = by_algorithm[algorithm]
                report.append(f"📍 {algorithm.upper()} ({len(alg_findings)} occurrences)")
                report.append(f"   ❓ {alg_findings[0].description}")
                report.append(f"   💡 {alg_findings[0].recommendation}")
                report.append("")
                
                # Show top findings with context
                for finding in alg_findings[:3]:
                    report.append(f"   📄 {finding.file_path}:{finding.line_number}")
                    report.append(f"      Code: {finding.line_content}")
                    report.append(f"      Usage: {finding.usage_type}")
                    
                    # Show relevant context
                    if finding.context_lines:
                        context_start = max(0, len(finding.context_lines)//2 - 1)
                        context_end = min(len(finding.context_lines), context_start + 3)
                        report.append("      Context:")
                        for i, ctx_line in enumerate(finding.context_lines[context_start:context_end]):
                            marker = "  >>> " if i == 1 else "      "
                            report.append(f"      {marker}{ctx_line}")
                    report.append("")
                
                if len(alg_findings) > 3:
                    report.append(f"   ... and {len(alg_findings) - 3} more occurrences")
                report.append("")
        
        report_findings_group(high_conf_findings, "HIGH CONFIDENCE")
        report_findings_group(medium_conf_findings, "MEDIUM CONFIDENCE") 
        
        # Migration roadmap
        report.append("🚀 POST-QUANTUM MIGRATION ROADMAP")
        report.append("-" * 60)
        
        if high_conf_findings:
            rsa_count = len([f for f in high_conf_findings if 'RSA' in f.algorithm])
            ecdsa_count = len([f for f in high_conf_findings if 'ECDSA' in f.algorithm])
            dh_count = len([f for f in high_conf_findings if 'DH' in f.algorithm])
            
            report.append("🔥 IMMEDIATE ACTION REQUIRED:")
            if rsa_count > 0:
                report.append(f"   • {rsa_count} RSA usages → Migrate to ML-DSA (Dilithium)")
            if ecdsa_count > 0:
                report.append(f"   • {ecdsa_count} ECDSA/EC usages → Migrate to ML-DSA + ML-KEM")  
            if dh_count > 0:
                report.append(f"   • {dh_count} DH key exchanges → Migrate to ML-KEM (Kyber)")
        
        report.append("")
        report.append("📋 IMPLEMENTATION CHECKLIST:")
        report.append("  ☐ Integrate liboqs (Open Quantum Safe) library")
        report.append("  ☐ Implement hybrid classical/post-quantum mode")
        report.append("  ☐ Update certificate handling for larger PQ signatures")
        report.append("  ☐ Test interoperability with trading partners")
        report.append("  ☐ Performance benchmark PQ vs classical crypto")
        
        return "\n".join(report)

    def export_findings_json(self, output_path: str) -> None:
        """Export findings to JSON for further processing"""
        findings_dict = [asdict(finding) for finding in self.findings]
        try:
            with open(output_path, 'w') as f:
                json.dump(findings_dict, f, indent=2)
            print(f"Findings exported to {output_path}")
        except Exception as e:
            print(f"Error exporting findings: {e}")
    
    def determine_usage_type(self, line: str, context_lines: List[str], algorithm: str) -> str:
        """Determine the usage type based on context analysis"""
        combined_text = line + ' ' + ' '.join(context_lines)
        line_lower = line.lower()
        
        # High-priority specific API patterns (most precise)
        specific_api_patterns = {
            'Key Exchange': [
                r'ssl_callback_tmpdh\b',
                r'SSL_CTX_set_tmp_(?:dh|ecdh)\s*\(',
                r'DH_generate_parameters\s*\(',
                r'EC_KEY_new_by_curve_name\s*\(',
                r'tmp.*(?:dh|ecdh)',
                r'ephemeral.*key',
                r'EVP_PKEY_(?:RSA|DSA).*(?:in.*dh|tmp.*dh|callback.*dh)',
            ],
            'Signature': [
                r'SSL_CTX_use_(?:certificate|PrivateKey)\s*\(',
                r'PEM_read.*(?:certificate|PrivateKey)\s*\(',
                r'X509.*(?:sign|verify)',
                r'RSA.*(?:sign|verify)',
                r'DSA.*(?:sign|verify)',
                r'ECDSA.*(?:sign|verify)',
            ],
            'Encryption': [
                r'(?:encrypt|decrypt).*(?:RSA|AES)',
                r'RSA.*(?:encrypt|decrypt)',
                r'cipher.*(?:encrypt|decrypt)',
            ],
            'Protocol/Transport': [
                r'SSL_PROTOCOL_\w+',
                r'TLS.*(?:method|version)',
                r'SSL.*(?:method|version)',
            ]
        }
        
        # Check specific API patterns first (highest priority)
        for usage_type, patterns in specific_api_patterns.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    return usage_type
        
        # Function context analysis
        function_context_patterns = {
            'Key Exchange': [
                r'(?:tmp|temp|ephemeral).*(?:dh|ecdh|key)',
                r'dh.*(?:callback|param|generate)',
                r'key.*(?:exchange|agreement)',
                r'handshake.*(?:dh|ecdh)',
            ],
            'Signature': [
                r'(?:sign|verify).*(?:cert|key)',
                r'certificate.*(?:load|use|set)',
                r'private.*key.*(?:load|use|set)',
                r'auth(?:entication)?.*key',
            ]
        }
        
        for usage_type, patterns in function_context_patterns.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    return usage_type
        
        # Variable name analysis  
        if re.search(r'(?:tmp|temp|ephemeral).*(?:dh|ecdh)', line_lower):
            return "Key Exchange"
        if re.search(r'(?:cert|certificate|private.*key)', line_lower):
            return "Signature"
            
        # Original broad patterns (lower priority)
        broad_patterns = {
            'Signature': [
                r'sign(?:ature)?', r'verify', r'certificate', r'auth(?:entication)?'
            ],
            'Encryption': [
                r'encrypt', r'decrypt', r'cipher'
            ],
            'Key Exchange': [
                r'key.*exchange', r'key.*agreement', r'handshake'
            ],
            'Protocol/Transport': [
                r'protocol.*version', r'ssl.*method', r'tls.*method'
            ]
        }
        
        for usage_type, patterns in broad_patterns.items():
            for pattern in patterns:
                if re.search(pattern, combined_text, re.IGNORECASE):
                    return usage_type
        
        # Algorithm-based defaults (last resort)
        algorithm_defaults = {
            'RSA': 'Signature',           # Most common RSA usage
            'DSA': 'Signature', 
            'ECDSA_EC': 'Key Exchange',   # Context usually shows ECDH
            'DH': 'Key Exchange',
            'Legacy_TLS': 'Protocol/Transport',
            'Weak_Cipher': 'Encryption',
            'Weak_Key_Size': 'General'
        }
        
        return algorithm_defaults.get(algorithm, 'Unknown')
    
    def export_findings_csv(self, output_path: str) -> None:
        """Export findings to CSV for analysis"""
        import csv
        
        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = [
                    'file_path', 'line_number', 'algorithm', 'usage_type', 
                    'severity', 'confidence', 'description', 'recommendation',
                    'line_content'
                ]
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                
                writer.writeheader()
                for finding in self.findings:
                    writer.writerow({
                        'file_path': finding.file_path,
                        'line_number': finding.line_number,
                        'algorithm': finding.algorithm,
                        'usage_type': finding.usage_type,
                        'severity': finding.severity,
                        'confidence': finding.confidence,
                        'description': finding.description,
                        'recommendation': finding.recommendation,
                        'line_content': finding.line_content
                    })
            print(f"CSV findings exported to {output_path}")
        except Exception as e:
            print(f"Error exporting CSV: {e}")

def main():
    """Enhanced main function with real file scanning"""
    import argparse
    import sys
    
    parser = argparse.ArgumentParser(description='Enhanced QuickFIX Legacy Cryptography Scanner')
    parser.add_argument('--path', '-p', default='.', 
                        help='Path to scan (default: current directory)')
    parser.add_argument('--config', '-c', 
                        help='Path to custom configuration file')
    parser.add_argument('--export-config', action='store_true',
                        help='Export default configuration to crypto_scan_config.yaml')
    parser.add_argument('--output', '-o', default='crypto_findings.json',
                        help='Output JSON file for findings')
    parser.add_argument('--csv', default='crypto_findings.csv',  
                        help='Output CSV file for findings')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Verbose output showing files being scanned')
    
    args = parser.parse_args()
    
    scanner = EnhancedLegacyCryptoScanner(args.config)
    
    print("🔍 Enhanced QuickFIX Legacy Cryptography Scanner")
    print("Features: Context analysis, confidence scoring, config externalization")
    print()
    
    # Export config if requested
    if args.export_config:
        scanner.export_config("crypto_scan_config.yaml")
        print("✅ Default configuration exported to crypto_scan_config.yaml")
        print()
    
    # Scan the specified path
    scan_path = os.path.abspath(args.path)
    print(f"🔍 Scanning path: {scan_path}")
    
    if not os.path.exists(scan_path):
        print(f"❌ Error: Path '{scan_path}' does not exist")
        sys.exit(1)
    
    # Count files before scanning
    cpp_extensions = set(scanner.config.get('file_types', ['.cpp', '.h']))
    total_files = 0
    
    if os.path.isfile(scan_path):
        if any(scan_path.endswith(ext) for ext in cpp_extensions):
            total_files = 1
            if args.verbose:
                print(f"📄 Scanning file: {scan_path}")
            scanner.scan_file(scan_path)
        else:
            print(f"❌ Error: File '{scan_path}' is not a supported C++ file type")
            sys.exit(1)
    else:
        # Count files first
        for root, dirs, files in os.walk(scan_path):
            # Apply directory exclusions
            exclude_dirs = set(scanner.config.get('exclude_dirs', []))
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if any(file.endswith(ext) for ext in cpp_extensions):
                    total_files += 1
        
        print(f"📊 Found {total_files} C++ files to scan")
        
        if args.verbose:
            print("📁 Scanning files:")
        
        # Now scan
        for root, dirs, files in os.walk(scan_path):
            # Apply directory exclusions
            exclude_dirs = set(scanner.config.get('exclude_dirs', []))
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            
            for file in files:
                if any(file.endswith(ext) for ext in cpp_extensions):
                    file_path = os.path.join(root, file)
                    if args.verbose:
                        print(f"   📄 {file_path}")
                    scanner.scan_file(file_path)
    
    print(f"✅ Scan complete. Analyzed {total_files} files.")
    print()
    
    # Generate and display report
    report = scanner.generate_detailed_report()
    print(report)
    
    # Export findings
    if scanner.findings:
        scanner.export_findings_json(args.output)
        scanner.export_findings_csv(args.csv)
        print(f"\n📄 Detailed findings exported to {args.output}")
    
    # Return appropriate exit code for CI/CD
    high_severity_count = len([f for f in scanner.findings if f.severity == 'HIGH'])
    if high_severity_count > 0:
        print(f"\n🚨 WARNING: {high_severity_count} high-severity crypto findings detected!")
        # Optionally exit with error code for CI/CD: sys.exit(1)
    
    

if __name__ == "__main__":
    main()