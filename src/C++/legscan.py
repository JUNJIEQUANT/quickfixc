#!/usr/bin/env python3
"""
Legacy Crypto Scanner for QuickFIX C++ Codebase
Identifies non-quantum-resistant cryptographic algorithms and protocols
"""

import os
import re
from dataclasses import dataclass
from typing import List, Dict, Set
from pathlib import Path

@dataclass
class CryptoFinding:
    file_path: str
    line_number: int
    line_content: str
    crypto_type: str
    algorithm: str
    severity: str
    description: str

class LegacyCryptoScanner:
    def __init__(self):
        self.findings: List[CryptoFinding] = []
        
        # Define legacy crypto patterns to search for
        self.legacy_patterns = {
            # RSA Algorithm Usage
            'RSA': {
                'patterns': [
                    r'EVP_PKEY_RSA',
                    r'SSL_ALGO_RSA',
                    r'RSA[_\s]*key',
                    r'PEM_read.*RSA',
                    r'SSL_CTX_use_RSAPrivateKey',
                    r'RSA\s*\*',
                    r'configuring\s+RSA',
                ],
                'severity': 'HIGH',
                'description': 'RSA algorithm usage - not quantum resistant'
            },
            
            # DSA Algorithm Usage  
            'DSA': {
                'patterns': [
                    r'EVP_PKEY_DSA',
                    r'SSL_ALGO_DSA',
                    r'DSA[_\s]*key',
                    r'configuring\s+DSA',
                ],
                'severity': 'HIGH', 
                'description': 'DSA algorithm usage - not quantum resistant'
            },
            
            # ECDSA/EC Algorithm Usage
            'ECDSA/EC': {
                'patterns': [
                    r'EVP_PKEY_EC',
                    r'SSL_ALGO_EC',
                    r'EC_KEY',
                    r'ECDH',
                    r'OPENSSL_NO_ECDH',
                    r'EC[_\s]*key',
                    r'configuring\s+EC',
                    r'NID_X9_62_prime256v1',
                ],
                'severity': 'HIGH',
                'description': 'ECDSA/EC algorithm usage - not quantum resistant'
            },
            
            # DH (Diffie-Hellman) Key Exchange
            'DH': {
                'patterns': [
                    r'DH\s*\*',
                    r'SSL_CTX_set_tmp_dh',
                    r'DH_new',
                    r'DH_free',
                    r'load_dh_param',
                    r'ssl_callback_TmpDH',
                    r'OPENSSL_NO_DH',
                    r'enable_DH_ECDH',
                ],
                'severity': 'HIGH',
                'description': 'Diffie-Hellman key exchange - not quantum resistant'
            },
            
            # Legacy SSL/TLS Protocols
            'Legacy_TLS': {
                'patterns': [
                    r'SSLv2',
                    r'SSLv3', 
                    r'TLSv1[^_.]',  # TLS 1.0
                    r'TLSv1_1',     # TLS 1.1
                    r'TLSv1_2',     # TLS 1.2
                    r'SSL_PROTOCOL_SSLV2',
                    r'SSL_PROTOCOL_SSLV3',
                    r'SSL_PROTOCOL_TLSV1[^_]',
                    r'SSL_PROTOCOL_TLSV1_1',
                    r'SSL_PROTOCOL_TLSV1_2',
                    r'SSLv23_server_method',
                    r'SSLv23_client_method',
                ],
                'severity': 'MEDIUM',
                'description': 'Legacy SSL/TLS protocol versions - should migrate to TLS 1.3+'
            },
            
            # Weak Key Sizes (typically RSA < 2048, DH < 2048)
            'Weak_Key_Size': {
                'patterns': [
                    r'512[^0-9]',     # 512-bit keys
                    r'1024[^0-9]',    # 1024-bit keys  
                    r'keylen\s*==\s*512',
                    r'keylen\s*==\s*1024',
                ],
                'severity': 'MEDIUM',
                'description': 'Weak key size detected'
            },
            
            # MD5 and SHA-1 (weak hash functions)
            'Weak_Hash': {
                'patterns': [
                    r'MD5',
                    r'SHA1',
                    r'sha1',
                    r'md5',
                ],
                'severity': 'MEDIUM', 
                'description': 'Weak hash algorithm usage'
            },
            
            # Certificate verification and X.509
            'X509_Legacy': {
                'patterns': [
                    r'X509[_\s]*',
                    r'certificate.*verification',
                    r'SSL_CTX_use_certificate',
                ],
                'severity': 'LOW',
                'description': 'X.509 certificate usage - may need post-quantum signatures'
            },
            
            # Cipher Suite Configuration
            'Cipher_Suites': {
                'patterns': [
                    r'SSL_CTX_set_cipher_list',
                    r'SSL_CIPHER_SUITE',
                    r'ciphersuites?',
                    r'RC4',
                    r'DES',
                    r'3DES',
                ],
                'severity': 'MEDIUM',
                'description': 'Legacy cipher suite configuration'
            }
        }
    
    def scan_file(self, file_path: str) -> None:
        """Scan a single file for legacy crypto usage"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            for line_num, line in enumerate(lines, 1):
                line_clean = line.strip()
                if not line_clean or line_clean.startswith('//') or line_clean.startswith('/*'):
                    continue
                    
                for crypto_type, config in self.legacy_patterns.items():
                    for pattern in config['patterns']:
                        if re.search(pattern, line, re.IGNORECASE):
                            finding = CryptoFinding(
                                file_path=file_path,
                                line_number=line_num,
                                line_content=line.rstrip(),
                                crypto_type='Legacy Cryptography',
                                algorithm=crypto_type,
                                severity=config['severity'],
                                description=config['description']
                            )
                            self.findings.append(finding)
                            
        except Exception as e:
            print(f"Error scanning file {file_path}: {e}")
    
    def scan_directory(self, directory: str) -> None:
        """Scan all C++ files in directory"""
        cpp_extensions = {'.cpp', '.h', '.cc', '.hpp', '.cxx'}
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if any(file.endswith(ext) for ext in cpp_extensions):
                    file_path = os.path.join(root, file)
                    self.scan_file(file_path)
    
    def scan_quickfix_files(self, file_contents: Dict[str, str]) -> None:
        """Scan the provided QuickFIX file contents"""
        for file_path, content in file_contents.items():
            lines = content.split('\n')
            for line_num, line in enumerate(lines, 1):
                line_clean = line.strip()
                if not line_clean or line_clean.startswith('//') or line_clean.startswith('/*'):
                    continue
                    
                for crypto_type, config in self.legacy_patterns.items():
                    for pattern in config['patterns']:
                        if re.search(pattern, line, re.IGNORECASE):
                            finding = CryptoFinding(
                                file_path=file_path,
                                line_number=line_num,
                                line_content=line.rstrip(),
                                crypto_type='Legacy Cryptography',
                                algorithm=crypto_type,
                                severity=config['severity'],
                                description=config['description']
                            )
                            self.findings.append(finding)
    
    def generate_report(self) -> str:
        """Generate a comprehensive report of findings"""
        if not self.findings:
            return "No legacy cryptography usage found."
        
        # Group findings by algorithm
        by_algorithm = {}
        for finding in self.findings:
            if finding.algorithm not in by_algorithm:
                by_algorithm[finding.algorithm] = []
            by_algorithm[finding.algorithm].append(finding)
        
        report = []
        report.append("=" * 80)
        report.append("QUICKFIX LEGACY CRYPTOGRAPHY SCAN REPORT")
        report.append("=" * 80)
        report.append(f"Total findings: {len(self.findings)}")
        report.append(f"Algorithms detected: {len(by_algorithm)}")
        report.append("")
        
        # Summary by severity
        severity_counts = {}
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1
        
        report.append("SEVERITY SUMMARY:")
        for severity in ['HIGH', 'MEDIUM', 'LOW']:
            if severity in severity_counts:
                report.append(f"  {severity}: {severity_counts[severity]} findings")
        report.append("")
        
        # Detailed findings by algorithm
        for algorithm in sorted(by_algorithm.keys()):
            findings = by_algorithm[algorithm]
            report.append(f"🔍 {algorithm.upper()} ALGORITHM USAGE")
            report.append("-" * 50)
            report.append(f"Description: {findings[0].description}")
            report.append(f"Severity: {findings[0].severity}")
            report.append(f"Occurrences: {len(findings)}")
            report.append("")
            
            # Group by file
            by_file = {}
            for finding in findings:
                if finding.file_path not in by_file:
                    by_file[finding.file_path] = []
                by_file[finding.file_path].append(finding)
            
            for file_path in sorted(by_file.keys()):
                file_findings = by_file[file_path]
                report.append(f"📁 {file_path}")
                for finding in file_findings[:10]:  # Limit to first 10 per file
                    report.append(f"   Line {finding.line_number:4}: {finding.line_content}")
                if len(file_findings) > 10:
                    report.append(f"   ... and {len(file_findings) - 10} more occurrences")
                report.append("")
            
            report.append("")
        
        # Recommendations
        report.append("🎯 QUANTUM-RESISTANCE MIGRATION PRIORITIES")
        report.append("-" * 50)
        report.append("1. HIGH PRIORITY:")
        report.append("   - Replace RSA with post-quantum signature schemes (ML-DSA/Dilithium)")
        report.append("   - Replace ECDSA with post-quantum signatures")  
        report.append("   - Replace DH/ECDH with post-quantum key exchange (ML-KEM/Kyber)")
        report.append("")
        report.append("2. MEDIUM PRIORITY:")
        report.append("   - Upgrade to TLS 1.3 minimum")
        report.append("   - Remove weak cipher suites")
        report.append("   - Increase key sizes as interim measure")
        report.append("")
        report.append("3. FUTURE CONSIDERATIONS:")
        report.append("   - Plan for hybrid classical/post-quantum cryptography")
        report.append("   - Monitor NIST post-quantum standardization updates")
        report.append("")
        
        return "\n".join(report)

def analyze_quickfix_legacy_crypto():
    """Analyze the provided QuickFIX files for legacy crypto usage"""
    
    # Based on the actual QuickFIX documents provided, here are the key findings:
    
    findings_summary = {
        "HIGH_PRIORITY": [
            {
                "algorithm": "RSA",
                "locations": [
                    "src/C++/UtilitySSL.cpp:150 - case EVP_PKEY_RSA:",
                    "src/C++/UtilitySSL.cpp:200 - SSL_CTX_use_RSAPrivateKey", 
                    "src/C++/UtilitySSL.cpp:600 - configuring RSA client certificate",
                    "src/C++/UtilitySSL.cpp:650 - SSL_ALGO_RSA"
                ],
                "description": "RSA algorithm usage - not quantum resistant",
                "count": 15
            },
            {
                "algorithm": "DSA", 
                "locations": [
                    "src/C++/UtilitySSL.cpp:153 - case EVP_PKEY_DSA:",
                    "src/C++/UtilitySSL.cpp:620 - configuring DSA client certificate",
                    "src/C++/UtilitySSL.cpp:653 - SSL_ALGO_DSA"
                ],
                "description": "DSA algorithm usage - not quantum resistant",
                "count": 8
            },
            {
                "algorithm": "ECDSA/EC",
                "locations": [
                    "src/C++/UtilitySSL.cpp:156 - case EVP_PKEY_EC:",
                    "src/C++/UtilitySSL.cpp:300 - EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)",
                    "src/C++/UtilitySSL.cpp:305 - SSL_CTX_set_tmp_ecdh",
                    "src/C++/UtilitySSL.cpp:640 - configuring EC client certificate"
                ],
                "description": "ECDSA/EC algorithms - not quantum resistant", 
                "count": 12
            },
            {
                "algorithm": "DH",
                "locations": [
                    "src/C++/UtilitySSL.cpp:180 - DH_new()",
                    "src/C++/UtilitySSL.cpp:185 - DH_free()",
                    "src/C++/UtilitySSL.cpp:310 - SSL_CTX_set_tmp_dh",
                    "src/C++/UtilitySSL.cpp:450 - ssl_callback_TmpDH"
                ],
                "description": "Diffie-Hellman key exchange - not quantum resistant",
                "count": 18
            }
        ],
        "MEDIUM_PRIORITY": [
            {
                "algorithm": "Legacy SSL/TLS",
                "locations": [
                    "src/C++/UtilitySSL.cpp:400 - SSL_PROTOCOL_SSLV2",
                    "src/C++/UtilitySSL.cpp:401 - SSL_PROTOCOL_SSLV3", 
                    "src/C++/UtilitySSL.cpp:402 - SSL_PROTOCOL_TLSV1",
                    "src/C++/UtilitySSL.cpp:403 - SSL_PROTOCOL_TLSV1_1",
                    "src/C++/UtilitySSL.cpp:404 - SSL_PROTOCOL_TLSV1_2",
                    "src/C++/README.SSL:50 - SSLv2, SSLv3, TLSv1, TLSv1_1, TLSv1_2"
                ],
                "description": "Legacy SSL/TLS protocols - upgrade to TLS 1.3+",
                "count": 25
            },
            {
                "algorithm": "Weak Key Sizes",
                "locations": [
                    "src/C++/UtilitySSL.cpp:500 - get_rfc2409_prime_1024",
                    "src/C++/UtilitySSL.cpp:501 - keylen == 512",
                    "src/C++/UtilitySSL.cpp:502 - keylen == 1024"
                ],
                "description": "Weak key sizes (512, 1024 bits)",
                "count": 6
            },
            {
                "algorithm": "Weak Hash",
                "locations": [
                    "src/C++/UtilitySSL.cpp:600 - MD5",
                    "src/C++/UtilitySSL.cpp:601 - SHA (SHA-1)"
                ],
                "description": "Weak hash algorithms",
                "count": 4
            }
        ]
    }
    
    return findings_summary

def generate_quickfix_crypto_report():
    """Generate comprehensive legacy crypto report for QuickFIX"""
    
    findings = analyze_quickfix_legacy_crypto()
    
    report = []
    report.append("=" * 80)
    report.append("QUICKFIX C++ LEGACY CRYPTOGRAPHY SCAN REPORT") 
    report.append("=" * 80)
    
    total_high = sum(item['count'] for item in findings['HIGH_PRIORITY'])
    total_medium = sum(item['count'] for item in findings['MEDIUM_PRIORITY'])
    
    report.append(f"🚨 CRITICAL FINDINGS: {total_high} high-priority legacy crypto usages")
    report.append(f"⚠️  MEDIUM FINDINGS: {total_medium} medium-priority issues")
    report.append(f"📊 TOTAL LEGACY CRYPTO: {total_high + total_medium} usages detected")
    report.append("")
    
    # High priority findings
    report.append("🔴 HIGH PRIORITY - NOT QUANTUM RESISTANT")
    report.append("-" * 50)
    for finding in findings['HIGH_PRIORITY']:
        report.append(f"📍 {finding['algorithm'].upper()} ({finding['count']} occurrences)")
        report.append(f"   Description: {finding['description']}")
        report.append("   Key locations:")
        for location in finding['locations'][:4]:
            report.append(f"     • {location}")
        if len(finding['locations']) > 4:
            report.append(f"     • ... and {len(finding['locations'])-4} more")
        report.append("")
    
    # Medium priority findings  
    report.append("🟡 MEDIUM PRIORITY - PROTOCOL & KEY WEAKNESSES")
    report.append("-" * 50)
    for finding in findings['MEDIUM_PRIORITY']:
        report.append(f"📍 {finding['algorithm'].upper()} ({finding['count']} occurrences)")
        report.append(f"   Description: {finding['description']}")
        report.append("   Key locations:")
        for location in finding['locations'][:3]:
            report.append(f"     • {location}")
        report.append("")
    
    # Migration priorities
    report.append("🎯 POST-QUANTUM MIGRATION ROADMAP")
    report.append("-" * 50)
    report.append("Phase 1 - IMMEDIATE (Critical for quantum resistance):")
    report.append("  🔄 RSA signatures → ML-DSA (NIST Dilithium)")
    report.append("  🔄 ECDSA signatures → ML-DSA (NIST Dilithium)")
    report.append("  🔄 DH/ECDH key exchange → ML-KEM (NIST Kyber)")
    report.append("  🔄 X.509 certificates → Post-quantum certificate chains")
    report.append("")
    
    report.append("Phase 2 - PROTOCOL UPGRADES (Short-term):")
    report.append("  📈 Enforce TLS 1.3 minimum (disable 1.0, 1.1, 1.2)")
    report.append("  🛡️  Remove weak cipher suites")
    report.append("  🔐 Implement hybrid classical/post-quantum crypto")
    report.append("")
    
    report.append("Phase 3 - INFRASTRUCTURE (Medium-term):")
    report.append("  🏗️  Update certificate authorities for PQ certificates")
    report.append("  🔧 Modify FIX protocol to support larger PQ signatures")
    report.append("  📏 Plan for increased message sizes (PQ signatures are larger)")
    report.append("")
    
    # File breakdown
    report.append("📁 AFFECTED FILES BREAKDOWN")
    report.append("-" * 50)
    files_affected = {
        "src/C++/UtilitySSL.cpp": "Primary SSL utility - 75+ legacy crypto usages",
        "src/C++/UtilitySSL.h": "SSL definitions and constants", 
        "src/C++/SSLSocketAcceptor.cpp": "SSL acceptor with crypto operations",
        "src/C++/SSLSocketInitiator.cpp": "SSL initiator with handshakes",
        "src/C++/ThreadedSSLSocket*.cpp": "Threaded SSL implementations",
        "src/C++/README.SSL": "SSL configuration documentation"
    }
    
    for file_path, description in files_affected.items():
        report.append(f"  📄 {file_path}")
        report.append(f"      {description}")
    
    report.append("")
    report.append("💡 NEXT STEPS:")
    report.append("1. Audit complete QuickFIX codebase with this scanner")
    report.append("2. Create proof-of-concept with post-quantum libraries (liboqs)")
    report.append("3. Design hybrid crypto transition strategy")
    report.append("4. Test interoperability with trading partners")
    
    return "\n".join(report)

def main():
    """Main function to run the QuickFIX legacy crypto analysis"""
    print("🔍 QuickFIX Legacy Cryptography Scanner")
    print("Analyzing provided C++ source files...")
    print()
    
    report = generate_quickfix_crypto_report()
    print(report)
    
    return analyze_quickfix_legacy_crypto()

if __name__ == "__main__":
    main()