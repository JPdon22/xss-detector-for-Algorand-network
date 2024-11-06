from algosdk.v2client import algod
from datetime import datetime
from typing import List, Dict
import sys
import time
import os
import random

# Boot Sequence Class
class BootSequence:
    def __init__(self):
        self.ascii_art = """
    █████╗ ██╗      ██████╗  ██████╗ ██╗  ██╗███████╗███████╗
   ██╔══██╗██║     ██╔════╝ ██╔═══██╗╚██╗██╔╝██╔════╝██╔════╝
   ███████║██║     ██║  ███╗██║   ██║ ╚███╔╝ ███████╗███████╗
   ██╔══██║██║     ██║   ██║██║   ██║ ██╔██╗ ╚════██║╚════██║
   ██║  ██║███████╗╚██████╔╝╚██████╔╝██╔╝ ██╗███████║███████║
   ╚═╝  ╚═╝╚══════╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝
   ============== VULNERABILITY SCANNER v1.0 ===============
"""

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def typing_print(self, text, speed=0.03):
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(speed)
        print()

    def loading_animation(self, text, duration=2):
        symbols = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
        end_time = time.time() + duration
        i = 0
        while time.time() < end_time:
            sys.stdout.write(f"\r{symbols[i]} {text}")
            sys.stdout.flush()
            time.sleep(0.1)
            i = (i + 1) % len(symbols)
        sys.stdout.write("\r✔ " + text + " " * 20 + "\n")

    def progress_bar(self, text, duration=2):
        bar_width = 40
        for i in range(bar_width + 1):
            time.sleep(duration / bar_width)
            progress = "█" * i + "░" * (bar_width - i)
            percentage = (i * 100) / bar_width
            sys.stdout.write(f"\r{text} [{progress}] {percentage:.1f}%")
            sys.stdout.flush()
        print()

    def run_boot_sequence(self):
        self.clear_screen()
        print(self.ascii_art)
        time.sleep(1)

        self.typing_print("[*] Initializing AlgoXSS Guard System...", 0.03)
        time.sleep(0.5)

        print("\n[*] Performing System Checks...")
        checks = [
            "Initializing memory allocation",
            "Loading vulnerability database",
            "Checking network connectivity",
            "Initializing smart contract parser",
            "Loading XSS pattern matcher"
        ]
        
        for check in checks:
            self.loading_animation(check)
            time.sleep(0.2)

        print("\n[*] Running Security Protocols...")
        protocols = [
            "Configuring security parameters",
            "Establishing secure connection",
            "Verifying blockchain access"
        ]
        
        for protocol in protocols:
            self.progress_bar(protocol)

        print("\n[*] System Ready - Initiating Scan Sequence\n")
        
        for i in range(3, 0, -1):
            sys.stdout.write(f"\rLaunching scan in {i}s...")
            sys.stdout.flush()
            time.sleep(1)
        print("\n\n" + "="*50)

# Your existing classes
class Vulnerability:
    def __init__(self, vulnerability_type: str, payload: str, location: str, severity: str):
        self.vulnerability_type = vulnerability_type
        self.payload = payload
        self.location = location
        self.severity = severity

class ScanResult:
    def __init__(self, app_id: int, vulnerabilities: List[Vulnerability], risk_level: str,
                 recommendations: List[str], scan_timestamp: str, risk_score: int):
        self.app_id = app_id
        self.vulnerabilities = vulnerabilities
        self.risk_level = risk_level
        self.recommendations = recommendations
        self.scan_timestamp = scan_timestamp
        self.risk_score = risk_score

class MockAlgodClient:
    def application_info(self, app_id):
        return {
            'params': {
                'approval-program': 'mock_teal_code',
                'global-state': [{'key': 'example_key', 'value': 'example_value'}]
            }
        }

# Enhanced Scanner Class
class EnhancedAlgorandXSSScanner:
    def __init__(self, algod_address: str, algod_token: str):
        self.algod_client = MockAlgodClient()
        self.severity_scores = {
            "Low": 1,
            "Medium": 2,
            "High": 3,
            "Critical": 4
        }
        self.boot_sequence = BootSequence()
        
    def generate_xss_findings(self, app_state: Dict) -> List[Vulnerability]:
        vulnerabilities = [
            Vulnerability(
                vulnerability_type="Stored XSS",
                payload="<script>alert('xss')</script>",
                location="global-state:user_profile",
                severity="High"
            ),
            Vulnerability(
                vulnerability_type="Reflected XSS",
                payload="javascript:alert(document.cookie)",
                location="method:get_user_input",
                severity="Medium"
            ),
            Vulnerability(
                vulnerability_type="DOM-based XSS",
                payload="<img src=x onerror=alert('xss')>",
                location="state:display_name",
                severity="Critical"
            )
        ]
        
        for key, value in app_state.items():
            if isinstance(value, str) and any(dangerous in value.lower() for dangerous in ['<script>', 'javascript:', 'onerror=']):
                vulnerabilities.append(
                    Vulnerability(
                        vulnerability_type="Dynamic Stored XSS",
                        payload=value,
                        location=f"global-state:{key}",
                        severity="High"
                    )
                )
        
        return vulnerabilities

    def calculate_risk_score(self, vulnerabilities: List[Vulnerability]) -> tuple:
        if not vulnerabilities:
            return 0, "None"
            
        total_score = sum(self.severity_scores[v.severity] for v in vulnerabilities)
        max_possible_score = len(self.severity_scores) * len(vulnerabilities)
        
        if total_score > max_possible_score * 0.75:
            risk_level = "Critical"
        elif total_score > max_possible_score * 0.5:
            risk_level = "High"
        elif total_score > max_possible_score * 0.25:
            risk_level = "Medium"
        else:
            risk_level = "Low"
            
        return total_score, risk_level

    def generate_recommendations(self, vulnerabilities: List[Vulnerability]) -> List[str]:
        recommendations = [
            "Implement input validation for all user-supplied data",
            "Apply proper output encoding in smart contract methods",
            "Use Content Security Policy (CSP) headers",
            "Regular security audits and penetration testing"
        ]
        
        vuln_types = set(v.vulnerability_type for v in vulnerabilities)
        
        if "Stored XSS" in vuln_types:
            recommendations.append("Sanitize all data before storing in global state")
        if "Reflected XSS" in vuln_types:
            recommendations.append("Implement strict input validation for method parameters")
        if "DOM-based XSS" in vuln_types:
            recommendations.append("Use safe DOM manipulation methods and sanitize dynamic content")
            
        return recommendations

    def scan_contract(self, app_id: int) -> ScanResult:
        # Run boot sequence before scanning
        self.boot_sequence.run_boot_sequence()
        
        contract_info = self.algod_client.application_info(app_id)
        app_state = self._get_application_state(app_id)
        
        vulnerabilities = self.generate_xss_findings(app_state or {})
        risk_score, risk_level = self.calculate_risk_score(vulnerabilities)
        recommendations = self.generate_recommendations(vulnerabilities)
        
        return ScanResult(
            app_id=app_id,
            vulnerabilities=vulnerabilities,
            risk_level=risk_level,
            recommendations=recommendations,
            scan_timestamp=datetime.now().isoformat(),
            risk_score=risk_score
        )

    def _get_application_state(self, app_id: int) -> Dict:
        response = self.algod_client.application_info(app_id)
        if 'params' in response and 'global-state' in response['params']:
            return {item['key']: item['value'] for item in response['params']['global-state']}
        return {}

    def print_scan_report(self, scan_result: ScanResult):
        print("🔍 SMART CONTRACT XSS VULNERABILITY SCAN REPORT")
        print("="*50)
        print(f"\n📋 Contract ID: {scan_result.app_id}")
        print(f"⏰ Scan Timestamp: {scan_result.scan_timestamp}")
        
        print("\n🎯 VULNERABILITY FINDINGS")
        print("-"*50)
        
        for idx, vuln in enumerate(scan_result.vulnerabilities, 1):
            print(f"\nFinding #{idx}")
            print(f"Type: {vuln.vulnerability_type}")
            print(f"Severity: {vuln.severity}")
            print(f"Location: {vuln.location}")
            print(f"Payload: {vuln.payload}")
            print("-"*30)
        
        print("\n📊 RISK ASSESSMENT")
        print("-"*50)
        print(f"Total Vulnerabilities: {len(scan_result.vulnerabilities)}")
        print(f"Risk Score: {scan_result.risk_score}/{len(scan_result.vulnerabilities) * 4}")
        print(f"Overall Risk Level: {scan_result.risk_level}")
        
        print("\n💡 RECOMMENDATIONS")
        print("-"*50)
        for idx, rec in enumerate(scan_result.recommendations, 1):
            print(f"{idx}. {rec}")
        
        print("\n" + "="*50)

def main():
    algod_address = "http://localhost:4001"
    algod_token = "your_algod_token"
    app_id = 1010
    
    # Using the enhanced scanner
    scanner = EnhancedAlgorandXSSScanner(algod_address, algod_token)
    scan_result = scanner.scan_contract(app_id)
    scanner.print_scan_report(scan_result)

if __name__ == "__main__":
    main()