
from src.scanner.xss_scanner import AlgorandXSSScanner
from src.reports.report_generator import ReportGenerator
from config.settings import ALGOD_ADDRESS, ALGOD_TOKEN

def main():
    """Main execution function."""
    print("Starting Algorand XSS Scanner...")
    
    # Initialize scanner
    try:
        scanner = AlgorandXSSScanner(ALGOD_ADDRESS, ALGOD_TOKEN)
        print("Successfully connected to Algorand node")
        
        # Get application ID from user
        app_id = input("Enter Algorand application ID to scan: ")
        
        # Perform scan
        print(f"Scanning application {app_id}...")
        scan_results = scanner.scan_contract(int(app_id))
        
        # Generate report
        report_generator = ReportGenerator()
        report = report_generator.generate_json_report(scan_results)
        
        # Save report to file
        report_filename = f"Backend/reports/scan_report_{app_id}.json"
        with open(report_filename, "w") as f:
            f.write(report)
            
        print(f"Scan complete. Report saved to {report_filename}")
        
    except Exception as e:
        print(f"Error during scan: {e}")
        print("Please make sure your Algorand node is running (algokit localnet start)")

if __name__ == "__main__":
    main()