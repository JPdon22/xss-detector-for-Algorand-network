# File: config/settings.py

# AlgoKit LocalNet connection settings
ALGOD_ADDRESS = "http://localhost:4001"  # Your LocalNet is running on port 4001 as shown in your status output
ALGOD_TOKEN = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"  # Standard LocalNet token

# Rest of your settings remain the same
XSS_PATTERNS = [
    r"<script\b[^>]*>(.*?)</script>",
    r"javascript:",
    r"onerror=",
    r"onload=",
    r"eval\(",
    r"document\.cookie",
]

RISK_LEVELS = {
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low"
}