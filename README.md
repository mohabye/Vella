#Vella
This PowerShell script provides a comprehensive set of tools for Incident Response (IR) and Threat Hunting, allowing users to gather valuable forensic data and analyze suspicious activities on local or remote machines. It is designed for ease of use and integrates with external services like AbuseIPDB and VirusTotal for enhanced threat intelligence.

Features
Network Connections Monitoring:

Retrieves active network connections and resolves related processes.
Integrates with AbuseIPDB to check for malicious IP addresses.
Running Processes Overview:

Lists all running processes along with their details.
Process Hunt:

Analyzes specific processes, including command-line arguments, executable paths, SHA256 hashes, and loaded DLLs.
Integrates with VirusTotal for hash reputation analysis.
Scheduled Tasks Inspection:

Displays details of all scheduled tasks, including creation time and command-line arguments.
Running Services Analysis:

Lists all running services, including their paths, command lines, and creation times.
Recent Downloads Tracking:

Scans the user's Downloads folder for files added in the last 7 days, highlighting any in-progress files.
Startup Entries Detection:

Examines auto-run entries from startup folders and registry keys, including hash calculations for executables.
Temporary Files Investigation:

Lists all temporary files and calculates their hashes for further analysis.
Prerequisites
Operating System: Windows
PowerShell: Version 5.0 or higher
Required Permissions: Administrator privileges are recommended for full functionality.
External Dependencies
AbuseIPDB API Key:

Used to check the reputation of IP addresses.
Get your API key from AbuseIPDB.
VirusTotal API Key:

Used for analyzing file hashes.
Obtain your API key from VirusTotal.
How to Use
Clone the repository:

bash
Copy code
git clone https://github.com/your-username/ir-threat-hunting-toolkit.git
cd ir-threat-hunting-toolkit
Open the script in PowerShell ISE or any text editor to replace the placeholder API keys:

Replace APIKey with your AbuseIPDB API key.
Replace VTAPIKey with your VirusTotal API key.
Run the script:

powershell
Copy code
.\IR-ThreatHunt.ps1
Follow the menu prompts to choose desired functionalities.

Benefits
Efficient Investigation: Quickly gather data on suspicious activities and processes.
Automated Threat Intelligence: Integrates with popular threat intelligence services for real-time analysis.
Comprehensive Analysis: Covers network, processes, services, files, and scheduled tasks in a single script.
User-Friendly: Simple menu-driven interface for easy navigation
