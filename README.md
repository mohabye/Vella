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
![photo_5965441272288233395_w](https://github.com/user-attachments/assets/e62c7d85-6941-4d05-9622-f6f7ef995774)


