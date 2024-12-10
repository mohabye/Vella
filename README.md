# Vella
This PowerShell script is designed to assist with basic host-based security investigations..
This PowerShell script is designed to assist with basic host-based security investigations. It retrieves and analyzes system information such as network connections, running processes, scheduled tasks, services, downloaded files, autorun entries, and temporary files. It also integrates with external APIs (AbuseIPDB and VirusTotal) to enrich findings with threat intelligence data.

Key Capabilities:

Enumerate network connections and retrieve abuse confidence scores for remote IPs from AbuseIPDB.
Hunt for suspicious processes, pulling file hashes and querying VirusTotal for malicious or suspicious detections.
Identify persistence mechanisms via scheduled tasks and autorun entries.
Provide insights into running services, downloaded files, and temporary files on the system.
This script can be especially beneficial for threat hunters, incident responders, and security analysts conducting host-based investigations or triage in Windows environments.

Requirements
Operating System: Windows (The script leverages Windows-specific cmdlets and CIM/WMI classes.)
PowerShell Version: PowerShell 5.1 or later is recommended for module compatibility.
APIs:
AbuseIPDB API Key (Replace the placeholder API key in the script with your own.)
VirusTotal API Key (Replace the placeholder API key in the script with your own.)
These API keys are optional but highly recommended for full functionality. Without them, the script will still run but will not return enriched threat intelligence data.

Note: Ensure that your network connectivity and proxy/firewall settings permit outbound HTTPS requests to the AbuseIPDB and VirusTotal endpoints.

Running the Script
Copy the script onto the target Windows machine.
Open PowerShell as an administrator (recommended).
Edit the script to insert your own AbuseIPDB and VirusTotal API keys in the designated variables.
Run the script:
powershell
Copy code
.\YourScriptName.ps1
Follow the on-screen menu to select your desired option.
How This Script Helps Threat Hunters and IR Professionals
Threat Hunting:
Quickly enumerate suspicious network connections and correlate IP addresses with known malicious activity via AbuseIPDB. Identify running processes and hash them to check against VirusTotal, providing a quick lead on whether a binary is potentially malicious.

Incident Response (IR):
During triage, use this script to gain immediate visibility into processes, services, scheduled tasks, and autoruns. This helps identify signs of persistence, malicious services, or abnormal user behavior. Rapid access to file hashes, DLL lists, and parent-child process relationships aids in understanding attacker techniques and intrusion scope.

Data Enrichment:
The integration with AbuseIPDB and VirusTotal provides instant threat intelligence, reducing manual lookups and expediting decision-making.

Explanation of Each Function
1. Show-ASCII-Banner
Displays an ASCII banner for branding and initial presentation. Primarily cosmetic.

2. Show-Menu
Prints a menu of options to the console, guiding the user through available investigations:
![image](https://github.com/user-attachments/assets/c142f908-c0be-4cce-91ec-2516823c8fe4)

![Uploading image.png…]()

![Uploading image.png…]()

Network Connections
Running Processes
Process Hunt
Scheduled Tasks
Running Services
Downloaded Files (Last 7 days)
Auto Run Entries
Temp Files
Exit
3. Get-NetworkConnections
Retrieves current TCP network connections along with owning process details. This maps local/remote IPs, ports, states, and correlates connections to their respective processes.

4. Check-AbuseIPDB
Queries the AbuseIPDB API for a given IP address. Returns details like Abuse Confidence Score, ISP, and Country. Useful for detecting known malicious infrastructure.

5. Check-VirusTotal
Queries the VirusTotal API for a given file hash (SHA256). Returns the analysis results, including malicious and suspicious detection counts, providing quick insight into a file's reputation.

6. Get-ProcessDetails
Retrieves details for a specified process, including:

Process object (name, PID)
Command line arguments
Executable path
SHA256 hash of the executable for threat intelligence queries.
7. Get-ProcessDLLs
Enumerates the DLLs loaded by a given process. Identifying unusual or malicious DLLs can be a key indicator of advanced persistence or injection techniques.

8. Get-ProcessFamily
Maps a process’s parent and child processes. Understanding the process lineage helps identify if the process is spawned by a known system binary or a suspicious parent, and if it launches other suspicious children.

9. Process-Hunt
Integrates all the above functions for a specified process:

Retrieves process details, hash, and queries VirusTotal.
Lists network connections made by that process and checks IPs via AbuseIPDB.
Shows loaded DLLs.
Prints parent and child processes to understand process lineage.
This function is a one-stop shop for investigating a suspicious process thoroughly.

10. Get-RunningProcesses
Lists all currently running processes, providing a quick overview of the system’s runtime environment.

11. Get-ScheduledTasksInfo
Enumerates all scheduled tasks, extracting command lines, creation times, and associated users. Scheduled tasks are a common persistence technique for adversaries.

12. Get-RunningServices
Lists all running services and their associated executables. Malicious services often disguise themselves as legitimate Windows services to maintain persistence.

13. Get-DownloadedFiles
Finds all files downloaded within the last 7 days in the user’s Downloads folder. This can reveal newly introduced files that might be malicious payloads.

14. Get-AutoRunEntries
Checks startup folders and registry “Run” keys for auto-start programs. Identifies potential persistence points where malware can automatically re-launch after a reboot.

15. Get-TempFiles
Retrieves files in the %TEMP% directory. Malware often drops payloads or stores temporary components in this directory.

