  
function Show-ASCII-Banner {
    Write-Host "
 __     __ ______  _    _   _      _    _  _____ 
 \ \   / /|  ____|| |  | | | |    | |  | ||  __ \
  \ \_/ / | |__   | |  | | | |    | |  | || |__) |
   \   /  |  __|  | |  | | | |    | |  | ||  _  / 
    | |   | |____ | |__| | | |____| |__| || | \ \ 
    |_|   |______| \____/  |______|\____/ |_|  \_\
" -ForegroundColor Cyan
}


function Show-Menu {
    Write-Host "Please choose an option:" -ForegroundColor Green
    Write-Host "1. Network Connections" -ForegroundColor Yellow
    Write-Host "2. Running Processes" -ForegroundColor Yellow
    Write-Host "3. Process Hunt" -ForegroundColor Yellow
    Write-Host "4. Scheduled Tasks" -ForegroundColor Yellow
    Write-Host "5. Running Services" -ForegroundColor Yellow
    Write-Host "6. Downloaded Files (Last 7 days)" -ForegroundColor Yellow
    Write-Host "7. Auto Run Entenis" -ForegroundColor Yellow
    Write-Host "8. Temp Files" -ForegroundColor Yellow
    Write-Host "9. Exit" -ForegroundColor Red
}


function Get-NetworkConnections {
    Get-NetTCPConnection | ForEach-Object {
        [PSCustomObject]@{
            LocalAddress  = $_.LocalAddress
            LocalPort     = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort    = $_.RemotePort
            State         = $_.State
            OwningProcess = $_.OwningProcess
            ProcessName   = (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
        }
    }
}


function Check-AbuseIPDB {
    param (
        [string]$APIKey,
        [string]$IPAddress
    )
    $url = "https://api.abuseipdb.com/api/v2/check?ipAddress=$IPAddress"
    $headers = @{
        "Key"    = $APIKey
        "Accept" = "application/json"
    }
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        return $response.data
    } catch {
        Write-Host "Error fetching data for IP $IPAddress" -ForegroundColor Red
        return $null
    }
}


function Check-VirusTotal {
    param(
        [string]$APIKey,
        [string]$SHA256
    )
    $url = "https://www.virustotal.com/api/v3/files/$SHA256"
    $headers = @{"x-apikey" = $APIKey}
    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get -ErrorAction Stop
        return $response.data
    } catch {
        Write-Host "Error fetching VirusTotal data for hash $SHA256" -ForegroundColor Red
        return $null
    }
}


function Get-ProcessDetails {
    param(
        [string]$ProcessName
    )
    $processes = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
    if (!$processes) {
        Write-Host "No process found with name: $ProcessName" -ForegroundColor Red
        return $null
    }

    $process = $processes | Select-Object -First 1
    $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId=$($process.Id)"
    if (!$wmiProc) {
        Write-Host "Unable to retrieve WMI details for process: $ProcessName" -ForegroundColor Red
        return $null
    }

    $commandLine = $wmiProc.CommandLine
    $executablePath = $wmiProc.ExecutablePath
    $hashInfo = if ($executablePath) { Get-FileHash -Algorithm SHA256 -Path $executablePath -ErrorAction SilentlyContinue } else { $null }

    return [PSCustomObject]@{
        ProcessObject  = $process
        CommandLine    = $commandLine
        ExecutablePath = $executablePath
        HashSHA256     = $hashInfo.Hash
    }
}


function Get-ProcessDLLs {
    param(
        [System.Diagnostics.Process]$ProcessObject
    )
    try {
        $modules = (Get-Process -Id $ProcessObject.Id -Module -ErrorAction SilentlyContinue).Modules
        return $modules
    } catch {
        Write-Host "Unable to retrieve modules for process: $($ProcessObject.ProcessName)" -ForegroundColor Red
        return $null
    }
}


function Get-ProcessFamily {
    param(
        [int]$ProcessID
    )

    $parent = Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -eq $ProcessID } | Select-Object ParentProcessId
    if ($parent) {
        $parentProc = Get-CimInstance Win32_Process | Where-Object { $_.ProcessId -eq $($parent.ParentProcessId) }
    } else {
        $parentProc = $null
    }

    $childProcs = Get-CimInstance Win32_Process | Where-Object { $_.ParentProcessId -eq $ProcessID }

    return [PSCustomObject]@{
        ParentProcess = $parentProc
        ChildProcesses = $childProcs
    }
}


function Process-Hunt {
    param(
        [string]$APIKey,
        [string]$VTAPIKey
    )

    $procName = Read-Host "Enter the process name you want to hunt"
    $details = Get-ProcessDetails -ProcessName $procName
    if ($null -eq $details) {
        return
    }

    Write-Host "`n[Process Details]" -ForegroundColor Cyan
    Write-Host "Name:           $($details.ProcessObject.ProcessName)"
    Write-Host "PID:            $($details.ProcessObject.Id)"
    Write-Host "Command Line:   $($details.CommandLine)"
    Write-Host "ExecutablePath: $($details.ExecutablePath)"
    Write-Host "SHA256:         $($details.HashSHA256)"

    if ($details.HashSHA256 -and $VTAPIKey -ne "") {
        Write-Host "`n[Checking VirusTotal]" -ForegroundColor Cyan
        $vtData = Check-VirusTotal -APIKey $VTAPIKey -SHA256 $details.HashSHA256
        if ($vtData) {
            Write-Host "VT Link: https://www.virustotal.com/gui/file/$($details.HashSHA256)"
            Write-Host "Malicious Detections: $($vtData.attributes.last_analysis_stats.malicious)"
            Write-Host "Suspicious Detections: $($vtData.attributes.last_analysis_stats.suspicious)"
        }
    } else {
        Write-Host "No hash or no VirusTotal API key provided, skipping VT check." -ForegroundColor Yellow
    }

    Write-Host "`n[Network Connections]" -ForegroundColor Cyan
    $connections = Get-NetworkConnections | Where-Object { $_.OwningProcess -eq $details.ProcessObject.Id }
    if ($connections) {
        foreach ($conn in $connections) {
            if ($conn.RemoteAddress -and $conn.RemoteAddress -notin @("0.0.0.0","::")) {
                $abuseData = Check-AbuseIPDB -APIKey $APIKey -IPAddress $conn.RemoteAddress
                if ($abuseData) {
                    Write-Host "Remote Address: $($conn.RemoteAddress)" -ForegroundColor White
                    Write-Host "Local Address:  $($conn.LocalAddress):$($conn.LocalPort)" -ForegroundColor White
                    Write-Host "Process Name:   $($conn.ProcessName)" -ForegroundColor White
                    Write-Host "Abuse Score:    $($abuseData.abuseConfidenceScore)" -ForegroundColor Green
                    Write-Host "ISP:            $($abuseData.isp)" -ForegroundColor Yellow
                    Write-Host "Country:        $($abuseData.countryCode)" -ForegroundColor Cyan
                    Write-Host "--------------------------------------------"
                }
            }
        }
    } else {
        Write-Host "No network connections found for this process."
    }

    Write-Host "`n[Loaded DLLs]" -ForegroundColor Cyan
    $dlls = Get-ProcessDLLs -ProcessObject $details.ProcessObject
    if ($dlls) {
        foreach ($dll in $dlls) {
            Write-Host $dll.FileName
        }
    } else {
        Write-Host "No DLLs found or unable to retrieve."
    }

    Write-Host "`n[Process Family]" -ForegroundColor Cyan
    $family = Get-ProcessFamily -ProcessID $details.ProcessObject.Id
    if ($family.ParentProcess) {
        Write-Host "Parent Process: $($family.ParentProcess.Name) (PID: $($family.ParentProcess.ProcessId))"
        if ($family.ParentProcess.Name -eq "reg.exe" -or ($family.ParentProcess.CommandLine -like "*reg.exe*")) {
            Write-Host "Parent process interacted with reg.exe" -ForegroundColor Yellow
        }
    } else {
        Write-Host "No parent process found."
    }

    Write-Host "`n[Child Processes]" -ForegroundColor Cyan
    if ($family.ChildProcesses) {
        foreach ($cp in $family.ChildProcesses) {
            Write-Host "$($cp.Name) (PID: $($cp.ProcessId))"
        }
    } else {
        Write-Host "No child processes found."
    }
}


function Get-RunningProcesses {
    Write-Host "`n[Running Processes]" -ForegroundColor Cyan
    $procs = Get-Process | Sort-Object ProcessName
    foreach ($proc in $procs) {
        Write-Host ("Name: {0}  PID: {1}" -f $proc.ProcessName, $proc.Id)
    }
}


function Get-ScheduledTasksInfo {
    Write-Host "`n[Scheduled Tasks]" -ForegroundColor Cyan
    $scheduledTasks = Get-ScheduledTask
    foreach($task in $scheduledTasks) {
        $taskName    = $task.TaskName
        $fullPath    = Join-Path "C:\Windows\System32\Tasks" ($task.TaskPath.TrimStart("\") + $task.TaskName)
        $createdTime = (Get-Item $fullPath -ErrorAction SilentlyContinue).CreationTime
        $action      = $task.Actions | Where-Object { $_.ActionType -eq 'Execute' }
        $command     = $action.Execute
        $arguments   = $action.Arguments
        $runAsUser   = $task.Principal.UserId

        Write-Host "TaskName:    $taskName"
        Write-Host "CommandLine: $command $arguments"
        Write-Host "FilePath:    $fullPath"
        Write-Host "CreatedTime: $createdTime"
        Write-Host "RunAsUser:   $runAsUser"
        Write-Host "--------------------------------------------"
    }
}


function Get-RunningServices {
    Write-Host "`n[Running Services]" -ForegroundColor Cyan

    $services = Get-CimInstance Win32_Service | Where-Object { $_.State -eq 'Running' }
    foreach ($service in $services) {
        $fullPath = $service.PathName
        
        $exePath = ($fullPath -split ' ')[0]

        
        $creationTime = $null
        if (Test-Path $exePath) {
            $creationTime = (Get-Item $exePath).CreationTime
        }

        Write-Host "Service Name:    $($service.Name)"
        Write-Host "Display Name:    $($service.DisplayName)"
        Write-Host "Command Line:    $($service.PathName)"
        Write-Host "Executable Path: $exePath"
        Write-Host "Created Time:    $creationTime"
        Write-Host "--------------------------------------------"
    }
}


function Get-DownloadedFiles {
    Write-Host "`n[Downloaded Files (Last 7 Days)]" -ForegroundColor Cyan
    $downloadsFolder = [Environment]::GetFolderPath("UserProfile") + "\Downloads"
    if (Test-Path $downloadsFolder) {
        $sinceDate = (Get-Date).AddDays(-7)
        $files = Get-ChildItem -Path $downloadsFolder -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -gt $sinceDate }
        if ($files) {
            foreach ($file in $files) {
                
                $inProcess = $false
                if ($file.Extension -match 'crdownload|partial|tmp') {
                    $inProcess = $true
                }

                Write-Host "Name:      $($file.Name)"
                Write-Host "Path:      $($file.FullName)"
                Write-Host "InProcess: $inProcess"
                Write-Host "--------------------------------------------"
            }
        } else {
            Write-Host "No files downloaded in the last 7 days found."
        }
    } else {
        Write-Host "Downloads folder not found."
    }
}


function Get-AutoRunEntries {
    Write-Host "`n[Auto Run Entenis]" -ForegroundColor Cyan

    
    $commonStartup = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
    $userStartup = Join-Path ([Environment]::GetFolderPath("StartMenu")) "Programs\Startup"

    $startupPaths = @($commonStartup, $userStartup)

    
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )

    
    function Get-ShortcutTarget($lnkPath) {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($lnkPath)
        return $shortcut.TargetPath
    }

    
    foreach ($sPath in $startupPaths) {
        if (Test-Path $sPath) {
            $files = Get-ChildItem -Path $sPath -File -ErrorAction SilentlyContinue
            foreach ($file in $files) {
                $fullPath = $file.FullName
                $commandLine = $fullPath
                $hash = $null

                
                if ($file.Extension -eq ".lnk") {
                    $target = Get-ShortcutTarget $fullPath
                    if ($target -and (Test-Path $target)) {
                        $commandLine = $target
                        try {
                            $hash = (Get-FileHash -Algorithm SHA256 -Path $target).Hash
                        } catch {}
                    } else {
                        $commandLine = $target
                    }
                } else {
                    
                    if (Test-Path $fullPath) {
                        try {
                            $hash = (Get-FileHash -Algorithm SHA256 -Path $fullPath).Hash
                        } catch {}
                    }
                }

                Write-Host "Name:         $($file.Name)"
                Write-Host "Folder Path:  $($file.DirectoryName)"
                Write-Host "Command Line: $commandLine"
                Write-Host "Hash:         $hash"

                
                $baseName = [System.IO.Path]::GetFileNameWithoutExtension($commandLine)
                $runningProc = Get-Process -Name $baseName -ErrorAction SilentlyContinue
                if ($runningProc) {
                    Write-Host "Currently Running: Yes (PID: $($runningProc.Id))"
                } else {
                    Write-Host "Currently Running: No"
                }
                Write-Host "--------------------------------------------"
            }
        }
    }

   
    foreach ($regPath in $regPaths) {
        if (Test-Path $regPath) {
            $runValues = Get-ItemProperty $regPath -ErrorAction SilentlyContinue
            if ($runValues) {
                foreach ($valueName in ($runValues.PSObject.Properties | Where-Object { $_.Name -notlike 'PSPath' -and $_.Name -notlike 'PSParentPath' -and $_.Name -notlike 'PSChildName' -and $_.Name -notlike 'PSDrive' -and $_.Name -notlike 'PSProvider'}).Name) {
                    $cmd = (Get-ItemProperty $regPath).$valueName
                    $hash = $null
                    $folderPath = $null

                    
                    $exePath = $cmd
                    if ($exePath -match '^"([^"]+)"') {
                        $exePath = $matches[1]
                    } else {
                        $exePath = ($exePath -split ' ')[0]
                    }

                    if (Test-Path $exePath) {
                        try {
                            $hash = (Get-FileHash -Algorithm SHA256 -Path $exePath).Hash
                            $folderPath = Split-Path $exePath -Parent
                        } catch {}
                    }

                    Write-Host "Name:         $valueName (Registry Run)"
                    Write-Host "Folder Path:  $folderPath"
                    Write-Host "Command Line: $cmd"
                    Write-Host "Hash:         $hash"

                    
                    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($exePath)
                    $runningProc = Get-Process -Name $baseName -ErrorAction SilentlyContinue
                    if ($runningProc) {
                        Write-Host "Currently Running: Yes (PID: $($runningProc.Id))"
                    } else {
                        Write-Host "Currently Running: No"
                    }
                    Write-Host "--------------------------------------------"
                }
            }
        }
    }
}


function Get-TempFiles {
    Write-Host "`n[Temp Files]" -ForegroundColor Cyan
    $tempFolder = $env:TEMP
    if (Test-Path $tempFolder) {
        $files = Get-ChildItem -Path $tempFolder -File -ErrorAction SilentlyContinue
        if ($files) {
            foreach ($file in $files) {
                $hash = $null
                try {
                    $hash = (Get-FileHash -Algorithm SHA256 -Path $file.FullName).Hash
                } catch {}

                
                $commandLine = $file.FullName

                Write-Host "Name:         $($file.Name)"
                Write-Host "Path:         $($file.FullName)"
                Write-Host "Hash:         $hash"
                Write-Host "Command Line: $commandLine"
                Write-Host "--------------------------------------------"
            }
        } else {
            Write-Host "No files found in the temp folder."
        }
    } else {
        Write-Host "Temp folder not found."
    }
}



Show-ASCII-Banner
$APIKey = "ABIP_API"  # Replace with your AbuseIPDB API key
$VTAPIKey = "VT_API" # Replace with your VirusTotal API key

do {
    Show-Menu
    $choice = Read-Host "Enter your choice (1-9)"
    switch ($choice) {
        "1" {
            Write-Host "Fetching all network connections..." -ForegroundColor Cyan
            $connections = Get-NetworkConnections
            foreach ($connection in $connections) {
                if ($connection.RemoteAddress -ne "0.0.0.0" -and $connection.RemoteAddress -ne "::") {
                    $abuseData = Check-AbuseIPDB -APIKey $APIKey -IPAddress $connection.RemoteAddress
                    if ($abuseData) {
                        Write-Host "Remote Address: $($connection.RemoteAddress)" -ForegroundColor White
                        Write-Host "Process Name: $($connection.ProcessName)" -ForegroundColor White
                        Write-Host "Abuse Confidence Score: $($abuseData.abuseConfidenceScore)" -ForegroundColor Green
                        Write-Host "ISP: $($abuseData.isp)" -ForegroundColor Yellow
                        Write-Host "Country: $($abuseData.countryCode)" -ForegroundColor Cyan
                        Write-Host "============================================" -ForegroundColor DarkGray
                    }
                }
            }
        }
        "2" {
            Get-RunningProcesses
        }
        "3" {
            Process-Hunt -APIKey $APIKey -VTAPIKey $VTAPIKey
        }
        "4" {
            Write-Host "Listing Scheduled Tasks..." -ForegroundColor Cyan
            Get-ScheduledTasksInfo
        }
        "5" {
            Write-Host "Listing Running Services..." -ForegroundColor Cyan
            Get-RunningServices
        }
        "6" {
            Get-DownloadedFiles
        }
        "7" {
            Get-AutoRunEntries
        }
        "8" {
            Get-TempFiles
        }
        "9" {
            Write-Host "Exiting... لا تنسى الصلاة على النبي!" -ForegroundColor green
            break
        }
        default {
            Write-Host "Invalid choice. Please select a number between 1 and 9." -ForegroundColor Red
        }
    }
} while ($choice -ne "9")
