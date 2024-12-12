$outputFile = "$env:USERPROFILE\Desktop\SystemInfo.txt"

# Clear the file if it already exists
if (Test-Path $outputFile) {
    Write-Host "Clearing existing output file..."
    Remove-Item $outputFile
    Write-Host "Output file cleared."
}

# 1. Basic System Information
Write-Host "Fetching Basic System Information using systeminfo..."
"1. Basic System Information" | Out-File -FilePath $outputFile -Append
systeminfo | Out-File -FilePath $outputFile -Append
Write-Host "Basic System Information fetched successfully."

# 2. CPU Information
Write-Host "Fetching CPU Information..."
"2. CPU Information" | Out-File -FilePath $outputFile -Append

# Get CPU information using Get-WmiObject (for compatibility with older versions of Windows)
$cpuInfo = Get-WmiObject Win32_Processor

# Output CPU details
$cpuInfo | ForEach-Object {
    "CPU Name: $($_.Name)"
    "CPU Cores: $($_.NumberOfCores)"
    "CPU Logical Processors: $($_.NumberOfLogicalProcessors)"
    "CPU Clock Speed: $($_.MaxClockSpeed) MHz"
    "CPU Architecture: $($_.Architecture)"
} | Out-File -FilePath $outputFile -Append

Write-Host "CPU Information fetched successfully."

# 3. Installed RAM Information
Write-Host "Fetching Installed RAM Information..."
"3. Installed RAM Information" | Out-File -FilePath $outputFile -Append

# Get Installed RAM details using Get-WmiObject (for compatibility with older versions of Windows)
$ramInfo = Get-WmiObject Win32_PhysicalMemory

# Output RAM details
$ramInfo | ForEach-Object {
    "Capacity: $($_.Capacity / 1GB) GB"
    "Speed: $($_.Speed) MHz"
    "Manufacturer: $($_.Manufacturer)"
    "Memory Type: $($_.MemoryType)"
    "Form Factor: $($_.FormFactor)"
} | Out-File -FilePath $outputFile -Append

Write-Host "Installed RAM Information fetched successfully."

# 4. System Uptime using systeminfo (Lolbin)
Write-Host "Fetching System Uptime using systeminfo..."
"4. System Uptime" | Out-File -FilePath $outputFile -Append
(systeminfo | Select-String "System Boot Time") | Out-File -FilePath $outputFile -Append
Write-Host "System Uptime fetched successfully."

# 5. Operating System Details
Write-Host "Fetching Operating System Details..."
"5. Operating System Details" | Out-File -FilePath $outputFile -Append

# Get Operating System details using Get-WmiObject
$osInfo = Get-WmiObject Win32_OperatingSystem

# Output Operating System details
"OS Name: $($osInfo.Caption)"
"OS Version: $($osInfo.Version)"
"OS Architecture: $($osInfo.OSArchitecture)"
"Build Number: $($osInfo.BuildNumber)"
"Manufacturer: $($osInfo.Manufacturer)"
"Last Boot Time: $($osInfo.LastBootUpTime)" | Out-File -FilePath $outputFile -Append

Write-Host "Operating System Details fetched successfully."


# 6. Current User Information using whoami (Lolbin)
Write-Host "Fetching Current User Information using whoami..."
"6. Current User Information" | Out-File -FilePath $outputFile -Append
whoami | Out-File -FilePath $outputFile -Append
Write-Host "Current User Information fetched successfully."

# 7. List of Local Users using net user (Lolbin)
Write-Host "Fetching List of Local Users using net user..."
"7. List of Local Users" | Out-File -FilePath $outputFile -Append
net user | Out-File -FilePath $outputFile -Append
Write-Host "List of Local Users fetched successfully."

# 8. Disk Space Details using dir (Lolbin)
Write-Host "Fetching Disk Space Details using dir..."
"8. Disk Space Details" | Out-File -FilePath $outputFile -Append
dir C:\ | Out-File -FilePath $outputFile -Append
Write-Host "Disk Space Details fetched successfully."

# 9. Disk Drive Information
Write-Host "Fetching Disk Drive Information..."
"9. Disk Drive Information" | Out-File -FilePath $outputFile -Append

# Using Get-PhysicalDisk (Requires PowerShell 5.1 or later)
Get-PhysicalDisk | ForEach-Object {
    "Device: $($_.DeviceID), Media Type: $($_.MediaType), Size: $([Math]::Round($_.Size/1GB, 2)) GB, Health Status: $($_.HealthStatus)" 
} | Out-File -FilePath $outputFile -Append

# Using Get-Disk
Get-Disk | ForEach-Object {
    "Disk Number: $($_.Number), Size: $([Math]::Round($_.Size/1GB, 2)) GB, Partition Style: $($_.PartitionStyle), Operational Status: $($_.OperationalStatus)" 
} | Out-File -FilePath $outputFile -Append

Write-Host "Disk Drive Information fetched successfully."

# 10. Network Adapter Information using netsh (Lolbin)
Write-Host "Fetching Network Adapter Information using netsh..."
"10. Network Adapter Information" | Out-File -FilePath $outputFile -Append
netsh interface ipv4 show config | Out-File -FilePath $outputFile -Append
Write-Host "Network Adapter Information fetched successfully."

# 11. IP Configuration using ipconfig (Lolbin)
Write-Host "Fetching IP Configuration using ipconfig..."
"11. IP Configuration" | Out-File -FilePath $outputFile -Append
ipconfig /all | Out-File -FilePath $outputFile -Append
Write-Host "IP Configuration fetched successfully."

# 12. Active Network Connections using netstat (Lolbin)
Write-Host "Fetching Active Network Connections using netstat..."
"12. Active Network Connections" | Out-File -FilePath $outputFile -Append
netstat -ano | Out-File -FilePath $outputFile -Append
Write-Host "Active Network Connections fetched successfully."

# 13. List of Running Processes using tasklist (Lolbin)
Write-Host "Fetching List of Running Processes using tasklist..."
"13. List of Running Processes" | Out-File -FilePath $outputFile -Append
tasklist | Out-File -FilePath $outputFile -Append
Write-Host "List of Running Processes fetched successfully."

# 14. List of Services using net start (Lolbin)
Write-Host "Fetching List of Services using net start..."
"14. List of Services" | Out-File -FilePath $outputFile -Append
net start | Out-File -FilePath $outputFile -Append
Write-Host "List of Services fetched successfully."

# 15. System Event Logs using wevtutil (Lolbin)
Write-Host "Fetching System Event Logs using wevtutil..."
"15. System Event Logs" | Out-File -FilePath $outputFile -Append
wevtutil qe System /f:text /c:10 | Out-File -FilePath $outputFile -Append
Write-Host "System Event Logs fetched successfully."

# 16. GPU Information using Get-WmiObject
Write-Host "Fetching GPU Information..."
"16. GPU Information" | Out-File -FilePath $outputFile -Append

# Get GPU Information using WMI
$gpuInfo = Get-WmiObject Win32_VideoController | Select-Object Name, DriverVersion, VideoProcessor, AdapterRAM, DeviceID
$gpuInfo | Out-File -FilePath $outputFile -Append

Write-Host "GPU Information fetched successfully."


# 17. Audio Device Information using WMIC (Lolbin)
Write-Host "Fetching Audio Device Information using WMIC..."
"17. Audio Device Information" | Out-File -FilePath $outputFile -Append
wmic sounddev get caption | Out-File -FilePath $outputFile -Append
Write-Host "Audio Device Information fetched successfully."

# 18. Network Interface Details using netsh (Lolbin)
Write-Host "Fetching Network Interface Details using netsh..."
"18. Network Interface Details" | Out-File -FilePath $outputFile -Append
netsh interface ipv4 show subinterface | Out-File -FilePath $outputFile -Append
Write-Host "Network Interface Details fetched successfully."

# 19. BIOS Version Information using WMIC (Lolbin)
Write-Host "Fetching BIOS Version Information using WMIC..."
"19. BIOS Version Information" | Out-File -FilePath $outputFile -Append
wmic bios get smbiosbiosversion | Out-File -FilePath $outputFile -Append
Write-Host "BIOS Version Information fetched successfully."

# 20. USB Devices Information using WMIC (Lolbin)
Write-Host "Fetching USB Devices Information using WMIC..."
"20. USB Devices Information" | Out-File -FilePath $outputFile -Append
wmic path Win32_USBHub get DeviceID | Out-File -FilePath $outputFile -Append
Write-Host "USB Devices Information fetched successfully."

# 21. Environmental Variables
Write-Host "Fetching Environmental Variables..."
"21. Environmental Variables" | Out-File -FilePath $outputFile -Append

# Get all environment variables
$envVars = [System.Environment]::GetEnvironmentVariables()

# Output all environment variables to the file
foreach ($key in $envVars.Keys) {
    "$key = $($envVars[$key])" | Out-File -FilePath $outputFile -Append
}

Write-Host "Environmental Variables fetched successfully."


# 22. Current Power Scheme using powercfg (Lolbin)
Write-Host "Fetching Current Power Scheme using powercfg..."
"22. Current Power Scheme" | Out-File -FilePath $outputFile -Append
powercfg /getactivescheme | Out-File -FilePath $outputFile -Append
Write-Host "Current Power Scheme fetched successfully."

# 23. Firewall Status using netsh (Lolbin)
Write-Host "Fetching Firewall Status using netsh..."
"23. Firewall Status" | Out-File -FilePath $outputFile -Append
netsh advfirewall show allprofiles | Out-File -FilePath $outputFile -Append
Write-Host "Firewall Status fetched successfully."

# 24. Antivirus Software Details using WMIC (Lolbin)
Write-Host "Fetching Antivirus Software Details using WMIC..."
"24. Antivirus Software Details" | Out-File -FilePath $outputFile -Append
wmic /namespace:\\root\SecurityCenter2 path AntiVirusProduct get displayName | Out-File -FilePath $outputFile -Append
Write-Host "Antivirus Software Details fetched successfully."

# 25. Antivirus Software Details
Write-Host "Fetching Antivirus Software Details..."
"25. Antivirus Software Details" | Out-File -FilePath $outputFile -Append

# Use Get-WmiObject to gather antivirus software details
$antivirusInfo = Get-WmiObject -Namespace "Root\SecurityCenter2" -Class AntiVirusProduct

# Output antivirus software details
$antivirusInfo | Out-File -FilePath $outputFile -Append


# 26. Installed Software Details
Write-Host "Fetching Installed Software Details..."
"26. Installed Software Details" | Out-File -FilePath $outputFile -Append

# Use Get-WmiObject to gather installed software details
$installedSoftware = Get-WmiObject -Class Win32_Product

# Output installed software details
$installedSoftware | Out-File -FilePath $outputFile -Append


# 27. List of Installed Software
Write-Host "Fetching List of Installed Software..."
"27. List of Installed Software" | Out-File -FilePath $outputFile -Append

# Use Get-WmiObject to get a list of installed software
$installedSoftware = Get-WmiObject -Class Win32_Product | Select-Object Name, Version

# Output installed software details
$installedSoftware | Out-File -FilePath $outputFile -Append


# 28. System Locale Information
Write-Host "Fetching System Locale Information..."
"28. System Locale Information" | Out-File -FilePath $outputFile -Append

# Get the system locale information
$locale = Get-WinSystemLocale

# Output the locale details
$locale | Out-File -FilePath $outputFile -Append


# 29. System Timezone Information
Write-Host "Fetching System Timezone Information..."
"29. System Timezone Information" | Out-File -FilePath $outputFile -Append
Get-TimeZone | Out-File -FilePath $outputFile -Append
Write-Host "System Timezone Information fetched successfully."

# 30. Processor Architecture
Write-Host "Fetching Processor Architecture Information..."
"30. Processor Architecture" | Out-File -FilePath $outputFile -Append

# Get processor architecture information
$architecture = Get-WmiObject -Class Win32_Processor | Select-Object -ExpandProperty Architecture

# Output the processor architecture details
$architecture | Out-File -FilePath $outputFile -Append

# You can map the output values:
# 0 = x86
# 1 = MIPS
# 2 = Alpha
# 3 = PowerPC
# 5 = ARM
# 6 = Itanium
# 9 = x64 (AMD or Intel)

Write-Host "Processor Architecture fetched successfully."

# 31. System Memory Details
Write-Host "Fetching System Memory Details..."
"31. System Memory Details" | Out-File -FilePath $outputFile -Append

# Get total physical memory and available memory
$memory = Get-WmiObject -Class Win32_OperatingSystem | Select-Object TotalVisibleMemorySize, FreePhysicalMemory

# Output the total and free memory details (in KB)
"Total Memory: $($memory.TotalVisibleMemorySize / 1MB) MB" | Out-File -FilePath $outputFile -Append
"Free Memory: $($memory.FreePhysicalMemory / 1MB) MB" | Out-File -FilePath $outputFile -Append

# Get detailed physical memory information (installed memory)
$physicalMemory = Get-WmiObject -Class Win32_PhysicalMemory | Select-Object Capacity, Manufacturer, PartNumber

# Output the detailed memory info
$physicalMemory | ForEach-Object {
    "Memory Module: $($_.Manufacturer) - Capacity: $($_.Capacity / 1GB) GB - Part: $($_.PartNumber)"
} | Out-File -FilePath $outputFile -Append

Write-Host "System Memory Details fetched successfully."

# 32. Disk Partition Information
Write-Host "Fetching Disk Partition Information..."
"32. Disk Partition Information" | Out-File -FilePath $outputFile -Append
Get-WmiObject -Class Win32_DiskPartition | Out-File -FilePath $outputFile -Append
Write-Host "Disk Partition Information fetched successfully."

# 33. IP Address Information
Write-Host "Fetching IP Address Information..."
"33. IP Address Information" | Out-File -FilePath $outputFile -Append

# Fetch IPv4 and IPv6 addresses
Get-NetIPAddress | ForEach-Object {
    "InterfaceAlias: $($_.InterfaceAlias), AddressFamily: $($_.AddressFamily), IPAddress: $($_.IPAddress), PrefixLength: $($_.PrefixLength)" 
} | Out-File -FilePath $outputFile -Append

# Alternative using ipconfig
Write-Host "Fetching IP Details using ipconfig..."
ipconfig | Out-String | Out-File -FilePath $outputFile -Append

Write-Host "IP Address Information fetched successfully."

# 34. System Boot Time
Write-Host "Fetching System Boot Time..."
"34. System Boot Time" | Out-File -FilePath $outputFile -Append
(Get-CimInstance -ClassName Win32_OperatingSystem).LastBootUpTime | Out-File -FilePath $outputFile -Append
Write-Host "System Boot Time fetched successfully."

# 35. System Logon Time
Write-Host "Fetching System Logon Time..."
"35. System Logon Time" | Out-File -FilePath $outputFile -Append
(Get-WmiObject -Class Win32_OperatingSystem).LastBootUpTime | Out-File -FilePath $outputFile -Append
Write-Host "System Logon Time fetched successfully."

# 36. System Memory Usage
Write-Host "Fetching System Memory Usage..."
"36. System Memory Usage" | Out-File -FilePath $outputFile -Append
Get-WmiObject -Class Win32_OperatingSystem | Select-Object FreePhysicalMemory, TotalVisibleMemorySize | Out-File -FilePath $outputFile -Append
Write-Host "System Memory Usage fetched successfully."

# 37. System Processes Information
Write-Host "Fetching System Processes Information..."
"37. System Processes Information" | Out-File -FilePath $outputFile -Append
Get-WmiObject -Class Win32_Process | Out-File -FilePath $outputFile -Append
Write-Host "System Processes Information fetched successfully."

# 38. Active Directory User Accounts (If applicable)
Write-Host "Attempting to Fetch Active Directory User Accounts..."
"38. Active Directory User Accounts (If applicable)" | Out-File -FilePath $outputFile -Append
# Commented out as AD module might not be present
# Get-ADUser -Filter * | Out-File -FilePath $outputFile -Append
Write-Host "Active Directory User Accounts fetch skipped (module not available)."

# 39. System DNS Information
Write-Host "Fetching System DNS Information..."
"39. System DNS Information" | Out-File -FilePath $outputFile -Append
Get-DnsClientServerAddress | Out-File -FilePath $outputFile -Append
Write-Host "System DNS Information fetched successfully."

# 40. Boot Device Information
Write-Host "Fetching Boot Device Information..."
"40. Boot Device Information" | Out-File -FilePath $outputFile -Append
(Get-WmiObject -Class Win32_OperatingSystem).BootDevice | Out-File -FilePath $outputFile -Append
Write-Host "Boot Device Information fetched successfully."

# 41. Active Directory Information (If applicable)
Write-Host "Attempting to Fetch Active Directory Information..."
"41. Active Directory Information (If applicable)" | Out-File -FilePath $outputFile -Append
# Commented out due to AD cmdlet not being available
# Get-ADDomain | Out-File -FilePath $outputFile -Append
Write-Host "Active Directory Information fetch skipped (module not available)."

# 42. List of Shares
Write-Host "Fetching List of Shares..."
"42. List of Shares" | Out-File -FilePath $outputFile -Append
Get-WmiObject -Class Win32_Share | Out-File -FilePath $outputFile -Append
Write-Host "List of Shares fetched successfully."

# 43. Network Connections
Write-Host "Fetching Network Connections..."
"43. Network Connections" | Out-File -FilePath $outputFile -Append
Get-NetTCPConnection | Out-File -FilePath $outputFile -Append
Write-Host "Network Connections fetched successfully."

# 44. User Login Information
Write-Host "Fetching User Login Information..."
"44. User Login Information" | Out-File -FilePath $outputFile -Append
Get-WmiObject -Class Win32_ComputerSystem | Select-Object UserName | Out-File -FilePath $outputFile -Append
Write-Host "User Login Information fetched successfully."

# 45. File System Information
Write-Host "Fetching File System Information..."
"45. File System Information" | Out-File -FilePath $outputFile -Append
Get-WmiObject -Class Win32_LogicalDisk | Out-File -FilePath $outputFile -Append
Write-Host "File System Information fetched successfully."

# 46. System Configuration
Write-Host "Fetching System Configuration..."
"46. System Configuration" | Out-File -FilePath $outputFile -Append
Get-WmiObject -Class Win32_OperatingSystem | Select-Object -Property OSArchitecture | Out-File -FilePath $outputFile -Append
Write-Host "System Configuration fetched successfully."

# 47. Shared Folders
"47. Shared Folders" | Out-File -FilePath $outputFile -Append
Write-Host "Shared Folders status: Retrieving shared folders..."
Get-WmiObject -Class Win32_Share | Out-File -FilePath $outputFile -Append
Write-Host "Shared Folders status: Complete"

# 48. Pending Windows Updates
"48. Pending Windows Updates" | Out-File -FilePath $outputFile -Append
Write-Host "Pending Windows Updates status: Retrieving pending updates..."
Get-WmiObject -Class Win32_QuickFixEngineering | Out-File -FilePath $outputFile -Append
Write-Host "Pending Windows Updates status: Complete"

# 49. Windows Firewall Configuration
"49. Windows Firewall Configuration" | Out-File -FilePath $outputFile -Append
Write-Host "Windows Firewall Configuration status: Retrieving firewall rules..."
Get-NetFirewallRule | Out-File -FilePath $outputFile -Append
Write-Host "Windows Firewall Configuration status: Complete"

# 50. System Services Status
"50. System Services Status" | Out-File -FilePath $outputFile -Append
Write-Host "System Services Status: Retrieving services..."
Get-Service | Out-File -FilePath $outputFile -Append
Write-Host "System Services Status: Complete"

# 51. VPN Connections (If applicable)
"51. VPN Connections (If applicable)" | Out-File -FilePath $outputFile -Append
Write-Host "VPN Connections status: Retrieving VPN connections..."
# Get-VpnConnection | Out-File -FilePath $outputFile -Append  # Disabled because VPN cmdlet may not be present
Write-Host "VPN Connections status: Complete"

# 52. Device Drivers Information
"52. Device Drivers Information" | Out-File -FilePath $outputFile -Append
Write-Host "Device Drivers Information status: Retrieving device drivers..."
Get-WmiObject -Class Win32_PnPEntity | Out-File -FilePath $outputFile -Append
Write-Host "Device Drivers Information status: Complete"

# 53. System Temperature (If applicable)
"53. System Temperature (If applicable)" | Out-File -FilePath $outputFile -Append
Write-Host "System Temperature status: Retrieving system temperature..."
Get-WmiObject -Class Win32_TemperatureProbe | Out-File -FilePath $outputFile -Append
Write-Host "System Temperature status: Complete"

# 54. Sysmon Configuration
Write-Host "Fetching Sysmon Configuration..."
"54. Sysmon Configuration" | Out-File -FilePath $outputFile -Append

# Check if Sysmon is installed
if (Get-Command sysmon.exe -ErrorAction SilentlyContinue) {
    Write-Host "Sysmon is installed. Fetching configuration..."
    sysmon.exe -c | Out-File -FilePath $outputFile -Append
} else {
    Write-Host "Sysmon is not installed on this system."
    "Sysmon is not installed on this system." | Out-File -FilePath $outputFile -Append
}
Write-Host "Sysmon Configuration: Complete"

# Open the file after generating it
Start-Process $outputFile




# Define the output file path
$outputFile = "$env:USERPROFILE\Documents\VulnerabilityDetectionOutput.txt"

# Initialize the output file (create or overwrite)
New-Item -Path $outputFile -ItemType File -Force | Out-Null

# Function to check Windows Updates
Write-Host "Checking Windows updates..."
$windowsUpdate = Get-WmiObject -Class Win32_QuickFixEngineering
$windowsUpdate | Out-File -FilePath $outputFile -Append
Write-Host "Windows updates check completed."

# Check antivirus status
Write-Host "Checking antivirus status..."
$antivirus = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct
if ($antivirus) {
    $antivirus | Out-File -FilePath $outputFile -Append
} else {
    "No Antivirus software detected!" | Out-File -FilePath $outputFile -Append
}
Write-Host "Antivirus check completed."

# Check for open ports
# Check Open Ports
Write-Host "Fetching open ports..."
"Checking Open Ports" | Out-File -FilePath $outputFile -Append

# Using 'netstat' via PowerShell
netstat -ano | ForEach-Object {
    if ($_ -match "LISTENING") {
        $_
    }
} | Out-File -FilePath $outputFile -Append
Write-Host "Open port information has been saved."


# Check for weak passwords (Local User Accounts)
Write-Host "Starting weak password checks..." -ForegroundColor Green

# Check for accounts with no passwords
Write-Host "\nChecking for accounts with no passwords..." -ForegroundColor Yellow
$NoPasswordAccounts = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.PasswordRequired -eq $false }
if ($NoPasswordAccounts) {
    $NoPasswordAccounts | Select-Object Name, Disabled, PasswordRequired | ForEach-Object {
        Write-Host "User: $($_.Name), Disabled: $($_.Disabled), Password Required: $($_.PasswordRequired)" -ForegroundColor Cyan
    }
} else {
    Write-Host "No accounts with blank passwords found." -ForegroundColor Green
}

# Check for accounts with non-expiring passwords
Write-Host "\nChecking for accounts with non-expiring passwords..." -ForegroundColor Yellow
$NonExpiringPasswordAccounts = Get-WmiObject -Class Win32_UserAccount | Where-Object { $_.PasswordExpires -eq $false }
if ($NonExpiringPasswordAccounts) {
    $NonExpiringPasswordAccounts | Select-Object Name, Disabled, PasswordExpires | ForEach-Object {
        Write-Host "User: $($_.Name), Disabled: $($_.Disabled), Password Expires: $($_.PasswordExpires)" -ForegroundColor Cyan
    }
} else {
    Write-Host "No accounts with non-expiring passwords found." -ForegroundColor Green
}

Write-Host "\nWeak password check completed." -ForegroundColor Green

Write-Host "Weak password check completed."

# Check for Windows Defender status
Write-Host "Checking Windows Defender status..."
$defenderStatus = Get-WmiObject -Namespace "root\Microsoft\Windows\Defender" -Class MSFT_MpComputerStatus
if ($defenderStatus) {
    $defenderStatus | Out-File -FilePath $outputFile -Append
} else {
    "Windows Defender is not active!" | Out-File -FilePath $outputFile -Append
}
Write-Host "Windows Defender status check completed."

# Check Firewall status
Write-Host "Checking Firewall Status..." -ForegroundColor Green

# Check if the Windows Firewall service is running
$FirewallService = Get-Service -Name "MpsSvc" -ErrorAction SilentlyContinue
if ($FirewallService -and $FirewallService.Status -eq "Running") {
    Write-Host "Windows Firewall Service is running." -ForegroundColor Cyan
} else {
    Write-Host "Windows Firewall Service is not running." -ForegroundColor Red
}

# Get the status of the firewall profiles (Domain, Private, Public)
Write-Host "Checking firewall profiles..." -ForegroundColor Yellow
$FirewallProfiles = Get-NetFirewallProfile
$FirewallProfiles | ForEach-Object {
    $ProfileName = $_.Name
    $Enabled = if ($_.Enabled) { "Enabled" } else { "Disabled" }
    Write-Host "$ProfileName Profile: $Enabled" -ForegroundColor Cyan
}

Write-Host "Firewall status check completed." -ForegroundColor Green

Write-Host "Firewall status check completed."

# Check for critical patches
Write-Host "Checking for critical patches..."
$criticalPatches = Get-WmiObject -Class Win32_QuickFixEngineering | Where-Object { $_.Description -match "Security Update" }
$criticalPatches | Out-File -FilePath $outputFile -Append
Write-Host "Critical patches check completed."

# Check for outdated software (using a list of known software)
Write-Host "Checking for outdated software..."
$outdatedSoftware = Get-WmiObject -Class Win32_Product | Where-Object { $_.Version -lt "2.0" }
$outdatedSoftware | Out-File -FilePath $outputFile -Append
Write-Host "Outdated software check completed."


# Final completion message
"Vulnerability Detection Completed. Results are saved in $outputFile" | Out-File -FilePath $outputFile -Append
Write-Host "Vulnerability detection completed and saved to $outputFile"

# Open the output file in Notepad
Start-Process notepad.exe $outputFile



# Define the output file
$outputFile = "$env:USERPROFILE\Desktop\NetworkScanResults.txt"

# Clear the file if it already exists
if (Test-Path $outputFile) {
    Remove-Item $outputFile
}

# Function to format and clean the output
function Write-FormattedOutput {
    param (
        [string]$text
    )
    $text | Out-File -FilePath $outputFile -Append
    $text
}

# List of commands to execute
Write-FormattedOutput "Running Network Neighbor and Adapter Information..."
Write-FormattedOutput "1. Get-NetNeighbor"
Get-NetNeighbor | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append

Write-FormattedOutput "2. Get-NetAdapter"
Get-NetAdapter | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append

# Get DNS Server Search Order
Write-FormattedOutput "Running DNS Server Search Order information..."
Write-FormattedOutput "3. Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.DNSServerSearchOrder }"
Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.DNSServerSearchOrder } | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append

# Get Network Connection Profile
Write-FormattedOutput "Running Network Connection Profile..."
Write-FormattedOutput "4. Get-NetConnectionProfile"
Get-NetConnectionProfile | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append

# Get SMB Share Information
Write-FormattedOutput "Running SMB Share information..."
Write-FormattedOutput "5. Get-SmbShare"
Get-SmbShare | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append

# Get TCP/UDP Connections
Write-FormattedOutput "Running TCP/UDP Connection information..."
Write-FormattedOutput "6. Get-NetTCPConnection; Get-NetUDPEndpoint"
Get-NetTCPConnection | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append
Get-NetUDPEndpoint | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append

# Get RPC Endpoint Information (with existence check)
Write-FormattedOutput "Running RPC Endpoint information..."
Write-FormattedOutput "7. Get-WmiObject -Class Win32_RpcEndpoint"
$rpcEndpoint = Get-WmiObject -Class Win32_RpcEndpoint -ErrorAction SilentlyContinue
if ($rpcEndpoint) {
    $rpcEndpoint | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append
} else {
    Write-FormattedOutput "Win32_RpcEndpoint class not found on this system."
}

# Get Listening TCP/UDP Ports
Write-FormattedOutput "Running Listening TCP/UDP Ports information..."
Write-FormattedOutput "8. Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }; Get-NetUDPEndpoint"
Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' } | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append
Get-NetUDPEndpoint | Format-Table -AutoSize | Out-File -FilePath $outputFile -Append

# Wait for all commands to finish
# Wait for all commands to finish
Start-Sleep -Seconds 2

# Ensure the Notepad process is invoked correctly by passing the correct file path
Start-Process "notepad.exe" -ArgumentList $outputFile

$time = (Get-Date).AddHours(-24).ToString("yyyy-MM-ddTHH:mm:ss")
$logFilePath = "$env:USERPROFILE\Desktop\event_logs.txt"
$backupFilePath = "$env:USERPROFILE\Desktop\event_logs_backup.txt"

# Retrieve the event logs and save them to the file
wevtutil qe System "/q:*[System[TimeCreated[@SystemTime>='$time']]]" /f:text > $logFilePath

# Copy the content to another document (backup)
Copy-Item -Path $logFilePath -Destination $backupFilePath

# Open the saved log file
Start-Process $logFilePath

Write-Host "Event logs saved to $logFilePath and opened. Backup saved to $backupFilePath."

