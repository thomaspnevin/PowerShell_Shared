<#
.SYNOPSIS
    PowerShell Packet Capture - No Install Required - Requires PowerShell v4.0 minimum.

.DESCRIPTION
    This script leverages Windows' native tracing capabilities to perform packet captures without the need for additional software installations, such as Wireshark. 
	It is designed to run on any Windows server with PowerShell 4.0 or later, providing a readable output of the captured data.

    Key features:
    - Runs packet captures without requiring any installations.
    - Outputs data in a readable format.
    - RUN AS ADMIN REQUIRED

	The script performs the following steps:
    1) Captures network traffic for a specified duration.
    2) Converts the captured ETL file to a TXT format.
    3) Parses the TXT file to identify TCP and UDP traffic.
    4) Extracts essential data from each line, including:
        - Local IP
        - Local Port
        - Remote IP
        - Remote Port
        - DateTimeStamp
    5) Validates the local and remote addresses and adds them to an array if valid.
    6) Filters the array to display only unique connections.
    7) Outputs the results as specified.
	
.PARAMETER [ParameterName]
    
.EXAMPLE
    This script will take several minutes to complete all activities after the capture duration has ended. 
	It processes the entire capture file twice to extract data for both UDP and TCP traffic. 
	The amount of data processed will vary depending on the environment where the script is run.

.NOTES
    Author:           Thomas Nevin
    Date:             23/09/2024
    Version:          1.0.1
    Script Name:      PowerShell_Packet_Capture.ps1
    Additional Notes:  

.LINK
    

#>

# Adding checkpoints so script duration can be monitored. 
$CheckPoint_1 = Get-Date

# Function to prompt the user with a Y/N question and ensures a valid response is captured.
# This function repeatedly asks the user for input until a valid 'Y' or 'N' response is provided.
# It returns $true for 'Y' and $false for 'N'.
function Get-logicalYesNo {
    param (
        [string]$question
    )
    do {
        $sAnswer = Read-Host "$question [Y/N]"
    } until ($sAnswer.ToUpper()[0] -match '[YyNn]')
    
    return ($sAnswer.ToUpper()[0] -eq 'Y')
}
$ExportReport = Get-logicalYesNo -question "Do you wish to output to CSV? Selecting N will store output in PowerShell arrays only. Y/N"

# ======================================================================================
# ============================= Required Input & Controls ==============================

# Set the time limit for the capture to run. 
$Duration_Minutes = 10

$Folder_Path = "C:\Temp\PoSh_Capture"
$NetEvent_Session_Name = "PoSh_Capture_Session"
$NetEvent_Provider_Name = "Microsoft-Windows-TCPIP"
$ETL_Path = "C:\WINDOWS\system32\config\systemprofile\AppData\Local\NetEventTrace.etl"
$ETL_Path_New = "C:\Temp\PoSh_Capture\NetEventTrace.etl"
$ETL_Parsed_TXT = "C:\Temp\PoSh_Capture\Trace_Converted.txt"
$Total_Out_File_Path  = "C:\Temp\PoSh_Capture\$($env:computername)_$($OutputTimeStamp)_Total.csv"
$OutputTimeStamp = (Get-Date).tostring("yyyyMMdd-hhmmss")
$Unique_Out_File_Path  = "C:\Temp\PoSh_Capture\$($env:computername)_$($OutputTimeStamp)_Unique.csv"

# ======================================================================================
# ============================= PreScript Checks & Actions =============================

# Creating an empty array to store the captured results. 
$Connections_Report = @()

# Creating the folder if it doesnt exist. 
if (Test-Path -Path $Folder_Path){
} else {
mkdir $Folder_Path
}

# Clean up any old capture files
if (Test-Path $ETL_Path_New) { Remove-Item $ETL_Path_New}
if (Test-Path $ETL_Parsed_TXT) { Remove-Item $ETL_Parsed_TXT}

# ======================================================================================
# ================================ Starting The Capture ================================

Write-Host "Creating a new capture session with designated session name & custom path"
try {	
New-NetEventSession -Name $NetEvent_Session_Name
} catch {
    Write-Host "Failed to assign parameters to capture - cancelling further action: $_"
    exit
}
Write-Host "Assigning the Microsoft-Windows-TCPIP provider to our custom capture session"
try {	
Add-NetEventProvider -Name $NetEvent_Provider_Name -SessionName $NetEvent_Session_Name
} catch {
    Write-Host "Failed to assign provider to capture - cancelling further action: $_"
    exit
}
Write-Host "Starting the capture"
try {	
Start-NetEventSession -Name $NetEvent_Session_Name
Write-Host "Network capture started successfully."
} catch {
    Write-Host "Failed to start capture - cancelling further action: $_"
    exit
}

# ======================================================================================
# ================================= Starting The Wait ==================================

# Sleep for a defined period to capture activity (change this as needed)
Write-Host "Allowing $Duration_Minutes minutes to capture network traffic..."

# Multiplying duration by 60 seconds and waiting. 
Start-Sleep -Seconds ($Duration_Minutes * 60)

# ======================================================================================
# ================================ Stopping The Capture ================================

Write-Host "Stopping network capture..."
try {
    Stop-NetEventSession -Name $NetEvent_Session_Name
    Write-Host "Network capture stopped successfully."
} catch {
    Write-Host "Failed to stop capture: $_"
    exit
}

# ======================================================================================
# =============================== Cleanup Capture Session ==============================

Write-Host "Removing Capture Session"
try {
Remove-NetEventSession -Name $NetEvent_Session_Name
} catch {
    Write-Host "Error cleaning up capture session: $_"
	continue
}

# ======================================================================================
# =============================== Checking Capture Output ==============================

copy $ETL_Path $ETL_Path_New

# Check if the capture file was created
if (-not (Test-Path $ETL_Path_New)) {
    Write-Host "Capture file was not created. Exiting..."
    exit
}

# ======================================================================================
# ============================== Converting Capture Output =============================

# Convert the .etl file to .txt format using Netsh
Write-Host "Converting ETL file to TXT format using netsh trace convert..."
try {
    netsh trace convert input=$ETL_Path_New output=$ETL_Parsed_TXT
    Write-Host "ETL file converted successfully to $($ETL_Parsed_TXT)"
} catch {
    Write-Host "Failed to convert ETL file: $_"
	exit
}

# Check if the parsed ETL file was created
if (-not (Test-Path $ETL_Parsed_TXT)) {
    Write-Host "Parsed ETL file was not created. Exiting..."
    exit
}

$CheckPoint_2 = Get-Date

# ======================================================================================
# ================================= UDP Connections ====================================

# Extract UDP details from the parsed file
Write-Host "Extracting UDP details..."
try {
	$UDP_Lines = Get-Content $ETL_Parsed_TXT | Select-String -Pattern "UDP:"
	ForEach ($Line in $UDP_Lines){
		# Setting variables to null & resetting at start of loop
		$LocalIP = $null
        $LocalPort = $null
        $RemoteIP = $null
        $RemotePort = $null
		$DateTimeStamp = $null 
		
        # Extract the local IP and port information
        if ($line -match "LocalAddress\s*=\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)") {
        $LocalIP = $matches[1]
        $LocalPort = $matches[2]
        }
        # Extract the remote IP and port information
        if ($line -match "RemoteAddress\s*=\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)") {
        $RemoteIP = $matches[1]
        $RemotePort = $matches[2]
        }
        # Extract the datetimestamp accounting for different formats
        if ($line -match "(?<DateTime>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})" -or $line -match "(?<DateTime>\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})" -or $line -match "(?<DateTime>\d{2}.\d{2}.\d{4} \d{2}:\d{2}:\d{2})") {
            $DateTimeStamp = $matches['DateTime']
        }
	
		$UDP_CustomObject = New-Object -TypeName PSObject -Property @{
			'Protocol'       = "UDP"
			'Local Address'  = $LocalIP
            'Local Port'     = $LocalPort
            'Remote Address' = $RemoteIP
            'Remote Port'    = $RemotePort
			'DateTimeStamp'  = $DateTimeStamp
			}
			# Add the custom object to the array only if it meets certain criteria
			if ($LocalIP -eq "0.0.0.0" -and $RemoteIP -eq "0.0.0.0"){
				# continue breaks the foreach loop
				continue 
				}
			if ($LocalIP -eq "127.0.0.1" -and $RemoteIP -eq "127.0.0.1"){
				continue 
				}
			if ($LocalIP -eq "0.0.0.0" -and $RemoteIP -eq "127.0.0.1"){
				continue 
				}
			if ($LocalIP -eq "127.0.0.1" -and $RemoteIP -eq "0.0.0.0"){
				continue 
				}
			if ($LocalIP -and $RemoteIP){
			$Connections_Report += $UDP_CustomObject
			}
}
			Write-Host "UDP Extractions Completed"
			} catch {
				Write-Host "Failed to extract UDP details: $_"
				}

$CheckPoint_3 = Get-Date
# ======================================================================================
# ================================= TCP Connections ====================================

Write-Host "Extracting TCP details..."
try {
	$TCP_Lines = Get-Content $ETL_Parsed_TXT | Select-String -Pattern "TCP:"
	ForEach ($Line in $TCP_Lines){
		$LocalIP = $null
        $LocalPort = $null
        $RemoteIP = $null
        $RemotePort = $null
		$DateTimeStamp = $null 
		
        if ($line -match "local=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)") {
        $LocalIP = $matches[1]
        $LocalPort = $matches[2]
        }
		
        if ($line -match "remote=(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d+)") {
        $RemoteIP = $matches[1]
        $RemotePort = $matches[2]
        }

        if ($line -match "(?<DateTime>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})" -or $line -match "(?<DateTime>\d{2}-\d{2}-\d{4} \d{2}:\d{2}:\d{2})" -or $line -match "(?<DateTime>\d{2}.\d{2}.\d{4} \d{2}:\d{2}:\d{2})") {
            $DateTimeStamp = $matches['DateTime']
        }
		
		$TCP_CustomObject = New-Object -TypeName PSObject -Property @{
			'Protocol'       = "TCP"
			'Local Address'  = $LocalIP
            'Local Port'     = $LocalPort
            'Remote Address' = $RemoteIP
            'Remote Port'    = $RemotePort
			'DateTimeStamp'  = $DateTimeStamp
			}
			if ($LocalIP -eq "0.0.0.0" -and $RemoteIP -eq "0.0.0.0"){
				continue 
				}
			if ($LocalIP -eq "127.0.0.1" -and $RemoteIP -eq "127.0.0.1"){
				continue 
				}
			if ($LocalIP -eq "0.0.0.0" -and $RemoteIP -eq "127.0.0.1"){
				continue 
				}
			if ($LocalIP -eq "127.0.0.1" -and $RemoteIP -eq "0.0.0.0"){
				continue 
				}
			if ($LocalIP -and $RemoteIP){
			$Connections_Report += $TCP_CustomObject
			}
}
			Write-Host "TCP Extractions Completed"
			} catch {
				Write-Host "Failed to extract TCP details: $_"
				}

$CheckPoint_4 = Get-Date
# ======================================================================================
# ================================= Results & Output ===================================

# Filtering for unique connection objects to create a summary. 
$Unique_Connections = $Connections_Report | Select 'Protocol', 'Local Address', 'Local Port', 'Remote Address', 'Remote Port' -Unique

# Seconds passed including capture duration
$Capture_Complete_Timer = ($CheckPoint_2 - $CheckPoint_1).Seconds
# Seconds to process UDP connections
$UDP_Complete_Timer = ($CheckPoint_3 - $CheckPoint_2).Seconds
# Seconds to process TCP connections
$TCP_Complete_Timer = ($CheckPoint_4 - $CheckPoint_3).Seconds
# Seconds from initial run to end
$Script_Complete_Timer = ($CheckPoint_4 - $CheckPoint_1).Seconds

$Total_Connections_Count = $Connections_Report.Count
$Unique_Connections_Count = $Unique_Connections.Count

Write-Host "---------------------------------------------------------"
Write-Host "--------------- Script Performance Report ---------------"
Write-Host "Network Capture Run Time              : $Duration_Minutes minutes"
Write-Host "Total TCP & UDP connections captured  : $Total_Connections_Count"
Write-Host "Unique TCP & UDP connections captured : $Unique_Connections_Count"
Write-Host "---------------------------------------------------------"
Write-Host "Script Duration Total                 : $Script_Complete_Timer (seconds)"
Write-Host "UDP Connections Processing Time       : $UDP_Complete_Timer (seconds)"
Write-Host "TCP Connections Processing Time       : $TCP_Complete_Timer (seconds)"
Write-Host "---------------------------------------------------------"
if ($ExportReport){
Write-Host "You have selected to output to CSV - C:\Temp\PoSh_Capture\ folder contains both the full capture details and a summary of unique connections"
} else {
Write-Host "You have selected not to output to CSV - All script data is avaible in PowerShell arrays as outlined below."
Write-Host "Full Report     : Connections_Report"
Write-Host "Unique Filtered : Unique_Connections"
}
# Output Preference
if ($ExportReport){
$Connections_Report | Select 'Protocol', 'Local Address', 'Local Port', 'Remote Address', 'Remote Port', 'DateTimeStamp' | Sort-Object 'DateTimeStamp' | Export-CSV -Path $Total_Out_File_Path  -NoTypeInformation
$Unique_Connections | Select 'Protocol', 'Local Address', 'Local Port', 'Remote Address', 'Remote Port' | Export-CSV -Path $Unique_Out_File_Path -NoTypeInformation
} else {
#$Connections_Report | Select 'Protocol', 'Local Address', 'Local Port', 'Remote Address', 'Remote Port', 'DateTimeStamp' | Sort-Object 'DateTimeStamp' | Ft -AutoSize
}
