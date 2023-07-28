function Get-SystemReport {
    <#
    .SYNOPSIS
    Generate a report of system changes

    .DESCRIPTION
    Generate a report of system changes
    If no Get-PastDate parameters are specified all UWP Apps are listed

    .LINK
    Get-PastDate
    #>

    [CmdletBinding()]
    Param (
        # File path to search
        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Dir')]
        [String]$FilePath,
        # Filename to save JSON output to (optional)
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [String]$JsonFile,
        # Parameters for Get-PastDate
        [parameter(ValueFromRemainingArguments = $True)]$RemainingArguments
    )

    Write-Output "Collecting Processes"
    $Processes = Get-NewProcess $RemainingArguments
    Write-Output "Collecting Apps"
    $Apps = Get-NewApp $RemainingArguments
    Write-Output "Collecting UWP Apps"
    $UwpApps = Get-NewUwpApp $RemainingArguments
    Write-Output "Collecting Drivers"
    $Drivers = Get-NewDriver $RemainingArguments
    Write-Output "Collecting Services"
    $Services = Get-NewService $RemainingArguments
    Write-Output "Collecting Port Monitors"
    $PortMonitors = Get-NewPortMonitor $RemainingArguments
    Write-Output "Collecting Protocol Handlers"
    $ProtocolHandlers = Get-NewProtocolHandler $RemainingArguments
    Write-Output "Collecting TCP Listeners"
    $TCPListeners = Get-NewTCPListener $RemainingArguments
    Write-Output "Collecting UDP Listeners"
    $UDPListeners = Get-NewUDPListener $RemainingArguments
    if ($FilePath) {
        Write-Output "Collecting Files"
        $Files = Get-NewFile $FilePath $RemainingArguments
    }

    if ($JsonFile) {
        $JsonData = New-Object PSObject
        Add-Member -InputObject $JsonData -Name "Processes" -MemberType NoteProperty -Value $Processes
        Add-Member -InputObject $JsonData -Name "Apps" -MemberType NoteProperty -Value $Apps
        Add-Member -InputObject $JsonData -Name "UWPApps" -MemberType NoteProperty -Value $UwpApps
        Add-Member -InputObject $JsonData -Name "Drivers" -MemberType NoteProperty -Value $Drivers
        Add-Member -InputObject $JsonData -Name "Services" -MemberType NoteProperty -Value $Services
        Add-Member -InputObject $JsonData -Name "PortMonitors" -MemberType NoteProperty -Value $PortMonitors
        Add-Member -InputObject $JsonData -Name "ProtocolHandlers" -MemberType NoteProperty -Value $ProtocolHandlers
        Add-Member -InputObject $JsonData -Name "TCPListeners" -MemberType NoteProperty -Value $TCPListeners
        Add-Member -InputObject $JsonData -Name "UDPListeners" -MemberType NoteProperty -Value $UEPListeners
        if ($Files) {
            Add-Member -InputObject $JsonData -Name "Files" -MemberType NoteProperty -Value $Files
        }
        $JsonData | ConvertTo-Json | Out-File -FilePath $JsonFile
    }
    else {
        Write-Output "================= New Processes ================="
        $Processes | Select-Object UserName, Name, CommandLine, Company, ProductVersion, StartTime, HasExited
        Write-Output "================= New Apps ================="
        $Apps
        Write-Output "================= New UWP Apps ================="
        $UwpApps
        Write-Output "================= New Drivers ================="
        $Drivers
        Write-Output "================= New Services ================="
        $Services
        Write-Output "================= New Port Monitors ================="
        $PortMonitors
        Write-Output "================= New Protocol Handlers ================="
        $ProtocolHandlers
        Write-Output "================= New TCP Listeners ================="
        $TCPListeners
        Write-Output "================= New UDP Listeners ================="
        $UDPListeners
        if ($Files) {
            Write-Output "================= New Files ================="
            $Files
        }
    }
}

# If you have a non-exported function and someone attempts to Get-Help on it then it will display a synopsis list
function DynamicHelper {
    <#
    .SYNOPSIS
    Placeholder module to trick Get-Help into giving a synopsis list of exported functions

    .DESCRIPTION
    Placeholder module to trick Get-Help into giving a synopsis list of exported functions
    #>
    return $true
}