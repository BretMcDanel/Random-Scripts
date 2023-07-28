function Get-NewDriver {
    <#
    .SYNOPSIS
    Lists new drivers installed

    .DESCRIPTION
    Lists new drivers installed
    If no Get-PastDate parameters are specified all drivers are listed

    .EXAMPLE
    # List all drivers installed in the last 30 minutes
    PS> Get-NewDriver -Min 30 | fl *

    InstallDate             : 6/2/2023 4:43:11 PM
    Status                  : OK
    Name                    : RasSstp
    State                   : Running
    ExitCode                : 0
    Started                 : True
    ServiceSpecificExitCode : 0
    Caption                 : WAN Miniport (SSTP)
    Description             : WAN Miniport (SSTP)
    CreationClassName       : Win32_SystemDriver
    StartMode               : Manual
    SystemCreationClassName : Win32_ComputerSystem
    SystemName              : WIN-VM
    AcceptPause             : False
    AcceptStop              : True
    DesktopInteract         : False
    DisplayName             : WAN Miniport (SSTP)
    ErrorControl            : Normal
    PathName                : C:\Windows\system32\drivers\rassstp.sys
    ServiceType             : Kernel Driver
    StartName               :
    TagId                   : 0
    PSComputerName          :
    CimClass                : root/cimv2:Win32_SystemDriver
    CimInstanceProperties   : {Caption, Description, InstallDate, Name…}
    CimSystemProperties     : Microsoft.Management.Infrastructure.CimSystemProperties
    ...

    .LINK
    Get-PastDate

    #>
    [CmdletBinding()]
    Param (
        # Parameters for Get-PastDate
        [parameter(ValueFromRemainingArguments = $True)]$RemainingArguments
    )

    $ExtraArgs = Get-VarsToHashTable $RemainingArguments
    $Date = Get-PastDate @ExtraArgs

    $Drivers = @()
    foreach ($Driver in (Get-CimInstance -ClassName Win32_SystemDriver)) {
        $DriverPath = $Driver.PathName
        if ($DriverPath) {
            if ($DriverPath.StartsWith('\??\')) {
                #Remove the possible \??\ at the beginning of the path
                $DriverPath = $DriverPath.Substring(4)
            } 

            $escapedPath = $DriverPath.Replace('\', '\\')
            $InstallDate = (Get-CimInstance -Class Cim_DataFile -Filter "Name='$escapedPath'").InstallDate
            Add-Member -Force -InputObject $Driver -Name "InstallDate" -MemberType NoteProperty -Value $InstallDate
        }
        $Drivers += $Driver
    }

    if ($Date) {
        $Drivers | Where-Object { $_.InstallDate -gt $Date } | Sort-Object InstallDate
    }
    else {
        $Drivers | Sort-Object InstallDate
    }
}

function Get-NewProcess {
    <#
    .SYNOPSIS
    Generate a list of new processes

    .DESCRIPTION
    Generate a list of new processes
    If no Get-PastDate parameters are specified all processes are listed

    .EXAMPLE
    Get-NewProcess

     WS(M)   CPU(s)      Id UserName                       ProcessName
     -----   ------      -- --------                       -----------
      0.01     0.00       0                                Idle
     80.85     2.70     108                                Registry
      0.08 1,221.17       4                                System
     13.27     1.81     620 NT AUTHORITY\SYSTEM            winlogon
    ...

    .LINK
    Get-PastDate
    #>

    [CmdletBinding()]
    Param (
        # Parameters for Get-PastDate
        [parameter(ValueFromRemainingArguments = $True)]$RemainingArguments
    )
    
    $ExtraArgs = Get-VarsToHashTable $RemainingArguments
    $Date = Get-PastDate @ExtraArgs

    if (!(Get-IsAdmin)) {
        Write-Warning "[$($MyInvocation.MyCommand)] Insufficient permissions to run this script. Open the PowerShell console as an administrator and run this script again."
        return $null
    }

    $Processes = Get-Process -IncludeUserName | Sort-Object StartTime
    if ($Date) {
        $Processes | Where-Object { $_.StartTime -gt $Date }
    }
    else {
        $Processes
    }
}

function Get-NewService {
    <#
    .SYNOPSIS
    Generate a list of services

    .DESCRIPTION
    Generate a list of services
    If no Get-PastDate parameters are specified all services are listed

    .EXAMPLE
    Get-NewService
    Type            : 16
    Start           : 3
    ErrorControl    : 1
    ImagePath       : "C:\Program Files (x86)\Microsoft\Edge\Application\114.0.1823.41\elevation_service.exe"
    DisplayName     : Microsoft Edge Elevation Service (MicrosoftEdgeElevationService)
    DependOnService : {RPCSS}
    ObjectName      : LocalSystem
    Description     : Keeps Microsoft Edge up to update. If this service is disabled, the application will not be kept up to date.
    PSPath          : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\MicrosoftEdgeElevationService
    PSParentPath    : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services
    PSChildName     : MicrosoftEdgeElevationService
    PSDrive         : HKLM
    PSProvider      : Microsoft.PowerShell.Core\Registry
    InstallDate     : 6/7/2023 6:36:48 AM

    .LINK
    Get-PastDate
    #>

    [CmdletBinding()]
    Param (
        # Parameters for Get-PastDate
        [parameter(ValueFromRemainingArguments = $True)]$RemainingArguments
    )

    $ExtraArgs = Get-VarsToHashTable $RemainingArguments
    $Date = Get-PastDate @ExtraArgs

    <# This seemed relevant
    Service Type Description
        0x1 A Kernel device driver.
        0x2 File system driver, which is also a Kernel device driver.
        0x4 A set of arguments for an adapter.
        0x10 A Win32 program that can be started by the Service Controller and that obeys the service control protocol. This type of Win32 service runs in a process by itself.
        0x20 A Win32 service that can share a process with other Win32 services.
    #>

    $Services = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\* | Select-Object *, @{Name = 'InstallDate'; Expression = { Get-RegItemLastWrite -RegKey (Get-Item $_.PSPath) } } | Sort-Object InstallDate
    if ($Date) {
        $Services | Where-Object { $_.InstallDate -gt $Date }
    }
    else {
        $Services
    }
}

function Get-NewPortMonitor {
    <#
    .SYNOPSIS
    Generate a list of port monitors

    .DESCRIPTION
    Generate a list of port monitors
    If no Get-PastDate parameters are specified all port monitors are listed

    .EXAMPLE
    Get-NewPortMonitor

    Driver       : APMon.dll
    PSPath       : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Monitors\WSD Port
    PSParentPath : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Print\Monitors
    PSChildName  : WSD Port
    PSDrive      : HKLM
    PSProvider   : Microsoft.PowerShell.Core\Registry
    InstallDate  : 10/18/2022 4:15:27 PM
    ...

    .LINK
    Get-PastDate
    #>

    [CmdletBinding()]
    Param (
        # Parameters for Get-PastDate
        [parameter(ValueFromRemainingArguments = $True)]$RemainingArguments
    )

    $ExtraArgs = Get-VarsToHashTable $RemainingArguments
    $Date = Get-PastDate @ExtraArgs

    $Monitors = Get-ItemProperty "HKLM:SYSTEM\CurrentControlSet\Control\Print\Monitors\*" | Select-Object *, @{Name = 'InstallDate'; Expression = { Get-RegItemLastWrite -RegKey (Get-Item $_.PSPath) } } | Sort-Object InstallDate
    if ($Date) {
        $Monitors | Where-Object { $_.InstallDate -gt $Date }
    }
    else {
        $Monitors
    }
    
}

function Get-NewProtocolHandler {
    <#
    .SYNOPSIS
    Generate a list of protocol handlers

    .DESCRIPTION
    Generate a list of protocol handlers
    If no Get-PastDate parameters are specified all protocol handlers are listed

    .EXAMPLE
    Get-NewProtocolHandler

    URI         : vsweb+diag
    InstallDate : 6/2/2023 6:13:43 PM
    Open        : "C:\Program Files (x86)\Microsoft Visual
                Studio\Shared\VsWebProtocolSelector\Microsoft.VisualStudio.VsWebProtocolSelector.exe" "%1"
    Edit        :
    Find        :
    Print       :
    Properties  :
    RunAs       :
    ...

    .LINK
    Get-PastDate
    #>

    [CmdletBinding()]
    Param (
        # Parameters for Get-PastDate
        [parameter(ValueFromRemainingArguments = $True)]$RemainingArguments
    )

    $ExtraArgs = Get-VarsToHashTable $RemainingArguments
    $Date = Get-PastDate @ExtraArgs

    # This is a merged view of HKLM:\Software\Classes\ and HKCU:\Software\Classes\
    # See https://learn.microsoft.com/en-us/windows/win32/sysinfo/hkey-classes-root-key
    $registryPath = 'Registry::HKEY_CLASSES_ROOT\'

    $Handlers = Get-ChildItem -Path $registryPath -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -match '^(?!\.).+' } |
    Where-Object { (Get-ItemProperty -Path "$registryPath\$($_.PSChildName)" -ErrorAction SilentlyContinue).'URL Protocol' -eq '' } | 
    Select-Object @{Name = 'URI'; Expression = { $_.PSChildName } },
    @{Name = 'InstallDate'; Expression = { Get-RegItemLastWrite -RegKey (Get-Item $_.PSPath) } },
    @{Name = 'Open'; Expression = { (Get-Item -Path "$($_.PSPath)\shell\open\command\").GetValue("") } },
    @{Name = 'Edit'; Expression = { (Get-Item -Path "$($_.PSPath)\shell\edit\command\").GetValue("") } },
    @{Name = 'Find'; Expression = { (Get-Item -Path "$($_.PSPath)\shell\find\command\").GetValue("") } },
    @{Name = 'Print'; Expression = { (Get-Item -Path "$($_.PSPath)\shell\print\command\").GetValue("") } },
    @{Name = 'Properties'; Expression = { (Get-Item -Path "$($_.PSPath)\shell\properties\command\").GetValue("") } },
    @{Name = 'RunAs'; Expression = { (Get-Item -Path "$($_.PSPath)\shell\runas\command\").GetValue("") } } |
    Sort-Object InstallDate
    
    if ($Date) {
        $Handlers | Where-Object { $_.InstallDate -gt $Date }
    }
    else {
        $Handlers
    }
}
