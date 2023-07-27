<# 
    @Author: Bret McDanel

    You probably just want to skip to the last function Get-SystemReport
#>
<# BEGIN INTERNAL HELPER FUNCTIONS #>
function Get-IsAdmin {
    <#
    .SYNOPSIS
    Returns boolean whether user is an administrator

    .DESCRIPTION
    Returns boolean whether user is an administrator

    .EXAMPLE
    PS> Get-IsAdmin
    False

    .EXAMPLE
    PS ADMIN> Get-IsAdmin
    True

    #>
    return ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}


function Get-PastDate {
    <#
    .SYNOPSIS
    Returns a date in the past

    .DESCRIPTION
    Returns a date in the past
    Default date is null

    .EXAMPLE
    PS> Get-PastDate -Minute 10
    Tuesday, June 6, 2023 12:06:44 PM

    .EXAMPLE
    PS> [PSCustomObject] @{s=10} | Get-PastDate
    Tusday, June 6, 2023 12:16:34 PM

    #>
    [CmdletBinding()]
    param (
        # Number of Seconds in the past
        # Aliases Sec
        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('Sec')]
        [Int]$Second = 0,
        # Number of minutes in the past
        # Aliases Min
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Alias('Min')]
        [Int]$Minute = 0,
        # Number of hours in the past
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Int]$Hour = 0,
        # Number of days in the past
        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Int]$Day = 0
    )

    PROCESS {
        if ($Second -eq 0 -and $Minute -eq 0 -and $Hour -eq 0 -and $Day -eq 0) { 
            $Null 
        }
        else {
            $Date = (Get-Date)
            if ($Second -ne 0) { $Date = $Date.addSeconds([Math]::Abs($Second) * -1) }
            if ($Minute -ne 0) { $Date = $Date.addMinutes([Math]::Abs($Minute) * -1) }
            if ($Hour -ne 0) { $Date = $Date.addHours([Math]::Abs($Hour) * -1) }
            if ($Day -ne 0) { $Date = $Date.addDays([Math]::Abs($Day) * -1) }

            $Date
        }
    }
}


function Get-RegItemLastWrite {
    <#
    .SYNOPSIS
    Get the last write date for a registry item

    .DESCRIPTION
    Get the last write date for a registry item
    This is useful for knowing when packages were last installed or modified

    .EXAMPLE
    PS> Get-RegItemLastWrite -RegKey (Get-Item HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\7-zip)
    Friday, June 2, 2023 9:01:10 PM

    #>

    [CmdletBinding()]
    param(
        # Registry key to inspect
        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Microsoft.Win32.RegistryKey]$RegKey
    )

    PROCESS {
        $Namespace = "nameSpace"
        Add-Type @"
        using System;
        using System.Text;
        using System.Runtime.InteropServices; 
        $($Namespace | ForEach-Object {"namespace $_ {"})
             public class advapi32 {
                [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
                public static extern Int32 RegQueryInfoKey(
                    Microsoft.Win32.SafeHandles.SafeRegistryHandle hKey,
                    StringBuilder lpClass,
                    [In, Out] ref UInt32 lpcbClass,
                    UInt32 lpReserved,
                    out UInt32 lpcSubKeys,
                    out UInt32 lpcbMaxSubKeyLen,
                    out UInt32 lpcbMaxClassLen,
                    out UInt32 lpcValues,
                    out UInt32 lpcbMaxValueNameLen,
                    out UInt32 lpcbMaxValueLen,
                    out UInt32 lpcbSecurityDescriptor,                
          out System.Runtime.InteropServices.ComTypes.FILETIME lpftLastWriteTime
                );
            }
        $($Namespace | ForEach-Object {"}"})
"@
        $RegTools = ("{0}.advapi32" -f ($Namespace -join ".")) -as [type]
        $LastWrite = New-Object System.Runtime.InteropServices.ComTypes.FILETIME
        $RegTools::RegQueryInfoKey($RegKey.Handle, $null, [ref] $null, $null, [ref] $null, [ref] $null, [ref] $null, [ref] $null, [ref] $null, [ref] $null, [ref] $null, [ref] $LastWrite) > $null
        $UnsignedLow = [System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes($LastWrite.dwLowDateTime), 0)
        $UnsignedHigh = [System.BitConverter]::ToUInt32([System.BitConverter]::GetBytes($LastWrite.dwHighDateTime), 0)
        $FileTimeInt64 = ([Int64] $UnsignedHigh -shl 32) -bor $UnsignedLow
        [datetime]::FromFileTime($FileTimeInt64)
    }
}


function Get-VarsToHashTable {
    <#
    .SYNOPSIS
    Converts arguments to a hashtable

    .DESCRIPTION
    Converts arguments to a hashtable

    .EXAMPLE
    PS> Get-VarsToHashTable -simpleVar 1 -arrayVar 2,3 -switchVar
    Name                           Value 
    ----                           ----- 
    switchVar                      True  
    arrayVar                       {2, 3}
    simpleVar                      1
    #>
    [CmdletBinding()]
    param(
        # Variables to process
        [parameter(ValueFromRemainingArguments = $True)]
        $vars
    )
    PROCESS {
        if ($vars) {
            $ht = @{}

            $vars | ForEach-Object {
                if ($_ -match '^-') {
                    #New parameter
                    $lastvar = $_ -replace '^-'
                    $ht[$lastvar] = $true
                }
                else {
                    #Value
                    if ($lastvar) {
                        $ht[$lastvar] = $_
                    }
                }
            }
            $ht
        }
    
        else {
            $Null
        }
    }
}
<# END INTERNAL HELPER FUNCTIONS #>


function Get-NewApp {
    <#
    .SYNOPSIS
    Lists new applications installed

    .DESCRIPTION
    Lists new applications installed
    If no Get-PastDate parameters are specified all applications are listed

    .EXAMPLE
    # List all applictaions installed in the last 30 minutes
    PS> Get-NewApp -Min 30

    AuthorizedCDFPrefix :
    Comments            :
    Contact             :
    DisplayVersion      : 10.1.18362.1
    HelpLink            :
    HelpTelephone       :
    InstallLocation     :
    InstallSource       : C:\ProgramData\Package Cache\{6E10A7E2-7D2A-3BCF-4C43-33A7CCDDD0A1}v10.1.18362.1\Installers\
    ModifyPath          : MsiExec.exe /I{6E10A7E2-7D2A-3BCF-4C43-33A7CCDDD0A1}
    Publisher           : Microsoft Corporation
    Readme              :
    Size                :
    EstimatedSize       : 61684
    SystemComponent     : 1
    UninstallString     : MsiExec.exe /I{6E10A7E2-7D2A-3BCF-4C43-33A7CCDDD0A1}
    URLInfoAbout        :
    URLUpdateInfo       :
    VersionMajor        : 10
    VersionMinor        : 1
    WindowsInstaller    : 1
    Version             : 167856058
    Language            : 1033
    DisplayName         : Windows 7 WDK Headers and Libs
    PSPath              : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\Cur
                        rentVersion\Uninstall\{6E10A7E2-7D2A-3BCF-4C43-33A7CCDDD0A1}
    PSParentPath        : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\Windows\Cur
                        rentVersion\Uninstall
    PSChildName         : {6E10A7E2-7D2A-3BCF-4C43-33A7CCDDD0A1}
    PSDrive             : HKLM
    PSProvider          : Microsoft.PowerShell.Core\Registry
    InstallDate         : 6/2/2023 9:10:14 PM
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

    $installedApps = @(); 

    foreach ($app in (Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*)) {
        Add-Member -Force -InputObject $app -Name "InstallDate" -MemberType NoteProperty -Value (Get-RegItemLastWrite -RegKey (get-item $app.PSPath))
        $installedApps += $app
    }

    if ([Environment]::Is64BitOperatingSystem) {
        foreach ($app in (Get-ItemProperty HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*)) {
            Add-Member -Force -InputObject $app -Name "InstallDate" -MemberType NoteProperty -Value (Get-RegItemLastWrite -RegKey (get-item $app.PSPath))
            $installedApps += $app
        }
    }

    # Filter non-apps
    $installedApps = $installedApps | Where-Object { (!([string]::isNullOrWhitespace($_.DisplayName))) -and ![string]::IsNullOrWhiteSpace($_.InstallDate) } | Sort-Object InstallDate

    if ($Date) {
        $installedApps | Where-Object { $_.InstallDate -gt $Date }
    }
    else {
        $installedApps

    }
}


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
    SystemName              : CEPS-VM
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


function Get-NewUwpApp {
    <#
    .SYNOPSIS
    Generate a list of UWP apps and their properties

    .DESCRIPTION
    Generate a list of UWP apps and their properties
    If no Get-PastDate parameters are specified all UWP Apps are listed

    .PARAMETER Filter
    A filter to be applied for UWP app names.

    Default value is all UWP apps.
    .EXAMPLE
    Get-NewUwpApp

    Name                : Microsoft.PowerAutomateDesktop
    Version             : 1.0.398.0
    Publisher           : CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
    Architecture        : X64
    InstallLocation     : C:\Program Files\WindowsApps\Microsoft.PowerAutomateDesktop_1.0.398.0_x64__8wekyb3d8bbwe
    PackageType         : Centennial
    ExtensionExecutable :
    HasPsf              : False
    Dependencies        : {Microsoft.PowerAutomateDesktop_1.0.398.0_neutral_split.scale-150_8wekyb3d8bbwe,
                          Microsoft.PowerAutomateDesktop_1.0.398.0_neutral_split.scale-100_8wekyb3d8bbwe,
                          Microsoft.PowerAutomateDesktop_1.0.398.0_neutral_split.scale-125_8wekyb3d8bbwe,
                          Microsoft.PowerAutomateDesktop_1.0.398.0_neutral_split.scale-300_8wekyb3d8bbwe}

    ...

    .LINK
    https://learn.microsoft.com/en-us/windows/msix/psf/package-support-framework-overview

    .LINK
    Get-PastDate
    #>

    [CmdletBinding()]
    Param (
        # App name filter
        [Parameter(ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String]$Filter = "*",
        # Parameters for Get-PastDate
        [parameter(ValueFromRemainingArguments = $True)]$RemainingArguments
    )

    # The default value is not working.  I think it is a collision from ValueFromPipeline.  
    if (!$Filter) {
        $Filter = "*"
    }

    $ExtraArgs = Get-VarsToHashTable $RemainingArguments
    $Date = Get-PastDate @ExtraArgs

    # Powershell > 7.1 in Windows 10 has intentional breakage.  It wont be fixed.
    # The work around to get Appx functionality is to import it with powershell 5.
    # Of note, this is not broken in Windows 11 regardless of PWSH version (yet?).
    if ($PSVersionTable.PSVersion -ge [System.Management.Automation.SemanticVersion]("7.1.0")) {
        Import-Module -Name Appx -UseWindowsPowerShell -WarningAction Ignore
    }

    if (Get-IsAdmin) {
        $InstalledApps = Get-AppxPackage -AllUsers -Name $Filter | Select-Object -Property Name, Version, Publisher, InstallLocation, Dependencies, PackageFullName, Architecture, PackageFamilyName
    }
    else {
        $InstalledApps = Get-AppxPackage -Name $Filter | Select-Object -Property Name, Version, Publisher, InstallLocation, Dependencies, PackageFullName, Architecture, PackageFamilyName
    }

    $AppData = @()

    ForEach ($InstalledApp in $InstalledApps) {
        $HasPsf = $false
        $PackageType = "Native"
        $ExtensionExecutable = ""
        $Dependencies = @()

        ForEach ($Dependency in $InstalledApp.Dependencies) {
            $Dependencies += $Dependency.ToString()
        }
        
        try {
            $appManifest = Get-AppxPackageManifest -Package $InstalledApp.PackageFullName
        }
        catch {}

        if ($null -ne $appManifest) {
            ForEach ($capabilities in $appManifest.GetElementsByTagName('Capabilities')) {
                ForEach ($rescapCapability in $capabilities.GetElementsByTagName('rescap:Capability')) {
                    if ($rescapCapability.Name -eq 'runFullTrust') {
                        $PackageType = 'Centennial'
                        if ($null -ne (Get-ChildItem -Filter 'config.json' -recurse -path $InstalledApp.InstallLocation)) {
                            $HasPsf = $true
                        }
                        break
                    }
                }
                ForEach ($capability in $capabilities.GetElementsByTagName('Capability')) {
                    if ($capability.Name -eq 'runFullTrust') {
                        $PackageType = 'Centennial'
                        if ($null -ne (Get-ChildItem -Filter 'config.json' -recurse -path $InstalledApp.InstallLocation)) {
                            $HasPsf = $true
                        }
                        break
                    }
                }
            }
        }

        if ($PackageType -eq "Centennial") {
            ForEach ($extensions in $appManifest.GetElementsByTagName('Extensions')) {
                ForEach ($desktopExtension in $extensions.GetElementsByTagName('desktop:Extension')) {
                    if ($desktopExtension.Category -eq 'windows.fullTrustProcess') {
                        $PackageType = "Extension"
                        $ExtensionExecutable = $desktopExtension.Executable
                        break
                    }
                }
            }
        }

        $UserDataLocation = "$env:LOCALAPPDATA\Packages\" + $InstalledApp.PackageFamilyName
        $InstallDate = ""

        # Installed/Last Updated Date
        if (Get-IsAdmin) {
            $InstallDate = (Get-Item $InstalledApp.InstallLocation).LastWriteTime
        }

        $UwpApp = New-Object PSObject
        Add-Member -InputObject $UwpApp -Name "Name" -MemberType NoteProperty -Value $InstalledApp.Name
        Add-Member -InputObject $UwpApp -Name "Version" -MemberType NoteProperty -Value $InstalledApp.Version
        Add-Member -InputObject $UwpApp -Name "Architecture" -MemberType NoteProperty -Value $InstalledApp.Architecture
        Add-Member -InputObject $UwpApp -Name "PackageType" -MemberType NoteProperty -Value $PackageType
        Add-Member -InputObject $UwpApp -Name "InstallLocation" -MemberType NoteProperty -Value $InstalledApp.InstallLocation
        Add-Member -InputObject $UwpApp -Name "Publisher" -MemberType NoteProperty -Value $InstalledApp.Publisher
        Add-Member -InputObject $UwpApp -Name "InstallDate" -MemberType NoteProperty -Value $InstallDate
        Add-Member -InputObject $UwpApp -Name "UserDataLocation" -MemberType NoteProperty -Value $UserDataLocation
        Add-Member -InputObject $UwpApp -Name "ExtensionExecutable" -MemberType NoteProperty -Value $ExtensionExecutable
        Add-Member -InputObject $UwpApp -Name "HasPsf" -MemberType NoteProperty -Value $HasPsf
        Add-Member -InputObject $UwpApp -Name "Dependencies" -MemberType NoteProperty -Value $Dependencies

        $AppData += $UwpApp
    }

    if ($Date) {
        $AppData | Where-Object { $_.InstallDate -gt $Date } | Sort-Object InstallDate
    }
    else {
        $AppData | Sort-Object InstallDate
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


function Get-NewFile {
    <#
    .SYNOPSIS
    Generate a list of new files

    .DESCRIPTION
    Generate a list of new files
    If no Get-PastDate parameters are specified all files are listed

    .EXAMPLE
    Get-NewFile C:\prog

        Directory: C:\prog

    Mode                 LastWriteTime         Length Name
    ----                 -------------         ------ ----
    d----            6/2/2023 11:26 PM                _build
    ...

    .LINK
    Get-PastDate
    #>

    [CmdletBinding()]
    Param (
        [parameter(position = 0, mandatory = $true)]
        [String]$Path,
        # Parameters for Get-PastDate
        [parameter(ValueFromRemainingArguments = $True)]$RemainingArguments
    )

    $ExtraArgs = Get-VarsToHashTable $RemainingArguments
    $Date = Get-PastDate @ExtraArgs

    $Files = Get-ChildItem -Path $Path -Recurse -Force | Sort-Object CreationTime
    
    if ($Date) {
        $Files | Where-Object { $_.CreationTime -ge $Date }
    }
    else {
        $Files
    }
}


function Get-NewUDPListener {
    <#
    .SYNOPSIS
    Generate a list of UDP listeners

    .DESCRIPTION
    Generate a list of UDP listeners
    If no Get-PastDate parameters are specified all UDP Listeners are listed

    .EXAMPLE
    Get-NewUDPListener

    LocalAddress  : 0.0.0.0
    LocalPort     : 123
    OwningProcess : 3724
    InstanceID    : 0.0.0.0++123
    Name          : svchost
    Path          : C:\Windows\system32\svchost.exe
    Company       : Microsoft Corporation
    Product       : Microsoft® Windows® Operating System
    User          : NT AUTHORITY\LOCAL SERVICE
    ProcStartTime : 6/6/2023 2:08:19 PM
    CreationTime  : 6/7/2023 7:33:50 AM
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

    $Listeners = Get-NetUDPEndpoint |
    Select-Object LocalAddress, LocalPort, OwningProcess, InstanceID,
    @{Name = "Name"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName } }, 
    @{Name = "Path"; Expression = { (Get-Process -Id $_.OwningProcess).Path } },
    @{Name = "Company"; Expression = { (Get-Process -Id $_.OwningProcess).Company } },
    @{Name = "Product"; Expression = { (Get-Process -Id $_.OwningProcess).Product } },
    @{Name = "User"; Expression = { (Get-Process -Id $_.OwningProcess -IncludeUserName).UserName } },
    @{Name = "ProcStartTime"; Expression = { (Get-Process -Id $_.OwningProcess).StartTime } },
    CreationTime
        
    if ($Date) {
        $Listeners | Where-Object { $_.CreationTime -ge $Date }
    }
    else {
        $Listeners
    }
}

function Get-NewTCPListener {
    <#
    .SYNOPSIS
    Generate a list of TCP listeners

    .DESCRIPTION
    Generate a list of TCP listeners
    If no Get-PastDate parameters are specified all TCP Listeners are listed

    .EXAMPLE
    Get-NewTCPListener

    LocalAddress  : 0.0.0.0
    LocalPort     : 135
    State         : Listen
    OwningProcess : 920
    InstanceID    : 0.0.0.0++135++0.0.0.0++0
    Name          : svchost
    Path          : C:\Windows\system32\svchost.exe
    Company       : Microsoft Corporation
    Product       : Microsoft® Windows® Operating System
    User          : NT AUTHORITY\NETWORK SERVICE
    ProcStartTime : 6/6/2023 2:06:01 PM
    CreationTime  : 6/6/2023 2:06:01 PM
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

    $Listeners = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } |
    Select-Object LocalAddress, LocalPort, State, OwningProcess, InstanceID,
    @{Name = "Name"; Expression = { (Get-Process -Id $_.OwningProcess).ProcessName } }, 
    @{Name = "Path"; Expression = { (Get-Process -Id $_.OwningProcess).Path } },
    @{Name = "Company"; Expression = { (Get-Process -Id $_.OwningProcess).Company } },
    @{Name = "Product"; Expression = { (Get-Process -Id $_.OwningProcess).Product } },
    @{Name = "User"; Expression = { (Get-Process -Id $_.OwningProcess -IncludeUserName).UserName } },
    @{Name = "ProcStartTime"; Expression = { (Get-Process -Id $_.OwningProcess).StartTime } },
    CreationTime
    
    if ($Date) {
        $Listeners | Where-Object { $_.CreationTime -ge $Date }
    }
    else {
        $Listeners
    }
}

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


