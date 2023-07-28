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
