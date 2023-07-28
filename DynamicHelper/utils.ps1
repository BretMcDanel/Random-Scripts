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

    .PARAMETER Second
    alias Sec
    the number of seconds in the past

    .PARAMETER Minute
    alias Min
    The number of minutes in the past

    .PARAMETER Hour
    The number of hours in the past

    .PARAMETER Day
    The number of days in the past
    
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