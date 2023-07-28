<# 
    @Author: Bret McDanel
#>
function Get-ServiceExecutable {
    <#
    .SYNOPSIS
    Get the binary path for a given service
    .DESCRIPTION
    Get the binary path for a given service.
    Quotes will be stripped and the path normalized.
    .PARAMETER ServiceName
    The name of the service to check
    .EXAMPLE
    Get-ServiceExecutable BITS
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, mandatory = $true)]
        [String]$ServiceName
    )
    $ServicePath = (Get-Service -ErrorAction SilentlyContinue $ServiceName).BinaryPathName

    if ($null -ne $ServicePath) {
        # Quoted executables
        if ($ServicePath -match '[''"]([^''"]+)[''"]') {
            $ServicePath = $Matches[1]
        }
        # Remove possible \??\ at the beginning of the path
        elseif ($ServicePath -like "\??\*") {
            $ServicePath = $ServicePath.Substring(4)
        }
        else {
            $ServicePath = $ServicePath.split(' ')[0]
        }
    }
    $ServicePath
}



function Get-ServiceWrite {
    <#
    .SYNOPSIS
    Find writable permissions for the service executable or a parent directory
    .DESCRIPTION
    Find writable permissions for the service executable or a parent directory
    .PARAMETER ServiceName
    The name of the service to check
    .PARAMETER IgnoreUsers
    An array of users to ignore
    Default is @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'NT Service\TrustedInstaller')
    .EXAMPLE
    Get-ServiceWrite BITS
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, mandatory = $true, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String]$ServiceName,
        [parameter(ValueFromRemainingArguments = $True)]$RemainingArguments
    )
    
    Write-Debug "Processing $ServiceName"
    $ServicePath = (Get-ServiceExecutable $ServiceName)
    write-debug "Service path: $ServicePath"

    if ($null -eq $RemainingArguments) {
        Get-WritePerms $ServicePath
    }
    else {
        Get-WritePerms $ServicePath $RemainingArguments
    }
}

function Get-WritePerms {
    <#
    .SYNOPSIS
    Find writable permissions for an file or directory
    .DESCRIPTION
    Find writable permissions for an file or directory
    .PARAMETER FilePath
    The path of the file to check
    .PARAMETER IgnoreUsers
    An array of users to ignore
    Default is @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'NT Service\TrustedInstaller')
    .EXAMPLE
    Get-WritePerms C:\Windows\System32
    #>

    [CmdletBinding()]
    param (
        [Parameter(Position = 0, mandatory = $true, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [String]$FilePath,
        [Parameter(Position = 1, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [array]$IgnoreUsers = @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators', 'NT Service\TrustedInstaller')
    )

    if ($null -ne $FilePath) {
        $FileAcls = @()

        $fileObject = Get-Item $FilePath -Force
        if ($fileObject) {
            do {
                write-debug "Getting ACL for $($fileObject.FullName)"
                $acls = ((Get-Acl -Path $fileObject.FullName).Access | Where-Object { $_.IsInherited -eq $false -and $_.FileSystemRights -match "Write|FullControl|Modify" -and $IgnoreUsers -NotContains $_.IdentityReference })
                if ($null -ne $acls) {
                    foreach ($acl in $acls) {
                        $FileAcl = New-Object -TypeName PSObject
                        Add-Member -Force -inputObject $FileAcl -Name "Path" -MemberType NoteProperty -Value $fileObject.FullName
                        Add-Member -Force -inputObject $FileAcl -Name "IdentityReference" -MemberType NoteProperty -Value $acl.IdentityReference
                        Add-Member -Force -inputObject $FileAcl -Name "FileSystemRights" -MemberType NoteProperty -Value $acl.FileSystemRights
                        $FileAcls += $FileAcl
                    }
                }
                # Go up one level in the filesystem
                if ($fileObject.PSIsContainer -eq $false) {
                    # Process file
                    $fileObject = $fileObject.Directory
                }
                else {
                    # Process directory
                    $fileObject = $fileObject.Parent
                }
            } while ($fileObject.Root -ne $fileObject.DirectoryName)
            if ($FileAcls) {
                $FileAcls | Sort-Object 
            }
        }
    }
}
