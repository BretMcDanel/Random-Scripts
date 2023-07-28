function Get-UnquotedService {
    <#
    .SYNOPSIS
    Displays all services that are unquoted and contain at least one space
    .DESCRIPTION
    Displays all services that are unquoted and contain at least one space
    
    Ignores common executables that often have a space and are not quoted
    #>
    $IgnoreServices = @(
        "c:\windows\system32\svchost.exe",
        "c:\windows\system32\msiexec.exe",
        "c:\windows\system32\dllhost.exe",
        "c:\windows\system32\searchindexer.exe"
    )
    Get-CimInstance -Query "SELECT name,pathname,startname FROM Win32_Service" | foreach-object {
        if ($_.PathName) {
            $firstArg = $_.PathName.Split(" ", [StringSplitOptions]"None")[0]

            if ($IgnoreServices -notcontains $firstArg -and
                $_.PathName.contains('"') -ne $True -and
                $_.PathName.contains(' ') -eq $True
            ) {
                $_
            }
        }
    } | Select-Object -Property @{Name = 'User Name'; Expression = { ($_.StartName) } }, @{Name = 'Service Name'; Expression = { ($_.Name) } }, @{Name = 'Path'; Expression = { ($_.PathName) } }
}
