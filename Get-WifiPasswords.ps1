<#
  @AUTHOR: Bret McDanel
  .SYNOPSIS
  Gathers all Wifi passwords saved on the system
  .DESCRIPTION
  Gathers all Wifi passwords saved on the system
#>
$networks = @()

$netshOutput = (netsh.exe wlan show profiles) | Select-String -Pattern '\s{2,}:\s(.*)'
foreach ($ssids in $netshOutput.matches.groups) { 
    if (-not $ssids.Groups) { 
        $keyContent = (netsh.exe wlan show profile $ssids.value key=clear) | Select-String -Pattern 'Key Content\s{2,}:\s(.*)'
        foreach ($passwords in $keyContent.matches.groups) {
            if (-not $passwords.Groups) {
                $networks += [PSCustomObject]@{SSID = $ssids.value; PASSWORD = $passwords.value }
            }
        }
    }
}

$networks
