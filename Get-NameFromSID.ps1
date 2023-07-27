function Get-NameFromSID {
    <#
    @AUTHOR: Bret McDanel
    .SYNOPSIS
    Resolves a SID into a username
    .DESCRIPTION
    Resolves a SID into a username
    .PARAMETER SID
    The SID to resolve
    .OUTPUTS
    PSCustomObject that contains account properties
    .EXAMPLE
    PS> Get-NameFromSID S-1-5-19

    NTAccount                  Domain       Username      SID
    ---------                  ------       --------      ---
    NT AUTHORITY\LOCAL SERVICE NT AUTHORITY LOCAL SERVICE S-1-5-19
    #>
    [cmdletbinding()]
    [OutputType("PSCustomObject", ParameterSetName = "ResolvedSID")]
    Param(
        [Parameter(
            Position = 0,
            Mandatory,
            ValueFromPipeline,
            ValueFromPipelineByPropertyName,
            HelpMessage = "Enter a SID string."
        )]
        [ValidateScript({
                if ($_ -match 'S-1-[1235]-\d{1,2}(-\d+)*') {
                    $true
                }
                else {
                    Throw "The parameter value does not match the pattern for a valid SID."
                    $false
                }
            })]
        [string]$SID
    )
    Begin {
        Write-Verbose "[$((Get-Date).TimeofDay) BEGIN  ] Starting $($myinvocation.mycommand)"
    } #begin

    Process {
        Write-Verbose "[$((Get-Date).TimeofDay) PROCESS] Converting $SID "
        Try {
            if ($SID -eq 'S-1-5-32') {
                #apparently you can't resolve the builtin account
                $resolved = "$env:COMPUTERNAME\BUILTIN"
            }
            else {
                $resolved = [System.Security.Principal.SecurityIdentifier]::new($sid).Translate([system.security.principal.NTAccount]).value
            }

            if ($resolved -match "\\") {
                $domain = $resolved.Split("\")[0]
                $username = $resolved.Split("\")[1]
            }
            else {
                $domain = $Null
                $username = $resolved
            }
            [PSCustomObject]@{
                PSTypename = "ResolvedSID"
                NTAccount  = $resolved
                Domain     = $domain
                Username   = $username
                SID        = $SID
            }
        }
        Catch {
            Write-Warning "Failed to resolve $SID. $($_.Exception.InnerException.Message)"
        }
    } #process

    End {
        Write-Verbose "[$((Get-Date).TimeofDay) END ] Ending $($myinvocation.mycommand)"
    } #end

} #close Resolve-SID