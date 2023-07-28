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