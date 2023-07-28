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
