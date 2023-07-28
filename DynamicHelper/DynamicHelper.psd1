<#
    Manifest for DynamicHelper module
#>

@{
    RootModule        = 'DynamicHelper.psm1'
    ModuleVersion     = '0.0.1'
    GUID              = '991c5f69-bf96-4e2f-bf08-d132ae7376d7'
    Author            = 'Bret McDanel'
    Copyright         = '(c) 2023 Bret McDanel All rights reserved.'
    Description       = 'Dynamic and Static analysis helper tools'
    PowerShellVersion = '7.0'

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport = @(
        # file.ps1
        'Get-NewFile', 
        # app.ps1
        'Get-NewApp', 'Get-NewUwpApp',
        # system.ps1
        'Get-NewDriver', 'Get-NewProcess', 'Get-NewService', 'Get-NewPortMonitor', 'Get-NewProtocolHandler',
        # network.ps1
        'Get-NewUDPListener', 'Get-NewTCPListener', 
        # DynamicHelper.ps1
        'Get-SystemReport'
    )
    
    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport = '*'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport   = @()


    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData       = @{
        PSData = @{
            # A URL to the license for this module.
            LicenseUri = 'https://opensource.org/license/bsd-3-clause/'
        } # End of PSData hashtable

    } # End of PrivateData hashtable
}
