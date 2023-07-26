function Get-FileMetaData {
    <#
    @AUTHOR: Bret McDanel
    .SYNOPSIS
    Gets file meta data including company, product, and signing information on an .EXE, .DLL, and .SYS
    .DESCRIPTION
    Gets file meta data including company, product, and signing information on an .EXE, .DLL, and .SYS
    .PARAMETER SCANPATH
    The path to a file or directory.  This can be an array of paths.
    .OUTPUTS
    PSCustomObject that contains file properties
    .EXAMPLE
    PS> Get-FileMetaData C:\Windows\bfsvc.exe
    
    Filename                : C:\Windows\bfsvc.exe
    ProductVersion          : 10.0.22621.1
    ProductName             : Microsoft® Windows® Operating System
    CompanyName             : Microsoft Corporation
    Status                  : Valid
    StatusMessage           : Signature verified.
    SiugnatureType          : Catalog
    SubjectName             : CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
    SubjectIssuer           : CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
    SubjectSerialNumber     : 330000033B655FAEFADB75E9D600000000033B
    SubjectNotBefore        : 9/2/2021 11:23:41 AM
    SubjectNotAfter         : 9/1/2022 11:23:41 AM
    SubjectThumbprint       : BBD2C438000344F439BFDFE5ABAC3223357CD67F
    TimeStamperName         : CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
    TimeStamperIssuer       : CN=Microsoft Windows Production PCA 2011, O=Microsoft Corporation, L=Redmond, S=Washington, C=US
    TimeStamperSerialNumber : 330000033B655FAEFADB75E9D600000000033B
    TimeStamperNotBefore    : 9/2/2021 11:23:41 AM
    TimeStamperNotAfter     : 9/1/2022 11:23:41 AM
    TimeStamperThumbprint   : BBD2C438000344F439BFDFE5ABAC3223357CD67F
    SignatureAlgorithm      : sha256RSA

    #>
    param (
        [Parameter(Mandatory = $true)]
        [String[]] $ScanPath
    )

    foreach ($path in $ScanPath) {
        if (!(Test-Path $path)) {
            Write-Error "File or directory not found: $path"
        }
    }

    $IncludeList = @("*.dll", "*.exe", "*.sys")
    $FileList += Get-ChildItem -Path $ScanPath -File -Recurse -Include $IncludeList -ErrorAction SilentlyContinue

    $Result = @()

    foreach ($file in $FileList) {
        $fdata = $file | Select-Object -ExpandProperty VersionInfo | Select-Object -Property FileName, ProductVersion, ProductName, CompanyName
        $fcrypto = $file | Get-AuthenticodeSignature | Select-object -Property Path, Status, StatusMessage, SignatureType,
        @{Name = 'SubjectName'; Expression = { ($_.SignerCertificate.Subject) } },
        @{Name = 'SubjectIssuer'; Expression = { ($_.SignerCertificate.Issuer) } },
        @{Name = 'SubjectSerialNumber'; Expression = { ($_.SignerCertificate.SerialNumber) } },
        @{Name = 'SubjectNotBefore'; Expression = { ($_.SignerCertificate.NotBefore) } },
        @{Name = 'SubjectNotAfter'; Expression = { ($_.SignerCertificate.NotAfter) } },
        @{Name = 'SubjectThumbprint'; Expression = { ($_.SignerCertificate.ThumbPrint) } },
        @{Name = 'TimeStamperName'; Expression = { ($_.SignerCertificate.Subject) } },
        @{Name = 'TimeStamperIssuer'; Expression = { ($_.SignerCertificate.Issuer) } },
        @{Name = 'TimeStamperSerialNumber'; Expression = { ($_.SignerCertificate.SerialNumber) } },
        @{Name = 'TimeStamperNotBefore'; Expression = { ($_.SignerCertificate.NotBefore) } },
        @{Name = 'TimeStamperNotAfter'; Expression = { ($_.SignerCertificate.NotAfter) } },
        @{Name = 'TimeStamperThumbprint'; Expression = { ($_.SignerCertificate.ThumbPrint) } },
        @{Name = 'SignatureAlgorithm'; Expression = { ($_.SignerCertificate.SignatureAlgorithm.FriendlyName) }
        }

        $Record = New-Object psobject
        Add-Member -InputObject $Record -MemberType NoteProperty -name 'Filename' -value $fcrypto.Path
        Add-Member -InputObject $Record -MemberType NoteProperty -name 'ProductVersion' -value $fdata.ProductVersion
        Add-Member -InputObject $Record -MemberType NoteProperty -name 'ProductName' -value $fdata.ProductName
        Add-Member -InputObject $Record -MemberType NoteProperty -name 'CompanyName' -value $fdata.CompanyName

        if ($fcrypto.SignatureType -ne "none") {
            Add-Member -InputObject $Record -MemberType NoteProperty -name 'Status' -value $fcrypto.Status
            Add-Member -InputObject $Record -MemberType NoteProperty -name 'StatusMessage' -value $fcrypto.StatusMessage
            Add-Member -InputObject $Record -MemberType NoteProperty -name 'SiugnatureType' -value $fcrypto.SignatureType
            Add-Member -InputObject $Record -MemberType NoteProperty -name 'SubjectName' -value $fcrypto.SubjectName
            Add-Member -InputObject $Record -MemberType NoteProperty -name 'SubjectIssuer' -value $fcrypto.SubjectIssuer
            Add-Member -InputObject $Record -MemberType NoteProperty -name 'SubjectSerialNumber' -value $fcrypto.SubjectSerialNumber
            Add-Member -InputObject $Record -MemberType NoteProperty -name 'SubjectNotBefore' -value $fcrypto.SubjectNotBefore
            Add-Member -InputObject $Record -MemberType NoteProperty -name 'SubjectNotAfter' -value $fcrypto.SubjectNotAfter
            Add-Member -InputObject $Record -MemberType NoteProperty -name 'SubjectThumbprint' -value $fcrypto.SubjectThumbprint
            Add-Member -InputObject $Record -MemberType NoteProperty -name 'TimeStamperName' -value $fcrypto.TimeStamperName
            Add-Member -InputObject $Record -MemberType NoteProperty -name 'TimeStamperIssuer' -value $fcrypto.TimeStamperIssuer
            Add-Member -InputObject $Record -MemberType NoteProperty -name 'TimeStamperSerialNumber' -value $fcrypto.TimeStamperSerialNumber
            Add-Member -InputObject $Record -MemberType NoteProperty -name 'TimeStamperNotBefore' -value $fcrypto.TimeStamperNotBefore
            Add-Member -InputObject $Record -MemberType NoteProperty -name 'TimeStamperNotAfter' -value $fcrypto.TimeStamperNotAfter
            Add-Member -InputObject $Record -MemberType NoteProperty -name 'TimeStamperThumbprint' -value $fcrypto.TimeStamperThumbprint
            Add-Member -InputObject $Record -MemberType NoteProperty -name 'SignatureAlgorithm' -value $fcrypto.SignatureAlgorithm
        }

        $Result += $Record
    }

    $Result
}