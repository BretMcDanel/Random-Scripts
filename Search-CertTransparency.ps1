<#
	.SYNOPSIS
	Fetches data from the SSL Certificate Transparency list for specified domains
	.DESCRIPTION
	Fetches data from the SSL Certificate Transparency list for specified domains
	.PARAMETER wildcard
	Search for wildcard domains, eg *.foo.bar
	.PARAMETER subdomain
	Search for subdomains under the listed domain
	.PARAMETER full
	Collect all data available
	.PARAMETER after
	Only get certs newer than a given date
	.PARAMETER days
	Only get certs newer than X days
	.PARAMETER domain
	Array of domain to search

	.EXAMPLES
	# Gets all certs issued after January 1, 2022 including wildcards and subdomains
	Search-CertTransparency.ps1 -domain deltadentalins.com -wildcard -subdomain -after 1/1/2022

	# Gets all certs issued less than 10 days ago for domains foo.com and bar.com
	Search-CertTransparency.ps1 -domain $("foo.com", "bar.com) -days 10
#>


param (
	[Switch]$wildcard = $false,
	[Switch]$subdomain = $false,
	[Switch]$full = $false,
	[String]$after,
	[Int]$days,
	[Parameter(Mandatory=$true)]
	[Array]$domain
)


# Free API key can be obtained at https://sslmate.com/ct_search_api/
$Token = "INSERT VALID TOKEN HERE"



$Url = "https://api.certspotter.com/v1/issuances"
# See https://sslmate.com/help/reference/ct_search_api_v1 for what these fields are
$ExpandAll = "expand=type&expand=sha256&expand=data&expand=name&expand=reason&expand=checked_at&expand=time"
$ExpandMin = "expand=dns_names&expand=issuer&expand=revocation&expand=cert"
$header = @{ Authorization = "Bearer $Token" }

# Date filtering
if ($after -and $days) {
	Write-Host "You may not use both -after and -days at the same time"
	break
} elseif ($PSBoundParameters.ContainsKey('after')) {
	try {
		$AfterDate = (Get-Date -Date $after)
	} catch {
		Write-Host "Invalid Date Format"
		Write-Host $_
		break
	}
} elseif ($PSBoundParameters.ContainsKey('days')) {
	try {
		$AfterDate = (Get-Date).AddDays("-" + $days)
	} catch {
		Write-Host "Invalid Date Format"
		Write-Host $_
		break
	}
}

# Main loop
foreach ($dom in $domain) {
	write-host "Looking up" $dom
	# Set request parameters
	$Request = $Url + "?domain=" + $dom + "&" + $expandMin
	if ($full) { $Request += "&" + $expandAll }
	if ($wildcard) { $Request += "&" + "match_wildcards=true" }
	if ($subdomain) { $Request += "&" + "include_subdomains=true" }

	$certs = $()
	$id=$null
	do {
		if ($id -ne $null) {
			$req = $Request + "&after=" + $id
			# Avoid rate limiter
			Start-Sleep -Seconds 1.5
		} else {
			$req = $Request
		}
		# Make the request and set TLS 1.2 for connection method (website rejects 1.0, the default)
		try {
			if ($PSVERSIONTABLE.PSVersion.Major -ge 6) {  
				$Response = Invoke-RestMethod $req -Headers $header -SslProtocol Tls12
			} else {
				[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
				$Response = Invoke-RestMethod $req -Headers $header
			}
		} catch {
			Write-Host "ERROR: " $_
			Exit
		}
		$certs += $Response
		$id=$Response[$Response.Count - 1].id

	} while ($Response.length -gt 0)

	# Filter by date
	if ($AfterDate -ne $null) { 
		$Response = $Response | Where-Object {(Get-Date -Date $_.not_before) -gt $AfterDate}
	}


	# Display results
	if ($full) {
		$Certs | Select-Object *,@{n='Info URL';e={  "https://search.censys.io/certificates/" + ($_.cert -replace '(.*sha256=)(.*?);.*','$2') }}

	} else {
		$Certs | select id, 
			@{n='dns_names';e={ $_.dns_names -join " " }},
			@{n='issuer'; e={ $_.issuer -replace '(.*O=")(.*?)".*','$2' }},
			not_before, not_after, revoked,
			@{n='Info URL';e={  "https://search.censys.io/certificates/" + ($_.cert -replace '(.*sha256=)(.*?);.*','$2') }}
	}
}
