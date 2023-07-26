<#
    @AUTHOR: Bret McDanel
	.SYNOPSIS
	Compiles a CSharp file into either an EXE or DLL
	.DESCRIPTION
	Compiles a CSharp file into either an EXE or DLL
	.PARAMETER EnableDebug
	Includes debug information in the output file
	.PARAMETER isLibrary
	Sets mode to generate DLL, unset an EXE will be produced
	.PARAMETER Script
	Path to the .cs file
	.EXAMPLE
	# Creates HelloWorld.exe from HelloWorld.cs
	Compile-CSharp -Script HelloWorld.cs

	.EXAMPLE
	# Creates HelloWorld.dll from HelloWorld.cs, enables debugging info in the DLL
	Compile-CSharp -Script HelloWorld.dll -isLibrary -Debug
#>
function Build-CSharp {
	[cmdletbinding()]
	param (
		[Switch] $EnableDebug,
		[Switch] $isLibrary,
		[ValidateScript({
				if (Test-Path -Path $_ -PathType Leaf) {
					$True
				}
				else {
					Throw "Unable to access $_"
					$False
				}
			})]
		[String] $Script
	)

	# Version check, PS7 does not like this script
	if ($PSVERSIONTABLE.PSVersion.Major -gt 5) {
		Write-Host "This script is not compatible with Powershell versions greater than 5.x"
		break
	}

	$ScriptContents = Get-Content $Script -Raw

	if ($isLibrary) {
		$cp = @{
			"OutputAssembly"     = $((Get-Item $Script).Basename + '.dll')
			"GenerateExecutable" = $false
		}
	}
	else {
		$cp = @{
			"OutputAssembly"     = $((Get-Item $Script).Basename + '.exe')
			"GenerateExecutable" = $true
		}
	}

	if ($EnableDebug) {
		Write-Host "Debugging is enabled"
		$cp['TreatWarningsAsErrors'] = $true
		$cp['IncludeDebugInformation'] = $true
	}

	Add-Type -TypeDefinition $ScriptContents -CompilerParameters $cp

}
