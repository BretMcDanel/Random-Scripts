<#
	.SYNOPSIS
	Compiles a CSharp file into either an EXE or DLL
	.DESCRIPTION
	Compiles a CSharp file into either an EXE or DLL
	.PARAMETER Debug
	Includes debug information in the output file
	.PARAMETER isLibrary
	Sets mode to generate DLL, unset an EXE will be produced
	.PARAMETER Script
	Path to the .cs file

	.EXAMPLES
	# Creates HelloWorld.exe from HelloWorld.cs
	Compile-CSharp -Script HelloWorld.cs

	# Creates HelloWorld.dll from HelloWorld.cs, enables debugging info in the DLL
	Compile-CSharp -Script HelloWorld.dll -isLibrary -Debug
#>
function Compile-CSharp
{
	param (
		[Switch] $Debug,
		[Switch] $isLibrary,
		[String] $Script
	)

	# Version check, PS7 does not like this script
	if ($PSVERSIONTABLE.PSVersion.Major -gt 5) {
		Write-Host "This script is not compatible with Powershell versions greater than 5.x"
		break
	}

	$ScriptContents = Get-Content $Script -Raw

	if($isLibrary) {
		$OutputFile = $((Get-Item $Script).Basename + '.dll')
	} else {
		$OutputFile = $((Get-Item $Script).Basename + '.exe')
	}

	$cp = @{
		"OutputAssembly" = $OutputFile
		"GenerateExecutable" = $(-not $isLibrary)
	}

	if ($Debug) {
		Write-Host "Debugging is enabled"
		$cp['TreatWarningsAsErrors'] = $true
		$cp['IncludeDebugInformation'] = $true
	}

	Write-Host "Saving output to $OutputFile"
	Add-Type -TypeDefinition $ScriptContents -CompilerParameters $cp

}
