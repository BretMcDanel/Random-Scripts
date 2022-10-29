$cp = new-object codedom.compiler.compilerparameters
$cp.ReferencedAssemblies.Add('system.dll') > $null
$cp.ReferencedAssemblies.Add('system.core.dll') > $null

# optionally turn on debugging support
if ($debugscript)
{
    $cp.TreatWarningsAsErrors = $true
    $cp.IncludeDebugInformation = $true
    $cp.OutputAssembly = $env:temp + '\-' + [diagnostics.process]::getcurrentprocess().id + '.dll'
}

$script = [io.file]::readalltext($scriptpath)
add-type $script -lang csharpversion3 -compilerparam $cp
