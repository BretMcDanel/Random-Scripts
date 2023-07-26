function Invoke-IdleOff {
        <#
        @AUTHOR: Bret McDanel
        .SYNOPSIS
        Prevents a system from going idle
        .DESCRIPTION
        Prevents a system from going idle
        .PARAMETER IdleTimeout
        Seconds between iterations, default is 300
        .PARAMETER StartTime
        Time of day to begin preventing idle, default is 9:00
        .PARAMETER EndTime
        Time of day to stop preventing idle, default is 17:00
        .PARAMETER DisableScreensaver
        If set screensaver is also disabled
        .PARAMETER IgnoreTime
        If set ignores the time of day
        .PARAMETER days
        Array containing the days of the week to operate on
        #>
        [cmdletbinding()]
        param (
                [Int]$IdleTimeout = 300,
                [String]$StartTime = '09:00',
                [String]$EndTime = '17:00',
                [Switch]$DisableScreensaver,
                [Switch]$IgnoreTime,
                [Array]$days = @('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday')
        )

        if (-not ([System.Management.Automation.PSTypeName]'Idle.UserInput').Type) {
                Add-Type @'
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace Idle {
        public static class UserInput {
        [DllImport("user32.dll", SetLastError=false)]
        private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);

        [StructLayout(LayoutKind.Sequential)]
        private struct LASTINPUTINFO {
                public uint cbSize;
                public int dwTime;
        }

        public static TimeSpan IdleSeconds {
                get {
                // Get the number of ticks since last input
                LASTINPUTINFO lii = new LASTINPUTINFO();
                lii.cbSize = (uint)Marshal.SizeOf(typeof(LASTINPUTINFO));
                GetLastInputInfo(ref lii);

                // Convert ticks to MS
                DateTime bootTime = DateTime.UtcNow.AddMilliseconds(-Environment.TickCount);
                DateTime lastInput = bootTime.AddMilliseconds(lii.dwTime);

                // Return as a TimeSpan object
                return DateTime.UtcNow.Subtract(lastInput);
                }
        }
    }
}
'@
        }


        if (!($DisableScreensaver)) {
                $Signature = @"
[DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
public static extern void SetThreadExecutionState(uint esFlags);
"@

                $ES_DISPLAY_REQUIRED = [uint32]"0x00000002"
                $ES_CONTINUOUS = [uint32]"0x80000000"

                Start-Job -Name "DisableScreensaver" -ScriptBlock {
                        $STES = Add-Type -MemberDefinition $args[0] -Name System -Namespace Win32 -PassThru
                        $STES::SetThreadExecutionState($args[2] -bor $args[1]) 

                        while ($true) { Start-Sleep -s 15 }
                } -ArgumentList $Signature, $ES_DISPLAY_REQUIRED, $ES_CONTINUOUS | Out-Null

        }

        Add-Type -AssemblyName System.Windows.Forms
        Add-Type -AssemblyName Microsoft.VisualBasic

        $State = $false

        try {
                $Wshell = New-Object -com "Wscript.Shell"
                while ($true) {
                        # Ensure that when midnight rolls over we get new dates
                        $min = Get-Date $StartTime
                        $max = Get-Date $EndTime
                        $now = Get-Date

                        if ($IgnoreTime -or ($min.TimeOfDay -le $now.TimeOfDay -and $max.TimeOfDAy -ge $now.TimeOfDay -and $now.DayOfWeek -in $days)) {
                                if ($State -ne "running") {
                                        write-host $now "Starting de-idle"
                                        $State = "running"
                                }
                                # write-host (Get-Date) ([Idle.UserInput]::IdleSeconds.TotalSeconds)
                                if ([Idle.UserInput]::IdleSeconds.TotalSeconds -gt $IdleTimeout) {
                                        write-host "You are idle, fixing"
                                        write-host "$IdleTimeout"
                                        #[System.Windows.Forms.SendKeys]::SendWait('{SCROLLLOCK}')

                                        # When in a VM scrolllock is eaten and lost
                                        $ExplorerPID = (get-process | Where-Object { $_.name -eq 'Explorer' -and $_.mainwindowhandle -ne 0 }).id
                                        [Microsoft.VisualBasic.Interaction]::AppActivate($ExplorerPID)

                                        $Wshell.SendKeys('{SCROLLLOCK}')
                                        Start-Sleep -Milliseconds 100
                                        $Wshell.SendKeys('{SCROLLLOCK}')
                                }
                        }
                        else {
                                if ($State -ne "pausing") {
                                        write-host $now "Pausing de-idle"
                                        $State = "pausing"
                                }
                        }

                        # Ignore any idle time below 1ms
                        $SleepSeconds = ($IdleTimeout - [Idle.UserInput]::IdleSeconds.TotalSeconds)
                        if ($SleepSeconds -gt 0.001) {
                                Start-Sleep -s $SleepSeconds
                        }
                }

        }
        finally {
                if (!($DisableScreensaver)) {
                        Stop-Job "DisableScreensaver"
                        Remove-Job "DisableScreensaver"
                }
        }
}

