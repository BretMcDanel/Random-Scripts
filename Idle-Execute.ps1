# Seconds of Idle before deploying payload
$IdleTimeout = 300
# "Office hours" to avoid running things at weird times
$StartTime = '09:00'
$EndTime = '17:00'


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


Add-Type -AssemblyName System.Windows.Forms


while ($true) {
	# Ensure that when midnight rolls over we get new dates
	$min = Get-Date $StartTime
	$max = Get-Date $EndTime
	$now = Get-Date

	$IdleSeconds = [Idle.UserInput]::IdleSeconds.TotalSeconds
	
	if ($min.TimeOfDay -le $now.TimeOfDay -and $max.TimeOfDAy -ge $now.TimeOfDay -and $IdleSeconds -gt $IdleTimeout) {
		write-host $now "Deploying Idle Payload"

    # Launch Notepad
		$cmd = [Diagnostics.Process]::Start("notepad")
		# Wait the window to appear
		while ($cmd.MainWindowHandle -eq 0){
		    sleep -Milliseconds 100
		}

		# Set Notepad to the active window
		$wshell = New-Object -ComObject wscript.shell
		$wshell.AppActivate('Notepad')

		# Send some keystrokes
		[System.Windows.Forms.SendKeys]::SendWait('P')
		[System.Windows.Forms.SendKeys]::SendWait('w')
		[System.Windows.Forms.SendKeys]::SendWait('n')
		[System.Windows.Forms.SendKeys]::SendWait('e')
		[System.Windows.Forms.SendKeys]::SendWait('d')
    
    # Exit
    # If the program does not reset idle it will launch the payload again immediately
    # A delta of idle time would need to be incorporated to avoid this
		break
	}

	# Ignore any idle time below 1ms
	$SleepSeconds = ($IdleTimeout - $IdleSeconds)
	if ($SleepSeconds -gt 0.001) {
		Start-Sleep -s $SleepSeconds
	}
}
