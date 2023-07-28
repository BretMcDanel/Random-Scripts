# DynamicHelper
## Introduction
This module has some tools that point you towards a newly installed app.  Each function should have help which can be accessed by invoking ```Get-Help <modulename>```

## License
This is released under a 3-clause BSD license (New BSD License)

> Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
> 
> 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
> 
> 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
> 
> 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
> 
> THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS” AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Installation
Load the module with the command ```Import-Module /path/to/DynamicHelper.psm1```
You may want to place this in your ~/Documents/Powershell/Microsoft.Powershell_profile.ps1 startup script if you want to have it available all the time.  Versions other than 7.x put the profile script in different locations and some of the code will not work in anything but version 7.x.

## QuickStart
The command ```Get-SystemReport``` will call every function except ```Get-NewFile``` and output a report (optional JSON output) of new things in the system.  You can specify the lookback period (default 30 minutes) with options specified  ```Get-Help Get-PastDate```.  Example: ```Get-SystemReport -hour 1```

## Commands
You can get a list of loaded commands by typing ```Get-Command -Module DynamicHelper```  
```
CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Function        Get-NewApp                                         0.0.1      DynamicHelper
Function        Get-NewDriver                                      0.0.1      DynamicHelper
Function        Get-NewFile                                        0.0.1      DynamicHelper
Function        Get-NewPortMonitor                                 0.0.1      DynamicHelper
Function        Get-NewProcess                                     0.0.1      DynamicHelper
Function        Get-NewProtocolHandler                             0.0.1      DynamicHelper
Function        Get-NewService                                     0.0.1      DynamicHelper
Function        Get-NewTCPListener                                 0.0.1      DynamicHelper
Function        Get-NewUDPListener                                 0.0.1      DynamicHelper
Function        Get-NewUwpApp                                      0.0.1      DynamicHelper
Function        Get-SystemReport                                   0.0.1      DynamicHelper
```

