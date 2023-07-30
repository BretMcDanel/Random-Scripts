# Random-Scripts
## Introduction
These are random things that I felt like sharing.  Mostly they are things I wrote to help me with small repetitive tasks.

## Powershell
* [Add-SpoolMonitor.ps1](Add-SpoolMonitor.ps1) - PoC based on Brady Bloxham's persistence technique presented at [Defcon 22](https://www.youtube.com/watch?v=dq2Hv7J9fvk).
* [Build-CSharp.ps1](Build-CSharp.ps1) - Rudimentary C# compiler.  Mostly useful for pentesting apps, real dev should be done with a real compiler
* [DynamicHelper](DynamicHelper) - Module with utilties to help with dynamic analysis (DAST) and static analysis (SAST) of executables
* [Get-FileMetaData.ps1](Get-FileMetaData.ps1) - Gets file data including company name, product name, and crypto signature information.
* [Get-NameFromSID.ps1](Get-NameFromSID.ps1) - Resolves a SID into a username
* [Get-SystemChanges.ps1](Get-SystemChanges.ps1) - Lists changes made in a specified time interval.  Useful for software analysis to find where to look after installation.
* [Get-WritePerms.ps1](Get-WritePerms.ps1) - Gets the write permissions of a service or file/directory and all the parent directories
* [Get-UnquotedService.ps1](Get-UnquotedService.ps1) - Lists all unquoted services that may be vulnerable to an unquoted search path CWE-428 attack
* [Invoke-IdleOff.ps1](Invoke-IdleOff.ps1) - Execute payload when the user goes idle so they are less likely to see any unusual activity.  Time bounds to limit during office hours so the system is not doing things at weird times.
* [Mouse.ps1](Mouse.ps1) - Randomly moves the mouse cursor, for maximum fun run remotely on your boss' system
* [Search-CertTransparency.ps1](Search-CertTransparency.ps1) - Search the Certificate Transparency Logs for a given domain, useful for footprinting or periodic checks on your own domain to see if anyone is abusing dangling DNS records.

## C#
* [CreateUser.cs](CreateUser.cs) - Generic .exe PoC that creates a user and adds them to the Administrator group
* [CreateUser_Service.cs](CreateUser_Service.cs) - Generic Service .exe PoC that creates a user and adds them to the Administrator group
