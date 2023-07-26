# Random-Scripts
## Introduction
These are random things that I felt like sharing.  

# Files
## Powershell
* [Compile-CSharp.ps1](Compile-CSharp.ps1) - Rudimentary C# compiler.  Mostly useful for pentesting apps, real dev should be done in a real compiler
* [PS_Persistence_Add-Monitor.ps1](PS_Persistence_Add-Monitor.ps1) - Based on Brady Bloxham's [Defcon 22](https://www.youtube.com/watch?v=dq2Hv7J9fvk) persistence technique.
* [Search-CertTransparency.ps1](Search-CertTransparency.ps1) - Search the Certificate Transparency Logs for a given domain, useful for footprinting or periodic checks on your own domain to see if anyone is abusing dangling DNS records.
* [Idle-Execute.ps1](Idle-Execute.ps1) - Execute payload when the user goes idle so they are less likely to see any unusual activity.  Time bounds to limit during office hours so the system is not doing things at weird times.

## C#
* [CreateUser.cs](CreateUser.cs) Generic .exe PoC that creates a user and adds them to the Administrator group
* [CreateUser_Service.cs](CreateUser_Service.cs) Generic Service .exe PoC that creates a user and adds them to the Administrator group
