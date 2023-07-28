# VPN in a Network Namespace

## Background
Network namespaces provide isolation of network resources (interfaces, routing tables, firewall rules, etc).  Basically, you have an environment you can execute programs in (webbrowsers, servers, etc) and they are isolated from other network interfaces and from other applications.  This version is **Linux Specific** and **OpenVPN specific** and probably will not run on other operating systems.

These scripts arent necessary, they just make it more convenient.  Most everything can be trivially done with ```ip netns``` commands.

![It's a surprise tool that will help us later](Suprise+Tool.png)

See ```man network_namespaces``` and ```man ip-netns``` for more information.

## Configuration
1. Copy the scripts to the location of your choosing.  For these examples ```~/vpn``` is used.  
2. ```mkdir -p ~/vpn/config/PROVIDER/config``` where PROVIDER is the VPN name (eg 'work' or 'SuperCoolVPNService')
3. Download your OpenVPN configuration files for your VPN provider and place them in ```~/vpn/config/PROVIDER/config```
4. If you have a passwordless set up you might want to ensure no one else can read your password file or configs.  ```man chmod```
5. Set up a per VPN resolv.conf  
    5.1. ```sudo mkdir -p /etc/netns/PROVIDER```  
    5.2. ```cp PROVIDER_resolv.conf /etc/netns/PROVIDER/resolv.conf```  

## Exec a command
```~/vpn/vpn.sh exec PROVIDER:us1234.ovpn bash```
This will check if the VPN is up, if not it will start it.  Once it is up it will execute your command of choice.  That process and all child processes will be in the Network Namespace and only have access to the VPN.  If the VPN dies there is no "backup" network interface.

## Stop a VPN
```~/vpn/vpn.sh stop PROVIDER:us1234.ovpn```  
As the name suggests this will terminate the openvpn session associated with PROVIDER:us1234.ovpn and remove the Network Namespace associated with it.  

## Start a VPN
```~/vpn/vpn.sh start PROVIDER:us1234.ovpn```  
This will choose the config us1234.ovpn from PROVIDER, and start the VPN.  You usually do not need to start the VPN by itself (see exec)

## List a VPN
```~/vpn/vpn.sh list```  
This will list all Network Namespaces, however you can easily see which ones are VPNs because the name will have the PROVIDER:conf format.
> ```~/vpn/vpn.sh list```  
> PROVIDER:us1234.ovpn (id: 1)
