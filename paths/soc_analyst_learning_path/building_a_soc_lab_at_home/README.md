# Building a SOC Lab at Home

If you want to build a SOC Lab with free tools, you should follow this course.

**Table of content:**

- pfSense

- Active Directory
- Windows Workstation
- Sysmon
- CrowdSec

## pfSense

### **Download**

Go to the [official site.](https://www.pfsense.org/download/)

Download the last stable version of the community edition.

### VirtualBox Settings

Create a new virtual machine.

![setting01](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/setting01.png)

![setting02](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/setting02.png)

![setting03](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/setting03.png)

![setting04](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/setting04.png)

![setting05](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/setting05.png)

![setting06](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/setting06.png)

Go to the VM properties.

In Network tab, activate 3 adapters.

Making note of the MAC Addresses of each adapters will be useful for  future actions. This will be the RED CARD. (external network)

![setting07](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/setting07.png)

This will be the GREEN CARD. (internal network)

![setting08](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/setting08.png)

This will be the orange CARD. (dmz)

![setting09](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/setting09.png)

Launch the VM. It will ask you which ISO Virtualbox must mount on the VM, load the pfsense one.

![setting10](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/setting10.png)

# 

### Installation

Accept the Copyright and Trademark Notices.

![install01](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/install01.png)

Select "install".

![install02](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/install02.png)

-Select your keymap

-Use the default partition (we're in a lab, we just need a firewall)

-Proceed with installation (no miror, no encrypt, nothing)

-Wait until the installation is complete

![install03](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/install03.png)

Do not load manual configuration.

![install04](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/install04.png)

Reboot on the new system.

### Configuration

Now, the server is powered on with the new system. 

![conf01](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/conf01.png)

Select 1 to configure interfaces.

![conf02](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/conf02.png)

We can see the MAC Addresses. Remember, we recommended to make a note of the MAC addresses. It is always helpful to have/know them.

-Select the RED INTERFACE for WAN

-Select the GREEN INTERFACE for LAN

-Select the last one (ORANGE) for DMZ

![conf03](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/conf03.png)

Confirm.

![conf04](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/01-PFSENSE/Images/Images/conf04.png)

\- Select 2 to configure the IP address

\- Leave the WAN interface as DHCP

\- Select 2 to change the LAN interface

\- Asssign the IP and subnet you want, *the gateway must be "none"* !

This course was prepared by Julien Garcia. You can find his social media accounts below.

Twitter: [geekmunity_FR](https://twitter.com/geekmunity_FR)

LinkedIn: [Julien G.](https://www.linkedin.com/in/jgarcia-cybersec/)

## Active Directory

### **Download**

Go to [Microsoft Evalcenter.](https://www.microsoft.com/en-us/evalcenter/evaluate-windows-server-2022)

Select "Download the ISO file."

![download1](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/download1.png)

Download the ISO in 64 bits in English.

### VirtualBox Settings

Create a new virtual machine.

![vm01](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/vm1.png)

![vm02](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/vm2.png)

![vm03](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/vm3.png)

![vm04](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/vm4.png)

![vm05](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/vm5.png)

![vm6](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/vm6.png)

Go to the VM properties.

In the Network tab, change the configuration to use internal network: GREEN

![vm7](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/vm7.png)

Launch the VM: It will ask you which ISO Virtualbox must mount on the VM, load the Windows Server one.

### Installation of Windows

Select the English language to install. The other settings can be  adjusted with your favorite configuration but the Windows must be  installed in English.

![install01](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/install01.png)

Select "install now."

Select "Windows Server 2022 Datacenter Evaluation (Desktop  Experience)". For a lab, the GUI can be usefull if you start a fresh  career in IT.

![install02](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/install02.png)

Accept software licence.

Select Custom install.

![install03](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/install03.png)

Select the only drive mount and click "next".

![install04](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/install04.png)

Wait until the installation is complete and the system reboots itself.

Set your password. (remember it's a lab, you can have a weak password)

### Configuration of Windows

Connect to your administrator account.

Go to "Open Network & Internet Settings."

![ad1](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/AD1.png)

Change adapter options.

Select your card properties.

Go to "Internet Protocol Version 4" > Properties.

Assign IP.

Try to join the gateway. (so your LAN INTERFACE in pfsense)

Rename the server with an easy name to remember/use.

![ad7](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/AD7.png)

Restart your VM.

### Installation of Active Directory

Connect to your administrator account.

Select "Add roles and features."

![ad8](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/ad8.png)

Add a role-based installation.

Select the only server you've got.

Add "Active Directory Domain Services."

![ad9](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/ad9.png)

![ad10](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/ad10.png)

Leave the other Windows settings with defaults configurations.

After it is complete, promote this server to a domain controller.

![ad11](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/ad11.png)

Add a new Active Directory Forest. 

![ad122](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/ad12.png)

Leave default configurations and give a password.

![ad13](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/ad13.png)

Leave DNS part by default.

Check the NetBIOS domain name. 

Leave the default path.

Launch the install.

Reboot when asked for it.

### Configuration of Active Directory

Now you have the Active Directory Server, you need to populate it with misconfiguration to perform analysis. We will use [BadBlood](https://github.com/davidprowe/BadBlood) for this task, Please follow the instructions below:

-Download it on the AD

-Extract it

-Launch Powershell as administrator

-Go to Badblood folder

-Launch Invoke-BadBlood.ps1

-Let the magic happen (this can take several minutes)

![badblood1](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/badblound1.png)

![badblood2](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/02-ActiveDirectory/Images/Images/badblound2.png)

Now, you have the Active Directory configuration (2500 users, 500 groups, OU, 100 computers, etc.), have fun!

## Windows Workstation

### **Download**

-Download the [tool offered by Microsoft.](https://go.microsoft.com/fwlink/?LinkId=691209)

-Launch it.

-Accept the software license.

-Select "create an installation support" to make an ISO.

-Select the English language.

![download1](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/download1.png)

-Select "ISO file."

-Save the file on your computer.

### VirtualBox Settings

Create a new virtual machine.

![vm01](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/vm1.png)

![vm02](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/vm2.png)

![vm03](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/vm3.png)

![vm04](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/vm4.png)

![vm05](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/vm5.png)

![vm6](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/vm6.png)

Go to the VM properties.

In the Network tab, change the configuration to use the internal network: GREEN

![vm7](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/vm7.png)

Launch the VM: It will ask you which ISO Virtualbox must mount on the VM, load the Windows Server one.

### Installation of Windows

Select the English language to install. The other settings can be  adjusted with your favorite configurations but Windows must be installed in English!

![install1](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/install1.png)

Select "install now".

Select "I don't have a product key". (or enter the one you have)

![install2](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/install2.png)

Select Windows 10 Pro version.

![install3](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/install3.png)

Accept the license terms.

Select a custom install.

![install4](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/install4.png)

Select the only drive you have and select "Next".

![install5](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/install5.png)

-Wait until the installation is complete and the system reboots itself.

-Select your region.

-Select your keyboard layout.

-Select "I don't have internet" in the left bottom corner.

![install6](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/install6.png)

Select " Continue with limited setup" in the left bottom corner.

![install7](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/install7.png)

-Name your local account and secure it with a password.

-Setup your 3 security questions.

-Set all other options to the minimal value. (no location, no track, etc.)

### Configuration of Windows

-Connect to your administrator account.

-Go to "Open Network & Internet Settings".

-Change the adapter options.

-Select your card properties.

-Go to "Internet Protocol Version 4" > Properties.

![setting01](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/setting01.png)

Assign IP.

![setting02](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/setting2.png)

Try to join the gateway. (so your LAN INTERFACE in pfSense)

![setting3](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/setting3.png)

Rename the server with another name you can remember easily.

![setting4](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/setting4.png)

![setting5](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/setting5.png)

Restart your VM.

### Add Your Workstation to the Domain

-Go to "Advanced system settings".

-Select "Change".

![setting6](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/setting6.png)

-Select "Domain" and give your netbios domain name.

-Give your Administrator domain account credentials.

![setting7](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/03-Windows_Workstation/Images/setting7.png)

Reboot your VM.

## Sysmon

### Download Sysmon

-Go to [Windows Sysinternals page.](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

-[Download Sysmon.](https://download.sysinternals.com/files/Sysmon.zip)

-Extract it.

### Download the Configuration File

-Download the [xml file.](https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml)

-Save it in the Sysmon's folder.

### **Install It**

-Launch Powershell in administrator.

-Install it with "sysmon.exe -accepteula -i YOURFILE.xml".

![install01](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/04-Sysmon/Images/install01.png)

Please review the '[Log Analysis with Sysmon](https://app.letsdefend.io/training/lessons/log-analysis-with-sysmon)' course to obtain further information on Sysmon.

## CrowdSec

### **Account**

-Go to the [crowdsec site.](https://www.crowdsec.net/)

-Select "create free account".

-Create the free account and log in to CrowdSec.

### Install for Linux

When you're logged in you will have all the information to install the Linux.

### **Install for Windows**

-Go to the [GitHub page.](https://github.com/crowdsecurity/crowdsec/releases/latest)

-Download the .msi file on the Windows computer. (server and workstation)

-Launch it.

![install01](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/05-CROWDSEC/Images/install01.png)

![install02](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/05-CROWDSEC/Images/install02.png)

![install03](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/05-CROWDSEC/Images/install03.png)

![install04](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/05-CROWDSEC/Images/install04.png)

![install05](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/05-CROWDSEC/Images/install05.png)

Contrary to Linux, CrowdSec does not support the automatic  configuration at installation time. If you want to be able to detect  something other than RDP or SMB brute force, then you will need to  customize your acquisition configuration.

\- Launch Powershell as an administrator in CrowdSec's folder.

*-* **Command:** .\cscli collections install crowdsecurity/windows-firewall

![install06](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/05-CROWDSEC/Images/install06.png)

-Open the acquis.yaml file in "C:\ProgramData\CrowdSec\config".

-Add this to it.

![install07](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/05-CROWDSEC/Images/install07.png)

-Reboot the computer.

### Advanced Install for Windows

If you want your Crowdsec with block abilities, then you need to install the Windows Firewall Bouncer Installation.

-Go to the [dedicated page.](https://github.com/crowdsecurity/cs-windows-firewall-bouncer/releases)

-Download the bundle file. (contain all dependancies)

-Launch it.

![install08](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/05-CROWDSEC/Images/install08.png)

![install09](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/05-CROWDSEC/Images/install09.png)

![install10](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/05-CROWDSEC/Images/install10.png)

![install11](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/05-CROWDSEC/Images/install11.png)

![install12](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/05-CROWDSEC/Images/install12.png)

![install13](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/05-CROWDSEC/Images/install13.png)

![install14](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/05-CROWDSEC/Images/install14.png)

![install15](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/05-CROWDSEC/Images/install15.png)

![install16](https://ld-images-2.s3.us-east-2.amazonaws.com/Building+a+SOC+Lab+at+Home/05-CROWDSEC/Images/install16.png)