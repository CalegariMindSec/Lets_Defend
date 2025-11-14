# Advanced Linux/Unix System Security

The  "Advanced Linux/Unix System Security" course is designed to empower  participants with the advanced knowledge and skills required to  effectively detect and defend against cyberattacks in Linux and Unix  environments. Through in-depth training, you will learn to secure  critical assets, data, and systems from evolving threats, making you a  proficient guardian of your digital infrastructure.

**Table of Contents:** 

- [Linux Log Infrastructure](#linux-log-infrastructure)
- [Syslog and Rsyslog](#syslog-and-rsyslog)
- [Rotation and Management of Log Files](#rotation-and-management-of-log-files)
- [SElinux/Apparmor-1](#selinuxapparmor-1)
- [SElinux/Apparmor-2](#selinuxapparmor-2)
- [Linux Firewall](#linux-firewall)
- [Uncomplicated Firewall (UFW)](#uncomplicated-firewall-ufw)

**Evaluate Yourself with Quiz**

- [Advanced Linux/Unix System Security](https://app.letsdefend.io/training/quiz/advanced-linux-unix-system-security)

## Linux Log Infrastructure

The Linux operating  system provides a good amount of information about how the system works  and what type of events occur. Log files store important information  about the system which provides in-depth information about it. In this  training,, we will learn about the Linux log engine, various log files  and how you can use them.

For any Linux system  administrator or security professional, log files are an indispensable  tool for identifying errors, monitoring system events, and detecting  security issues. However, to be able to use the information provided by  these files effectively requires certain knowledge and skills.

This training will help  you gain a deep understanding of the Linux log engine and teach you how  to use these powerful tools. You will learn where the log files are  located, how to read and analyze them, what information they contain and how to manage log files. We will also cover topics such as rotation of  log files and the use of log analysis tools.

### Importance of Log Files  

Linux log files give  system and network administrators detailed information about what is  happening on a system. Examining the log files of various services and  applications is often an important step when administering a Linux  system.

We can collect the importance of Linux log files under the following headings:

**Debugging**

Log files are often the  first place to look to understand why a service or application is not  working properly. Log files are often helpful in finding causes and  solutions to errors.

**Security Auditing**

Log files are used to  detect suspicious or malicious activities. This may include login  attempts, unauthorized file access, or system changes.

**Performance Monitoring**

Log files provide  information about the performance of a system. For example, you can see  how quickly a service responds or how long a transaction takes to  complete.

**System Maintenance**

Log files allow you to  monitor events on a system over a long period of time. This can help  system administrators plan maintenance requirements, anticipate  unexpected events, and intervene as needed.

For these reasons, checking log files regularly and taking action when necessary is an  essential part of keeping a Linux system safe and running efficiently.

### Locations and Functions of Log Files

Locations and  functionality of log files may vary depending on distribution and  configuration. The table below contains commonly used log files. If you  are using a different Linux distribution or your system configuration  has changed, it is important to verify the location and name of the log  files.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/1/l-table-1.png)

### Reading and Understanding Log Files

Reading and understanding Linux log files is an essential skill for system administrators and  security professionals. Log files help monitoring system status, analyze errors and examine security events by recording events that occur  during system operation. Below are important steps for reading and  understanding Linux log files:

**Log File Location**

We first need to  determine the location of the log files that we need to read and review. In addition to the locations of the log files mentioned above the  "/var/log" directory is another important location where the common log  files are usually stored.

**Reading Log File**

You can use "less" or  "tail" commands in the terminal to open a log file. For example, you can open the "syslog" file with the command "less /var/log/syslog". With  the “tail -f /var/log/messages” command, you can follow the file  continuously and see the newly added logs instantly.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/1/image6-1.png)

The “/var/log” directory  may contain many log files and directories where logs of applications  are stored. We can use the "grep" command, where we can search for  string expressions in the files if we are not sure where to search for  data (IP address, domain, username, etc.).

For example, let's search for user "vivek" in all log files:

**-r parameter:** It is also used to search for files in directories.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/1/image6-2.png)

In this part of the  training, we have covered the log infrastructure in Linux, the  importance of log files, the locations and functions of log files, and  how to read log files. We will learn about the “Syslog and Rsyslog” topic in the next part of our training.

### Questions

1 - In which log file are the kernel logs saved? 

Note: Enter the full path.

> **Answer:** /var/log/kern.log

## Syslog and Rsyslog

“Syslog” is a standard  protocol for collecting, processing and managing log messages on Linux  systems. It is also a service used to collect log messages from  different sources in the system (e.g. kernel, services, applications)  and save them in a central location. It is used by many log files  located in the “/var/log” directory and accepts log messages (debug,  info, warning, error, critical, alert, emergency) at different levels.  Syslog also has the ability to transmit log messages over the network to a remote syslog server.

“Rsyslog” is a modern log management system with more advanced features based on the syslog  service. Rsyslog has a faster and more powerful structure than previous  syslog versions. It also supports previous syslog configurations to  ensure compatibility. It receives, processes and manages log messages  using the Syslog protocol and features. It is recommended to be used  instead of syslogd and is included as the default log management service in most Linux distributions.

Rsyslog also offers  advanced features such as converting logs to various formats, filtering, processing and routing. This allows you to forward log messages to  different files or even remote servers.

Rsyslog's configuration  file can usually be found as “/etc/rsyslog.conf” or  “/etc/rsyslog.d/*.conf”. These files determine how rsyslog works and how log messages are routed.

The rsyslog configuration file consists of the following sections:

**Global Directives**

This section contains  commands that generally affect the rsyslog service. These commands  determine the configurations that will apply system-wide. For example,  general configurations such as where the logs will be saved and in what  format the logs will be are specified here.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/2/image6-3.png)

**Module Directives**

This section contains  configurations related to a specific module. For example, settings  specific to imudp or imtcp modules are included in this section.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/2/image6-4.png)

**Ruleset and Template Definitions**

Rsyslog can process log messages according to logical groups called "rulesets". This section  defines configurations for a specific ruleset. Additionally, structures  called "templates" can also be defined to determine in which format the  logs to be saved.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/2/image6-5.png)

**Log Directives**

This section determines  how log messages will be routed. Logs can be routed to files, remote  servers, console, email addresses or other destinations. For example,  "kern.* /var/log/kernel.log" will redirect the kernel logs to  "/var/log/kernel.log".

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/2/image6-6.png)

**Include Directives**

The Rsyslog configuration file can get quite complex. Therefore, "include" commands can be used  to keep the configuration file organized and managed. "Include" commands include configurations from different files into the main  configuration.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/2/image6-7.png)

Each rsyslog configuration file may be different, but the above sections are  generally the sections most likely to be present in the configuration.  There are also many documents and resources available with descriptions  of rsyslog's configuration files, which will help you better understand  the configuration.

In summary, syslog and  rsyslog are important services used for log management in Linux systems. Rsyslog is a more advanced version of syslogd and is a log management  solution recommended and used in most Linux distributions.  

In this part of the training, we have covered the details about syslog and rsyslog. We will learn about the "Rotation and Management of Log Files" topic next.

### Questions

1 - What is the destination IP address that the "mail.info" logs are sent on the system you access?

> **Answer:** 172.16.1.100

## Rotation and Management of Log Files

The rotation and  management of Linux log files are one of the most important points to  prevent the uncontrolled growth of logs and to ensure that the logs in  the system are managed in an orderly manner. Log rotation is the process of compressing, deleting or moving log files to another location within a specified time period. This process prevents uncontrolled growth of  log files, avoids problems such as running out of disk space, and makes  logs easier to read and manage.

One of the mostly preferred solution for rotation and management of Linux log files is the "logrotate" tool.

“Logrotate” is a tool  that provides automatic management of log files on Linux systems.  Configuration files are located under the “/etc/logrotate.conf” and  “/etc/logrotate.d/” directories. These configurations determine when log files are rotated, compressed, deleted, and moved to another location.

Logrotate gives system  administrators the flexibility to specify details such as how long log  files will be kept and how many archive files will be preserved.  Logrotate is usually run on a daily, weekly or monthly basis.

The main rotation types/features are as follows:

**Size-based Rotation**

Rotation can be done by controlling the size of the log files. For example, when the log file  reaches a certain size, a new file can be created and the old file is  backed up.

**Time-based Rotation**

Log files can be rotated  in a certain time period (daily, weekly, monthly). This keeps the log  files in a clean state and allows them to use disk space more  effectively.

**Compressing Logs**

Old log files can be compressed and stored. This helps you use disk space more efficiently and is useful for archiving purposes.

Here are some of the Linux log rotate parameters:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/3/rotation-table.png)

For example, the log rotation config file of firewalld logs is shown below:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/3/image6-8.png)

Rotation and management  of log files is an important process for system administrators as it  allows to clean disk space regularly, improve readability of logs and  manage logs effectively. Correct log rotation policies are also critical for system security and performance.

In this part of the  training, We have covered the log rotation on Linux, its importance,  types and features. We will learn about the “SElinux/Apparmor-1” topic in the next part of our training.

### Questions

1 - At what intervals are the "dpkg" logs rotated on the system you access? (eg daily, weekly, monthly, etc.)

> **Answer:** monthly

## SElinux/Apparmor-1

SELinux and AppArmor are  two different security mechanisms used to increase the level of security in Linux-based operating systems. Both work on the basis of Mandatory  Access Control (MAC) and are used to control the type of resources a  process or application can access.

### SELinux

“SELinux” is a security  module for the Linux kernel and gives systems more control to limit  malicious or erroneous behavior. This is accomplished through security  policies such as Access Control List (ACL), Role-Based Access Control  (RBAC), and Mandatory Access Control (MAC).

“SELinux” defines  specific permissions and capabilities for each process running on the  system, thus controlling how a process can use resources and file  system. This prevents malware or erroneous applications from wreaking  havoc on the system.

SELinux is a project  initiated by the National Security Agency (NSA) and is widely used in  Red Hat-based distributions, especially Fedora, CentOS, and Red Hat.

Example SELinux config file contents are as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/4/image7-1.png)

SELinux (Security-Enhanced Linux) can basically run in the following three modes:

**Enforcing**

In this mode, SELinux  enforces policy rules and blocks and logs any rule violation. This is  the default operating mode where SELinux actively enforces security  policies.

**Permissive**

In this mode, SELinux  only logs policy violations, but does not prevent these violations. This is typically used when system administrators set SELinux policies or  perform debugging operations. This mode preserves SELinux's ability to  report potential problems while avoiding the actual impact of these  problems on the system.

**Disabled**

In this mode, SELinux is completely disabled. It is not possible for SELinux to enforce any security policy or log violations.

If you want to check in  which mode SELinux is running, you can use the "getenforce" command. To  change the mode, you can make a permanent change by editing the  "setenforce" command or the "/etc/selinux/config" file.

SELinux offers flexibility with different policy types. The most common policy types used in SELinux are:

**Targeted Policy**

This is the most commonly used policy type. This policy runs most processes on the system as  "unconfined", meaning no stringent SELinux rules apply to those  processes. However, some important potentially risky services (eg HTTPD, SSHD) are marked as "confined" and special SELinux policies apply to  these services.

**Minimum Policy**

This is a variant of the  "targeted" policy and only enforces SELinux policies for certain  services. This policy is only suitable for those who want to take  security measures for certain services.

**Multi-Level Security (MLS) Policy**

This is used to limit  access to sensitive information. Controls access to data using different security levels and categories. It is particularly suitable for  organizations with very high security requirements such as military and  government agencies.

These policy types  determine how SELinux is run in general. However, each policy type comes with many modules, rules, and tags within itself, so the details of  SELinux configuration can be quite complex. Choosing a policy that fits  the needs is important for optimizing system security and performance.

**Examples;**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/4/image7-2.png)

In this part of the tutorial, we have covered SELinux, its modes and common policy types. We will keep learning about Selinux “SElinux/Apparmor-2” in the next part of our training.

### Questions

1 - What is the command used to check the SELinux mode on RHEL systems?

> **Answer:** getenforce

2 - What SELinux mode logs policy violations only and not prevent violations?

> **Answer:** Permissive

## SElinux/Apparmor-2

“AppArmor” is a security  module and is integrated into the Linux kernel. It controls what certain programs can do on the system. Using a permission-based system,  AppArmor determines which files and directories programs can access,  what capabilities they have, and which system calls they can use.

AppArmor is widely used,  especially in distributions such as Ubuntu and openSUSE, and is  generally preferred by users as it has a simpler configuration than  SELinux.

Both security modules  have been developed to increase the security of Linux systems. Which  security module to use often depends on personal preference and the  Linux distribution used. Both are powerful security tools and help  protect systems from malicious or erroneous behavior.

The main operating modes of AppArmor are:

**Enforce Mode**

In this mode, AppArmor  enforces policies and prevents policy violations. It also records these  violations in logs. This mode is the default operating mode where  AppArmor actively enforces access control policies.

**Complain Mode (or Permissive Mode)**

In this mode, AppArmor logs potential violations, but does not prevent these violations. This  is used when developing policy or detecting potential access issues in  the system.

**Disabled**

AppArmor is completely disabled. Access control policies are not enforced or saved.

You can use commands like “aa-status”, “aa-enforce” and “aa-complain” to control and change what  mode the AppArmor profile is in. These commands are part of the AppArmor tools and are required to check if AppArmor is installed on the system.

**Examples;**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/5/image7-3.png)

### SELinux and Apparmor Usage Examples

**Web Servers**

SELinux or Apparmor  forces web servers (eg Apache) to access only certain directories. This  makes it difficult for a malicious attacker to compromise the system if a web application is compromised.

**Database Servers**

SELinux or Apparmor  policies for database servers such as PostgreSQL and MySQL force these  services to access only database files and necessary system resources.

**File Sharing**

For file sharing services like Samba or NFS, SELinux or Apparmor forces these services to access only certain folders and files.

**Network Isolation**

SELinux or Apparmor  forces certain services to access only certain network ports and  protocols. For example, a web server may be blocked from accessing its  SMTP port.

**User Isolation**

SELinux or Apparmor  forces users to access only their own files and certain system  resources, ensuring that any potential harm to other users or processes  running on the system is limited.

### SELinux and Apparmor Differences

The main differences between Apparmor and SELinux are:

**Origin**

“AppArmor” was developed by the  SUSE Linux company and was originally used for SUSE Linux Enterprise  Server (SLES), but has since been used in other Linux distributions as  well.  

“SELinux” was developed by the  NSA (National Security Agency) and Red Hat and later used in Red Hat  Enterprise Linux (RHEL) and other Linux distributions.

**Basic Working Principle:**

  “AppArmor” is a profile-based  system that defines the resources and files that apps can access.  Applications' access to allowed resources is determined by profiles.  

“SELinux” is a tag-based system  that determines the resources that applications can access. Files and  objects are tagged, applications' access permission is determined based  on these tags.

**Usage and Prevalence:**

“AppArmor” is simpler and easier to use than SELinux, so it may be preferred by default on some distributions.  

“SELinux” has a more complex and  flexible structure. It is widely used, especially in military,  government agencies, and security-oriented environments. It is preferred in distributions with high security requirements such as Red Hat  Enterprise Linux.

**Authorization System:**

“AppArmor” has a file path based authorization system. The application can access certain files or access certain file types.

“SELinux” has a tag-based  authorization system. Tags are set for files, folders and other objects  and these tags are used in access control.  

Generally, security  mechanisms such as AppArmor and SELinux are used in Linux-based systems  to reduce vulnerabilities and minimize potential threats. The selection  may vary depending on the policy, requirements, and management  capabilities of the distribution to be used.

### Conclusion/Summary

SELinux  (Security-Enhanced Linux) and AppArmor are security modules for the  Linux operating system that provide enforced access control. These  modules limit access to system resources and processes, specifying what  applications and services can and cannot do in accordance with certain  policies and profiles. While SELinux provides more granular control, it  is often more difficult to learn and configure due to its complexity.  AppArmor, on the other hand, offers a user-friendly approach and limits  app permissions based on file paths. Both modules aim to secure the  system by offering an additional layer of protection against potential  security threats.  

In this part of the  tutorial, we have covered Apparmor, its basic operating modes, usage  examples, and differences between SELinux & Apparmor. We will be  learning about the “Linux Firewall” topic next.

### Questions

1 - How many modules are installed in the "apparmor" on the system you access?

> **Answer:** 50

2 - What is the mode in which Apparmor enforces policies and blocks violations?

> **Answer:** Enforce Mode

## Linux Firewall

Firewalls are simply  security systems that monitor and analyze traffic in a computer network. These systems control which traffic can pass into or out of the network based on the security policies set. Firewalls can exist as hardware  devices, software applications, or a combination of both.

### Purpose

**Data Protection**

Firewalls protect the network by preventing unauthorized access to sensitive and private data.

**Preventing Attacks**

Protects the network by  identifying and blocking potential threats. For example, it can prevent  malware from infiltrating the network.

**Traffic Management**

Provides effective use of network resources by determining allowed traffic and applications.

**Logging and Reporting**

It keeps track of all the activities that occur on the network traffic. This is important for  identifying suspicious activity, investigating potential security  breaches, and blocking future threats.

**Access Control**

Limits the access of users, devices or applications to certain network services or resources.

**Connection Status Monitoring**

The firewall monitors the status of connections, allowing only legitimate and well-known  connections to travel through the network.

### Linux Firewalls

There are many different  firewall solutions in Linux. These solutions basically use the kernel's  netfilter infrastructure. Common firewall models used in Linux are:  

**Iptables**

It is the standard  firewall used in Linux for many years. It is used to manage IPv4  traffic. It works based on Netfilter infrastructure and supports  functions such as packet filtering, Network Address Translation (NAT)  and packet conversion. 

**Ip6tables**

A version of iptables for managing IPv6 traffic.  

**Nftables**

It is a new generation firewall that started to replace iptables as of Linux kernel 3.13. It is a single tool for both IPv4 and IPv6 traffic and offers a richer  syntax.  

**Uncomplicated Firewall (UFW)**

It is a firewall tool with a user-friendly interface, created to remove the complexity of iptables.  

**Firewalld**

A tool used in RPM-based distributions such as Red Hat, CentOS, and Fedora that makes it easy to  dynamically manage firewall rules.  

**Shorewall (Shoreline Firewall)**

Serving as a shell for iptables, this firewall helps to manage complex network configurations in a simple way.  

**Arptables**

A tool for filtering Address Resolution Protocol (ARP) packets.

When choosing between  these firewall solutions, you should choose the most suitable one based  on your needs and experience. For example, for a simple home network,  ufw may be sufficient, while for a large-scale business network,  granular control of iptables or nftables may be more appropriate.

Details for commonly used firewalls on Linux are as follows:

### iptables

“iptables” is a very  powerful tool used for packet filtering and routing in Linux. iptables  can control incoming and outgoing traffic, redirect traffic with custom  rules, block or allow packets.

The basic iptables components are as follows:  

**Tables:** iptables has several different tables. The most commonly used of these tables are filter, nat, and mangle.

**Chains:** Each table has several  predefined chains that determine how packets are handled. For example,  the filter table has INPUT, FORWARD, and OUTPUT chains. 

The detailed table about iptables management is as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/6/fw-table-1.png)

  Some example rules of iptables are as in the image below:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/6/image8-1.png)

### firewalld

“firewalld” is a firewall manager used in modern Linux distributions. It is the default firewall  tool especially for Red Hat based distributions (CentOS, Fedora). By  using firewalld, you can perform operations such as packet filtering,  NAT and port forwarding.  

**Key Features**

**Zones:** Used to classify network  interfaces and IP addresses according to different security levels and  features. Example zones: public, home, internal, work, external, etc.  

**Services:** A service refers to a specific protocol and port number. For example, there are predefined  settings for standard services such as SSH or HTTP.  

The usage examples of Firewalld are as follows: 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/6/fw-table-2.png)

This table summarizes the basic functions that firewalld offers. For more complex configurations, you can review firewalld's main page or official documentation page. In particular, you should be careful when making permanent changes. After  making the configuration changes permanent, do not forget to restart the firewalld service for these changes to take effect. 

In this part of the  training, we have covered the usage purposes of Linux firewall, Linux  firewall solutions and the details of these solutions. We will continue  learning the “Uncomplicated Firewall (UFW)” next.

### Questions

1 - To which file are the “UFW” logs sent on the system you access?

> **Answer:** /var/log/ufw.log

2 - What is the tool used to filter Address Resolution Protocol (ARP) packets?

> **Answer:** Arptables

3 - What is the parameter that should be used to reset all rules via iptables?

> **Answer:** -F

## Uncomplicated Firewall (UFW)

Uncomplicated Firewall  (UFW) is a user-friendly tool designed for IP-based firewall management  on Linux. Essentially, it can be seen as an interface that simplifies  the complex configuration of iptables. It is especially popular in  Ubuntu and similar distributions. Thanks to its simple syntax, users can easily control network traffic, open or close specific ports, and set  permissions for specific IP addresses or IP ranges. Although powerful  and flexible, UFW’s purpose is to make firewall configuration more  understandable and accessible.

The UFW's graphical interface may not be installed by default. The following command can be used to install:

**Command**: “sudo apt install gufw -y”

Afterwards, you can open and use the “gufw” application.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/7/image8-2.png)

The default interface of the “gufw” application is as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/7/image8-3.png)

To add rules from the  “gufw” application interface, open the “Rules” tab, click on the “+”  button and after entering the relevant rule details, finally click on  the “Add” button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/7/image8-4.png)

Usage examples of ufw are as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced-Linux-Unix-System-Security/7/ufw-table.png)

This table summarizes the basic operations that can be done using a UFW. You can review the UFW main page or documentation for more complex configurations and features.  

### Conclusion/Summary

Linux has many powerful  tools to provide full control over network security and traffic. In this article, we talked about Linux's most popular firewall management  tools: iptables, firewalld, and UFW. As a result, there are many options for managing network security in Linux. Depending on your needs,  distribution, and level of technical expertise, you can choose any of  these tools. But the important thing is that no matter which tool you  choose, you should regularly review and keep your firewall rules up to  date.

### Questions

1 - What is the firewall action taken for the “1521” port on the system you access?

> **Answer:** deny

2 - What is the firewall action taken for port “22” on the system you access?

> **Answer:** allow

3 - Which source IP address can access the “3306” port on the system you are accessing?

> **Answer:** 172.16.1.54

