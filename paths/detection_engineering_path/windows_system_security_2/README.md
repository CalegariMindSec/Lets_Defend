# Windows System Security - 2

Take your Windows system security knowledge to the next level with our  advanced course, designed to provide in-depth insights and practical  skills for securing Windows-based environments.

**Table of Contents:**

- [Local Security Policy, Group Policy and UAC](https://app.letsdefend.io/training/lesson_detail/local-security-policy-group-policy-and-uac)
- [Authentication and Authorization on Windows](https://app.letsdefend.io/training/lesson_detail/authentication-and-authorization-on-windows)
- [Update and Patch Management](https://app.letsdefend.io/training/lesson_detail/update-and-patch-management)
- [Antivirus, Malware and Threat Protection](https://app.letsdefend.io/training/lesson_detail/antivirus-malware-and-threat-protection)
- [Windows Log Infrastructure](https://app.letsdefend.io/training/lesson_detail/windows-log-infrastructure)

Evaluate Yourself with Quiz

- [Windows System Security-2](https://app.letsdefend.io/training/quiz/windows-system-security-2)

## Local Security Policy, Group Policy and UAC

Windows operating system  is the main operating system on millions of computers, servers and  laptops around the world. Its widespread use makes Windows a potential  target for security threats. Therefore, effectively managing Windows'  built-in security settings and policies is vital to ensuring the overall security of your computer and network.

The security framework of Windows provides a number of built-in mechanisms and services to  protect users and system resources. These include features like User  Account Control (UAC), Windows Defender, Windows Firewall, file system  access controls, and BitLocker drive encryption.

### Local Security Policy

Windows Local Security  Policy is a tool used to manage security settings on a Windows computer. It is a way to configure a computer's security settings, usually in  accordance with an organization's policies, but it also allows  individual users to control the security of their computers.

Local Security Policy  controls a number of different settings, including user rights  assignments, audit policies, user account control settings, and more.  These policies control the computer's operating system and how users can access the system.

Local Security Policy in  Windows is managed through a Microsoft Management Console (MMC) plug-in, usually accessed via the 'secpol.msc' command. This console allows a  system administrator or user to view and change all local security  policies.

For example, a system administrator might use Local Security Policy for:

- Setting password policies (for example, minimum length of a password or remembering password history),  
- Managing user rights assignment to allow or prevent users or groups from performing certain tasks,  
- Setting auditing policies so that certain types of events can be monitored and recorded (for example, failed login attempts).  

However, improper use of  Local Security Policy can reduce the security of a computer or cause  systems to operate incorrectly, so changes made with this tool should be performed with caution and should generally only be made by experienced IT professionals or conscious users.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/1/image5-1.png)

For example, you can view and edit local users' password policies under the "Accounts Policies" -> "Password Policy" section.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/1/image5-2.png)

### Group Policy (gpedit.msc)

Windows Group Policy  Editor is a Microsoft Management Console (MMC) plug-in that helps a  system administrator manage certain user and system settings in Windows  operating systems. This tool is often used to centrally control settings on multiple computers on a network.

Group Policy Editor  allows you to set and edit policies that apply to users and computers.  These policies can affect system security, user experience, system  performance, and more. Some of the main functions you can implement with Gpedit.msc are:

**Managing User Settings**

User settings control the user's Windows experience. For example, whether to allow the user to  change the desktop background, screen saver, menu options, taskbar, and  other similar features.

**Managing System Settings**

System settings control  the overall functionality of the computer. For example, managing Windows Update settings, security settings, network connections and services,  error reporting, and more.

**Control Security Settings**

You can adjust Windows'  security settings and determine how often users change their passwords,  user account control settings, secure login settings, and more.

**Application Restrictions**

You can determine which  applications can or cannot be run. This may restrict the use of certain  applications or require certain applications to run at all times.

**Network Settings**

Provides control over  network connections, shares and protocols. This includes features such  as VPN connections, firewall settings, and network shares.

**Startup and Shutdown Scripts**

You can specify scripts to run during Windows startup or shutdown.

**Manage Windows Components**

You can edit how certain  components of Windows work. For example, Internet Explorer or Microsoft  Edge settings, Windows Defender settings, and more.

To open Group Policy  Management, run this application with admin rights by typing  “gpedit.msc” in the start section. You can then locate a specific  setting in the tree structure on the left and edit the setting in the  window on the right.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/1/image5-3.png)

It is necessary to be  careful when using this tool. An incorrect setting can make your system  unstable or prevent you from accessing certain features. Therefore, it  is recommended that you always make a backup before making changes and  ensure that you fully understand each setting you are changing.

For group policy  settings, right-click on the relevant domain on the relevant “Group  Policy Management” screen and select the “Create a GPO in this domain,  and Link it here…” option.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/1/image5-4.png)

Name your newly created GPO policy and click “OK”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/1/image5-5.png)

Right click on the relevant policy and select "Edit".

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/1/image5-6.png)

At this stage, policies are created in 2 main basic sections: "Computer Configuration" and "User Configuration".

**Computer Configuration**

This section determines  the policies and settings to apply to computers within a Group Policy  Object (GPO). These settings are applied when the operating system  starts or when a computer is joined to the domain. In this section,  system services, security settings, network protocols and other  computer-level configurations can be defined.

**User Configuration**

This section determines  the Group Policy settings to apply for user accounts. These settings are applied when a user signs in or Group Policy is refreshed. This section allows managing policies for users' desktop environment, application  settings, network connections, and other user-level settings.  

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/1/image5-7.png)

### User Account Control (UAC)

User Account Control  (UAC) is a security component in Windows Server and other Windows  operating systems. UAC determines whether an application requires  administrator-level privileges to make a change. This especially helps  prevent malware from making changes to the system.

The way UAC works is when a user or application performs an action that requires  administrator-level privileges, a UAC prompt is displayed. This prompt  gives the user the option to confirm or reject the transaction.

For administrator  accounts, this is usually just a warning. For standard user accounts,  this typically requires the user to enter an administrator password.

To configure UAC on Windows Server, you can follow these steps:

Open the start menu and type 'User Accounts', then press enter.

In the User Accounts window, click 'Change User Account Control Settings'.

Determine how UAC reacts  using the slider. If you move the slider up, UAC will alert you with  more notifications. If you move the slider down, UAC will notify you  less. Once you have set your settings, click 'OK' and enter the desired  administrator password.

**Note**: You should be extremely careful when changing UAC settings. Disabling UAC completely may make  it less effective at protecting your system from malware. To make UAC  most secure, it's usually best to specify that you should always approve users or applications from making changes that require  administrator-level privileges.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/1/image5-8.png)

In the Windows operating  system, User Account Control (UAC) can be set at four different levels.  These levels alerts users with different level of notifications about  important changes to be made to the system. Here are those levels:

**Always notify:** This is the highest level of UAC and ensures that users are always notified if applications  attempt to make changes to their computer. This level includes the  application trying to change system settings or triggering a software or application installation. This setting always requires the user to  consent to such changes.

**Notify me only when apps try to make changes to my computer (default):**   This setting notifies the user when apps need to make changes, but does not dim the secure  desktop (it only shows the UAC prompt, dimming the rest of the screen).  This may be slightly less intrusive, but still requires the user to  consent to such changes.

**Notify me only when apps try to make changes to my computer (do not dim my desktop):**   This level notifies the  user when an app requires a change, but does not require approval for  the user's own changes (for example, changing system settings or  installing a new app, etc.).

**Never notify:** The lowest level of UAC  and users are not notified if applications attempt to make changes to  their computer. This disables all UAC warnings and can potentially make  the system more vulnerable to security risks.

To set these levels, go  to the "User Accounts" control panel, click "Change User Account Control Settings" and then select your preferred level. You may need to restart your computer for the changes you make to take effect.

### Conclusion/Summary

Windows Security Settings and Policies provide a variety of tools and methods to gain control  over users and systems in Windows operating systems. These include Local Security Policy, Group Policy and User Account Control (UAC).

Local Security Policy is  used to control the security settings of a single computer. This  includes various policies such as user rights assignments, security  options, auditing policies, and more.

Group Policy Editor is  used to control settings on multiple computers on a network centrally.  This is a powerful tool for managing user and system settings, security  settings and more.

User Account Control  (UAC) controls what changes users can make to a computer. This is used  to block potentially harmful or unwanted actions.

These tools and policies  are essential components for ensuring and managing user and system  security in Windows operating systems. When used correctly, they provide an effective way to keep a Windows environment safe and prevent  unwanted or harmful activity.

In this part of the  training, we have covered local security policy on Windows. We have  learned what the Group policy is, what the UAC is and how they can be  managed. We will learn about the   **"Authentication and Authorization on Windows" topic** in the next part of our training.

### Question

1 - How many characters is the  "minimum password length" in the password policy in the "Local Security  Policy" on the system you access?

> **Answer:** 7

2 - What is the maximum kerberos ticket lifetime for the user in the "Local Security Policy" on the system you access?

> **Answer:** 10

## Authentication and Authorization on Windows

Windows operating systems constitute the basic technological infrastructure of many organizations today. However, in order to use this infrastructure safely and  effectively, authentication and authorization mechanisms are critical  importance. Authentication is the process of user’s or system’s proof of identification to verify who they really are that will allow them to  access to the systems securely. Authorization determines which resources can be accessed by those who have successfully completed this  authentication.

In this lesson, we will review Windows' authentication and authorization processes in detail and learn the basic concepts of these subjects.

### Authentication

Windows operating systems rely on authentication and authorization policies to control access to system resources and services.

Authentication is the  process of verifying who a user is. Windows typically uses a combination of username and password, but it also supports other authentication  methods such as smart cards, biometric data, or multi-factor  authentication methods.

Windows supports various authentication protocols such as:

**Kerberos**

Kerberos is the default  authentication protocol in Windows operating systems. Kerberos provides  secure authentication through a Key Distribution Center (KDC). When a  user logs into the system for the first time, they receive a "ticket"  from the KDC. This ticket is used to verify the user for a certain  period of time. The Kerberos protocol provides fast and secure  authentication and supports authentication between services on the  network.

Important points to keep in mind:

- **Clock Synchronization**: Kerberos uses time-based tokens. If the clocks are out of sync, it can lead to authentication errors.  
- **Service Principal Names (SPN) Check**: Ensure SPNs are configured correctly and are unique.  
- **Using AES Encryption**: Use AES instead of older encryption algorithms.  

**NTLM (NT LAN Manager)**

NTLM is an older  authentication protocol and is often used in situations where the  Kerberos protocol is not available. NTLM hashes the user's credentials  and uses these hashes for authentication.

Important points to keep in mind: 

- **Using NTLMv2**: Force NTLMv2 instead of legacy NTLMv1.  
- **Migrating to Kerberos**: Use Kerberos instead of NTLM by upgrading or configuring legacy systems.  

**Digest**

Digest authentication  encrypts the user's password through a hash function. This method is  designed for use with protocols such as HTTP and LDAP.

Important points to keep in mind:

- **Strong Hash Algorithms**: Choose stronger hash algorithms instead of weak hash algorithms such as MD5.  
- **Using TLS**: Use TLS for an extra layer of security during data transmission.  

**Basic**

Basic authentication sends the username and password in clear text. Therefore, it is typically used over a Secure Sockets Layer (SSL) or Transport Layer  Security (TLS) connection.

Important points to keep in mind:

- **Using SSL/TLS**: Basic authentication sends plain text, so it should always be used with SSL/TLS.  
- **Using 2FA**: Use two-factor authentication (2FA) for added security.  

**Smart Card**

Smart card authentication allows a user to verify their identity using a smart card and a PIN code.

Important points to keep in mind:

- **PIN Protection**: It should require a PIN code as well as the smart card.  
- **Security of Card Readers**: Limit physical access.  

**Certificate-Based Authentication**

This method uses digital  certificates and is often used in conjunction with a Public Key  Infrastructure (PKI). A user's identity is verified through a digital  certificate signed by a certificate authority and owned by the user.

Important points to keep in mind:

- **Certificate Revocation List (CRL)**: Update and check the CRL regularly so that invalid certificates can be quickly detected.  
- **Private Key Protection**: Ensure private keys are stored securely.  

The most commonly used  protocols are Kerberos and NTLM. Each protocol has its own advantages  and disadvantages, and which protocol to use often depends on an  organization's needs and infrastructure.

### Authorization

Authorization is the  process that controls what a user can access and do. Authorization  usually occurs following the authentication process. The user is issued a security token, and this token defines the user's privileges and group  memberships.

An important part of  Windows authorization is using Access Control Lists (ACL) and Access  Control Entries (ACE). ACLs determine what type of access a user or  group has to an object (for example, a file, folder, or registry key).  ACEs are individual entries in ACLs and determine how a particular user  or group can access an object.

**Access Control Lists (ACL)**

A user's ability to  access an object (for example, a file, folder, or registry key) is  controlled by access control lists (ACL). An ACL lists the users and  groups that have permission to access the object. Each entry is called  an access control entry (ACE) and determines how a particular user or  group can access the object.

Users and groups are also subject to group policies controlled by Group Policy Objects (GPO).  These policies determine what a user or group can access and what  actions they can take.

**Group Policies**

Windows also controls  authorization through Group Policy objects (GPO). GPOs are used in  Active Directory environments and are used to manage the settings of  multiple users or computers from a central location.

To define access rights  to a folder or file on Windows, right-click on the relevant object and  open the properties section. On the screen that opens, open the Security tab. 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/2/image6-1.png)

By clicking the “Edit” button, you can edit the new user and the access rights for this user.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/2/image6-2.png)

Details regarding authorization are given in the table below.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/2/w-table.png)

These permissions can be  granted individually or in combination for various users or groups.  Additionally, subfolders and files can inherit the permissions of parent folders or have their own unique permission sets. This means that the  security model can be flexible but also complex, so careful planning is  important.

### Conclusion/Summary

In a nutshell, Windows  authentication and authorization policies are used to verify who a user  is and control what they can access. These policies are vital to keeping a Windows system safe and organized.  

In this part of the  training, we have covered the authentication and authorization processes on Windows, and we will learn about the “Windows Update and Patch Management” topic in the next part of our training.

### Question

1 - What access authority does the “letsdefend” user have over the C:\testexc folder on the system you access?

> **Answer:** Read

2 - Can the “letsdefend” user read the “C:\Users\socadmin\Documents\readme.txt” file on the system you access?  

Answer Format: Y/N

> **Answer:** Y

## Update and Patch Management

Windows Update and Patch  Management plays a vital role in ensuring the security of computer  systems and networks. Patch management means fixing bugs,  vulnerabilities, and other problems found in a particular version of an  operating system or software. The Windows operating system uses the  Windows Update service, especially for security fixes and improvements  that are regularly released by Microsoft.

Windows Update allows  systems to automatically download and install the latest updates and  patches. This helps keep the operating system and Microsoft software  secure and up-to-date. However, simply enabling automatic updates may  not always be enough. It is also important to understand the potential  impacts that a particular update or patch may have on a system or  application.

In addition, regularly  updating and patching operating systems and applications is also an  important task for information technology (IT) departments and system  administrators. A patch management strategy ensures that systems and  networks remain secure by closing potential vulnerabilities.

Patch management also  includes proper testing and implementation of each patch. Each patch,  especially on a large-scale network, must be carefully applied through a predetermined process. This process usually includes the steps of  applying, testing, and deploying a patch.

For all these reasons,  Windows Update and Patch Management is an important task for every  Windows user and system administrator. Effective management of this  process ensures that a system or network remains secure and performs at  its peak.

### Update and Patch Management in Large Organizations

Update and patch  management is usually performed using a centralized approach. This makes it easier to manage large numbers of computers and servers and keep  them updated. Here's an overview of how Windows Update and Patch  Management is done in large organizations:

**Centralized Patch Management**

Large organizations often use centralized patch management solutions. These solutions ensure that all systems receive the latest updates and patches. For example,  solutions such as Microsoft's Windows Server Update Services (WSUS) or  Microsoft Endpoint Configuration Manager (MECM) software management  suites that are natively used for this purpose on the Windows Operating  systems.  

**Patch Testing**

It is very important that each patch is properly tested. This is done to check a patch's  application compatibility, identify possible bugs, and evaluate overall  performance. The testing process ensures that the patch works properly  before it is deployed to live systems.

**Patch Distribution**

Once patch testing is  completed, patches are typically distributed on a predetermined  schedule. This process usually involves choosing a time that will  minimally impact the organization's workflow. Deployment is typically  done automatically using a patch management solution.

**Patch Tracking and Reporting**

The final phase of patch  management typically involves tracking and reporting the effectiveness  of patch deployment. This includes identifying which systems have been  updated, which patches have been successfully installed, and any  potential problems.

**Emergency Patch Management**

Some security  vulnerabilities and bugs can cause serious problems if not fixed. For  such situations, organizations should have emergency patch management  processes. This process typically involves rapid testing, approval, and  deployment of a patch.

These steps provide an  overview of Windows Update and Patch Management in a large organization. Every organization must create a strategy that best meets its specific  needs and workflow.

### Windows Update Operation Specific to the System

You can also perform  Windows updates within each system. Of course, this operation will be  more laborious, but in some organizations, when there is no central  management, the update operation can be done this way.

Open Windows Settings  -> Update & Security section and click on “Windows Update”. The  current update statuses and new updates, if any, are displayed on the  screen that opens. If you wish, you can install these updates by  clicking “Install Now”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/3/image7-1.png)

You can set the time  periods in which the update process should be active with the “Change  active hours” option on the relevant screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/3/image7-2.png)

You can edit the update  options in the “Advanced Options” section. Here you can enable/disable  options such as automatic downloading of updates, update notifications,  update pausing. 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/3/image7-3.png)

The “Delivery  Optimization” option (WUDO) is a feature included in Windows 10 and  later versions. This feature helps download large files for the Windows  updates from Microsoft Store faster and more reliably. Additionally,  this technology aims to reduce network traffic and bandwidth usage.

Options;

**Computers on the local network only:** Updates are shared only among other Windows computers on your local network (LAN).

**Computers over the Internet:** Updates are also shared  with other Windows computers over the internet. This option can reduce bandwidth usage but may affect your internet quota.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/3/image7-4.png)

When we come to the  "Advanced options" section on the "Delivery Optimization" screen, we can set download and upload limits from this section.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/3/image7-5.png)

### Conclusion/Summary

Updating the operating  system or other software to the latest and more secure versions plays a  critical role in ensuring the security of Windows operating systems and  other software. Since new vulnerabilities are constantly discovered,  keeping the operating system and applications updated is the first line  of defense against potential cyber attacks and malware, especially  against the “Zero HourVulnerabilities”. Features such as Windows Update  Delivery Optimization (WUDO) ensure that updates are delivered quickly  and efficiently, improving overall system security. In this way, users  and organizations become more resilient to security risks and proactive  protection is provided against cyber security threats.

In this part of the  training, we have covered the update and patch management and how to  perform these critical tasks in Windows operating systems. The next part of the training will be about “Antivirus, Malware and Threat Protection” topic.

### Question

1 - What is the feature in Windows 10 and later versions that helps download updates faster and more reliably?

> **Answer:** Delivery Optimization

2 - Which service provides regular security fixes and improvements for the Windows operating system?

> **Answer:** Windows Update

## Antivirus, Malware and Threat Protection

Computer security has  become one of the top priorities in this technological era. With  constantly developing technology, malware and cyber threats have become  increasingly complex which automatically come with a critical task of  protecting computers, servers, and the users with Windows operating  system from malware, viruses and other threats.

The Windows operating  system has a number of built-in tools and features to help users deal  with these threats such as Antivirus, Malware and Threat Protection  tools. These tools refer to a set of prevention, detection and response  mechanisms that help protect your computer and data from a variety of  threats.

Windows Defender, Windows' built-in antivirus software that helps prevent malware,  viruses, and other threats from infecting the computer. Because new  threats emerge rapidly, it is important to ensure that Windows Defender  is regularly updated and includes new threat identifications.

Additionally, Windows  users can also use Windows Firewall that provides additional protection  against threats coming over the internet. A firewall monitors all  internet traffic directed to your computer and blocks potentially  harmful or unwanted traffic.

Malware, viruses and  other cyber threats are designed to steal users' personal and financial  information, damage systems or disrupt operations. Therefore,  effectively using Windows' Antivirus, Malware and Threat Protection  features ensures that your computers and data remain safe from these  threats. This is vital for both individual users and corporate users.

**NOTE:** Some 3rd party endpoint security solutions may need to work by disabling Windows Defender.

### Windows Defender

Windows Defender in  Windows systems by default. You can see it in the "Features" section on  the Server Manager screen on the Windows Servers.

There is no central  management for this Defender version that comes by default. Microsoft  has “Defender for Endpoint Plan” for such additional features and you  can take a look at these plans.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/4/image8-1.png)

You can access Defender-related settings by clicking “Virus & Threat Protection” on the “Windows Security” screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/4/image8-2.png)

On this screen, you can  see the “Virus & Threat Protection” summaries. You can see many  critical information such as when the last scan was performed, how many  threats were detected, how many files were scanned, and how long the  scan took, and etc.

You can choose which protection modules will work or not from the “Virus & Threat protection settings” menu.

You can manually check for updates from the “Virus & Threat protection updates” menu.

You can determine which files/directories will be protected from ransomware attacks from the “Ransomware Protection” menu.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/4/image8-3.png)

“Virus & Threat  Protection Settings” menu will show you what you can do on the  protection modules and how you can protect your system.

Real-Time Protection  continuously scans files, programs and system activities running on your computer. If any threat is detected, this feature can instantly  quarantine or delete the threat. In this way, it can be prevented from  the malicious software damaging your system. Real-time protection is  often a very important feature for system security and is usually  enabled by default.

Cloud-Delivered  Protection creates a connection between Microsoft's cloud-based  analytics engines and the local Windows Defender client. In this way,  faster and more comprehensive protection is provided against new and not yet identified threats. Unknown files can be sent to Microsoft's  cloud-based service for analysis and threat identification. This feature further strengthens real-time protection.

Automatic Sample  Submission allows Windows Defender to send anonymous samples of files it deems potentially harmful to Microsoft. This helps Microsoft identify  new threats more quickly and improve protection measures. This feature  provides more effective protection in combination with cloud-delivered  protection, but some users and organizations may choose to disable this  feature due to privacy concerns.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/4/image8-4.png)

“Ransomware Protection”  module is disabled by default. When you activate this module, it  provides special protection against threats that may be caused by  ransomware. Ransomware often encrypts user files and demands a ransom.  This module aims to prevent such harmful activities.

### Main Features

**Controlled Folder Access**

This feature allows files in certain folders to be modified only by trusted applications. This  way, any suspicious or malicious application is blocked when it tries to access the folder contents.

**OneDrive Integration for File Recovery**

Thanks to the integration with Microsoft OneDrive, encrypted files can be easily recovered If you accidentally delete a file or folder in OneDrive.

### How does it work?

When the Controlled  Folder Access feature is enabled, certain folders and files on the  system become accessible only to applications deemed trusted by the  system. When an application tries to make changes to these folders,  Windows Defender evaluates the request. If the application is not in a  trusted application list, access is blocked and a notification is sent  to the user.

### How to Activate?

- Open Windows Security App.  
- Go to the Virus & Threat Protection menu.  
- Under Manage Settings, find Ransomware Protection and turn it on.  
- Enable Controlled Folder Access.  

### Suggestions

Usually, folders where user files are stored, such as "Documents", "Pictures", "Videos", are  protected by this, but users can also add additional folders.

If a trusted application is having trouble accessing it, it is possible to manually add it to the list of trusted applications.

Ransomware Protection is  part of the overall Windows Defender security suite and is recommended  to be used in conjunction with other security settings for best  performance.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/4/image8-5.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/4/image8-6.png)

### Conclusion/Summary

In summary, Windows  Defender is a comprehensive security software that works integrated with Windows operating systems. Thanks to its real-time protection feature,  it provides effective defense against viruses, ransomware, spyware and  other threats. Its high compatibility and deep integration with the  system offer fast and reliable protection without the need to install  additional software or complex settings.

Features such as  cloud-based protection and automatic sample submission provide  up-to-date and effective protection against the latest threats. Its  user-friendly interface makes it easy to use without requiring any  technical skills. With extra modules such as ransomware protection, it  also protects your critical data against specific threats.

In short, Windows  Defender stands out as a user-friendly, compatible and up-to-date  security solution for systems running on the Windows operating system.   

In this part of the training, we have covered the Windows Defender and its features. We will learn abou the "Windows Log Infrastructure" in the next part of our training.

### Question

1 - Which directory is excluded in “Windows Defender” on the system you access?

> **Answer:** C:\testexc

2 - What is the name of the module that protects protected objects by  accessing files/directories specified by Microsoft Defender only by  secure applications determined by the system?

> **Answer:** Ransomware Protection

## Windows Log Infrastructure

In the world of  cybersecurity, recording and tracking events is a fundamental part of  the strategy for responding to incidents and protecting against  potential threats. Windows Log Engine is an essential tool for any IT  professional managing a Windows system.

The Windows Log Engine  allows monitoring and recording many different activities of a Windows  machine. These activities can range widely, from system and application  errors to security incidents, network activity, and even specific user  activities.

Windows Log Engine is  generally divided into the following three main categories: Application  Logs, Security Logs and System Logs.

**Application Logs**

These logs monitor and  record the activities of applications running on a system. This is  especially useful for detecting errors and app crashes.

**Security Logs**

Security logs record  successful and unsuccessful login attempts, file and folder access, and  other security-related events. This is vital for monitoring unauthorized activity on a system and detecting potential security breaches.

**System Logs**

System logs record  system-level events, errors, and warnings. This is important to monitor  the overall health and performance of the operating system.

These logs enable IT  professionals to effectively monitor a system, detect potential problems and find solutions. Moreover, many regulatory bodies and industry  standards require appropriate logging and review infrastructure, further increasing the importance of Windows Log Engine.

### Windows Log Engine Components

**Event Log Service**

This service collects and stores events generated by the Windows operating system and  applications running on it. This service also runs logs of events and  triggers them when necessary.

**Event Viewer**

Event Viewer provides  system administrators and users with the ability to view and analyze  event logs. It also provides the ability to trigger specific events and  view more detailed information about events.

**Windows Logs**

Windows Logs stores  information about a number of categories such as application, security,  setup, system events, and also some events related to the future. This  is used to detect errors, monitor security threats, and analyze system  performance.

**Applications and Services Logs**

This stores more detailed information about events of applications, services, and other Windows  components. This information is used to detect errors with a particular  application or service.

**Subscriptions**

Subscriptions allow a  system administrator to collect events from one or more remote  computers. This is especially useful in situations where there is a need to monitor events on a large number of systems in large networks.

These components work  together to enable events on a Windows system to be monitored, recorded, analyzed and notified when necessary. This provides Windows with the  ability to monitor and manage the performance and security of the  operating system, applications, and services.

### Logging Policy

There are some critical points that need to be taken into consideration in order to use the  Windows log infrastructure effectively in terms of system security.  These critical points are not just the ones mentioned below, but they  are indispensable:

**Setting Log Levels Correctly**

Log levels determine the  types of events to be logged. For example, logs at the "Error" level  usually indicate critical problems, while logs at the "Information"  level record more general events. Logging at the wrong levels can lead  to either collecting too much unnecessary information or missing  critical information. For security-related events, for example, it is  critical to record events such as successful and unsuccessful login  attempts, privilege changes, and system access attempts.

**Sufficient Disk Space Should Be Allocated**

Log files can grow rapidly over time, especially on high-traffic or critical systems.  Insufficient disk space may result in failure to save new logs or loss  of existing data. As a recommendation, it is useful to create a separate disk partition for log files or set a certain disk size limit.  Additionally, alerts should be generated when disk usage exceeds a  certain threshold.

**Archiving Old Logs**

Old log files can be  valuable for future audits or incident investigations. However, these  files take up a lot of space. It is recommended that old log files be  archived regularly in a compressed format and stored in an easily  accessible location when needed. This setting can be made by  right-clicking on the relevant log source and clicking on the  "Properties" screen.

**Tightening Access Controls**

Log files often contain  sensitive information and unauthorized access can lead to a security  breach. Therefore log files should be stored on a file server and  allowed access only to authorized users (for example, system  administrators and security analysts). Mechanisms such as ACL (Access  Control List) or RBAC (Role Based Access Control) can be used to control the access.

**Using Central Log Management**

Multiple systems and  applications can create different log files, making analysis and  monitoring difficult. For example, by using centralized log management  systems such as SIEM (Security Information and Event Management), you  can collect logs in a single location and analyze these events more  quickly and create correlations.

**Creating Automatic Alerts**

Certain security  incidents may require rapid response. Create automatic alert mechanisms  for Event IDs where critical events are logged. For example, for cases  where a firewall rule has been violated or the administrator account has been used in a suspicious manner. You can easily do this by creating  use-cases with SIEM.

**Conducting Regular Reviews**

Automated systems may not be able to detect all anomalies. Review log files at regular intervals  (weekly, monthly, etc.). Suspicious activities should be identified by  performing time series and pattern analysis and action should be taken  if necessary.

### Critical Logs for Security Violations

As mentioned in the  introduction, logs are created for different needs as well as security.  Among these logs, there are some logs that are indispensable for  detecting security violations. In Windows, these logs are:

### Security Logs

Security logs provide  information about activities from an organization's network, systems and endpoints. These events may include user activities, network traffic,  access control logs, and error logs. Security logs are important for  detecting and responding to the first signs of a security breach.

Security logs are useful in detecting security breaches in the following ways:

**Identifying abnormal activity**

Security logs can be used to identify abnormal or unexpected activity. For example, if a user  enters multiple incorrect passwords or a network connection suddenly  drops, it could be a sign of a security breach.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/5/image9-1.png)

**Correlating threats**

Security logs can be used to correlate different threats. For example, if a user downloads a  malicious file and then initiates a network connection, it may be sign  of a security breach.

**Analyzing threats**

Security logs can be used to better understand threats. For example, it is possible to analyze  security logs to determine the techniques and methods used by an  attacker.

Security logs are an  important tool for detecting the first signs of a security breach.  However, they need to be examined and reviewed carefully to be used  effectively. It is important to remember that security logs can contain  large amounts of data and this data can be difficult to analyze  manually. Therefore, it is always useful to utilize automated tools to  analyze security logs.

### Powershell Logs

PowerShell logs in  Windows Eventlog record events that occur during the execution of  PowerShell commands and scripts. These logs can be very useful for  detecting security breaches because PowerShell is frequently used for  automation, configuration, and even cyber attacks. Here are the benefits of these logs:

**Command & Script Execution Logs**

These logs show in detail which PowerShell commands were executed. If an unauthorized user or  malicious software tries to make changes to the system, this can be  detected through executed commands and scripts.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/5/image9-2.png)

**User Authentication**

PowerShell logs also  contain information about who executed the commands. In this way, the  activities of an unauthorized or suspicious users can be quickly  detected.

**Module Installations**

Installed PowerShell  modules and added snap-ins can be tracked through these logs. This can  help determine if a malicious module has been loaded.

**Remote Execution**

PowerShell's remote  execution capabilities are monitored through logs. If an unauthorized  user is running PowerShell commands remotely, this can be detected  through the logs.

**Detailed Parameter and Output Information**

Some PowerShell logs also record the parameters and output of executed commands. This may provide clues as to what type of information was leaked or what type of  activity was carried out.

As a result, PowerShell  logs provide valuable information to understand whether a security  breach has occurred. However, these logs are only useful when enabled,  so review your security policies to ensure this type of logging is  enabled.

### Terminal Services Remote Connection Manager Logs

Terminal Services Remote  Connection Manager logs provide critical information specifically about  how Remote Desktop Services (formerly knows as Terminal Services) is  used. These logs can be used in many ways to detect security breaches  and manage potential risks. Here are some important benefits these logs  can provide:

**Unauthorized Access Attempts**

These logs provide  information about who attempted to connect remotely, when and from  where. If there is an unauthorized or unexpected connection attempt,  this will be noticed immediately.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security-2/5/image9-3.png)

**IP Address and User Authentication**

Logs also record the IP  addresses of users trying to connect remotely. This information can be  used to detect connection attempts from an unauthorized or suspicious IP address.

**Connection Status and Errors**

Events such as successful and unsuccessful connection attempts, connection or disconnection  errors are included in the logs. This is especially important if an  unauthorized person is trying to connect.

**Configuration Changes**

Terminal Services Remote  Connection Manager logs also show whether there have been any changes to the Remote Desktop Services configuration on the system. This can be  very important if an attacker tries to manipulate the system.

**Detailed Session Information**

Logs can also provide  information about how long users stayed connected, which applications  they used, and what types of actions they performed. This can be useful  to understand what an attacker is using the system for.

This information is  invaluable for detecting security breaches or suspicious activity at an  early stage, especially when reviewed regularly. However, such logs need to be effectively monitored and managed. Inadequate log management can  lead to critical information being missed or false positives occurring.

### Conclusion/Summary

Recording and monitoring events are of critical importance in terms of cybersecurity. Windows Log Engine offers a comprehensive system to meet this need. This  infrastructure enables IT professionals to effectively monitor systems,  detect potential problems and take appropriate interventions. Correctly  setting log levels, allocating sufficient disk space, archiving old  logs, tightening access controls, central log management, automatic  alerts and regular reviews are critical points to be considered in terms of system security. Security Logs, in particular, are very critical in  terms of unauthorized access or other potential security breaches.

In this part of the  training, we have covered the log infrastructure in Windows, its  components, importance, some major logging policies as well as major  critical logs.

### Question

1 - In which section of the event log are records of successful login or unsuccessful login attempts on Windows systems stored?

> **Answer:** Security





























































