# Windows System Security

The  "Windows System Security" course is a comprehensive program that equips  participants with the knowledge and skills needed to protect  Windows-based systems. Through in-depth exploration of threat detection, security configurations, and risk mitigation strategies, this course  empowers individuals to secure their systems effectively. Whether you're a Windows user looking to enhance your personal cybersecurity or an IT  professional responsible for managing corporate systems, this course  provides practical insights and actionable techniques to strengthen the  security of Windows-based environments, ensuring data integrity and  peace of mind in today's digital age.

**Table of Contents:**

- [Windows System Security Fundamentals](#windows-system-security-fundamentals)
- [User and Group Management](#user-and-group-management)
- [Active Directory Security - 1](#active-directory-security---1)
- [Active Directory Security - 2](#active-directory-security---2)
- [Windows DNS Security](#windows-dns-security)
- [Windows DHCP Security](#windows-dhcp-security)

Evaluate Yourself with Quiz

- [Windows System Security](https://app.letsdefend.io/training/quiz/windows-system-security)

## Windows System Security Fundamentals

Businesses and  individuals are increasingly reliant on platforms and operating systems  to process, store and access their data. However, this dependence brings with it the need to significantly increase the security of systems.

Windows Operating system  is one of the platforms that is widely used and system security is the cornerstone of its information security. Data breaches and cyber attacks are an increasingly significant threat to businesses across all  industries. These threats may result in financial losses, disruptions in business processes, data losses and reputational losses.

The security of a Windows system ensures the protection of data and processes, which keeps  private and sensitive information of individuals and organizations safe. A secure system prevents service disruptions and protects users against cybercrime. In addition, secure Windows systems ensure that businesses  offer a secure digital environment to their customers and employees.

Windows system security  is ensured by the combination of a number of components and services.  Each of these components plays an important role in improving the  security of systems and data. Windows system security basically consists of the following topics:

- User and Group Management  
- Active Directory Security  
- Windows DNS Security  
- Windows DHCP Security  
- Windows Local Security Policy, Group Policy, and UAC  
- Authentication and Authorization on Windows  
- Windows Update and Patch Management  
- Antivirus, Malware and Threat Protection  
- Windows Log Engine  

In this part of the  training, we have made a general introduction to Windows system  security. We will start our training with the “**User and Group Management**” topic next.

## User and Group Management

Windows user and group  management plays a critical role in keeping Windows systems running  securely and efficiently. This lesson will help you understand how both  Administrator and Standard user accounts work, how they are managed, and how the privileges can be assigned. You will also learn how the group  management can collectively manage the privileges of multiple users.

### User Accounts and Management

A user account is an  identity defined in Windows for a person or service. Each user account  is typically associated with a username and password.

**Administrator Accounts**

These accounts provide  full access to all system resources and settings. Administrator accounts also have the ability to create, modify, or delete other user accounts.

**Standard User Accounts**

These accounts provide  users with the ability to run certain programs and manage personal files and settings. However, the ability to change system-wide settings is  often limited.

For user management in Windows Server;

The Start -> Computer Management -> Local Users and Groups -> Users screen opens:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/2/image2-1.png)

The main default users that come with Windows Server are as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/2/img1.png)

To create a new local  user, right-click on the Users screen, select "New User", type the user  information and click the "Create" button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/2/image2-2.png)

We can delete a user  account from the system by right-clicking on the user account on the  same screen and clicking the "Delete" button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/2/image2-3.png)

So far, we have covered  topics like the user management screen on Windows Server, the default  users and the features of these users, and how operations such as  creating and deleting users.

Below are important points to be considered regarding "User Accounts and Management" in terms of Windows system security:

### User Permissions and Authorizations

**Principle of Least Privilege**

Give users only as much authority as necessary which is to create the lowest level of privileges for users.

**Limit Administrator Accounts**

Administrator accounts should be used in limited numbers and only when necessary.

### Password Policies

**Strong Password Rules**

It must contain at least 12 characters, letters, numbers and special characters.

**Mandatory Password Change**

Users must change their passwords periodically.

**Two-Factor Authentication (2FA)**

Evaluate the usability of 2FA and enable it if possible. This creates an extra layer of security  in case a password is compromised.

**User Account Control (UAC)**

Enable UAC features so programs and applications can only gain elevated privileges with administrator approval.

**Session Timeouts and Screen Locks**

Enable automatic timeout  and screen lock features, so their systems are protected when users  physically move away from the keyboard.

**Account Control and Monitoring**

Enable auditing of user accounts and access. Review logs regularly to identify abnormal or suspicious activity.

These precautions are  critical to the security of Windows systems. A good user account  management practice plays a crucial role in improving system security.

### Groups and Management

A group is a collection of one or more users. Groups make it easier to manage users and system resources.

**Local Groups**

Groups defined on a computer. Local groups are used to manage resources on a specific computer.

**Domain Groups**

Domain groups are used to manage resources across multiple computers on the network.  

Group members can have  certain privileges through group policies. Adding or removing a user  from a group is an easy way to quickly change a user's privileges.

The Start -> Computer Management -> Local Users and Groups -> Groups screen opens:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/2/image2-4.png)

The default local groups that come with Windows Server are as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/2/img2.png)

The default groups that come with the Windows Server Active Directory role are as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/2/tt1.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/2/tt2.png)

Below are important points to be considered regarding "Groups and Management" in terms of Windows system security:

**Group Types and Usage**

It is important to  determine the types of groups. Windows offers different types of groups  such as local, global, and universal. Understanding which type to use  and when can improve safety.

**Group Access Controls**

Group permissions: Set  the access permissions to be assigned to groups according to the least  privilege principle. For example, when granting Read and Write Access,  carefully determine who gets read and write permissions.

### User-Group Relationship

**Adding/Removing Users**

Establish an effective management process to add or remove users from groups as needed.

**User Reports**

Review group memberships regularly, check members of each group and keep them up-to-date.

### Group Control and Monitoring

**Group Logs**

Review logs regularly for group changes, access requests, and other events.

**Regular Review**

Group permissions and memberships should be reviewed at regular intervals.

### Group Backup and Recovery

**Group Backups**

Regularly backup configuration settings, especially for important and critical groups.

While these topics are  important for the security of the group and its members, they are also  critical for the overall system security. When groups are managed  effectively, this often contributes to a broader understanding of system security.

In this part of the  training, we have covered the management of user and group accounts, and its importance from the Windows System Security aspect. We will learn  about the “Active Directory Security-1" in the next part of our training.

### Questions

1 - What is the username added to the "Domain Admins" group on the system you access? 

> **Answer:** Administrator

2 - How many different groups is the "socadmin" user a member of on the system you access?

> **Answer:** 3

## Active Directory Security - 1

Active Directory (AD) is a directory service developed by Microsoft and used in Windows-based  network environments. AD enables centralized management of user  accounts, groups, resources, and other network devices. This centralized structure helps ensure network security and data integrity while  facilitating users' authentication, authorization processes and access  to resources. Active Directory is a critical component that offers  organizations efficiency, security and ease of management.

The importance and common usage areas of Active Directory are as follows:

**Centralized Identity Management**

Active Directory manages  user accounts and credentials centrally. In this way, users can access  multiple resources on the network with a single identity. Secure  identity management is ensured by centrally managing user accounts,  implementing password policies and facilitating authorization processes.

**Centralized Management of Resources**

Active Directory provides centralized management of resources on the network. These resources may include user accounts, groups, shared folders, printers, servers, and  other network devices. Centralized management of resources facilitates  regular configuration and updating of resources and control of access  rights.

**Security and Access Control**

Active Directory helps  enforce security policies on the network. Thanks to authorization and  access control mechanisms, users' access levels to certain resources are controlled. This prevents unauthorized access to sensitive data and  increases data security.

**Group Policies**

One of the most important features of Active Directory is Group Policies. Group Policies are used to centrally manage configuration settings of users and computers.  These policies include security settings, desktop settings, application  settings, and more. Group Policies provide consistency across the  network and make management easier.

**Business Continuity and Recovery**

Active Directory plays an important role in ensuring business continuity of organizations. In  case of data loss or system failures, it is possible to quickly restore  systems using Active Directory's backup and restore mechanisms. This  minimizes data loss and allows organizations to continue operating  without interruption.

**Compliance and Audit**

Many industry standards  and regulatory requirements encourage organizations to comply with the  auditing capabilities and security features that Active Directory  provides. Active Directory facilitates compliance requirements by  providing audit trails and tracking mechanisms.

Active Directory is a  critical component that increases the efficiency of organizations,  ensures security and facilitates management. Therefore, many  organizations actively use and care about Active Directory.

Domain, Organizational  Units (OU), Groups and Objects are some of the major topics that we must know before starting Active Directory security:

**Domain**

Domain is used as the  basic management unit of a network. User accounts, groups, computer  accounts and other objects are located in the domain that provides  common authentication and access control.

**Organizational Unit (OU)**

Organizational Unit (OU)  is used to group and manage objects within the domain in a more  organized manner. OUs are used for administration, access control, and  Group Policy enforcement.

**Groups**

Groups are used to  logically group users or computers together. Grouping users by similar  features or functions makes it easier to manage access rights and  permissions.

**Objects**

Basic elements in Active  Directory. Users, computers, printers, groups, OUs, and other objects  form the building blocks of the database in Active Directory.

These concepts describe  the basic components and structures of Active Directory. Domain provides centralized management of objects and structures and facilitates  organization in large networks.

So far, we have talked  about the importance of Active Directory, common usage examples and  basic things to know about it. Active Directory Security is not just  about these topics. Now, let's start talking about "Active Directory  Security", and what important points should be considered about it and  what precautions should be taken to ensure its security. In addition to  these measures, Active Directory Hardening is also recommended.

### Use of Default Accounts

"Default Accounts" are  accounts that are pre-created by the operating system or applications  and usually have a unique username and password. These accounts are  created automatically when you install or configure the system or  applications. For example, "Administrator" or "Guest" accounts created  by the Windows operating system fall into this category. However, the  use of these default accounts is generally dangerous in terms of  security.

Default accounts often  come with basic security settings and may use frequently used passwords  or weak security policies. Therefore, using these accounts can create a  point that attackers can easily access. Attackers may know the weak  security settings and names of default accounts. Attempts to infiltrate  systems and attacks can be carried out by targeting these accounts.  Because default accounts can often be used across multiple systems or  applications, it can be difficult to monitor and audit the activities of these accounts. If default accounts continue to be used, these accounts may provide ongoing access permissions even if they are no longer  needed. This increases unnecessary risks.

As a result, instead of  using default accounts, it is a safer approach to create special and  need-based accounts and protect these accounts with security measures as necessary. Access permissions of default accounts should be reviewed  regularly and unnecessary ones should be disabled or deleted.

### Use of Authorized Groups

Other privileged group  members such as Domain Admins and Enterprise Admins are very powerful.  They can access the entire domain, all systems, all data, computers,  laptops and similar resources.

It is recommended that  ordinary user accounts not be in these authorized groups, the only  exception should be the default domain admin account. What attackers are looking for is to access accounts belonging to domain administrators.

Microsoft recommends that you temporarily add the account to the Domain Admins group when Domain  Admin access is required. Once the process is completed, the account  should be removed from the Domain Admins group.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/3/image3-1.png)

### Using Multiple Accounts (Normal User and Administrator Account)

One of the cornerstones  of computer security is distinguishing between a regular user account  used for day-to-day tasks and a separate administrator account used for  administrative tasks. This approach involves custom configuring and  security measures for both accounts to suit their needs.

**Why Should We Use Multiple Accounts?**

**Separation of Privileges**

A regular user account  has limited permissions while the administrator account has higher  privileges. This prevents day-to-day business from interfering with  administrative tasks.

**Limiting Attacks**

If daily tasks and  administrative operations are done with the same account, malware or  attackers can also access administrator privileges when they take over a regular user account.

**Data and System Security**

Using different accounts  for different roles and using the administrator account only when  necessary and on a private computer increases data and system security.

### How to use?

**Regular User Account**

A normal user account is  used for routine activities such as daily tasks, internet browsing, and  email checking. This account has limited permissions, reducing potential risks.

**Administrator Account**

This is an administrator  account that is used only for special operations such as administrative  tasks, system configuration, and software installation. This account has high privileges and it is important to keep it secure.

As a result, using  multiple accounts for different roles increases computer security by  ensuring separation of transactions. This approach minimizes risks and  provides better protection against attacks. Note that the account used  for administrative tasks should be kept particularly secure.

### Creating an Audit Policy

Audit policy settings are an important security measure used to monitor, control and record  events on a network. These policies are used to increase the  cybersecurity of an organization and detect unwanted activity. Enabling  auditing policies through Group Policy is a critical step in detecting  vulnerabilities and defending against cyber attacks.

Make sure that the Audit  Policy settings mentioned below are configured in group policy and  applied to all computers and servers.

For audit policy settings;

The “Computer  Configuration -> Policies -> Windows Settings -> Security  Settings -> Advanced Audit Policy Configuration” section opens:

**Account Logon**

- Ensure 'Audit Credential Validation' is set to 'Success and Failure'

**Account Management**

- Audit 'Application Group Management' is set to 'Success and Failure'
- Audit 'Computer Account Management' is set to 'Success and Failure'
- Audit 'Other Account Management Events' is set to 'Success and Failure'
- Audit 'Security Group Management' is set to 'Success and Failure'
- Audit 'User Account Management' is set to 'Success and Failure'

**Detailed Tracking**

- Audit 'PNP Activity' is set to 'Success'
- Audit 'Process Creation' is set to 'Success'

**Logon/Logoff**

- Audit 'Account Lockout' is set to 'Success and Failure'
- Audit 'Group Membership' is set to 'Success'
- Audit 'Logoff' is set to 'Success'
- Audit 'Logon' is set to 'Success and Failure'
- Audit 'Other Logon/Logoff Events' is set to 'Success and Failure'
- Audit 'Special Logon' is set to 'Success'

**Object Access**

- Audit 'Removable Storage' is set to 'Success and Failure'

**Policy Change**

- Audit 'Audit Policy Change' is set to 'Success and Failure'
- Audit 'Authentication Policy Change' is set to 'Success'
- Audit 'Authorization Policy Change' is set to 'Success'

**Privilege Use**

- Audit 'Sensitive Privilege Use' is set to 'Success and Failure'

**System**

- Audit 'IPsec Driver' is set to 'Success and Failure'
- Audit' Other System Events' is set to 'Success and Failure'
- Audit 'Security State Change' is set to 'Success'
- Audit 'Security System Extension' is set to 'Success and Failure'
- Audit 'System Integrity is set to 'Success and Failure'

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/3/image3-2.png)

Suspicious activities  often start on end-user systems. You must monitor all systems constantly to be able to detect the security incidents immediately.

### Local Admin Account Management

Windows Local  Administrator Password Solution (Windows LAPS) is a method that enables  regular and automatic management of passwords of local admin accounts on workstations and servers. This solution provides a higher level of  security against cyber attacks by constantly updating the passwords of  local admin accounts.

### Why Should We Use Windows LAPS?

**Streamline Password Management**

Windows LAPS allows you  to centrally manage passwords for all local admin accounts. This  replaces manual password updates and hassle with an automatic and  regular password rotation.

**Improving Password Security**

Automatic password  changes and complex password policies increase password security. It  reduces the risk of using old or weak passwords for a long time.

**Preventing Attacks**

Strong and regularly  changing passwords for local admin accounts reduce the risk of malicious attackers taking over these accounts.

### Benefits and Best Practices

**Automatic Password Rotation**

Regular automatic change of local admin passwords.

**Strong Password Policies**

Use of strong passwords with complex password requirements and length limitations.

**Historical Password Records**

Storing old password records and preventing the use of past passwords.

**Password Logs**

Logging of password changes and updates.

In summary, Windows LAPS  is an important security step that ensures safe and automatic management of local admin accounts. Thanks to password rotation, automatic updates and strong password policies, it increases resistance to cyber attacks, simplifies management and reduces workload.

### Creating a Password Policy

Creating a password  policy in Active Directory is an important step to minimize security  vulnerabilities and increase account security. A password policy  contains rules and restrictions that determine how users' passwords are  created, how complex they must be, and how long they must be changed.

### Why Should We Create a Password Policy?

**Require Strong Passwords**

The password policy  allows users to use strong and hard-to-guess passwords. This makes  accounts more resistant to malicious attacks.

**Increase Complexity**

Password policy enforces  the use of complex passwords that contain different elements such as  lowercase letters, uppercase letters, numbers, and symbols.

**Regular Password Change**

The policy may require that passwords be changed periodically. This prevents the use of old or weak passwords.

**Active Directory Password Policy Creation Steps**

- Open Active Directory Administration Tools and select Group Policy Management.  
- To Manage Passwords, go to Password Policies.  
- Create a new password policy and name it.  
- Specify the level of  complexity you require in the password policy. For example, the use of  uppercase letters, lowercase letters, numbers and symbols.  
- Specify time period  that the password will be valid. The password will then get disabled and the user will need an administrator help get it enabled back again.  This ensures that the password is changed regularly.  
- Specify the minimum number of times users must remember their previous passwords. This prevents old passwords from being reused.  
- Set time limits or lockout of accounts as a result of attempts to enter incorrect passwords.  

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/3/image3-3.png)

As a result, creating a  password policy is a critical step in improving Active Directory  security and ensuring your accounts are more resilient to cyber attacks. Enforcing strong, complex passwords and regular password changes  reduces risks while increasing security. By creating the right policies, you can enable users to manage their accounts more securely.

In this part of the  training, we have covered the Active Directory, its importance,  security, and the usage areas. We will keep learning about the "Active Directory Security-2" topic in the next chapter.

### Questions

1 - What are users, computers and printers called in Active Directory?

> **Answer:** Object

2 - What does "OU" mean in Active Directory?

> **Answer:** Organizational Unit

3 - What is the Microsoft solution that automatically manages the passwords of local admin accounts?

> **Answer:** Windows LAPS

## Active Directory Security - 2

### Creating a Lockout Policy

Lockout policy is an  important security measure that locks accounts and prevents access for a certain period of time as a result of specified number of incorrect  password attempts. This policy is used to protect against cyber attacks  and account security threats. Here are detailed explanations about the  importance of the Lockout Policy:

**Protection Against Brute Force Attacks**

Brute force attacks are  attempts by attackers to take over accounts by quickly and continuously  trying different password combinations. The lockout policy protects  against such attacks by ensuring that accounts are locked after a  certain number of incorrect password attempts.

**Protection Against Pass-the-Hash Attacks**

Pass-the-hash attacks are attacks where attackers gain unauthorized access to accounts by  obtaining password hashes. The lockout policy reduces the impact of such attacks because attackers face more difficult obstacles when there are a limited number of attempts.

**Increase Account Security**

Lockout policy increases  account security because if account owners forget or lose their  passwords, the possibility of third parties hijacking the accounts by  making endless password attempts is reduced.

**Account Awareness**

If it is noticed that  accounts are constantly locked or blocked, it raises awareness that this may be a sign of a potential attack or security breach. In this way,  security threats can be detected at an early stage.

**Slowing Down Attackers:**

The lockout policy slows  down attackers' attempts to quickly take over accounts. To have the  accounts locked after a certain number of attempts by using the proper  measures is an effective way that avoid attackers easily take control of the systems.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/4/image3-4.png)

In conclusion, creating a Lockout Policy is an important step in increasing account security and  protecting against cyber attacks. A properly configured lockout policy  strengthens your security while protecting users' accounts.

### Secure Admin Workstation (SAW)

Secure Admin Workstation  (SAW), is a specialized computer system used only to perform  administrative tasks with privileged accounts. This approach is an  effective way to increase cybersecurity and minimize potential threats.  SAW ensures that administrator operations are secured and is an  important step towards maximizing security.

### The Importance of Secure Admin Workstation

The use of Secure Admin Station is of great importance for the following reasons:

**Isolated Environment for Privileged Operations**

SAW provides an isolated  environment where privileged accounts will be used only to perform  administrative tasks. This ensures that transactions and systems are  secured even if attackers take over accounts.

**Access Control**

SAW can be secured as it  is used only for administrative operations. This makes it difficult for  malware or attackers to access the system during ordinary user  operations.

**Reducing Cyber Threats**

Using SAW reduces the risk of downloading malware, getting infected with ransomware or malicious links.

### Secure Admin Workstation Features

The Secure Admin Station must have the following features:

**Isolated Environment**

SAW should be isolated from normal user operations and network traffic.

**No Internet Access**

SAW should not be used for tasks such as checking email or web browsing. Internet access should be blocked.

**Strong Authentication**

Access to SAW should only be possible with privileged accounts, and these accounts should be  protected with strong passwords or multi-factor authentication.

**Only Required Applications Should Be Installed**

Only applications  required for administrative operations should be installed in SAW.  Unnecessary software and applications should be removed.

**Keeping Up-to-Date**

The operating system and  applications in SAW should be updated regularly. Security updates and  patches should be applied regularly.

### Advantages of Secure Admin Workstation

Advantages of using Secure Admin Workstation for the organization:

**Better Security**

SAW increases cybersecurity by performing privileged operations in an isolated environment.

**Reduced Threat Risk**

The risk of malicious software or attacks reaching organizational systems is reduced.

**Control of Administrator Operations**

SAW allows you to  centrally control administrator operations, which is advantageous in  terms of authorization and access monitoring.

**Rapid Response**

Since only administrative operations are performed in SAW, any security incident can be quickly detected and responded to.

The use of SAW offers an  effective way to increase cybersecurity and reduce potential risks.  Performing privileged transactions in an isolated environment helps you  create a stronger defense against cyber attacks. Organizations should  consider the use of secure executive station as a serious security  measure.

### Operating System Support

With each new Windows  operating system release, Microsoft introduces built-in security  features and improvements. More importantly, you get security updates.  Operating systems that have come to end of life whose security updates  are not provided by the manufacturers anymore are one of the biggest  risks to organizational security.

Just using the latest operating system version will increase overall security.

For example, New Security Features in Windows Server 2022:

- Secured-core Server  
- Hardware root of trust  
- Firmware protection  
- UEFI secure boot  
- Virtualization based security  

### Management of Service Accounts

In the Active Directory  (AD) environment, service accounts are accounts used to ensure the  proper functioning of systems, applications and services. However, these accounts are security sensitive and can cause cybersecurity risks if  not managed properly. These accounts can often have high privileges and  lead to security weaknesses such as prolonged use of passwords or access rights.

How service accounts should be managed from a security perspective:

- A separate account  should be used for each service or application. This ensures isolation  and protects the security of other accounts when one account is  affected. Using a shared service account may increase security risk.  
- Giving service accounts only the minimum privileges they need prevents attackers from taking  advantage of their access rights. Each service account should only have  access to the resources and functions it requires.  
- Passwords for service  accounts should be changed regularly and comply with strong password  policies. Passwords should not always remain the same. Automation tools  and managed service accounts can be used for password management.  
- Service accounts should only be given access to the systems and resources they need. Network  access should not be expanded unnecessarily. Unnecessary network traffic should be blocked.  
- The activities of  service accounts should be regularly monitored and audited. Abnormal  activities must be detected and responded to quickly. Access records  should be reviewed regularly.  
- Systems and  applications containing service accounts must be kept up to date and  patched. Regular updates should be made to avoid being vulnerable to  security vulnerabilities.  

Service accounts  management stands out as a key element of Active Directory security.  When properly managed, service accounts can increase system security and provide a more effective defense against cyber attacks.

### Important User and Group Changes

In Active Directory  security, effective tracking of important user and group changes is  critical to ensuring network security and data integrity. Monitoring  these changes is necessary to detect unauthorized access attempts,  prevent security breaches, and meet compliance requirements.

Event logs of Active  Directory servers are used to track these changes. Transactions such as  account creation, deletion, password changes, and group memberships are  recorded in these logs. However, in large-scale networks, manually  monitoring these event logs can be difficult and time-consuming.  Therefore, using automation and monitoring tools can be an effective  solution. Security Information and Event Management (SIEM) systems  collect and analyze these events at a central point, identify abnormal  activities and send alerts to the security team.

Below are the basic events that need to be followed regarding users and groups.

**User Activities Table**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/4/win-table-1.png)

**Group Activities Table**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/4/win-table-2.png)

### Local Admin Group Membership Control

A user with local admin  rights has full access to the entire Windows Operating System and has  the ability to download and install software which may include malicious software as well, enable/disable accounts, disable security feature of  the system, access user information and steal credentials or data which  may lead to various security issues.

A standard user must not be in the local admin group.

The Microsoft security vulnerabilities report states:

“Of all the Windows vulnerabilities discovered in 2018, 169 of these were considered  'critical'. Removing admin rights could have mitigated 85% of these critical vulnerabilities”

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/4/image3-5.png)

By removing users from  the local admin group, you greatly reduce the risks of attackers to gain access to your computer and network. 

It is recommended to use  group policy to control the local admin group. If you remove these  permissions from the local computer without central control, these  rights can be added again.

### Conclusion/Summary

Active Directory is one  of the cornerstones of an organization's IT infrastructure, but its  security is also critically important. Without proper configuration and  monitoring, malicious users or attackers can infiltrate your network,  gain access to sensitive data, or cause service disruptions. Therefore,  it is critical to take measures such as strong password policies,  regular account monitoring, and restriction of unnecessary access  rights. In addition, regular application of security patches,  installation of firewalls, and use of appropriate authentication methods are also necessary to improve Active Directory security.

We will learn about the “Windows DNS Security” topic in the next part of our training.

## Windows DNS Security

The security of the  Domain Name System (DNS) service is extremely important for the overall  security of a network. It facilitates the communication of users and  systems on the network. However, this important service can also be the  target of malicious attackers, so the security of this service is  extremely important.

DNS translates these  names into corresponding IP addresses when a URL is entered in a web  browser, or when an application connects to a web service or wants to  resolve a domain. However, if the DNS service is not secure, attackers  can manipulate DNS queries and redirect users to fake or malicious  sites. This type of attack is often called DNS poisoning or DNS spoofing and can be used to steal users' personal information or sensitive  information (password, credit card, etc.). Additionally, a DDoS  (Distributed Denial of Service) attack on the DNS service can cause a  complete collapse of a network or web service.

The security of the DNS  service ensures that the exchange of information on the network remains  secure and private. This not only protects users' personal information  but also protects businesses' sensitive information and services from  malicious attackers. Therefore, the security of the DNS service is vital to the overall security of a network.

Windows DNS Server is a  DNS service provided by Microsoft and is typically used by Windows-based networks. This service is widely preferred, especially in Windows  environments, as it is tightly integrated with the Windows Active  Directory service. However, the security of Windows DNS Server is a  critical issue due to the fact that attackers can target this service  and compromise the network.

This highlights that the  security of Windows DNS Server is an integral part of the overall  security of a network. Therefore, these service protection strategies  and practices should be understood and implemented by network  administrators and security professionals. Continual evaluation and  improvement of Windows DNS Server security is necessary to protect  against DNS attacks, ensure proper routing of network traffic, and  maintain overall network security. Here are the main issues related to  Windows DNS Server security.

### DNS Zone Transfer Restriction

DNS Zone transfer is the  process of copying all DNS records from the primary DNS server (master)  to the secondary DNS servers (slave or backup). This process is often  used for DNS backup and load balancing.

DNS data is usually  organized in a structure called a "zone", which contains all the records of a particular DNS namespace (domain). A DNS zone transfer copies all  the data of a zone from one server to another. This usually happens when changes are made to the primary server and those changes need to be  pushed to all backup servers.

Zone transfers can be of two types:

**Full Zone Transfer (AXFR)**

This copies all the  information of a zone from the primary DNS server to the backup DNS  server. Such transfers usually occur when a zone is created for the  first time or when the backup server is completely rebooted.

**Incremental Zone Transfer (IXFR)**

This only copies changes  in a zone from the primary DNS server to the backup DNS server. When a  zone changes, the backup server only receives the changes, increasing  efficiency and reducing network traffic.

Zone transfers usually  occur automatically, but a network administrator can trigger them  manually. The security of zone transfers is important because if an  attacker gains access to a zone transfer, they can learn about all the  records in the DNS server. For this reason, we usually restrict zone  transfers to only allow reliable backup servers.

You can follow the steps below to restrict DNS Zone transfers in Windows Server 2019:

Open the DNS management  console. To do this, open "Server Manager", then select the "Tools" menu and click "DNS". On the screen that opens, right-click on the relevant  zone and click on “Properties”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/5/image4-1.png)

On the screen that opens, switch to the “Zone Transfers” tab and select the “Allow zone  transfers:” option and select the “Only to the following servers” option to allow only certain IP addresses. Then write the list of IP addresses to be allowed by saying “Edit”. (As seen in the screenshot below, the  IP address 172.16.8.1 is allowed to make zone transfer.)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/5/image4-2.png)

Let's try DNS Zone transfer over the server with 172.16.8.1 IP Address. You can see it succeeded in the output below.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/5/image4-3.png)

When a zone transfer  attempt is made from a system that does not have zone transfer  permission, the result will be a "Transfer Failed" message as below.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/5/image4-4.png)

### DNSSec

DNSSEC or Domain Name  System Security Extensions is a set of Internet Engineering Task Force  (IETF) standards used to verify the integrity and authenticity of DNS  queries and responses. Simply put, DNSSEC helps verify that the results  of a DNS query have not been manipulated or altered.

DNSSEC actually  determines whether a DNS response is genuine and has been modified. It  does this by digitally signing DNS responses and using that digital  signature in the response to every DNS query.

To set DNSSEC, you can follow the steps below in Windows Server 2019:

Open the DNS management  console. To do this, open the "Server Manager", then select the "Tools"  menu and click on the "DNS" option. Right-click on the zone you will  apply and click “DNSSEC” -> “Sign the Zone”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/5/image4-5.png)

A special signature etc.  if it will not be used, select the “Use default settings to sign the  zone” option and click the “Next” button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/5/image4-6.png)

DNSSec settings defined as default are shown briefly. You can complete the DNSSec setting by clicking “Next” and then “Finish”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/5/image4-7.png)

DNSSEC has cons and pros. For example, DNSSEC can be complex to implement and manage and use more system resources. Therefore, a DNSSEC implementation must be carefully  planned and managed.

### DNS Server Monitoring

Monitoring DNS server  activity can help identify a number of potential threats and attacks.  These activities are located in Microsoft -> Windows ->  DNSServer\Audit on Windows Eventlog. Some important events included here are:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/5/img3.png)

DNS server activities must be monitored constantly which will avoid “DNS Hijacking    attacks by early  detecting them. DNS Hijacking is a type of attack made by directing DNS  queries to different DNS servers and changing the response as desired.  This can be done by changing the DNS records on the DNS Server.

### Additional Information

**Updates**

It is very important to  regularly update associated software such as update, Windows DNS service and operating system. Updates usually fix security vulnerabilities and  protect the service against new threats.

**Access Limitation**

Access to the DNS service should be provided to users and services as needed. A policy of  limiting high-privilege accounts and keeping authorization to a minimum  can help mitigate potential harm.

**Training**

IT personnel and users are required to be aware of threats to DNS security and receive training in secure practices.

In this part of the training, we have covered the Windows DNS security topic, and we will be learning about “Windows DHCP Security” in the next chapter of our training.

### Questions

1 - What is the IP address where DNS Zone Transfer is allowed on the system you access?

> **Answer:** 172.31.0.2

2 - Which IP address is defined in the "testlab" A (address) record in the "soclab.local" DNS records on the system you access?

> **Answer:** 172.16.10.54

## Windows DHCP Security

The security of the  Dynamic Host Configuration Protocol (DHCP) service is extremely  important for the overall security of a network. It facilitates the  communication of users and systems on the network. However, this  important service can also be the target of malicious attackers, so the  security of this service is extremely important.

DHCP ensures that devices connected to the network are automatically assigned IP addresses. This  makes it easier to manage large networks without having network  administrators manually set IP addresses for each device. However, if  the DHCP service is not secure, an attacker can add his or her own DHCP  server to the network and thus provide misleading network configuration  information to devices connecting to the network. This allows the  attackers to redirect traffic to their system and steal potentially  sensitive information.

The security of this  service ensures that information exchange on the network remains safe  and private. This not only protects users' personal information but also protects businesses' sensitive information and services from malicious  attackers. Therefore, the security of the DHCP service is vital to the  overall security of a network.

DHCP, one of the  indispensable elements of networks, prevents network administrators from manually assigning IP addresses to each device by automatically  assigning IP addresses to devices on the network. However, the security  of this important service is often overlooked. Windows DHCP server  security is critical to the overall security of the network. To prevent  potential threats such as unintended network access, denial of service  (DoS) attacks, or data leaks, it is essential to secure the Windows DHCP server.

Due to the way DHCP  works, there are various security vulnerabilities. For example, the DHCP service will usually assign an IP address to any device on the network. This means that an unauthorized device can connect to the network and  perform potentially harmful activities. Additionally, DHCP-based attacks can knock out the DHCP service or spoof network traffic. Finally, the  confidentiality and integrity of DHCP data must be protected against the possibility of misleading or malicious alteration of IP address  information.

### MAC Filtering

MAC Filtering can be  implemented via Media Access Control (MAC) addresses using DHCP on  Windows Server. It is used to control whether devices with a specific  MAC address receive an IP address or not.

MAC address filtering is  used when you want only certain devices on your network to obtain an IP  address, or when you want to prevent certain devices from obtaining an  IP address. This can improve your network security because it only  allows certain devices to access your network.

You can follow the steps below to perform DHCP MAC address filtering on Windows Server:

After opening "Server  Manager", select "DHCP" from the "Tools" menu. On the DHCP Management  screen that opens, from the “IPv4” -> “Filter” section, right-click  on the “Allow” or “Deny” section and select “New Filter”.

The "Allow" option in the filter type only gives IP addresses to certain MAC addresses, while the "Deny" option prevents certain MAC addresses from obtaining IP  addresses.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/6/image4-8.png)

In the "New Filter"  window, enter the MAC address you want to filter in the "MAC Address"  field and click the "Add" button. This way MAC address filtering is  enabled.

  

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/6/image4-9.png)

MAC filtering can be an  effective way to increase network security, but it is not a sufficient  security measure on its own because MAC addresses can easily be spoofed. That's why it should often be used in conjunction with other security  measures.

### Rogue DHCP Blocking

Rogue DHCP is when an  unauthorized and unexpected DHCP server starts serving on a network,  often for malicious purposes. A Rogue DHCP server can provide clients  with misleading network configuration information, which can redirect  network traffic to unwanted destinations or even redirect users to  malicious websites.

To detect the Rogue DHCP  server on Windows Server, the DHCP server authorization mechanism that  Microsoft designed to automatically monitor DHCP servers and detect  unauthorized servers is used.

DHCP server authorization verifies that a DHCP server is registered and authorized in Active  Directory. If a DHCP server is not authorized, the DHCP service is  automatically stopped and that server cannot distribute IP addresses.

To use DHCP server  authorization, the DHCP server must be in an Active Directory domain. To authorize the DHCP server, open the DHCP console, right-click the DHCP  server and click "Authorize"

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/6/image4-10.png)

Monitor DHCP servers  regularly and if you detect an unauthorized DHCP server running on your  network, deauthorize or remove it immediately.

By default, you can see  DHCP logs under the "C:\Windows\system32\dhcp" directory and follow them from there. For Rogue DHCP detection, critical logs with id 50 and  above should be especially monitored.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/6/image4-11.png)

The meanings of some DHCP Event IDs are as follows. 50+ Event ID is important for Rogue Server detection.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/6/img4.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-System-Security/6/img5.png)

### Conclusion

The security of the  Windows DHCP service is a critical issue that the network administrators must constantly consider and work on. Network administrators should  always be proactive in understanding new threats and risks, adopting new security technologies and best practices, and continually improving the security of their network. Your network security is ultimately part of  the overall security and success of your business.

In this part of the  training, we have covered the importance of Windows DHCP security, MAC  filtering and Rogue DHCP blocking topics.

### Questions

1 - What is the MAC address that is blocked from receiving an IP address from DHCP on the system you access?

> **Answer:** AA-BB-CC-11-22-33





































































































































