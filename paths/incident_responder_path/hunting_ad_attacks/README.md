# Hunting AD Attacks

This course will teach you how to hunt common active directory attacks. Each  lesson has 3 sections: Attack, Detection, and Mitigation. In this way,  you'll understand how the attack works and learn to detect it.

**Table of Contents:**

- [Introduction to Active Directory](#introduction-to-active-directory)
- [Hunting AS-REP Roasting Attack](#hunting-as-rep-roasting-attack)
- [Hunting for Kerberoasting Attacks](#hunting-for-kerberoasting-attacks)
- [Hunting for LDAP Enumerations (Bloodhound_Sharphound)](#hunting-for-ldap-enumerations-bloodhound_sharphound)
- [Hunting for NTDS Database Dumping](#hunting-for-ntds-database-dumping)
- [Hunting for Golden Ticket Attacks](#hunting-for-golden-ticket-attacks)
- [Hunting for NTLM Relay Attacks](#hunting-for-ntlm-relay-attacks)

**Evaluate Yourself with Quiz**

- [Hunting AD Attacks Quiz](https://app.letsdefend.io/training/quiz/hunting-ad-attacks-quiz)

## Introduction to Active Directory

Active Directory (AD) is a directory service developed by Microsoft  for Windows domain networks. It is a centralized database that stores  information about resources on a network, such as users, computers, and  applications, and provides a hierarchical structure to organize and  manage these resources.

AD is used to manage and control access to network resources, such as files, printers, and other shared resources. It provides a centralized  authentication and authorization mechanism, allowing users to access  resources on the network using a single set of credentials. AD also  provides a single point of management for network administrators,  allowing them to easily manage and control access to network resources.

AD is an important component of many enterprise networks and is  widely used in organizations of all sizes. It integrates with other  Microsoft technologies, such as Exchange and SharePoint, to provide a  comprehensive solution for managing user authentication, authorization,  and access to resources on the network. Additionally, it supports the  use of Group Policy Objects (GPOs) to enforce security and compliance  policies, as well as provide an infrastructure for software distribution and patch management.

The main core of Active Directory is Kerberos. It is a protocol used  for authentication, authorization process for large scale environments.  We will cover basic terms in Active Directory as well as how Kerberos  authentication works.

### What is Kerberos?

Kerberos is the default authentication service for Microsoft Windows  domains. It is intended to be more "secure" than NTLM by using third  party ticket authorization as well as stronger encryption. Even though  NTLM has a lot more attack vectors to choose from it still has a handful of underlying vulnerabilities just like Kerberos which still makes it a target for threat actors. It runs on UDP port 88.

**Common Terminologies:**

- Key Distribution Center (KDC): The Key Distribution Center is a  service for issuing TGTs and service tickets that consist of the  Authentication Service and the Ticket Granting Service.
- Ticket Granting Ticket (TGT): A ticket-granting ticket is an  authentication ticket used to request service tickets from the TGS for  specific resources from the domain.
- Authentication Service (AS): The Authentication Service issues TGTs to be used by the TGS in the domain to request access to other machines and service tickets.
- Ticket Granting Service (TGS): Ticket Granting Service in Active  Directory is responsible for granting Service Tickets (STs) to clients  that have already obtained a Ticket Granting Ticket (TGT) from the  Authentication Server (AS).
- Service Principal Name (SPN): A Service Principal Name is an  identifier given to a service instance to associate a service instance  with a domain service account. Windows requires that services have a  domain service account which is why a service needs an SPN set.

Lets imagine an active directory user needs to access a file share.  The user simply opens the share and enter his/her credentials if they  have permissions to access the share. In backend, here's how The whole  authentication flow works:

1. The client requests authentication from KDC. This authentication request would be in plain text.
2. KDC sends a TGT and a session key if the client exists in the  database. If the client is not in the database, the authentication  fails.
3. The client asks for the service ticket of the fileshare along with the TGT sent earlier by the KDC.
4. KDC sends the ticket encrypted with the session key. The client  can use the session key sent earlier by KDC to decrypt the service  ticket.
5. The client requests the Fileshare server for access using the service ticket.
6. The Fileshare server authenticates the client. It sends a ticket that will grant access to the file share.

The service ticket has a specific expiration time. You can use the  same session ticket to access services until it expires. The default  lifetime of a Kerberos ticket is 600 minutes.

This was just a basic overview to make you familiar with the basics  of how Active Directory authentication works. If you are a beginner and  want to learn more about how kerberos work, checkout this awesome blog: [ https://blog.netwrix.com/2022/08/18/what_is_kerberos/](https://blog.netwrix.com/2022/08/18/what_is_kerberos/)

## Hunting AS-REP Roasting Attack

AS-REP Roasting dumps the Kerberos hashes of user accounts that have  Kerberos pre-authentication disabled. The only requirement for AS-REP to roast a user is that the user must have the pre-authentication  disabled. Pre-authentication is the first step in Kerberos  authentication, and is designed to prevent brute-force password guessing attacks. During the pre-authentication, the user's hash will be used to encrypt a timestamp that the domain controller will attempt to decrypt  to validate that the right hash is being used and is not replaying a  previous request. After validating the timestamp the KDC will then issue a TGT for the user. If pre-authentication is disabled you can request  any authentication data for any user and the KDC will return an  encrypted TGT that can be cracked offline because the KDC skips the step of validating that the user is really who they say they are.

This is exactly how attackers misuse the pre-authentication feature  as this is the way how Active Directory works and is designed. This also makes it difficult to detect this attack as it blends in with  legitimate events and activities occurring in active directory  environments. However, thankfully, there are some properties which  differentiates a legitimate event to that of a malicious one. We will  discuss this in the detection part of the lesson. First, let’s cover how an attacker would perform AS-REP roasting.

So, to summarize this is how this attack occurs:

1. Attacker enumerates against Active Directory user accounts that do not require pre-authentication.
2. Attacker requests the Kerberos Ticket-Granting Ticket (TGT).
3. The AD Domain Controller responds back with the TGT without requiring the account password as a pre-authentication.
4. The attacker uses a tool to extract the hashes from a captured packet.

### Attack 

From an attacker perspective, the attacker would only need a valid  domain username and should know the IP Address of the domain controller. Attackers can craft a list of usernames and use an impacket suite of  python scripts. Impacket is a collection of Python classes for working  with network protocols. It was made for legitimate purposes and is  widely used by system administrators, penetration testers and  adversaries alike. We will use “GetNPUsers.py'' script to perform this  attack.

Let's assume the attacker don't know any valid account names in the  domain. Attackers can use a tool like “kerbrute” which enumerates valid  usernames.

> **Command:** ./kerbrute_linux_amd64 userenum -d CYBERCONSULTING.org --dc 192.168.230.140 users.txt 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/2-+Asrep+roasting/1.png)

So far what we have discussed is not part of ASREP roasting attack,  that was shown just to let you know how valid account names can be  enumerated by attackers.

Let's proceed by taking the previous example, we know 2 valid usernames so far. Let’s update our username list for valid users.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/2-+Asrep+roasting/2.png)

So far we don't know if any of these users have pre-authentication  disabled or not. When we use "GetNPUsers.py" script from impacket and  provide it a list of valid users, it will retrieve the hash of user if  they have pre-authentication disabled.

> **Command:** python3  /usr/share/doc/python3-impacket/examples/GetNPUsers.py  CYBERCONSULTING.org/ -dc-ip 192.168.230.140 -user users.txt -no-pass 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/2-+Asrep+roasting/3.png)

We provide the path of the python script, then the domain name which  is “CYBERCONSULTING.org'', then the domain controller IP address which  is “192.168.230.140”, then list of valid usernames then a "-no-pass"  switch which indicates we don't have any valid credentials so far. Lets  say if an attacker already has a valid set of credentials of a domain  user and wants to perform lateral movement, they can use those  credentials and also perform AS-REP roasting to get the user's hash and  then crack it.

Lets run the command and see the output.

> **Command:** python3  /usr/share/doc/python3-impacket/examples/GetNPUsers.py  CYBERCONSULTING.org/ -dc-ip 192.168.230.140 -user users.txt -no-pass  -format john 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/2-+Asrep+roasting/4.png)

We can see that we got the user “abdullah” hash meaning  preauthentication was disabled for this user. But it was enabled for  user “cyberjunkie” that’s why we did not get any hash for that user. At  the end, we specified a format flag to “john” who makes this hash  crackable by “John the Ripper” tool which is a password cracking tool.

> **Command:** john --wordlist=pass.txt hash.txt 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/2-+Asrep+roasting/5.png)

Here we see the password of user “abdullah” is "Password1".

This attack can also be carried out by other tools like “Rubeus” and  can be directly run from a compromised machine. The attack we carried  out was from a Kali Linux machine, which shows that attackers only need  access to the internal network, they don’t even need to carry out the  attack from a compromised machine or necessarily require a set of  credentials.

### Detection 

Whenever a user logs on a domain or performs any type of  authentication like accessing a service etc. an event is logged in  Windows Security Event logs with event ID 4768. This event is recorded  whenever a Kerberos authentication ticket or in other words a Ticket  Granting Ticket (TGT) is requested from the KDC which is the Domain  Controller.

For example a valid user logged on to his/her workstation, an event  ID of 4768 is logged along with some other events too. This makes it  very difficult to detect and hunt for AS-REP roasting attacks because  these tickets are requested for daily operations and is the essence of  Kerberos authentication mechanism. However when a legitimate operation  occurs (like a user logon to his/her workstation) the ticket has an  encryption type of “0x12” which indicates that it's encrypted using  AES-256. Lets see a legitimate event.

**Note:** All the Kerberos events are logged in the domain controller for all the users, computers in the active directory environment.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/new/6-edited.png)

The above screenshot shows that the ticket encryption type is “0x12”  and pre-authentication type is 2. Anything other than 0  pre-authentication type means that the user has pre-authentication  enabled. Now let’s review the event from our attack.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/new/7-edited.png)

Here, we see that encryption type is “0x17”. This means that ticket  is encrypted using RC4 encryption algorithm. This is one of the major  indicators that this attack occured, however it still leaves room for  doubt as some older services in Active Directory still requires RC4  encrypted tickets. But the pre-authentication type is 0 which means it's disabled for the user and it fulfills the requirements of AS-REP  roasting attack. This can greatly reduce our events and should be  definitely looked into.

A SOC analyst would be looking through thousands of logs. So, to  greatly reduce the noise and only look for indications of AS-REP  roasting attack, analysts should use queries only to look for Event ID  4768 with the ticket encryption type of “0x17” and pre-authentication  type “0”. These events should be definitely further looked into and  investigated.

So to hunt for indications of AS-REP roasting accounts, analyst should look for:

1. Event ID 4768 on Domain Controller
2. Ticket Encryption Type of “0x17”
3. Pre-Authentication Type of "0"

### Mitigation Steps 

1. Find any accounts in the environment which have disabled  pre-authentication. This can be done by running following command from  the domain controller.

   > **Command:** ‘ get-aduser -f * -pr DoesNotRequirePreAuth | where {$_.DoesNotRequirePreAuth -eq $TRUE} ’

2. Enforce complex and lengthy passwords policy in the domain. This  would make it difficult or impossible for attacker to crack the password of a valid user.

### Questions

There’s a folder on Desktop named “Evidence”. Open the file “Security-DC” to answer the questions.

1 - Which user account was targeted in AS-REP roasting attack?

> **Answer:** robstark

2 - At what time did this attack occur? (Format: Same as in Event Log)

> **Answer:** 7:50:47

## Hunting for Kerberoasting Attacks

Kerberoasting allows an attacker to request a service ticket for any  service with a registered SPN then use that ticket to crack the service  password. If the service has a registered SPN then, it may be  Kerberoastable if its password is not strong, if it is trackable as well as the privileges of the cracked service account. What makes this a  common attack is that to perform this attack, attacker don't need to be  admin. This can be done with privileges of just a domain user.

Oftentimes in real active directory environments, service accounts  are given privileges and permissions that they don't even require.  System administrators grant service accounts domain admin privileges  most of the time and this happens more than you think so. This is why  attackers perform these attacks in hope to escalate their privileges or  even to have domain admin privileges. If an attacker gets domain admins  privileges, they can do anything they want to in all of the active  directory environment, not only on a single machine.

### Attack 

Let's assume that the attacker just got a foothold in the internal  network. Attackers don't know what kind of service accounts are present  in the environment. There is a Framework called “**PowerSploit**” which contains different type of powershell scripts for internal enumeration and exploitation. One of the script is called “**Powerview.ps1**” which is a great script for internal enumeration in active directory environment.

Lets see how an attacker would first find Service accounts:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/3-+Kerberoasting/1.png)

Attacker first imported the modules from Powerview. This is seen from the command:

> **Command:** “. .\Desktop\PowerView.ps1”

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/3-+Kerberoasting/2.png)

Then the attacker used a cmdlet module from the script and the name  of the cmdlet is “Get-NetUser”. Attacker provided a switch of SPN which  will enumerate all accounts which have a service principal name. 99% of  time SPNs are only set for service accounts. Here we see a service  account named krbtgt and this is the default service account in Active  Directory. Another one we can see is the SQLService account. We can see  the password in the description. This is a very common occurrence in  Active Directory environments as system administrators make this mistake most of the time by making a note of their passwords in the description area thinking that they are the only one who can see the password. For  this lesson let's ignore the description part as that was only an  example for depicting real world habits.

Now the attacker knows a ServiceAccount name. For this attack we can  use Impacket scripts again to perform the attack and that requires a set of valid credentials. Let's assume that the attacker doesn't know any  valid credentials and just got access through a phishing mail.

We will use rubeus tool which is very easy to use and will dump hashes of service accounts which are kerberoastable.

> **Command:** .\Rubeus.exe kerberoast 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/3-+Kerberoasting/3.png)

Then the attacker can copy this hash and crack it on their machine.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/3-+Kerberoasting/4.png)

For this course exercise, this service account has the same password as the user which we discussed in the previous lesson.

### Detect 

Now let's discuss how we can detect kerberoasting activity. Once  again detecting this is difficult as services are accessed and used in  daily usages. For example, if a user accessed a file share, a service  ticket would be requested by that user from the domain controller to  access the service. Since there are thousands and thousands of events  occurring at a time, detecting this attack gets harder and more  difficult.

Let's take a look at the event which was recorded because of the attack above.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/new/5-edited.png)

We can see a TGT being requested with an encryption type of “0x17”  just like we saw in previous lesson of AS-REP roasting. The main event  occurs immediately after this event with event ID “4769”. Again, there  are thousands of events recorded with this event ID on a daily basis but we will look for a field that would indicate kerberoasting.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/new/61-edited.png)

In legitimate use cases of this event ID, encryption type would be  0x12 or 0x11. But, if we see an encryption type “0x17” that would be a  call to further investigation. To further reduce chances of false  positives, we can filter out requests from other service accounts.  Service accounts work requesting service tickets from the domain  controllers on a regular basis. To further reduce the events to look  into we can filter out requests from account names starting with “$” as  these are computer accounts or other service accounts which Windows uses as part of its operations. SOC Analysts can query the logs in SIEM  creating a filter for all the things mentioned in this paragraph.  Moreover attackers sometimes use scripts or tools to perform  kerberoasting on more than one service account at a time. If we see many events with EventID 4769 and encryption type “0x17 '' in a small time  period this would be a confirmed red flag.

So, to summarize, here's how you can detect kerberoasting activities from event logs:

1. Event ID 4768 with encryption type “0x17”.
2. Above event is immediately followed by Event ID 4769 also with encryption type “0x17”.
3. The account name requesting the service ticket is a domain user  account and not a service account or computer account (starting with $).
4. Filter for Audit success keywords in event 4769 (Meaning the attacker got the hash).
5. In some cases, many requests for service tickets in a short period of time.

### Mitigation Steps 

1. Service accounts must have complex and lengthy passwords.
2. Appropriate permissions on service accounts (so if the attacker  does get access to it, they can't do too much damage with it).

### Questions

There’s a folder on Desktop named “Evidence”. Open the file “Security-DC” to answer the questions.

1 - What is the name of the service account which was kerberoasted?

> **Answer:** MSExchangeService

2 - At what time the service ticket was requested from the domain controller? (Format: Same as in event log)

> **Answer:** 7:53:25

3 - Which user’s credential did the attacker use to perform this attack?

> **Answer:** jonsnow

## Hunting for LDAP Enumerations (Bloodhound_Sharphound)

LDAP (Lightweight Directory Access Protocol) is a protocol for  accessing and maintaining distributed directory information services  over an Internet Protocol (IP) network. LDAP is an important part of  Active Directory as it provides the underlying protocol for accessing  and maintaining the information stored in the directory. With LDAP,  Active Directory can be queried and updated in a standardized way,  allowing various applications and services to interact with the  directory. LDAP is used by Active Directory to authenticate users,  enforce security policies, and manage access to resources. For example,  when a user logs into a Windows domain, Active Directory uses LDAP to  verify the user's credentials and determine whether they have the  necessary permissions to access the requested resources.

The use of LDAP in Active Directory also makes it possible to  integrate with other systems and applications that support the LDAP  protocol. This allows organizations to leverage their investment in  Active Directory and provides a single, centralized location for  managing user and resource information.

So why are the attackers interested in this? Because this allows the  attacker to enumerate and gather lots of information about the domain  and get the lay of the land. They can get domain users account names,  computer names, and lots of more information. In fact this is one of the first thing that the attackers perform to create a plan on how to  further penetrate the network.

### Attack 

There's a tool called “**bloodhound**” which enumerates  LDAP in active directory and then creates a whole visual graph,  displaying the logical structure of the entire domain which makes it  easier for the attacker to further plan their attack to compromise  Domain Controller/Domain Admins as quickly as possible. Bloodhound has a collector named “**sharphound**” which when run in a  computer in an active directory, it will query LDAP and collect lots of  information and then create a zip file of it. Then that zip file is  ingested in the Neo4j database which then creates a whole graph. In this lesson, we will just demonstrate usage of sharphound as it will be the  one querying LDAP and generating all the logs. However just for  curiosity here's how the bloodhound graphs look like:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/4-+Ldap+enumeration/1.png)

Let’s run sharphound in the user “cyberjunkie” machine.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/4-+Ldap+enumeration/2.png)

Here, we see that the enumeration got completed.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/4-+Ldap+enumeration/3.png)

Now, the attacker would move the zip file to their computer and use  bloodhound to create a logical map of the entire domain. Bloodhound also hints shortest paths to higher privileges depending upon the  configurations and privileges in the domain.

### Detection 

LDAP is a functional requirement of active directory hence there are  thousands of interactions with this in Active Directory. Attackers take  the advantage of this as they can do enumeration in plain sight as  there's no straight way to tell whether the LDAP request belongs to a  malicious actor or if it is a legitimate request. This is why auditing  on object access is disabled by default in Active Directory. If every  object (every account, every service, every computer and many more)  starts getting logged whenever queried via LDAP, this would cause a  significant performance problems in the domain and operations would be  disrupted. That’s why it’s not ideal to log every object whenever LDAP  is queried about them. If a user logs in a computer, 5 to 6 audit logs  would be logged just for that event. And as the corporate environment  has thousands of users this is not ideal and not recommended.

Enter CANARY objects. A viable solution to the problem above is to  create user accounts, computer names, groups etc. in the Active  Directory that are not used by anybody and instead just play the role of dummy accounts/computer/groups. Make them look like they are legitimate accounts, computers, etc. and nicely blend in the environment. No one  would be able to tell the difference between a dummy account and a legit one. Then enable auditing on these dummy objects and whenever an  attacker uses automated tools like bloodhound, these dummy objects would also be queried from LDAP, causing the event to be logged without any  performance issues. There should be hundreds of CANARY objects in order  to have a better detection chance in large environments.

A system administrator can query LDAP about anything related to  domain like computer names, permissions, user accounts, etc. from  command line. Similarly, an attacker can do this from the command line  too, using the same command. So, there's no way of telling the  difference between a legitimate request and a malicious intent one  unless, attacker uses automated tools like bloodhound (which they do!).  If attackers started querying LDAP about all the information they are  interested in via command line, that would take many hours and the  process would not be as efficient. They could not even make sense of all those LDAP responses when combined. Bloodhound does all this and gives  us a map in under 5 minutes.

The event ID associated with LDAP enumeration is 4662. If we spot  many events in a very short period of time from the same user account  then that is an indication of LDAP enumeration. Let's view the first  event generated when we ran sharphound.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/4-+Ldap+enumeration/4.png)

Here, we can see that the LDAP query was done from “cyberjunkie”  account and it queried a username (notice the object type field) named  “dr strange”. which was placed as a canary object for this exercise.

We see 2 other events on the same object (dr strange user) which indicates what kind of operation was performed.

Moving on to the next one.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/4-+Ldap+enumeration/5.png)

Here, we see the same case where the user “cyberjunkie" enumerated a  computer named "Test" which was placed as a canary object for this  exercise. If you take a close attention to the timestamps between the 2  events you will notice that there is literally no time difference which  indicates that it was automated. A normal service operation or normal  usage would not do this in a short amount of time and that is our clue  that LDAP enumeration took place. If there were hundreds of canary  objects, we would see all of them in these events in a very short period of time and that would make it more easier to deduce that this is a  malicious activity. However, this was only done for a demonstration on  how to detect and hunt for indications that automated LDAP enumerations  occured in the environment.

So, to summarize:

1. Filter for event ID 4662.
2. If too many events occur in a very short time of period then, it  may be a strong indication for an LDAP enumeration has taken place.

### Mitigation Steps

1. Prevent unprivileged session enumeration.

### Questions

There’s a folder on Desktop named “Evidence”. Open the file “Security-DC” to answer the questions.

1 - Which user account was used by the attacker to enumerate LDAP?

> **Answer:** jonsnow

2 - At what time the first LDAP enumeration event was logged? Format: (Same as in event logs)

> **Answer:** 7:55:39

## Hunting for NTDS Database Dumping

Ntds.dit (NT Directory Services DataBase) is the database file in  Active Directory (AD) that contains all the information about the AD  database, including the configuration of the AD domains, users, groups,  security policies, password hashes and other objects. It is stored on  each domain controller (DC) in the AD forest and is used to authenticate users and manage access to resources. The Ntds.dit file is used by the  Active Directory Domain Services (AD DS) to store and manage the  directory data, and it is critical to the proper functioning of the AD.  The database is a critical component of the AD and should be backed up  regularly to ensure that it can be recovered in the event of a disaster  or failure.

By default the Ntds.dit file will be located in “%SystemRoot%\NTDS\Ntds.dit” of a domain controller.

If attacker gets hold of this database, they can recover cleartext  passwords (doing this would require SYSTEM registry hive too) and in  theory, they would have hold on entire domain. They can then get remote  access of any machine in the domain including domain controllers and  with full privileges. There are many tools that can be used to dump this database, including a built in Windows utility named "ntdsutil". This  utility is used by Windows to backup the Ntds.dit database file  regularly and can also be used via command line. Attackers use this  utility to blend in the environment as this utility is used normally on  the domain controller itself for backup purposes.

### Attack 

Let’s dump the Ntds.dit database on our domain controller “DC-01”.

> **Command:** ntdsutil "ac i ntds" "ifm" "create full C:\Users\Administrator\Desktop\NTDS_BACKUP" q q 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/5-NTDS+dumping/1.png)

Here we see that ntds database is dumped in a specified location. Let's break down the command line arguments:

\- **ac i ntds:** This is the option to activate the instance of the NTDS service that is running on the local machine.

\- **ifm**: This is the option to start the NTDS Instance Management submenu, which provides access to commands for backup and  restore operations.

\- **create full C:\Users\Administrator\Desktop\NTDS_BACKUP:** This is the command to create a full backup of the Ntds.dit database.  The backup will be saved to the specified location  C:\Users\Administrator\Desktop\NTDS_BACKUP.

1st - **q**: This is the option to quit the ntdsutil utility.

2nd - **q**: This is the option to quit the NTDS Instance Management submenu.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/5-NTDS+dumping/2.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/5-NTDS+dumping/3.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/5-NTDS+dumping/4.png)

Here, we can see that Ntds.dit is dumped alongside the “SYSTEM” and  “SECURITY” registry hives. Attackers can now exfiltrate this dump to  their machine/server and decrypt the database to get the crown jewels  (sensitive data) of the environment.

### Detect 

Now let’s focus on the detection part and the types of events that  are generated due to the above activity. We would need to view  application event logs. Go to application logs and then in Filter  current log.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/5-NTDS+dumping/5.png)

Then go to the event sources option.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/5-NTDS+dumping/6.png)

And select the source “ESENT”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/5-NTDS+dumping/7.png)

As previously mentioned, ntdsutil is used as a common routine in  active directory environments, so we should look at few Event IDs and  focus on the PATH of the database. Attackers try to trick and evade by  naming the path of the files as backup, critical backup, etc.

The first event ID we should look for is Event ID 325.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/new/8-edited.png)

This Event ID is generated when a new database is created, which in  our case was the dumped one. In most cases, this event ID alone can help us determine Ntds.dit dumping activity, but just to avoid any possible  false positives, we can also look for another event that is associated  with it.

Let’s see the Event ID 327 which is generated when a database engine  detached a database, in our case the dumped copy of ntds is detached.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/new/9-edited.png)

Another crucial Event ID, which can really add more context to our  analysis is Event ID 216. This Event ID does not contain the location  path of our dumped database but its generated whenever the ntds is  written to disk instead of its default location.

“%Systemroot\NTDS\ntds.dit”. If this event is generated around the  time of above events we discussed, then that can clear our doubts and  can be a confirmed case of Ntds.dit dumping.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/new/10-edited.png)

Notice that the time when this event occurred is just 2 milliseconds before Event ID 325 and 327.

So to summarize:

1. Select Event ID 325, 327, and 216 in Application Event logs and select event source as “ESENT”.
2. Look for abnormal paths (Anything other than C:\Windows\NTDS\) in Event ID 325 and 327.
3. The event time of Event ID 216 would be just around the events 325 and 327.
4. If there are a lot of events even after filtering using the Event  IDs, you can use the “Find” option in EventViewer and search for the  keyword “ntds”. This would really help and reduce the amount of events  to analyze.

### Mitigation Steps 

There are no direct mitigations against this as the process of this  attack is a normal Windows server operation. However, some things can be done to reduce the risk:

1. Restrict administrative privileges across the environment.
2. Routinely audit administrative access and logins to domain  controllers as this attack can only be performed on domain controllers.

### Questions

There’s a folder on Desktop named “Evidence”. Open the file “Application-DC” to answer the questions.

1 - At what time the NTDS database is dumped? (Format: Same as in event log)

> **Answer:** 7:58:02

2 - What's the path where NTDS database was dumped?

> **Answer:** C:\Users\Administrator\Documents\Backup\Active Directory\ntds.dit

## Hunting for Golden Ticket Attacks

Golden Ticket attack is an attack type that involves an attacker  compromising a Kerberos Ticket Granting Ticket (TGT) for a Privileged  user account like domain admins or krbtgt service. This TGT can be used  to request a Service Ticket (ST) for any service on the network,  effectively allowing the attacker to impersonate any user on the  network, including privileged users such as administrators. The attack  is called a "Golden Ticket" because it gives the attacker a golden  ticket to access any resource on the network, without the need for a  password.

Attackers should gain domain administrator privilege in Active  Directory to create a golden ticket. This ticket leaves attackers to  access any computers, files, folders, and most importantly Domain  Controllers (DC). Successful creation of this ticket will give the  attacker complete access to your entire domain with an access time of 10 hours or can be expanded up to several years to stay in your domain  controller and move laterally to discover more machines and infect them.

Golden Ticket attacks can be difficult to detect, as they often  involve valid credentials and appear to be normal, legitimate  authentication events. To prevent Golden Ticket attacks, it is important to implement strong password policies, monitor for suspicious activity  in the event logs, and ensure that all systems are up to date with the  latest security patches.

### Attack 

To perform Golden ticket attack, attackers would require NTLM hash of the kerberos service account. Tools like mimikatz can help us in  dumping NTLM hashes from lsass.exe.

> **Command:** lsadump::lsa /inject /name:krbtgt 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/6-+Golden+ticket+attacks/1.png)

The things marked in image are:

- SID
- RID(user ID)
- NTLM hash

We would require all these things when crafting a golden ticket.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/6-+Golden+ticket+attacks/2.png)

> **Command:** kerberos::golden /User:Administrator  /domain:CYBERCONSULTING.org  /sid:S-1-5-21-2612289411-4282575245-2512524665 /id:502  /krbtgt:2e3d7350dd8210ebe7f03ce2147d8786 /ptt

Here, in the krbtgt field the NTLM hash is provided and in domain  field domain name is provided. The ‘/ptt’ switch injects the ticket into our memory and now, the attacker has privileges of the krbtgt service,  which has all the permissions in the active directory and is just like a domain admin account. Attackers can also save the ticket to the file  for future use.

Now, attackers can interact with any computer in the environment,  even domain controllers and can get a shell with system privileges.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/6-+Golden+ticket+attacks/3.png)

Here, the attacker used a command called klist which will list all  the active tickets in memory. Now, the cyberjunkie user which was just a normal domain user has domain admin privileges.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/6-+Golden+ticket+attacks/4.png)

Here, the attacker confirmed his/her privileges by connecting to the  “C$” share on domain controller and can be seen that command was  successful.

### Detection 

Detecting golden ticket attacks is quite hard because of its nature  and the way it blends in the daily usage operations in the environment.  Detecting this attack requires correlation between events.

Let’s visit the events associated with this attack.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/new/51-edited.png)

We first see that the administrator user requested a service ticket  for the service named “krbtgt”. Now, this is a very common occurrence as admin users' operations typically require interacting with different  services including kerberos service (krbtgt). What makes this request a  little bit benign is that the client address from where this request  originated is not a domain controller but rather a normal workstation.  Now, this event can also typically happen if a domain admin logins to a  user workstation and performs some operations. This still pose a risk  even though it is not common in real environments. This is why detecting this attack gets complex as it's prone to false positives but it still  is worth a look.

Now, another event that may be an indication for the golden ticket  attack is Event ID 4624 which is when a user session successfully starts or in Windows Words (an account was successfully logged on). Now, this  event is also recorded in thousands as it is also a part of how Windows  and Active Directory works. We need to check these events carefully and  correlate with Event ID 4769 which we just discussed.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/6-+Golden+ticket+attacks/6.png)

Here the key indicators that a golden ticket attack possibly occured  are the blank value in Subject Account Domain. Again this is also very  common in Windows logon/logoff events so we cannot just rely on this one indicator, we need to correlate the other factors too. Also logon type  must be noted as mostly golden ticket attacks are done over network so  logon type will be 3 which can greatly reduce the amount of events/logs  when analysts use SIEM to query events.

Next up, we should see the impersonation level, security ID, username of the account (which we used in mimikatz while crafting the golden  ticket) and the account domain. Impersonation level would be delegation  whereas in legit cases it would be impersonation. Here, we see that SID  is of krbtgt account, not that of a user but the Account Name is  Administrator. If in the account name there was name of Domain  controller (Computer Account for e.g DC-01$) then it could have made  sense but there is a mismatch here. Then, if you look at the Account  Domain, it's a FQDN (Fully qualified Domain name which is  CYBERCONSULTING.org) but it should be CYBERCONSULTING (just domain). The last thing we see is the source network address which is IP of the  workstation. Correlating all these factors we can say that this was a  golden ticket attack.

Here's what a normal request should look like:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/6-+Golden+ticket+attacks/7.png)

Here, we see the user is administrator and security ID is also of  administrator and not mismatched like above. Also the domain name is not FQDN but just a domain.

Another great way to monitor and detect possible golden ticket  attacks is by inspecting the tickets lifespan. By default a ticket in  active directory is valid for only 10 hours, but as we did see earlier,  mimikatz creates a ticket with a lifespan of 10 years. This can be done  via running the command klist on the endpoint under suspicions or  investigation.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/6-+Golden+ticket+attacks/8.png)

Detecting a golden ticket attack still remains a challenge because of the nature of the attack, and activities going on in the environment.  Detecting this via log analysis still remains a challenge for SOC  Analysts as there are too many factors involved so that's why security  products like Microsoft advanced threat analytics uses AI and machine  learning to detect such attacks and are recommended in production  environments. However we can still greatly reduce our chances of  detecting and hunting these attacks by providing more visibility and  granularity by using Sysmon. Analysts can then corelate Sysmon logs with the event logs discussed to remove any chances of false positives or  going down a rabbit hole. Tools like mimikatz, rubeus, etc. are commonly used and analysts can search Sysmon logs for malicious keywords like  “golden”, "lsadump", "lsa", etc. and track the process creations, there  are arguments to hunt for the usage of these malicious tools. We just  discussed native event logs to get you an idea of how this attack works  and to this date remains a challenge to confidently detect them.

So to summarize:

1. A krbtgt ticket is requested (Event ID 4769) from a machine that is not domain controller.
2. In event ID 4624, security ID and account name must be related to  each other, meaning the user administrator should have security ID of  administrator. If not, then it might be indication of golden ticket  attack.
3. Logon type would be “3” which is network logon and this would be in most of the cases in the attack.
4. The account domain name would be a fully qualified domain name and this might be indication of attack.
5. A network address of a machine that's not a domain controller.  This machine should then be investigated to confirm the attack  suspicions.

These all points must be correlated with each other in order to detect the attack.

**Note:** As there are many logon events going on a computer, you should look for Event ID 4769 and then Event ID 4624 followed by it.

### Mitigation Steps 

1. This attack requires a krbtgt hash which is only accessible by  privileged accounts. So the best mitigation is to restrict  administrative rights in the environment as much as possible.
2. The administrative account passwords must be changed routinely.

### Questions

There’s a folder on Desktop named “Evidence”. Open the file “Security-DC” to answer the questions.

1 - What is the source network address from where the golden ticket attack was performed?

> **Answer:** 192.168.230.133

2 - Which account name did the attacker use when injecting the golden ticket in memory?

> **Answer:** Abdullah

3 - What is the login GUID value?

> **Answer:** {23ec4d9b-f16e-12a6-e057-a9c42faa4b29}

## Hunting for NTLM Relay Attacks

NTLM relay is a type of attack that takes advantage of a weakness in  the NTLM authentication protocol. It works by relaying authentication  requests from one machine to another, essentially bypassing  authentication requirements. The attacker acts as a relay between the  client and the target system, relaying the authentication request and  capturing the response.

Once the attacker has captured the response, they can use it to  impersonate the original client and gain access to the target system or  resource. The attack is made possible because the NTLM protocol does not validate the authenticity of the relay machine, making it possible for  an attacker to intercept and forward the request to a machine under  their control.

For this attack to be successful, SMB signing is needed to be  disabled which is done by default on Windows. Attackers can discover the endpoints with SMB signing disabled by using tools like Nmap, Nessus,  etc. Lets see this attack in action.

### Attack 

Let's start by discovering endpoints with SMB signing disabled with Nmap.

> **Command:** nmap --script=smb2-security-mode.nse -p445 192.168.230.0/24 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/7-+NTLM+relay/1.png)

Here a Nmap built in script is used which checks for smb signing and the whole network (running active directory) is scanned.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/7-+NTLM+relay/2.png)

Here, we can see that SMB signing is enabled for user workstations  but it's not required meaning that our attack can still work because of  it not being a REQUIREMENT. For the domain controller signing is enabled and required. It's important to note that these are default settings  for both workstation and the Windows server.

**The attack will go as follows:**

1. A user (jon snow) at Workstation-02 (192.168.230.133) will issue a network connection (For e.g SMB file share) that is not the correct  path. For example a file share path is “\\192.168.230.100\Share” but the user types in an incorrect path, lets say “\\192.168.230.100\Sare”. The user mistakenly forgot to add "h" in share which caused the whole file  share to be wrong (non-existent). This happens very commonly in active  directory environments as end users can cause a spelling mistake or  incorrect IP address or workstation name etc. If such an event occurs  active directory uses LLMNR protocol when DNS fails. There's a tool  called “Responder” which acts as a LLMNR server acting as man in the  middle and this the network requests go through the attackers server.
2. The attacker knows that SMB signing is disabled on Workstation-01  (192.168.230.134) and will run another tool called “ntlmrelayx” which is part of “impacket framework”. What this will do is that when the above  scenario occurs, the user (jonsnow) sends his hash for authentication to the attacker-controlled server (192.168.230.129) thinking that it's an  LLMNR server. This hash is then used to authenticate to the destination  endpoint (Workstation-01) which the attacker wants to target. Then  hashes are dumped for the target endpoint.

Now. let's start the actual part of our attack. There's a tool called “Responder” which acts as a man in the middle and can be used for the  majority of network related attacks in active directory environments.  Let’s run the Responder.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/7-+NTLM+relay/3.png)

Now, an attacker would have an active listener in the internal network. Now let’s run **ntlmrelayx**.

> **Command:** python3 ntlmrelayx.py -tf target.txt -smb2support 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/7-+NTLM+relay/4.png)

Here the target.txt file contains the IP address of the endpoint  which attacker wants to target. In our case it's WORKSTATION-01 which is used by user “cyberjunkie”.

Now, let's assume that user jonsnow typed a wrong file share path to access from his WORKSTATION-02.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/7-+NTLM+relay/5.png)

Now, when this path is tried to be accessed, as it does not exist the whole ntlm relay attack occurs as explained above.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/7-+NTLM+relay/6.png)

And in ntlmrelayx output the Hashes from WORKSTATION-01 are dumped.  The attacker only had access to WORKSTATION-02 (192.168.230.133), but by NTLM relay attack the attacker now has access to an entirely different  workstation which is WORKSTATION-01(192.168.230.134). Now, attackers can perform lateral movement or try to escalate privileges.

### Detection 

To detect NTLM relay attacks, we need to analyze security event logs  from the target machine, not the domain controller logs we have been  doing so far.

The Event ID we are interested in is the one we have previously  discussed too, Event ID 4624 which is for successful logon. Let’s visit  event logs of WORKSTATION-01 which was targeted in this attack.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Hunting-AD-Attacks/new/71-edited.png)

The detection logic is simple but not efficient for manual analysis.  In the relevant event, the IP Address is of our attacker machine but  workstation name is correct, which is WORKSTATION-02. This is because  logon was performed by attacker machine which was acting as a MITM,  relayed the actual request on behalf of user “jonsnow” from  WORKSTATION-02. The logon was not directly from WORKSTATION-02 but  rather from attacker's machine running ntlmrelayx tool server.

If a validation can be performed on workstation names and the IP  addresses, to compare whether the IP address is that of the workstation  in an event, NTLM relay attacks can be detected and hunted. This  validation can be done in numerous ways and requires a list of  IP-Hostnames pairs to cross reference. Some of recommendations to do  this are:

\- When EDR agents transmit telemetry about endpoints network  information, the hostname and IP address can be validated for  comparison. Microsoft Defender for Endpoint periodically sends this  information.

\- Computers that are part of a domain are frequently authenticated.  The hostname and IP address of the computer can be obtained from these  events and matched with the NTLM logon events using automation  scripts/techniques.

This method is also prone to false positives. If the environment uses load balancers or proxies, any authentication requests passing through  devices would also be detected as IP-Hostname mismatch. These  IPs/hostnames must be used in a whitelist to reduce risk of false  positives.

### Mitigations 

1. Enabling and making SMB signing a requirement on endpoints.
2. Disable NTLM authentication in domain environments. Prefer Kerberos authentication over NTLM.

### Questions

There’s a folder on Desktop named “Evidence”. Open the file “Security-Workstation” to answer the questions.

1 - A user entered an incorrect file share address which caused ntlmrelay  attack in the network. Which workstation was the user using? 

Sample Answer: Workstation-23

> **Answer:** Workstation-01

2 - What’s the attacker IP address acting as man in the middle in the network?

> **Answer:** 192.168.230.129





























