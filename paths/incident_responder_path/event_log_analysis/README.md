# Event Log Analysis

This course will teach you the structure of Windows event logs and how you  can detect persistence, manipulation, execution, etc. in a hands-on way. You'll do lots of practice during the course.

**Table of Contents**:

- [Introduction to Event Logs](#introduction-to-event-logs)
- [Event Log Analysis](#event-log-analysis-1)
- [Authentication Event Logs](#authentication-event-logs)
- [Windows Scheduled Tasks Event Logs](#windows-scheduled-tasks-event-logs)
- [Windows Services Event Logs](#windows-services-event-logs)
- [Account Management Events](#account-management-events)
- [Event Log Manipulation](#event-log-manipulation)
- [Windows Firewall Event Logs](#windows-firewall-event-logs)
- [Windows Defender Event Logs](#windows-defender-event-logs)
- [Powershell Command Execution Event logs](#powershell-command-execution-event-logs)

**Practice with SOC Alert**

- [64 - SOC130 - Event Log Cleared](https://app.letsdefend.io/monitoring?channel=investigation&event_id=64)
- [101 - SOC153 - Suspicious Powershell Script Executed](https://app.letsdefend.io/monitoring?channel=investigation&event_id=101)

**Evaluate Yourself with Quiz**

- [Detailed Event Log Quiz](https://app.letsdefend.io/training/quiz/detailed-event-log)

## Introduction to Event Logs

### Introduction to Event Logs

Event logs are records of events that occur on a Windows computer.  They contain vital information about system events, such as user  log-ins, service starts or stops, as well as application events, such as system errors, etc. Event logs also contain security events, such as  user login attempts to login with an incorrect password or when  suspicious activity is detected. Event logs are useful for a variety of  purposes, including troubleshooting problems, tracking down issues, and  identifying patterns or trends. They can also be used for security and  compliance purposes, such as auditing and monitoring for security  breaches or compliance violations.

Event logs are typically stored on a computer or server, and can be  viewed and accessed using tools such as Event Viewer on a Windows system or logrotate on a Linux system. They can also be viewed and accessed  remotely, using tools such as Windows Remote Event Log Management.

Event logs are not in human readable format but rather stored as a  binary format. We cannot read these logs with text editors like web logs or linux logs. We need specialized tools which convert the event logs  in human readable format. Event logs are stored at:  “C:\Windows\System32\Winevt\Logs”

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/1-+Introduction+to+Event+logs/1.png)

Event log files have the extension “evtx”. Here are properties of an event log file.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/1-+Introduction+to+Event+logs/2.png)

Event logs are categorized according to the nature of the information being recorded. Event logs related to the Windows operating system and  the operations carried out by the OS are categorized as:

- **Application Logs**: Events related to the installed applications are stored here.
- **Security Logs**: Events related to Sessions  logon/logoff, RDP successful/failed connections, services installed,  tasks created, etc. are stored here.
- **System Logs**: Events related to hardware states, drivers, etc. are stored here.
- **Setup:** The setup log contains events that occur  during the installation of the Windows operating system. On domain  controllers, this log will also record events related to Active  Directory.
- **Forwarded Events:** Contains event logs forwarded from other computers in the same network.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/1-+Introduction+to+Event+logs/3.png)

These logs are categorized as “Windows logs”. There is another  category called “Application and Services logs” which stores detailed  logs about installed applications on the system, either native or  installed by users.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/1-+Introduction+to+Event+logs/4.png)

Event logs of the majority of applications are stored under  Microsoft->Windows . We will be discussing Windows Defender, firewall logs and RDP logs in upcoming lessons.

An event ID is a numerical identifier assigned to each event that is  recorded in an event log. It is a unique identifier that is used to  identify a specific event or type of event. Event IDs are typically used in conjunction with other event log data, such as the event source and  the event time, to provide more context about the event. For example  when we logon successfully to our computer, an event is recorded with  Event ID 4624 in Security log.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/5-edited.png)

Event IDs are useful for filtering and organizing event log data, as  they allow you to quickly identify and group similar events. Many event  logs include a list of common event IDs and their meanings, which can be helpful for interpreting and understanding the events that are  recorded. We will discuss many Event IDs useful for SOC analysts and  incident responders in upcoming lessons.

Event logs are further classified into event types. This indicates  what kind of event was recorded. These are also called levels. There are 5 types of event logs.

- **Information**: This event type means that an operation was successfully completed and a general description of it is recorded.
- **Warning**: This event type means that there is some kind of minor problem that may cause bigger issues in future events.
- **Error**: This type of event means that a problem occurred causing a loss of functionality.
- **Critical:** Indicates a significant issue in an application or a system needing urgent attention.
- **Verbose:** Indicates progress or success messages for a particular event.

There are also keywords which are similar to levels in Windows Security logs. Some of the important things are.

- **Audit Success**: This event type means that successful security access was attempted.
- **Audit Failure:** This type of event means that a failed security access was attempted.

In this lesson, we discussed what are event logs, where and how they  are stored, and how events are categorized by event IDs and types of  events. In the next lesson, we will discuss some tools to view and  analyze event logs to make sense of them. Then we will discuss important event IDs from a security perspective and how to uncover malicious  activities from event logs.

## Event Log Analysis

In this lesson we will be discussing some tools used to View and  analyze event logs. We already discussed that event logs are not in  human-readable format so we cannot rely on any normal text editor. We  will discuss three tools which are present natively on windows systems.

### Event Viewer

Event viewer is a GUI-based application present natively on Windows.  We will be using this tool for the rest of the course so pay close  attention. It can be launched by searching for event viewer in the  windows search:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/1.png)

This is the main menu of the event viewer. You can see the event logs on left, the summary in the center which shows what levels of events  logs are stored on the computer, and Actions tab on the right which we  will discuss shortly.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/2.png)

Our main logs will be in Windows logs. Let's expand it.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/3.png)

Here we see some of the Event logs we discussed like Security,  Application and System. In this lesson we will explore event viewers and how to search and filter efficiently to view only the data we are  interested in. Lets select System logs:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/4-edited.png)

Here we see in the middle pane the event logs which are categorized  under System Logs. We can see the level of event, date and time when the event was recorded by the operating system, the source  software/application that logged the event, Event ID of the event, Task  category helps organize events so we can filter on the basis of it if  needed.

On top, we can see the number of events in the selected category. In our case, System logs have 42,380 events.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/5.png)

Let's select the second event. We can see the information of that event below:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/6-edited.png)

Here we can see what and how this event occurred, and the same  information we discussed above and some more info like username and the  computer name is also displayed here.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/7-edited.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/8.png)

We can view this information in another type of presentation by  clicking the details view. Here we can see the data in friendly view or  xml view.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/9.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/10.png)

Now let's discuss the Action tab:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/11.png)

We can filter logs by Event ID, or date and time. Click “Filter Current Log”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/12.png)

If we want to filter on the basis of event IDs, click here and enter the event ID of events you want to view.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/13.png)

Lets filter on event ID 7040 in the same system logs events we are discussing so far. Click ok after entering the event ID.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/14.png)

Now we can only see events with event ID 7040. We can see on top that the events are being filtered by event ID 7040 and there are 6,658  events with this event ID.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/15-edited.png)

We can also filter for multiple event IDs by providing event IDs separated by commas:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/16.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/17-edited.png)

We can further filter the logs by date and time. We can use event ID  filters alongside the date and time filters or we can use them  independently too. Let's do it on top of our current filter. Click  filter current log again. Click the dropdown menu.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/18.png)

We can select Predefined time or can provide custom range.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/19.png)

Lets select a custom range.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/20.png)

Select "Events on" in From and To dropdowns.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/21.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/22.png)

Now select the time and date ranges from which we want to see events  on. Lets filter for events between 14 December 2022 12:00:00 AM and 15  December 2022 12:00:00 AM.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/23.png)

We can see that between 14 and 15 December 2022 there were a total of 22 events with event IDs 7040 and 10016.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/24-edited.png)

If we want to remove the filter, click the “Clear Filter” option.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/25.png)

**Note:** Do not click the "Clear Log" option as it deletes the events from the computer.

If you want to save the event logs click “Save Selected Events''.  Those events which are being displayed in the center pane will be saved. So if you apply filters on events and then save the events, those  filtered events will be saved, not all of them.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/26.png)

In this section we discussed how to use the event viewer to efficiently read and filter event logs according to our needs.

Now we will briefly discuss 2 other tools which are CLI based and are native to Windows systems.

### Wevtutil

Wevtutil is a command line-based tool which allows us to retrieve  information about event logs, apply filters, clear logs, etc. To view  the help menu of the tool run.

“wevtutil.exe /?” in administrator cmd.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/27.png)

To view available event logs run:

“wevtutil.exe el” which will list all available logs.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/28.png)

You can use “/?” to list more info about a command

Lets try to view an event using wevtutil:

> **Command:** “wevtutil.exe qe System /c:3 /rd:true /f:text”

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/29.png)

You can refer to the help menu to understand the arguments we used in the above command.

### Get-WinEvent 

This is a PowerShell cmdlet which enables us to read events from  event logs from local or even remote computers. It is a very flexible  tool as it allows combining data from multiple sources in a single  command using queries such as hash table queries, structured XML  queries, etc. We won't go in detail but will just explore basic commands of this tool.

Open Powershell as administrator. We can list available event logs using the command:

> “Get-WinEvent -Listlog *”

**Note:** This command is similar to the el argument of wevtutil.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/30.png)

We can filter logs from any event log and filter by Event ID or  Source of the event. Lets view the events from system logs and from  source “Service Control Manager” which we saw in Event Viewer section:

> **Command:** “Get-WinEvent -LogName System | Where-Object {$_.ProviderName -Match 'Service Control Manager'}”

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/2-+Tools+for+reading+event+logs/31.png)

In this lesson, we discussed how to view and filter event logs using  tools available natively on Windows systems. We discussed Event Viewer  in detail and explored how to filter event logs for specific criteria,  and how to understand the data stored in logs. In the next lesson, we  will start discussing important event IDs and event logs from a security point of view.

### Questions

1 - How many events were recorded in the System log between 5 PM and 8 PM on 17 September 2021?

> **Answer:** 854

## Authentication Event Logs

Brute force authentication is a method of attempting to gain  unauthorized access to a computer or other system by trying every  possible combination of passwords or other authentication factors.  Attackers can gain passwords for user accounts from breaches, or from  other sources like social engineering. In Windows systems whenever we  login to a computer and start a session, it is recorded in event logs.  Similarly, when we fail to login, that failed attempt is also recorded.  We can use this information to potentially find any brute force attempts or suspicious activities.

We can determine that someone is attempting to login to an account  that's not his/her by viewing these events. For example, If we see many  failed attempts in event logs, and after that, we see a successful  login, we need to further investigate that user account in case of an  outsider/threat gaining access to an unauthorized account. Similarly we  can see failed and successful authentication attempts for RDP (Remote  Desktop Protocol).

There are 9 types of logon types in Windows. Some of logon types are:

- **Interactive (Logon type 2)**: This type of logon happens when a user logs on to the computer physically.
- **Network (Logon type 3)**: This type of logon occurs when a user or computer logs on to the computer from the network.
- **Batch (Logon type 4)**: This type of logon is used by batch servers. Scheduled tasks are executed on behalf of a user without human intervention.
- **Services (Logon type 5)**: This type of logon is used for services and service accounts that logon to run a service.
- **RemoteInteractive (Logon type 10)**: This logon type  occurs when a user remotely accesses the computer through RDP  applications such as Remote Desktop, Remote Assistance or Terminal  Services.

It's important to note that Logon types except type 5 (Services)  should be focused on. When we open Security logs, we will see a lot of  events in a small amount of time with many successful logins. Most of  these logons are of type 5 which is done by services and services  account when a user logon. This causes a lot of unnecessary noise and  makes it difficult for us to analyze the events.

Now, lets start detecting successful and failed authentication in event logs.

### Local/Domain User Authentication Attempts

**Successful attempts**

Whenever we successfully logon to our computer and start our session, an event is recorded with Event ID “4624” in Windows Security Logs with the date and time of event occuring and Keywords “Audit success”. Lets  filter the events with event id 4624.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/3-+Detecting+Authentication+attempts+and+Bruteforcing/1.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/2-edited.png)

As we discussed previously, we see a lot of successful logons. These  are mostly of Logon type 5 and done by Windows when a session is  started. Lets see an event.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/3-edited.png)

We can see here that this logon was done by Services.exe and is of  type 5. If we filter event logs around the time of logon, we would need  to find a logon of type other than 5.

Now let's try to find a logon of type 2 (Interactive).

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/4-edited2.png)

In our case, logon type is 2 which means the user successfully  authenticated to the computer by physically interacting with the system. We can see the user account name and the domain name of the account.  The nature of authentication attempts depends on the logon type of the  event. In this lesson we will be discussing the interactive and RDP  logon types only as the analysis procedure is the same for all of them.

**Failed attempts** 

Now lets see some failed authentication attempts. Failed  authentication attempts have event ID “4625”. Lets filter with this  event ID and view the results.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/3-+Detecting+Authentication+attempts+and+Bruteforcing/5.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/3-+Detecting+Authentication+attempts+and+Bruteforcing/6.png)

We can see 7 failed authentication attempts within a small period of time. If we click an event to view details:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/7-edited2.png)

We can see logon type, account name for which logon failed and the  failure reason. This can be helpful in case the user entered the correct password and wrong username as a typo. Since we saw multiple failures  together in a short amount of time we can conclude that either the legit user forgot his/her password or some unauthorized person was attempting to logon. Again this depends on the logon type like an attacker trying  to move laterally in the network and trying different passwords in the  network. Then the logon type would be 3. Extending our hypothetical  scenario, if we see failed logon attempts for logon type 3 (Network) in  multiple computers in a network, this would be a suspicious activity and would indicate a possible intrusion where the attacker is trying to  perform lateral movement.

### Remote Desktop Protocol Authentication Attempts

RDP is widely used in corporate environments due to its flexibility  and ease. Users can easily use their workstations/computers from remote  locations or System Administrators use RDP to fix issues, update devices without having to be physically present. Unfortunately, this makes RDP a favorite of attackers. Attackers having RDP access will be able to  perform any operation from that computer without having to be physically present. RDP is also widely used by attackers to perform lateral  movement.

One important thing to note is that when investigating event logs for RDP related events, the source computer connecting to the remote  computer via RDP also stores event logs related to that session and the  computer on which user RDP into also stores event logs related to that  session. The source computer event logs would be very helpful when  investigating lateral movements in an internal network as the attacker  would have moved from an internal workstation to another one. In case of external RDP attacks where the RDP computer is internet facing and  someone unauthorized logons to the computer via RDP then we would only  have even logs on the RDP computer as we would not have access to the  attackers machine.

We discussed important RDP artifacts in the Windows Forensics course  where we discussed how attacker activities over RDP can be uncovered and help in incident response. We will discuss RDP authentication events in this lesson.

**Successful Attempts**

As you might have guessed, Successful RDP logon is also stored in  Security logs with event ID “4624” but with logon type 10. But Windows  also stores RDP logs under “Applications and Services Logs” in an  Application Log named “TerminalServices-RemoteConnectionManager”. This  makes it easy to analyze RDP logs because there's a lot of unnecessary  noise in Security Logs.

Go to the following location.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/3-+Detecting+Authentication+attempts+and+Bruteforcing/8.png)

When we expand Windows, we can see lots of application names. Scroll  to the bottom until we read TerminalServices, expand it and select  operational.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/3-+Detecting+Authentication+attempts+and+Bruteforcing/9.png)

Here we see 1,873 events in RDP event logs

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/10-edited.png)

Event ID 1149 can be used to find successful RDP connections. Lets see the latest Event ID 1149 event.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/11-edited.png)

We can see the Account domain and IP Address from where the  connection was initiated. Let's say that we are investigating Computer B and find these event logs . We can find other compromised machines too  from which the attacker laterally moved from to Computer B. In our case, RDP connection was initiated from IP ADDRESS 192.168.18.8 which was  Computer A. We didn't know previously that Computer A was also  compromised but we strongly assume it is , because of the RDP events  during the incident time frame. This scenario is illustrated in diagrams below:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/3-+Detecting+Authentication+attempts+and+Bruteforcing/12.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/3-+Detecting+Authentication+attempts+and+Bruteforcing/13.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/3-+Detecting+Authentication+attempts+and+Bruteforcing/14.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/3-+Detecting+Authentication+attempts+and+Bruteforcing/15.png)

### Detecting Lateral Movement from Source Computer From Where RDP was Initiated

Expanding upon the scenario in the previous paragraph, We can also  find information about the computers to which the attacker further  laterally moved to. We are analyzing Computer B, in our hypothetical  scenario. Attacker moved laterally to another Computer which is Computer C. We didn't know that Computer C was also compromised, but finding the event logs which we will be discussing below will allow us to know that Computer C is also compromised because of the RDP connection in the  known incident time frame and then we would analyze Computer C too. This can help us stop the network-wide infection and help determine the  degree/scope of the incident. 

The scenario discussed in this section is also illustrated in the below diagrams:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/3-+Detecting+Authentication+attempts+and+Bruteforcing/16.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/3-+Detecting+Authentication+attempts+and+Bruteforcing/17.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/18-edited.png)

Lets discuss the event logs found on the source computer from where RDP connection was initiated.

These events are under “Applications and Services logs” under  application “TerminalServices-ClientActiveXcore” then  “Microsoft-Windows-TerminalServices-RDPClient/Operational”. Event ID  1102 will give us the events which store the destination IP Address of  the server running RDP. Lets filter and view these events.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/19-edited.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/3-+Detecting+Authentication+attempts+and+Bruteforcing/20.png)

Lets view an event.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/21-edited.png)

This gives us the IP address that may help us to know where to look  for but doesn't tell us whether it was successful or not. We can find  more information related to this event in the security log with event ID 4648 and filtering with the time frame of the event discussed  previously. Here we can see the target account name which we were using  to logon to the remote computer and the target server domain. You can  see that we were remotely connecting to a letsdefend machine on cloud  with the IP 3.142.35.163 which we saw in the previous event above.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/22-edited.png)

This is helpful in investigating lateral movements. For example if we find an IP address in these logs on a compromised machine during the  incident time frame, we must investigate the computer having that IP  address because maybe the attacker was successful in moving laterally to that computer via RDP.

**Failed Attempts**

Now let's discuss failed RDP connection attempts. In  “TerminalServices-RemoteConnectionManager” events there isn’t an Event  ID for failed authentication. An Event ID 261 tells us that RDP port  received an TCP connection.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/23-edited.png)

We can still deduce a failed authentication attempt by observing  whether there are any successful RDP authentication events after the 261 Event ID events in a short period of time. When someone tries to  connect to RDP, the computer receives an 261 Event ID event and if  successfully authenticated then we see event ID 1149 which have already  been discussed. However, if there's no successful authentication event,  we can assume that the authentication failed. This methodology is not  always 100% accurate as receiving a TCP connection does not always mean  that the user is trying to authenticate. For example, if someone is  performing a port scan on an RDP port, An event with event ID 261 will  be recorded but there was no authentication attempt.

We can also view failed RDP logins from security logs with event ID  4625. We discussed the previous events first because there's a lot going on in security logs and it's very noisy. This way if we can first find  event ID 261 and then view Security logs with Event ID 4625 during the  timeframe of the events with event ID 261 from Remote Connection Manager logs.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/24-edited2.png)

Here we can see the username with which the user authenticated, IP address of the source machine initiating the connection.

In order to avoid such attacks its recommended in corporate  environments to set an account lockout policy where after a certain  number of failed attempts, the user account is locked out and is not  allowed to connect for some time. In this lesson we discussed different  types of authentication events and how to detect and uncover an  attacker's progress. Next up we will discuss how to detect persistence  activities setup by attackers.

### Questions

**Scenario:**
An attacker gained credentials of a user through social engineering.  Attacker IP is originating from Pakistan and the victim belongs to an  organization in USA. Attacker performs OSINT and discovers that the  victim has an RDP connection facing to the internet. Attacker leverages  the brute force technique to connect to the RDP server with variations  of passwords and able to login to it successfully after a few attempts. A SOC analyst belonging to that organization in the USA sees an alert in  the SIEM tool where it says that RDP connection is successful to the  user account from an IP belonging to Pakistan which is not usual. The  time of connection was also not during office hours so the analyst will  investigate the event logs and analyze the RDP logs to confirm the  alerts. Then necessary actions can be taken if device is compromised and escalate the alert to the Incident Response team.  The incident  occurred on January 13th around 3:15 pm. 

**Note:** Assume this scenario as beginning of investigation for rest of lessons too.  Assuming this scenario, answer the following questions. 

1 - How many events were recorded in the System log between 5 PM and 8 PM on 17 September 2021?

> **Answer:** 6

2 - What’s the IP Address of the attacker who attempted the brute-force attack?

> **Answer:** 72.255.51.37

3 - Which city does the IP originates from?

> **Answer:** Lahore

4 - At what time the attacker was able to login via RDP? Format (Same as in event logs)

> **Answer:** 1/13/2023 3:16:32

5 - The Lab machine you are connected to, was used by the attacker to move  to another Internet facing RDP computer which was only accessible from  certain IPs. What's the IP address of that RDP machine?

> **Answer:** 3.15.195.136

## Windows Scheduled Tasks Event Logs

The Task Scheduler is a utility in Windows that allows you to  schedule automated tasks on your computer. These tasks can be simple  actions, such as starting a program or running a script, or more complex operations, such as backing up data or synchronizing files. Scheduled  tasks can be configured to run at a specific time, on a recurring  schedule, or in response to certain events. You can use the Task  Scheduler to schedule tasks on your computer or on a remote computer,  and you can use it to automate a wide range of tasks and processes.

There are several ways that attackers can abuse scheduled tasks to  gain access to a system or to perform malicious actions. For example:

1. An attacker could create a new scheduled task on a victim's  computer that runs a malicious program or script. This could allow the  attacker to execute arbitrary code on the victim's machine with the  privileges of the task scheduler. This could allow the attacker to  maintain a foothold on the victim's machine and potentially evade  detection.
2. An attacker could modify an existing scheduled task on a victim's  machine to run a different program or script. This could allow the  attacker to change the behavior of the task and potentially execute  malicious code.
3. An attacker could use a scheduled task to ensure that malware is  consistently running on a victim's machine. This could allow the  attacker to maintain a foothold on the victim's machine and potentially  evade detection.
4. An attacker could create or modify a scheduled task that runs with elevated privileges, potentially allowing the attacker to gain access  to resources or perform actions that would otherwise be restricted.

Event Logs are an excellent source to view and analyze past scheduled tasks, even which have been deleted by attackers. Attackers delete  scheduled tasks when they no longer need them, but task creation events  still remain. This allows us to see what kind of activity a scheduled  task was doing which no longer exists and can help us find undetected  intrusions.

**Note:** The events related to scheduled tasks are not recorded  in security logs by default. They need to be enabled from GPO, and it's  highly recommended to enable for maximum visibility.

### Scheduled Task Created 

Let's first discuss events when a task gets created. In security logs if logging is enabled, an event with event ID 4698 is recorded whenever a task is created either via task scheduler app or via command line.  The name of the task is recorded which can potentially hint us of  something malicious, the trigger time of the task which is the time or  date or event which will cause the task to get executed, and the program name or commands alongside arguments which is the task contents itself. For example, an attacker can schedule a task where a malicious script  placed by the attacker is executed every day at 9:00pm, the commands of  the task would be “PowerShell -File **C:\Users\username\documents\maliciousscript.ps1**”.

Lets see another example and analyze the events. Filter the events by Event ID 4698 and the time of the incident if known in security logs.  Here we filter only by Event ID.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/4-+Scheduled+Tasks+Creation_Modification/1.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/2-edited2.png)

We need to look out for Task Author(User who created the task),  scheduled time of the task, description of the task if any and the  command of the task which will be executed. Some automated tasks are  created/modified by the operating system and the author of such tasks  are usually NT AUTHORITY/SYSTEM. If an attacker has admin access, he/she can also create tasks with NT AUTHORITY/SYSTEM privileges so it's  important to keep a few of these points in mind.

Let's Explore the latest event.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/30-edited.png)

Here we can see that task name is "Windows Update Task" and is  scheduled by user CyberJunkie which is suspicious. Attackers use such  wordings to blend in the environment and fool users who are not tech  savvy like employees in the finance department for example. Then we see a description of the task which says that it's critical and doesn't  delete the file, again such wordings are used to sway away users. Below  we see the time at which the task is scheduled to execute which is  15:00:00 or 3:00 pm. Below we see that it's scheduled by week and day of week is Friday and week interval is 1. This means that this task is  scheduled to execute every week on friday at 3:00 pm. Attackers use such tactics to remain persistent and make sure Command and Control(C&C) server communications are always up.

Now let's view the main important piece of information to us in this event.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/4-+Scheduled+Tasks+Creation_Modification/4.png)

If we see the command tags, we can see the command which would  execute at the scheduled time. The binary name is "Windows Update" and  is stored under the documents folder of a user. This is a very odd place for such a file so we can safely say that it's placed by an attacker.  We can determine from the file paths, the command line arguments if any  that whether the task is legit or malicious. Also If we know the  incident time frame and such events are occurring in that time frame,  that adds more context and makes it more likely to be a part of the  intrusion.

As discussed previously, in order for the events to be recorded under Security Logs, we need to set up via Group policy object in Windows. It is highly recommended to enable in corporate environments and active  directory environments where maximum visibility is needed. If for some  reason these are not enabled on an endpoint you are analyzing, then we  can also find events related to task scheduler in Application and  service logs under Microsoft->Windows ->Task Scheduler in  operational logs.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/4-+Scheduled+Tasks+Creation_Modification/5.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/4-+Scheduled+Tasks+Creation_Modification/6.png)

Here we can filter by Event ID 106 and see the Task registered event. Unfortunately these event logs don't provide us detailed information  like the security logs, here it only records the task name when it's  created.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/70-edited.png)

However when the task is executed at its scheduled time, there's  another event with Event ID 201 that tells us that the scheduled task  completed its execution and that event records only the commands of the  task.

Lets manually execute the task now in the task scheduler to generate this event for demonstration.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/4-+Scheduled+Tasks+Creation_Modification/8.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/4-+Scheduled+Tasks+Creation_Modification/9.png)

As a defender, these events are useful to us because even if the  actual task is deleted by the attacker and is no longer available on the system, we can still find details of the task. This can uncover past  malicious activities and TTPs of threat actors involved.

### Scheduled Task Updated

As discussed before, attackers also modify already created tasks in  order to avoid creating more noise. Lets say a system administrator  knows that a computer has 3 scheduled tasks normally. If an attacker  creates a new task, the sysadmin would immediately know that there's a  new task and may look into it. So to avoid such scenarios, If attackers  get a chance to modify a scheduled task which is not of great  significance and would not disrupt daily operations for that system,  they would do this instead of creating a new one for reasons mentioned  above.

Events related to updated scheduled tasks are recorded under Security logs with Event ID 4702. These events also store the same kind of  information like scheduled task created ones. Let's update the task we  discussed in the task creation section and then analyze the results  here.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/100-edited.png)

Now let's filter the event logs for event ID 4702 and view the latest event.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/111-edited.png)

We can see what was modified by comparing the task creation event for that task and the task modification event. Here we can see that  everything is the same except the scheduled date and time. Instead of  executing at 3:00 pm every week on Friday, now the task is scheduled for execution at 12:00 pm daily.

We can also find events related to scheduled task update/modification in Application and service logs under Microsoft->Windows->Task  Scheduler in operational logs. Here we can filter by Event ID 140 and  see the Task update event. Unfortunately these event logs don't provide  us detailed information like the security logs, here it only records the task name and time when the event was recorded.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/12-edited.png)

### Scheduled Task Deletion

Attackers delete their unneeded scheduled tasks. For example,  attackers moved laterally to a different network with higher privileges  and setup persistence there. They no longer need the scheduled task  which has lower privileges. Attackers don't want to alert SOC teams or  trigger any alerts so they tend to clean after their mess when it's no  longer needed.

Scheduled task deletion events are recorded in security logs with  Event ID 4699. Let's delete the scheduled task we have been discussing  so far and then filter the events with this event ID.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/4-+Scheduled+Tasks+Creation_Modification/13.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/14-edited.png)

Only the task name is visible in this event.

We can also find events related to scheduled task deletion in  Application and service logs under Microsoft->Windows->Task  Scheduler in operational logs. Here we can filter by Event ID 141 and  see the Task deletion event. Unfortunately these event logs don't  provide us detailed information like the security logs, here it only  records the task name and time when the event was recorded.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/150-edited.png)

We can only see the task names in deletion events. These events are  less useful then the ones discussed above but is still useful for  security analysts to track attackers activities.

In this lesson, we discussed the following Event IDs related to scheduled tasks.

**In Security logs**

- Event ID 4698: Task created. Shows task name, scheduled time and command to execute.
- Event ID 4699: Task deleted. Shows task name and time when deleted.
- Event ID 4702: Task updated. Shows task name, scheduled time and command to execute.

**For TaskScheduler logs under “Application and Services”**

- Event ID 106: Task created/registered shows task name.
- Event ID 140: Task updated.
- Event ID 141: Task deleted.
- Event ID 201: Task action completed and command executed.

### Questions

1 - How many scheduled tasks were created by a user account between the incident timeframe (13 January -14 January 2023)?

> **Answer:** 2

2 - What is the task name of the suspicious scheduled task?

> **Answer:** Connect_Backend_Server

3 - What is the command which is being executed by the suspicious task?

> **Answer:** C:\Users\LetsDefend\Documents\jbi-kkh39\nc64.exe

4 - Which port number is the backdoor communicating to?

> **Answer:** 4444

5 - What Time is the suspicious task scheduled for?

> **Answer:** 2023-01-14 19:28:13

6 - What is the updated description of the task which was modified by user account from the previously found created tasks?

> **Answer:** LetsDefend is awesome. This is the modified task

## Windows Services Event Logs

Windows services are background processes that run on Windows  computers. They can be configured to start automatically when the  computer boots and runs in the background, even when no user is logged  in. Services can be used to perform various tasks, such as running a  program that listens for incoming network connections, performing  maintenance tasks at predefined intervals, or running a program that  provides a specific service to other programs. Some examples of common  services include the Print Spooler, which manages print jobs, and the  Task Scheduler, which schedules tasks to be performed at a specific  time.

There are two types of services:

1. System services are installed as part of the operating system and  are intended to be used by the system, device drivers, and other  programs.
2. Application services are installed with an application and are intended to be used by that application.

There are a number of ways that attackers can abuse Windows services  to gain access to or compromise a system. Some common tactics include:

- Modifying the configuration of a legitimate service to execute malicious code or redirect the service to a malicious website.
- Creating a new service that runs malicious code or connects to a command and control(C&C) server.
- Disabling or stopping critical services to disrupt the normal functioning of the system.
- Exploiting vulnerabilities in the service executable or its dependencies to gain elevated privileges.

As discussed briefly previously, attackers install services on the  system to maintain persistence. There are hundreds of running services  on a Windows machine, making this an ideal place to blend in and set up a malicious service. They can name the service like a legit-looking  service in order to blend in and evade defenses. It's common for threat  actors to set up malicious services for Command and Control(C&C)  communication or reverse shells. Every time system boots up or a user  logins, the service gets executed depending upon how it was configured.  Attackers can maintain their remote access and can also act as a backup  Command and Control(C2) channel, in case their main C2 communication is  taken down or disrupted. Let's discuss the service that was  installed/created.

### Service Creation/Installation

We will be setting up the same binary we set as a scheduled task as a service. The binary was named “Windows Update” and was a meterpreter  reverse shell. Let's create a service.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/5-+Services+creation/1.png)

Service name is WindowsUpdateCritical and its friendly name is LetsDefend Event Log Demo for convenience.

Service Creation event is stored in System logs with event ID of  7045. We can filter systems log for event ID of 7045 and incident  timeframe for finding any possible suspicious activity during that time. Let's view in the Event Viewer.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/5-+Services+creation/2.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/300-edited.png)

We can see the file path for the service, time when service was  installed, the service name and start type of service. Auto start means  service will be executed whenever the computer boots up. Service type  denotes whether the service was installed by the user or by the  operating system for its operation. User mode service is of interest for security analysts as attackers setup these services themselves and it  is very rare to cause legit software to install malicious service on  behalf of attackers.

For example, here's a service handled by the kernel itself.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/40-edited.png)

It's important to look for service binary paths to find any benign  and suspicious looking binaries. In our case, a Windows Update binary  present in the documents folder of a User is surely a red flag. As a  security analyst if we spot suspicious binary via event logs of  services, we must get a copy of that suspicious file from the location  if it isn't yet deleted, and analyze. Lets upload this binary in  VirusTotal to see the results.

Here we can see the results that it's a malicious binary. Now in real scenarios, an attacker would be using a fully obfuscated malware to  evade EDR and AntiVirus and VirusTotal wouldn't be of much help in that  case. Then static and dynamic analysis should be done on the malware to  understand its behavior and adversaries capabilities. Since we are doing an exercise and this was a demonstration, we disabled antivirus for the time being.

In this lesson, we discussed how attackers can abuse Windows services for malicious intent and how to detect malicious installed services.

### Questions

1 - What’s the Service name which was created by a user account between January 13 and 14, 2023?

> **Answer:** Connect_Backend

2 - What's the binary path which will be executed as a Service?

> **Answer:** c:\users\LetsDefend\Documents\jbi-kkh39\reverse.exe

## Account Management Events

Attackers may add new users to a Windows system for several reasons.  One reason may be to gain persistence on the system. This means that the attacker wants to ensure that they can continue to access the system  even if their original method of access is discovered and blocked.  Adding a new user can allow the attacker to log in to the system using a different account, which may make it more difficult for defenders to  identify and stop the attack.

Another reason an attacker may add a new user to a system is to gain  additional privileges on the system. By default, newly created users  have relatively limited privileges, but an attacker may be able to  escalate their privileges by adding themselves as a member of certain  groups or modifying the permissions on certain system resources.

Attackers may also add a new user to a system simply as a means of  hiding their tracks. By using a separate account for their malicious  activities, the attacker can make it more difficult for forensic  investigators to identify which actions were taken by the attacker and  which were taken by legitimate users.

We will discuss user account creation and adding accounts to a group  from analyzing event logs in this lesson. These two activities are a  common tactic of attackers as a mean for persistence. These are also  more stealthy and less noisy then the 2 persistence techniques we  discussed in previous 2 lessons because there's no constant network  activity caused by these.

**Note:** User account changes are not logged by default and need to be enabled via Group Policy Object(GPO).

### New User Account Created

Let's create a new user.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/6-+Account+Management/1.png)

When a new user account is created, an event with Event ID 4720 is  recorded in Security logs. We can filter with Event ID 4720 and date  time of known incident time frame in order to find any possible accounts created by attackers. Let's view in the event viewer.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/6-+Account+Management/2.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/3000-edited.png)

We can see a message “A user account was created”. The Subject  account name is of the user account which created the new user account.  The New account “Account name” is user account which is created. In our  example, the user CyberJunkie created a new account named  “letsdefenddemo”. We can say that user “CyberJunkie” account was  compromised first and the account “letsdefenddemo” was created by the  attacker for persistence. Now the attacker can log on to this computer  anytime he/she wants as they created the user with their own password.  As a Security Analyst, we should make sure that endpoints always have  the required amount of users, and anything out of ordinary should be  looked into. Attackers often create accounts with names like "System  Administrator", “SysAdmin”, “helpdesk”, “supportdesk”, or names like  “Service accounts” etc. This way they can blend in the environment and  keep hidden.

### Adding a User to a Group

Attackers may add their newly created user account to a highly  privileged group like “Administrators” group. By default when a user  account is created, it has limited privileges. Attackers want higher  privileges so he/she can reach their goal faster and can do more damage. This is why it's important for security analysts to know how to catch  suspicious accounts with higher privileges added by threat actors.

Let's add the previously created user account “letsdefenddemo” to a high privilege group “Administrators”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/6-+Account+Management/4.png)

This event will be recorded in the Security log with event ID 4732.  We can filter with this event ID and date time of known incident  timeframe to find any suspicious activity. Let's filter and analyze this event.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/6-+Account+Management/5.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/60-edited.png)

First we will see the event information which says that a member was  added to a localgroup. The Subject Account Name is the user account  which added an user account to a localgroup. In the member section, the  Security ID shows the user account alongside the Domain/Computer Name  which was added to the localgroup. In the Group Section the Group Name  shows the localgroup in which the account was added.

For example if there was an incident around 2:00pm , and found the  events we discussed in this lesson on the compromised machine, It's  highly possible that the attacker created a new account and added it to  the Administrator group for persistence. Then we would track the  activities of the user account which created the new account as well as  track the new user account. Abusing account management is not only for  persistence, these activities are also performed by some exploits for  privilege escalation abusing vulnerabilities in Windows systems. These  include Print spooler exploits, Juicy potato, Hot potato etc.

In this lesson we discussed 2 important Event IDs:

**In Security Logs**

- Event ID 4720 : New User Account Created
- Event ID 4732 : User Account added to a localgroup

### Questions

1 - Which user account was added after 15 November 2022?

> **Answer:** CyberJunkie_SysAdmin

2 - In which local group was the user added?

> **Answer:** incidentresponders

## Event Log Manipulation

There are a few reasons why attackers might try to delete event logs:

1. To cover their tracks: If an attacker is able to compromise a  system, they may try to delete event logs to remove any evidence of  their actions. This can make it more difficult for administrators to  identify what happened and how the system was compromised.
2. To disrupt security monitoring: Event logs are an important tool  for security monitoring, as they can provide clues about potential  attacks or other security issues. By deleting event logs, an attacker  can make it more difficult for administrators to detect and respond to  security threats.
3. To avoid detection: If an attacker knows that their actions are  being logged, they may try to delete the logs to avoid being detected.  This can be especially useful if the attacker knows that the logs are  being regularly reviewed by security personnel.

It's worth noting that deleting event logs is not always easy, and an attacker may need to have high-level privileges on the system in order  to do so.

There are several ways to delete event logs, depending on the  operating system you are using and the level of access you have to the  system. Few of them are:

**1. Using the Event Viewer:** On Windows systems, you  can use the Event Viewer to delete event logs. To do this, open the  Event Viewer and navigate to the log that you want to delete.  Right-click on the log and select "Clear Log." Keep in mind that you  need to have administrator privileges to do this.

**2. Using the command line:** On Windows systems, you  can also use the command line to delete event logs. The command you will need to use is: "wevtutil.exe cl logname". For example, to delete the  Security log, you would use the command: "wevtutil.exe cl Security".

It wouldn't matter how the attacker deleted event logs, the same event would be generated in event logs when logs are cleared.

### Security Log Cleared

Lets first explore the events in Security logs whenever audit logs  are cleared. We have discussed and demonstrated so far how security logs are very important source of informations for analysts and aid us in  intrusion detection. This makes it a high priority target for attackers. If an attacker is covering his/her tracks, security logs will be one of the first ones. Event with Event ID 1102 is generated in the Security  log whenever its cleared and previous events are deleted. Events related to Security Log events getting deleted are only stored in Security Log  itself. Lets Explore this. We first deleted the events.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/7-+EventLog+Manipulation/1.png)

We are now left with 2 events, where 1 event is of interest to us.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/200-edited.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/88-edited.png)

We can see the time when the event was recorded, the message saying  audit log was cleared and the user who cleared the event logs. We would  want to track the user activity who deleted the event logs as that may  be a compromised account or a newly created one by the attacker.

### Any Audit Log Cleared/Deleted

We discussed many logs under “Application and Services Logs”. Any  event log deleted other than the Security Log, would be recorded in  System Log with event ID 104. Only the Security Log cleared event is  recorded in Security Log itself. Let's see this in action now. We  cleared System log, then powershell logs from “Application and Services  Log” and then cleared Microsoft Office alerts log.

First filter System Log with event ID 104.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/7-+EventLog+Manipulation/4.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/50-edited.png)

We can see 3 events. Let's explore the oldest one which would have the log we cleared first, in our case System log.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/63-edited.png)

We can see a message that indicates System Log was cleared.

Now see for Powershell Logs.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/71-edited.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/80-edited.png)

### Event Logging Disabled

Attackers can completely disable the event log service in order to  reduce their footprints. By default Event Log service starts with boot  up of the system. In order to stop this service higher privileges are  required. Let's disable event loggings.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/7-+EventLog+Manipulation/9.png)

Now any activities performed on the system will not be recorded in  event logs. However, an event with Event ID 1100 is generated in  Security Logs right before event logging is disabled. This is good news  for SOC analysts because this event could be fetched by the SIEM and  generate an alert before the attacker can reach his/her goal. Although  the rest of the attackers activities would not be logged, disabling  event logging is highly suspicious by itself and should be strictly  monitored.

Let's start the service again and analyze the event with filtering for event ID 1100.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/7-+EventLog+Manipulation/10.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/7-+EventLog+Manipulation/11.png)

We can see this event only gives us a description and not any other data. 

This is not a common event which is generated on a daily basis so  this is a high-value event. It is also important to note that this event is not generated when the computer shuts down, it's only generated when event log service is shutdown while the computer is up and running.

Now a question will pop in your mind, that if event logs can be  deleted and/or disabled what we studied so far seems to be wasted. No,  here's why.

1. To clear event logs, you need administrator privileges. So if the  attacker is not a high privilege account then this cannot happen.
2. In case an attacker gets high privileges through privilege  escalation and deletes event logs, all previous event logs and events  recorded during the intrusion (Attacker activities so far) would be sent off to SIEM, which would be obviously available in a SOC environment.
3. Attackers also don't delete event logs because this is a highly  noisy activity and certainly stands out. So by not deleting event logs,  there's a chance that their activities would blend in with thousands of  other events occuring at a time.

There are more advanced techniques used by threat actors to evade  defenses and hide there tracks, which are out of scope for this course.  We will discuss those advanced techniques in a future course.

In this lesson, we discussed some event IDs which allows us to detect possible suspicious activities performed by attackers in order to hide  their tracks.

- Event ID 1102: Security log cleared in the security log
- Event ID 104: Any log cleared in the system log
- Event ID 1100: Disabling Event Logging in the security log

### Questions

1 - At what time the firewall event logs got cleared on the incident time frame (January 13, 2023)?

> **Answer:** 1/13/2023 3:42:23

2 - When was the event logging got disabled around the incident time frame(January 13, 2023)?

> **Answer:** 1/13/2023 3:43:52

## Windows Firewall Event Logs

The Windows Firewall is native to Windows that helps protect your  computer by blocking unwanted connections from and to the Internet. It  does this by examining the inbound and outbound traffic to and from your computer and allowing or blocking traffic based on the rules you have  configured beforehand. You can use the Windows Firewall to block or  allow traffic for specific programs or services, or you can use it to  block or allow traffic based on the type of traffic, such as incoming  traffic from the Internet or outgoing traffic to a local network. You  can also use the Windows Firewall to block or allow traffic based on the IP address or domain name of the sender or recipient.

Firewall logs are very important in order to detect suspicious  network activity like internal port scanning, lateral movement or C2  communications. Windows Firewalls can also log dropped packets, which  may help us in analyzing network traffic for possible intrusions. There  are more reliable sources like hardware-based firewall logs being used  in corporate environments, Netflow for analyzing network traffic etc.  However, this course is about event logs so we will be focusing on that  aspect, and how attackers can tamper endpoints for their network  activity.

Attackers can try to trick a firewall by spoofing the IP address of a trusted host. If the firewall allows traffic from the spoofed IP  address, the attacker may be able to gain access to the network.

Let's assume we want to detect C2 communications using these events.  Windows Firewall can help protect against C2 communication in several  ways:

- **Blocking incoming C2 traffic:** Windows Firewall  can be configured to block inbound traffic from known C2 servers or  other untrusted sources. This can help prevent the compromised device  from establishing a connection to the C2 server.
- **Blocking outgoing C2 traffic:** Windows Firewall can also be configured to block outbound traffic to known C2  servers or other untrusted destinations. This can help prevent the  compromised device from sending sensitive information or other data to  the C2 server.

Attackers can tamper with firewall configuration for many reasons,  like when setting up persistence with a C2 beacon as a backup, they may  create a new rule or modify an existing one to allow inbound/outbound  traffic from that application with no restriction. They can also  configure such rules to exfiltrate data without any disruptions. We will be discussing events generated when a new rule is added, when an  existing rule is modified and when firewall is disabled.

### Firewall Rule Added to Exception List

Let’s add the same binary we have been using so far in the exception list which is “Windows Update”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/8-+Firewall/1.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/8-+Firewall/2.png)

The Events related to this will be stored under “Application And  Service Logs” under Microsoft->Windows->Windows Firewall with  advanced security in “Firewall” log file.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/8-+Firewall/3.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/8-+Firewall/4.png)

The Event ID we would be interested in this case is 2004. It's  important to note that Windows operating system keeps adding rules to  service applications as part of its operation, in this modifying user  would SYSTEM. Although if attackers escalate privileges, they can also  add rules with the same privileges so this doesn't mean we should  discard the events with the User SYSTEM. We must see the application  paths or ports number which were added in rule in order to spot anything suspicious. It was just mentioned because a lot of noise is generated  by those events which are of no importance to us as an analyst. We can  filter the events with Event ID 2004 and known incident timeframe if  any, which will help us cut off a lot of unnecessary events so it's  nothing to sweat on.

We just filtered with Event ID 2004 and see 387 events so far.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/51-edited.png)

These are lots of events, so let's apply filters for the last hour (Known Incident time).

Now only 6 events are available:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/61-edited.png)

Let’s analyze 2 events, one with the rule we just added for the  Windows Update file and one legitimate rule added by Windows itself as  part of routine.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/72-edited.png)

We can see the event description, rule name, either if it's active or not, and the direction of rule meaning if its set for inbound or  outbound, as in our case its outbound meaning this application will  communicate with an application/service in the internet which can be a  C2 Server, the application path of the binary for which this rule is  created. We can see that the path is not the correct path for the file,  this is because the rule is handled by the service account of windows  firewall. You can discard the path from **\windows\ServiceProfiles\LocalService\**. The full path will be of the User Profile of the modifying User in most cases. The modifying user is CyberJunkie so the actual path of the file is "C:\Users\CyberJunkie\Documents\Windows Update.exe". We can also see the protocol for which rule has been created, for example a rule  created for th UDP protocol after the incident time frame can be  suspicious as it can be an attempt of data exfiltration over DNS.

Now let’s explore a legitimate event to see the difference.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/8-+Firewall/8.png)

Here, we can see that Modifying Application is a Windows service  binary which handles network related activities. Also, the modifying  user is SYSTEM and there's no application for which this is configured,  as these rules are temporarily set by the system and are not persistent.

Look out for modifying applications values like MMC, PowerShell or  cmd. Because if someone adds a rule from the GUI of the firewall,  modifying applications will be mmc, similarly if done from cmd or  powershell those will be the modifying applications. These are important as these indicate that the rules were added either by human  intervention or by scheduled scripts. Any other application name would  usually denote that it's done by Windows.

### Modifying Existing Rule

Attackers can modify existing rules instead of adding new ones. The  reason can be anything like. For example, they don't want to catch the  attention of system administrators by adding new rules.

Let’s modify the rule we created above, and change a few things.  Events related to modification are stored in the same firewall event  logs and with Event ID 2005. We can filter with this event ID and known  incident time frame. Let's view the latest event of this event ID.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/9-edited.png)

Here, we see the rule name is changed, and the Protocol for the rule  is changed. Previously it was any protocol, now it's only for TCP.  Attackers can change the application path of legit rules to the path of  their malicious files, like a C2 Implant or a reverse shell.

The rule ID value can help us in knowing which rule was changed. An  attacker can entirely change the name of a rule from the original one  and then it would be difficult to know what was the original rule. The  Rule ID remains the same and cannot be modified, so even though an  attacker entirely modifies all aspects of a rule, the rule ID will be  the same and with rule ID we can figure out the event for the original  rule creation thus finding what things the attacker modified.

### Disabling Firewall

Attackers may also entirely disable Windows firewall for literally no restrictions related to network activity. Since this is a highly  suspicious event, it's monitored by SOC Analysts so attackers also  refrain from disabling this because this event would surely stand out as a suspicious activity. However, if they create/add rules there's less  chance of detection as those events would blend in among thousands of  other events at a time. Rules are constantly being added/deleted by  Windows OS as discussed above so in a corporate environment, attackers’  activities have less chance to catch an eye then the disabling firewall  one which will surely raise suspicions.

This event is also recorded in the same firewall event log as  discussed above. Whenever the Windows firewall application setting is  changed an event of Event ID 2003 is generated. We will be interested in this event with this event ID with New Setting Type “Enable Windows  Defender Firewall” and Value “NO”.  

 Let’s analyze the event. Let’s filter with the event ID and see.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/101-edited.png)

The Type field tells us what kind of setting was changed. The Value  "No" means that setting “Enable Windows firewall” is false and is not  enabled, which means it was disabled. If we find such an event around  the time of the incident, then we must track the User which disabled the firewall, as it can be a compromised account or new account added by an attacker.

Let's enable the firewall and see the Events just for demonstration.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/112-edited.png)

We can see the Value is “Yes” which means the setting “Enable Windows Defender Firewall” is true and enabled.

In this lesson, we discussed some important event IDs related to Windows Firewall and how attackers abuse these features.

- Event ID 2004: A new rule was added to the exception list.
- Event ID 2005: A rule was modified from the exception list.
- Event ID 2003: Firewall was disabled.

### Questions

1 - What's the rule name which was added by a user on January 13, 2023 between 3pm and 4 pm?

> **Answer:** Allow_Backend_Server_Connection

2 - What's the network direction configured for the rule?

> **Answer:** Outbound

3 - What's the protocol configured for the rule?

> **Answer:** Any

4 - What is the application name for which this firewall rule was added?

> **Answer:** reverse.exe

5 - What's the protocol after the rule is modified/updated?

> **Answer:** TCP

6 - At what time the firewall was disabled?

> **Answer:** 1/13/2023 3:54:31

## Windows Defender Event Logs

Windows Defender is a built-in Antivirus solution that protects your  computer against malware and other threats. It is included with Windows  10 and can be used to protect your computer even if you don't have any  other antivirus software installed. Windows Defender provides real-time  protection to scan your computer and detects the threats before they  occur. It can also scan your computer on demand to check for any issues. If it finds any threats, it will remove them or quarantine them to  avoid intrusion.

Windows Defender Logs can help us find historic malware detections or detections during time of incident. This may give us clue about the  attacker's goal. One of the first things that the attackers do when they control the systems is to disable Windows Defender to perform their  activities without being disrupted. We will discuss about these in event logs and why they are important for SOC analysts and Incident  Responders.

### Malware Detected 

Let’s analyze events when a malware or a malicious file is detected by Windows Defender. These events are stored under **“Application and Service Logs” under Microsoft->Windows->Windows Defender** in the Operational log file. Event ID for malware detection events is 1116. Let’s filter for this event ID.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/9-+Defender/1.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/210-edited.png)

There are 9 events some of which are about a month apart by the occurrence time and date. Let's analyze the latest one.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/310-edited.png)

The fields we can see are the detection time, the name of the  malware, severity which is an indicator on how dangerous the malware is, the path of the file that is located on the system, category of  malware, and the process name which is the actual agent that was  leveraged for the malware to be installed on the computer. In this case, it's explorer because we copied the malware from a safe location  (Folder which is excluded from defender scan) to a location where  defender can detect malware. Let’s try copying this from the CMD to see  the change.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/9-+Defender/4.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/56-edited.png)

Here we can see that the process name is cmd.exe.

These events can help us understand the type of malware or about the  malicious activities they are capable of on an endpoint which Microsoft  Defender will most likely be detecting. Attackers use obfuscated  tools/malwares to evade defenses but they most likely get stumble upon  the Antivirus engines as they constantly improve and update their  signature database with malicious signatures and take the advantage of  artificial intelligence for suspicious activities. That same malware  could have been bypassing Windows Defender when the attacker tested it,  but at the time of using its signature database will result in it being  detected.

### Malware Action Taken

After the Windows Defender detects malware or suspicious files, it  may take an action like removing the file or quarantining it. This  depends upon how the Windows Defender was configured. This activity is  also logged, with event ID 1117. Let's filter this and view. Let's view  the latest event.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/67-edited.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/73-edited.png)

We can see most of the information the same as the malware detection  event with some additional information. The event description tells us  what this event stands for, the action event indicates whether the  malware was deleted, quarantined or allowed. The error description says  whether this was successful or failed.

These events may be important in cases where an attacker is able to  place the malware successfully on the device, so in this case the  “Action” field is important to note. Also, the "Error description"  indicates whether the operation was successful or not.

### Disabling Real Time Protection

Windows Defender has a core feature called “Real Time Protection”  which is the main core of this Antivirus product. It detects threats in  real time as soon as it's present on the disk or run. If we disable this setting, new files will not be scanned by its engine in real time and  will fail to detect the malware.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/9-+Defender/8.png)

Attackers can also disable this if they have higher privileges and  then they can transfer their malicious tools for further exploitation in the network. This event is recorded with Event ID 5001. Let's analyze  this event.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/94-edited.png)

This event does not have any additional parameters as other events,  this event ID is solely for disabling of real time protection  irrespective of other variables. This is a highly suspicious event,  especially in corporate environments.

### Detecting Excluded Files and Folders

Attackers can exclude specific files or folders from being flagged  and scanned. For example, if an attacker wants to use Mimikatz to steal  some authentication tokens or impersonation tokens for a service, the  attacker can exclude the Mimikatz binary in Microsoft defender settings. This can also be applicable to any file or folders. Attackers can even  add the whole user profile to exclusion, meaning antivirus will not  perform detection and prevention on that path/file while still being  active and running. This is less noisy than disabling of the Windows  Defender itself but still benefits the attacker’s motivation and goal.

This event is recorded in the same event log file with Event ID 5007. This Event ID is not specifically for exclusion paths, but rather for  any configuration change in Windows Defender. This means that there will be a lot of unnecessary events recorded just like when Windows changes  settings for its regular operations. If the incident time frame is  known, we can reduce a lot of noise and try to find exclusion there.  This can help us find possible files or folders containing  malwares/tools being used by an attacker in an internal network while  still being undetected as they would have been added to exclusions. 

Let's analyze an event for demonstration.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/9-+Defender/10.png)

Let’s explore an exclusion related event and one legit configuration change.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/9-+Defender/11.png)

In event description we need to look for this path:
“**HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\**”

If this registry path is present, then this event would be related to Exclusions being added. Remember that event ID 5007 is logged for any  kind of configuration change so that’s why we need to look for this  specific path in those events to distinguish.
The actual exclusion path will be after the **\Paths\.** In our case it’s: “**C:\Users\pc\Desltop\CyberJunkie’s APT Tools**”

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/9-+Defender/12.png)

**In this Lesson we discussed:**

- Event ID 1116: Malware or suspicious files detected.
- Event ID 1117: Action taken against Malware or suspicious file.
- Event ID 5001: Real Time Protection disabled.
- Event ID 5007: File/Folder Excluded.

### Questions

1 - What malicious file was detected by Windows Defender after 4 PM on 13 January 2023?

> **Answer:** Invoke-Mimikatz.ps1

2 - What is the category of the malicious file?

> **Answer:** trojan

3 - What action was taken against the malicious file?

> **Answer:** remove

4 - Which folder was excluded last from the defender scanner around the time of the incident?

> **Answer:** C:\Users\LetsDefend\Documents

## Powershell Command Execution Event logs

PowerShell is a powerful tool that is included in many versions of  Windows, and it is often used by system administrators to manage their  systems. However, it may also be leveraged by the hackers to perform  their malicious activities. This is because PowerShell allows an  attacker to execute arbitrary code, access system resources, and control other programs through its extensive functionality. PowerShell can be  used to bypass security controls that are in place to protect a system.  For example, an attacker could use PowerShell to disable firewalls or  antivirus software, making it easier for them to carry out their attack. PowerShell has many built in cmdlets, modules which are made for legit  purposes but can be abused by attackers to blend in to look legit.  PowerShell also allows creating scripts, which an attacker can use to  maintain persistence by creating scheduled tasks for executing malicious scripts.

PowerShell is one of the most favorite tools that attackers like to  leverage and is widely abused by threat actors as it is so powerful.  Monitoring PowerShell activity can provide better visibility on  activities occurring on an endpoint. PowerShell commands are recorded  under “Applications and Services Logs” in  Microsoft->Windows->PowerShell->Operational.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/10-+Powershell/1.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/10-+Powershell/2.png)

Let's see what kind of events are present.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/38-edited.png)

We are interested in Event ID 4104 which has the Task Category of  “Executing a Remote Command” and the event level “Verbose”. In this  event, command executed is recorded along with some other relevant  information. When a single command is executed in PowerShell, there are a lot of events occurring in a short period of time related to that  command execution. Let’s see how to filter these events to eliminate  unnecessary noise and get the information useful to us.

First, we need to filter for only Event ID 4104, Event Level  “Verbose'' and date and time of incident if it's known. In our case,  let's assume that the incident occurred around January 5, 2023 around  2:02:00 AM at night.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/10-+Powershell/4.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/10-+Powershell/5.png)

Applying this filter will greatly reduce our events and make it  easier for us to analyze. Even if the event time is not accurately  known, filtering by the Event ID and the Event Level will save us from  all those events belonging to Task category “Executing Pipeline” which  are activities occurring in background by PowerShell when a command is  executed.

Let’s analyze the filtered events.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/65-edited.png)

We can see that 6 out of 29 events match our conditions. Let's view the data in the event which occurred first.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/76-edited.png)

We can see the command executed below the text “Creating Scriptblock  text” which is “whoami”. Time of the event was recorded right after the  command was executed. The user account and the Domain/Computer name were also recorded as helpful information. If we view the next event which  occurred immediately after this we can see “prompt” in the place where  there should be the executed command as well. After every command  executed in an event, we will see an event with this "prompt" string.  So, skip an event after the event holding the command information. After analyzing the first event we should skip to the third one, then the  fifth one and so on.

However sometimes PowerShell executes commands in the background which can still cause some noise in our filter.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/10-+Powershell/8.png)

Anyway, let's view Third event to see which command was executed after the first one.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/97-edited.png)

The third command is “Get-LocalUser” which displays available user  accounts on the computer. These kind of commands are expected from  threat actors after they gain initial access to a system as they start  enumerating the system to escalate privileges and move laterally. Now  let's see the fifth event.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Event-Log-Analysis/new/103-edited.png)

The command “Get-LocalGroup” displays the available groups on the  computer and is also part of the enumeration phase for attackers.

From the nature of these commands, it is obvious that these are not  commands that a legitimate user would execute. Also, these commands are  known to be used in the initial phase of post exploitation activities of threat actors. Any commands executed by attackers, like executing  malicious tools for e.g., mimikatz.exe from PowerShell would be logged  and would give us evidence of intrusions. From the example we discussed, it can be concluded that there's a confirmed intrusion in the system as these commands were executed shortly after the incident time. Then  further actions can be taken on the computer before the attacker causes  any more damage.

In this lesson we discussed:

- Event ID 4104 : Command Execution in PowerShell log.

### Questions

1 - What command was executed after 4:10 PM time on 13 January date by the attacker as part of internal enumeration?

> **Answer:** Get-LocalGroupMember Administrators





