# SIEM Log Collection and Parsing

The "SIEM  Log Collection and Parsing" course is dedicated to providing specialized training in log collection and parsing for Security Information and  Event Management (SIEM) systems. It focuses on equipping participants  with the skills and techniques necessary to effectively collect,  process, and interpret log data, essential for enhancing cybersecurity  measures within organizational frameworks.

**Table of Contents:**

- [Introduction to Log Collection and Parsing](#introduction-to-log-collection-and-parsing)
- [Determining Log Sources](#determining-log-sources)
- [Log Collection Methods](#log-collection-methods)
- [IBM QRadar - Firewall Log Collection](#ibm-qradar---firewall-log-collection)
- [IBM QRadar - Windows Log Collection](#ibm-qradar---windows-log-collection)
- [IBM QRadar - Linux Log Collection](#ibm-qradar---linux-log-collection)
- [Log Analysis and Parsing](#log-analysis-and-parsing)
- [Log Parsing with IBM QRadar](#log-parsing-with-ibm-qradar)

Evaluate Yourself with Quiz

- [SIEM Log Collection and Parsing](https://app.letsdefend.io/training/quiz/siem-log-collection-and-parsing)

## Introduction to Log Collection and Parsing

In the world of  information technologies, logs are records that provide valuable  information about the activities of systems, applications and devices.  These records contain details about when and how an event occurred. But  the meaning of these raw data is often complicated without collecting  and analyzing them effectively. At this point, the titles "log  collection", "log analysis" and "parsing" come into play.  

**Log Aggregation** is the process of  transferring logs from multiple sources (e.g. servers, network devices,  applications) to a central location. This allows organizations to access data from dispersed systems from a centralized perspective. Collection  is typically accomplished using log collectors, agents or routers.

**Log Analysis** is the process of  examining recorded log data in depth and revealing hidden information,  trends and patterns in this data. This analysis is a critical tool for  diagnosing performance problems in a system or application, detecting  security breaches, or understanding user behavior.

**Parsing** is the process of  transforming these collected logs into meaningful and questionable  information. Raw log data often comes as long strings of text whose  meaning is complex to humans. Parsing allows us to segment this complex  data and identify specific events, states or values. For example, we may extract an IP address or a username from raw log data.

Log collection, analysis  and parsing are critical in many areas, from security notifications to  performance monitoring, from error detection to regulatory compliance.  These processes help organizations both understand the current situation and anticipate future risks.

In this part of the  training, the subject of log collection and parsing was introduced. In  the next part of the training, the subject of “Determining Log Sources” is explained.

## Determining Log Sources

The effective functioning of SIEM (Security Information and Event Management) solutions depends  on identifying the correct log sources and collecting data from these  sources. Different log sources provide data in different types and  formats, so identifying these sources plays a critical role in the  success of the SIEM.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/2/image2-1.png)

(Image Source:   [https://layots.com/security-information-and-event-management-siem-solution-its-importance/ ](https://layots.com/security-information-and-event-management-siem-solution-its-importance/)  )

### Why is it important?

Determining log sources  is necessary for the detection and analysis of security events.  Different log sources provide unique information for threat hunting and  incident response processes. The importance of "Determining Log  Sources":

**Comprehensive Visibility**

Identifying the right log sources allows the organization to gain comprehensive visibility over  its entire network and systems. This is necessary to detect potential  threats and security breaches.

**Faster Detection and Response**

SIEM solutions can detect abnormal activities and security breaches in real time. However, this  depends on having accurate and complete log sources. Incomplete or  incorrect log sources can extend detection times.

**Regulatory Compliance**

In many industries,  organizations are required to comply with certain security standards and regulations. Identifying the right log sources plays a critical role in meeting compliance requirements.

**Data Integrity**

Data collected from  accurate log sources is essential for the accuracy of analyzes and  reports. Misleading, incomplete or inaccurate data can lead to incorrect security decisions.

**Optimization and Performance**

Collecting all log  sources may result in unnecessary data load and cost increase.  Identifying the right resources optimizes the performance of the SIEM by reducing unnecessary data traffic and storage costs.

**Strategic Planning**

Accurate log sources  guide the planning and implementation of the organization's security  strategy. Understanding which systems, devices, and applications are  most exposed to risk helps determine where to focus resources and  efforts.

As a result, "Identifying Log Sources" is a critical step that directly affects the success of  SIEM solutions. This process ensures that the right foundations are laid for effective security monitoring and incident detection.

### Important Log Sources

SIEM is a critical tool  for detecting, analyzing and responding to an organization's security  threats. For SIEM to work successfully, it is essential to collect data  from the correct log sources. Important log sources include network  devices (router, switch, firewall, etc.), servers and operating systems  (such as Windows, Linux, Unix), applications (web servers, databases,  e-mail servers), security solutions (antivirus software, IDS/ IPS  systems) and IoT devices (cameras, sensors). Logs from these sources  allow the SIEM to detect abnormal or suspicious activity in real time,  so security breaches can be quickly detected and responded to.  

Below is a summary table of important log sources: 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/2/log-table.png)

This table provides a  summary of the different log sources that can be considered in SIEM  solutions. However, since every organization's needs and infrastructure  are different, you can expand or customize this list to suit your  specific needs.  

In this part of the  training, determining log sources, the importance of determining log  sources and important log sources are mentioned. In the next part of the training, the subject of “Log Collection Methods” is explained.

## Log Collection Methods

A SIEM system collects  log information from various devices and systems to detect, analyze and  respond to security threats. Effective collection of these logs is the  basis of security analysis and incident response. Common log collection  methods include:  

### Collecting Logs with Agent

Agent-based collection is a method used to collect logs in a SIEM system. In this method, a  special software agent is installed on target devices, servers or  applications. Agents collect log information and route it for  transmission to a central SIEM system.

**Advantages**

- Agents can be customized to specific log formats or resources.  
- Agents can compress and encrypt logs and transmit them to the central system more quickly and securely.  
- Agents can collect logs in near real-time, allowing the SIEM system to respond faster to potential threats.  

**Disadvantages**

- Agent setup and management across multiple devices can be complex.  
- Agents use resources such as CPU and memory on the device on which they are installed, which may cause some performance issues.  

**Application Steps**

- An appropriate agent is selected according to the type of logs to be collected, the operating  system and the needs of the organization.  
- The selected agent is installed on the target devices or servers.  
- The agent is configured to determine which logs to collect, how often to collect them, and where to send the logs.  
- The agent is constantly monitored to ensure it is working properly. Additionally, updates  released for agent software should be applied regularly.  

**Suggestions**

- When adopting agent-based collection method, check whether agents are updated regularly.  
- Choose agents that provide encryption and compression of collected logs.  
- Periodically check the resource consumption of agents and prevent performance problems.    

### Agentless Log Collection

Agentless log collection is a method used in SIEM systems to collect log information directly  without installing any software agent on the target systems. This method generally collects log information over network protocols, especially  standardized protocols such as Syslog.

**Advantages**

- Management complexity is reduced because there is no agent installation, update and maintenance.  
- It is possible to collect logs from many devices and systems with industry standards such as Syslog.  
- Since no additional software is run on target systems, resource consumption is minimal.  

**Disadvantages**

- Agentless collection may be less flexible for some specific log formats or specific needs.  
- The risk of losing log information is higher in cases of network outages or heavy traffic.  

**Application Steps**

- The protocol to be used for agentless collection (e.g. Syslog, SNMP) is determined.  
- It is determined which devices and systems logs will be collected.  
- Necessary settings are made on the target systems to route the logs to the SIEM system.  
- The collected logs are transmitted to the SIEM system by filtering and compressing unnecessary information.  
- The agencyless collection process is constantly monitored to detect any interruptions or problems.  

**Suggestions**

- When using agentless collection, regularly check on target systems whether logs are correctly routed to the SIEM system.  
- Ensure the security of the protocol used for log collection; If possible, choose encrypted channels for log transmission.  
- Monitor the collection  process to identify potential bottlenecks or delays that may occur  during collection and take precautions.  

### Collecting Logs with Syslog

Syslog is a standard that was originally developed on *nix-based systems and is now supported on  many devices and platforms. This protocol allows network devices,  servers and applications to send log information to a central log  server. SIEM systems collect log information from these devices using  this protocol.

**Advantages**

- Syslog is widely used because it is a standard supported on a wide range of devices and platforms.  
- It has a simple structure to easily route and collect log information.  
- Log information from different devices and platforms can be collected in a single center.  

**Disadvantages**

- The standard Syslog protocol supports unencrypted transmission, which introduces the risk of logs being intercepted.  
- Since Syslog operates over UDP, there is a risk of logs being lost due to network problems.  

**Application Steps**

- A Syslog server (e.g. rsyslog, syslog-ng) is installed for a centralized log collection.  
- Devices and applications sending logs are configured to route to the Syslog server.  
- The format in which the logs will be sent (e.g. RFC3164, RFC5424) is determined.  
- If possible, encryption is done with protocols such as TLS/SSL to transmit log information securely.  
- Rules are created to filter unnecessary log information and direct important logs to specific files or systems.  

**Suggestions**

- Consider using  encrypted versions of Syslog (e.g. Syslog over TLS) to protect the  confidentiality and integrity of log information.  
- For high volumes of log traffic, opt for TCP-based Syslog transmission to prevent log loss.  
- Ensure that collected logs are periodically archived and backed up.  

### API Based Log Collection

API (Application  Programming Interface)-based log collection is a method of transferring  log information to the SIEM system using APIs offered by specific  applications, cloud services or platforms. This method involves  exchanging data in formats such as JSON and XML using HTTP/HTTPS  protocols, usually via web APIs.

**Advantages**

- Thanks to APIs, it offers the opportunity to collect customized log information from different sources.  
- Encrypted transmission over secure protocols such as HTTPS is supported.  
- Modern cloud services deliver log information through APIs.  

**Disadvantages**

- Some APIs limit the maximum number of logs that can be retrieved per second per request.  
- In situations with heavy log traffic, API requests can be costly.  

**Application Steps**

- Obtain API keys from the service from which you want to collect log information.  
- Review the API documentation to learn which endpoints to use and the required parameters.  
- Query log information at specific time intervals or specific events using relevant API endpoints.  
- The received log information is converted into a format that the SIEM system can understand (e.g. JSON to a native format).  
- The converted log information is transferred to the SIEM system and relevant analysis and alarming operations are performed.  

  **Suggestions**

- When making API requests, make regular and balanced queries, taking into account service outages and speed limitations.  
- Protect your API security keys and change them regularly.  
- Prevent data loss in  case of possible disruptions by temporarily storing the received log  information with caching or intermediate storage methods.  

### IBM QRadar Log Collection Methods

IBM QRadar offers a wide variety of log collection methods. Here are QRadar's log collection methods:

The most commonly used methods are log collection methods with syslog and wincollect.

**Collecting Logs with Syslog**

It is the most common log collection protocol. Network devices, security devices and many  operating systems can naturally send logs via syslog.

**Collecting Logs with Wincollect**

WinCollect for IBM QRadar is a tool for log collection from Windows-based systems. WinCollect  collects data from the Windows Event Log and transmits this data to  QRadar.

**Log Collection Using QRadar Log Source Extension (LSE)**

It enables the creation  of custom parsers and protocols for customized log sources. It offers  adaptation for complex log formats.

**Collecting with Directory/File**

Collects file-based logs  directly from the file system. Particularly suitable for file-based  logs, for example: Windows event logs.

**Collecting Network Traffic with QRadar QFlow**

It is used to collect network traffic content and metadata. Provides detailed data analysis with deep packet inspection (DPI).

**Log Collection with Database Protocol**

Collecting logs directly from databases via JDBC protocol. Ideal for database transactions and events.

**Collecting Logs with SNMP Traps**

It is used to collect SNMP trap information. Ideal for collecting alarms and event information from network devices.

**Log Collection with OPSEC/LEA**

Check Point collects logs from security devices. It is a method compatible with products such as Check Point Firewall and VPN.

**Log Collection with Microsoft Security Event Log over MSRPC**

Collects security event  logs from Windows servers and clients. It receives logs directly from  Windows machines via the MSRPC protocol.

**API Based Log Collection**

It is especially used for log collection from modern cloud services and web applications. JSON,  XML etc. via HTTP/HTTPS protocols. It takes logs in formats.

**Collecting Logs by Creating Custom DSM**

Customized parsers can be created for log sources that are not available in the existing DSM (Device Support Module) library.

These methods reflect  QRadar's versatile log collection capabilities. Depending on your needs, you can create an effective log collection strategy using one or more  of these methods.  

In this part of the  training, log collection methods, advantages, disadvantages and  application steps of these methods are mentioned. In the next part of  the training, the subject "IBM QRadar - Firewall Log Collecting" is explained.

### Question

1 - On which network protocol is there a risk of losing logs for Syslog?

> **Answer:** UDP

2 - From which platform (operating system) does IBM QRadar use the "WinCollect" tool to collect logs?

> **Answer:** Windows

3 - Which protocol and log collection method is ideal for database operations and events?

> **Answer:** JDBC

## IBM QRadar - Firewall Log Collection

In order to receive  firewall logs to QRadar, logs are sent to QRadar by defining syslog on  the firewall device. QRadar will collect these logs by default. QRadar  IP Address must be defined as the target IP address of the syslog  definition on the firewall device, and UDP 514 must be defined as the  target port.  

For example, syslog can be defined on pfSense Firewall as follows.

Syslog can be defined via pfSense -> Status -> System Logs -> Settings -> “Remote Logging Options” screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/4/image3-1.png)

You can view the firewall logs sent on QRadar via the QRadar -> Admin -> Data Sources -> Log Sources screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/4/image3-2.png)

Collected logs are  filtered by pressing the “Add Filter” button on the Qradar -> Log  Activity screen and pfSense events are filtered and displayed on the  “Log Activity” screen.  

The filter to be written  is selected from the “Log Source [indexed]” section and “Netgate  pfSense” is selected and the “Add Filter” button is pressed.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/4/image3-3.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/4/image3-4.png)

When you double-click on one of the events, the raw version and parsed outputs of the event can be seen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/4/image3-5.png)

In this way, a firewall log that sends logs via syslog can be easily imported to QRadar.  

In this part of the  training, it is mentioned how to collect firewall logs with QRadar. The  next part of the training explains the topic “IBM QRadar - Windows Log Collection”.

## IBM QRadar - Windows Log Collection

In order to receive the  logs on the Windows operating system to QRadar, the generally followed  method is to collect the logs with Wincollect Agent.  

Before installing Wincollect Agent on the Windows system, an "Authorization Token" is created on QRadar.

It is added with the "Add" button on the Qradar -> Admin -> User Management -> Authorized Services screen.  

Service Label, Security Profile and User Role information is determined as follows and saved with the Save button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-6.png)

The resulting token is saved for later use.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-7.png)

The relevant installation file is started on the Windows system where Wincollect Agent will be installed.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-8.png)

The license agreement is accepted and continued.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-9.png)

Continue by typing Customer Information information.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-10.png)

The directory where Wincollect agent will be installed is determined.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-11.png)

Installation type is selected as “Managed” and continued.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-12.png)

Console Connection  Parameters are added. At this stage, the token information created  through the console is added for “Authentication Token”. Console host  and port information is continued by typing QRadar console host/IP  information and 8413 port information, which is the default port.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-13.png)

Since the log source creation step is safer via the QRadar console, it is continued without taking any action at this stage.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-14.png)

Continue by making advanced settings.  

**Machine pool interval**: Specifies how many seconds it checks to collect events.  

**Event Rate Tuning Profile**: This specifies a profile used to tune the rate at which QRadar WinCollect collects events.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-15.png)

The address to which  Heartbeat parameters will be sent is determined. In All-In-One  installation, the same address is written as the QRadar console IP  address.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-16.png)

The screen where the installation parameters are summarized, the information is checked and if there are no errors, continue.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-17.png)

Click the “Install” button to start the installation.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-18.png)

After the installation is completed, click the “Finish” button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-19.png)

After the agent  installation on the server is completed, the Admin -> Data Sources  -> Events -> Log Sources screen opens via QRadar Console and click on “Log Sources (Managed Log Sources)”.

On the screen that opens, click on the “+ New Log Source” menu and select Log Source Type as  “Microsoft Windows Security Event Log” and proceed to Step2. 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-20.png)

Select the protocol type as “Wincollect” and proceed to Step3.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-21.png)

Log Source Parameters are selected and continue with Step4. At this stage, it is important to  determine “Name” and “Target Interval Destination”.  

**Name**: Determining the log source name  

**Target Interval Destination**: Determining how the log will be collected by QRadar

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-22.png)

Protocol parameters are determined and completed.  

**Log Source Identifier**: This credential helps identify the source from which the log data collected by QRadar comes.  

**Standard Log Types**: Which logs will be collected from the relevant system are determined and selected.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-23.png)

**Note**: The image above is a continuation of the previous screenshot.

**Event Types**: The severity of the events to be collected is determined.

**Wincollect Agent**: The relevant wincollect agent is selected.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-24.png)

In this way, the  "Wincollect Agent" installation and definition on the QRadar Console are completed and changes are deployed via the QRadar Console.  

QRadar Console -> Admin -> “Deploy Changes” button is clicked and the changes are deployed.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-25.png)

To check the added log source;  

“Log Sources (Managed Log Sources)” is opened and checked via the Admin -> Data Sources ->  Events -> Log Sources screen on the QRadar Console.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-26.png)

You can follow the logs  collected by “Wincollect Agent” on the relevant server by selecting  LAB-TEST as log sources by clicking “Add Filter” on the QRadar Console  -> “Log Activity” screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/5/image3-27.png)

In this way, logs can be collected to QRadar with “Wincollect Agent”.  

In this part of the training, it is mentioned how to collect Windows logs with QRadar. In the next part of the training, “IBM QRadar - Linux Log Collection” is explained.

## IBM QRadar - Linux Log Collection

In order to collect logs  from Linux distributions to QRadar, the logs are sent to QRadar with the rsyslog/syslog service on Linux. Sent logs are automatically recognized and collected by QRadar.  

To define syslog on Ubuntu 22.04, it is defined in the /etc/rsyslog.conf file as follows.  

The /etc/rsyslog.conf  file is opened with a text editor (e.g. vim) and a definition is made at the bottom of the file to send all logs, as follows.

*.* @qradar_IP_address  

After the definition is  made, the file is saved and the rsyslog service is restarted to make the definition active and the logs are sent to QRadar.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/6/image3-28.png)

“Log Sources (Managed Log Sources)” is opened and checked via the QRadar Console via the Admin  -> Data Sources -> Events -> Log Sources screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/6/image3-29.png)

You can follow the logs  sent from the relevant server by clicking "Add Filter" on the QRadar  Console -> "Log Activity" screen and selecting "Linux Server  @ubuntuvm" as the log sources.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/6/image3-30.png)

In this way, logs can be collected from Linux systems to QRadar.  

### Conclusion/Summary

This lesson and previous  lessons provide a comprehensive guide to learn how to use the QRadar  security information and event management platform and effectively  collect log data from Windows, Linux and firewall devices. These  sections of the training teach how to integrate QRadar with different  data sources and how to analyze log data from these sources and detect  threats. In the next part of the training, “Log Analysis and Parsing” is explained.

## Log Analysis and Parsing

Log analysis and parsing  have become an important need faced by information technology  professionals in today's IT world. Logs contain records from computer  systems, networks and applications, and are used for many purposes such  as reviewing these records, debugging, detecting security threats and  monitoring system performance. Experts in this field need special skills and tools to understand, analyze logs, and extract meaningful  information from them.  

Additionally, Log  Analysis and Parsing is of critical importance for SIEM projects. Log  analysis and parsing increases the functionality of SIEM solutions  because it makes data more meaningful and actionable. Effectively  analyzing logs helps detect potential security breaches faster, evaluate incidents more accurately, and help the security team respond to  incidents faster. Additionally, log analysis and parsing play a critical role in meeting data management and compliance requirements in SIEM  projects, as many regulatory agencies mandate regular monitoring and  preservation of log records. Therefore, log analysis and parsing are  indispensable for the success of security-focused SIEM projects.  

### Log Analysis Fundamentals

Log analysis is the  process of examining log files from various sources and extracting  meaningful information from these logs. Details about log analysis:  

**What is Log?**

Files containing log  records produced by a computer or network system. Logs are used for many purposes such as recording events, debugging, monitoring and detecting  security incidents.  

**Sample Log Types**

- **Operating System Logs:** Records operating system-related events, e.g. logins, shutdowns, error messages.  
- **Application Logs:** Logs produced by applications are used to monitor application behavior and errors.  
- **Security Logs:** Records security-related events and is used to detect malicious activities.  
- **Network Logs:** Logs produced by network devices and servers are used to monitor network traffic and connections.  

**Structure of Log Files**

Log files are generally  text-based and each line represents a log record. Each log record  usually contains fields such as a timestamp, source, event type, and  details. Log files can be in different formats, for example JSON, XML,  CSV, etc.  

Additionally, there may  not be a standard or structure for keeping log data, but log files have a general structure and commonly used components.

- **Timestamp:** Contains the date and  time information when the log record was created. Usually a specific  timestamp format is used, such as "yyyy-MM-dd HH:mm:ss".
- **Source:** Indicates which system,  application or device the log record comes from. This is important to  determine which source the logs come from.
- **Event Type or Log Level:** It refers to the type or  severity level of the log record. Generally, levels such as DEBUG, INFO, WARNING, ERROR, CRITICAL are used.
- **Event Description:** Contains a detailed  description of the log record. It may contain different information  depending on the content of the log, for example error messages, process name, user activity, etc.
- **Identity:** It may contain  information indicating which user or entity created the log record. This is important for security monitoring purposes.
- **IP Address or Host Name:** May contain the IP  address or host name of the device on which the relevant event occurred. It is especially important for network logs.
- **Additional Information:** It may contain additional information specific to the event. For example, details such as port  number, protocol used, processing time can be provided as additional  information.
- **Event ID or Number (Event ID):** May contain a unique ID or number of the event. This is useful for tracking events and debugging.
- **Log File Name or Source File:** Indicates which log file  the log record comes from. It provides ease of monitoring and analysis  when there are logs from more than one source.
- **Log File Format:** Specifies the format of the log file. Formats such as text, JSON, XML, CSV are commonly used.

### Log Analysis Tools

There are various tools  and software to perform log analysis. These tools provide the ability to search, filter, analyze and report logs. It is also used by  professionals such as system administrators, security experts, and data  analysts to analyze and understand log data. 

**ELK Stack (Elasticsearch, Logstash, Kibana):**

- ELK Stack is an open source platform used to collect, store, analyze and visualize log data.  
- Elasticsearch offers a fast search engine for searching and querying log data.  
- Logstash collects, organizes and imports log data from various sources into Elasticsearch.  
- Kibana is used for visualization and data analysis.  

**Splunk:**

- Splunk is a platform for big data analysis and log management.  
- It has the capabilities to collect, index and query log data.  
- Meaningful information can be extracted from logs with a powerful query language.  
- It is frequently used especially in security and compliance monitoring areas.  

**Graylog:**

- Graylog is an open source platform with capabilities to collect, process and visualize log data.  
- It can collect and analyze logs from multiple sources.  
- Supports security monitoring processes by generating alerts and reports.  

These tools have  different capabilities in collecting, analyzing, visualizing and  reporting log data. The choice should be made depending on the need and  requirements of the project. Factors such as security monitoring,  debugging, performance monitoring, and compliance requirements play an  important role in determining which log analysis tool to use.

### Regex

Regex (regular expressions) is a powerful tool used in text processing and searching.  Regex is used to identify certain patterns and find or replace text that fits those patterns. Knowing regex is an important skill and tool in  SIEM projects. SIEM processes log data from different sources to monitor and analyze security events. This log data can often be in various  formats and structures.  

Reasons explaining the importance and benefits of knowing regex in SIEM projects:

- **Filtering and Extracting Log Data:** In SIEM projects, it is  very important to filter log data and extract unwanted information to  analyze security events. Using Regex, it becomes possible to filter  specific events or data and focus only on information of interest. For  example, you can select only events from a specific IP range or logs  that contain a specific event type.
- **Normalization:** Organizing and  normalizing log data is a critical step for a SIEM system. Regex can be  used to convert log data from different sources into the same structure. Especially in cases where log files are in different formats, regex  ensures that the data is brought to the same standard format. This helps in accurate identification and analysis of events.
- **Threat Detection:** To detect security  threats, regex can be used to identify specific threat patterns or  anomalies. Regex expressions are used to define certain patterns,  especially to track attack attempts or malware activities. In this way,  potential threats can be detected faster.
- **Analysis and Reporting:** SIEM projects analyze  security events in detail and create reports and present them to  security experts. Using Regex, it is possible to select and analyze log  data containing specific events or conditions and create detailed  reports based on this data.

Regex knowledge is  crucial for effectively processing log data and detecting security  incidents in SIEM projects. This capability helps security professionals analyze log data quickly and accurately, improving organizations'  processes for detecting and responding to vulnerabilities.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/7/parse-table.png)

Examples;

```txt
Sample logs: (sample.txt file)
User: john.doe@example.com, Visit this website: https://www.example.com
Server IP: 192.168.1.1, Send an email for information: info@company.com
Document server: ftp://fileserver/documents, IP: 10.0.0.2
For more information, visit: http://website.org/page          
```

### Example-1: Finding Email Addresses

**Command:**   grep -oE '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\ b' sample.txt 

This command finds valid email addresses in the text.

**Detail:**

**\b**   : Marks the beginning and end of the word.

**[A-Za-z0-9._%+-]+**   : Defines the username of the e-mail address. Uppercase letters, lowercase letters, numbers, and  certain special characters (period, underscore, percent sign, plus sign, etc.) are allowed here and at least one character is required.

**@**   : Represents the "@" symbol of the e-mail address.

**[A-Za-z0-9.-]+**   : Defines the domain part of the e-mail address. Here again, uppercase letters, lowercase  letters, numbers, and certain special characters (dots and dashes) are  allowed and at least one character is required.

**\.**   : Indicates the dot character.

**[A-Za-z]{2,}**   : Represents the top-level domain of the email address. This section must contain at least two letters.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/7/image4-1.png)

### Example2: Finding IP Addresses

**Command:**   grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' sample.txt

This command finds IP addresses in text.

**Detail:** 

**\b**   : Marks the beginning and end of the word.

**([0-9]{1,3}\.){3}**   : This part represents  the first three sets of digits and a dot character of the IP address.  Here are more detailed explanations:

**([0-9]{1,3}\.)**   : Represents the first  three groups of digits. Within this group, each digit can have 1 to 3  digits (for example, 1, 12, 123). The dot character is found at the end  of each group of digits.

**{3}**   : This group is repeated three times, representing four groups of numbers.

**[0-9]{1,3}**   : This represents the last group of digits. Each digit can be 1 to 3 digits long.

**\b**   : Marks the beginning and end of the word.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/7/image4-2.png)

### Log Parsing

Log parsing is the  process of analyzing the data in log files and converting them into  meaningful information. Log files are text-based files that record  events and information recorded from a computer system, network, or  application. These files can often have different structures and formats and can be difficult for humans to read and understand. Log parsing  organizes these log files, extracts certain data and converts it into a  structured format, making it easier to analyze and monitor this data.

SIEM is a set of security technologies and processes used to monitor, analyze and respond to  security events. SIEM collects security events and information from a  variety of sources, analyzes this data, and provides alerts and reports  to security professionals.  

The relationship between log parsing and SIEM can be explained as follows:

- **Collection of Log Data:** SIEM collects log data from different sources. This log data can often be in different formats and structures.
- **Log Parsing:** The collected log data is passed through the log parsing process. At this stage, the data in the  log files are analyzed, parsed and structured. It is especially  important to convert the data into a consistent format and clean up  unnecessary information.
- **Extraction of Meaningful Information:** The log parsing process  allows the extraction of meaningful information from log data. For  example, it is possible to extract critical information such as IP  addresses, user IDs, event types, date-time information from a log  record.
- **Log Analysis:** The data obtained as a  result of log parsing is analyzed by the SIEM system. During this phase, security incidents and threats are detected, patterns and anomalies are looked for, and notifications are sent to security experts.

Below you can see an  example that extracts IP addresses and accessed URLs from a log file  using the Linux command line using the grep command and regex.

Sample logs to be parsed:

```txt
192.168.1.100 - - [21/Sep/2023:14:30:45 +0300] "GET /page1.html HTTP/1.1" 200 1234
192.168.1.101 - - [21/Sep/2023:14:31:12 +0300] "GET /page2.html HTTP/1.1" 404 567
192.168.1.102 - - [21/Sep/2023:14:32:05 +0300] "GET /page1.html HTTP/1.1" 200 987

                  
# Using grep and regex to extract IP addresses
grep -oE "\b([0-9]{1,3}\.){3}[0-9]{1,3}\b" access.log

# Using grep and regex to extract accessed URLs
grep -oE '"GET [^"]+"' example.log | cut -d' ' -f2

                  
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/7/image4-3.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/7/image4-4.png)

As a result, log parsing  is a key component of SIEM projects because SIEM uses log data to  monitor and analyze security events. Log parsing allows this data to be  processed and made meaningful so that security incidents can be detected and responded to more effectively.  

In this part of the  training, what log is, the structure of log files, log analysis tools,  how to perform log analysis with regex, what log parsing is and examples of these topics are mentioned. In the next part of the training, the  topic “Log Parsing with IBM QRadar” is explained.

### Question

1 - What is the information indicating the date and time when the log record was created?

> **Answer:** timestamp

2 - What is the name of editing and normalizing log data?

> **Answer:** Normalization

3 - How many source IP addresses starting with 10 are there in the log file?

Connect to the lab and answer the rest of the questions. 

**File Location:**  /root/Desktop/QuestionFiles/apache.log

> **Answer:** 12

4 - Which is the referer URL that appears the most in the log file? (Type full URL.)

> **Answer:** http://www.referer20.com/congrats

5 - How many responses in the log file have HTTP response status code 302?

> **Answer:** 4

6 - How many POST request log entries are there in the log file?

> **Answer:** 12

## Log Parsing with IBM QRadar

In cases where data is  transmitted to QRadar but not parsed by QRadar or when more advanced  parsers are needed, new parsers can be written using “DSM Editor”.  

For example, let's start  with Suricata events, which we know as Network IDS, transmitted to  QRadar. We can see the sent events on the "Log Activity" screen, but the "Log Source" section appears as "SIM Generic Log" and the "Low Level  Category" section appears as "Stored". This situation; This means that  QRadar collects the logs but cannot parse them.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/8/image4-5.png)

For the parsing process, one of these logs is selected and the Actions -> DSM Editor section opens.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/8/image4-6.png)

On the screen that opens, the relevant log source, if any, is selected from the "Select Log  Source Type" section, otherwise a new one is created by clicking "Create New".

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/8/image4-7.png)

On the screen that opens, you can see that the relevant event cannot be parsed.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/8/image4-8.png)

To start the parsing  process, first determine the “Event ID”. To do this, Event ID is  selected from the “Properties” section and a specific section within the log is selected to ensure that all events coming from the relevant  source are parsed with this parser.  

**By**   typing:  “suricata\[\d+\]\:” in the Expression section, the unique value in the  log is filtered and all future suricata events are included in this  parcel. In other words, since there is a special character after the  suricata expression, the square brackets are preceded by an escape sign  followed by decimal values, so the regex is defined by closing the  square brackets and specifying the next ":" value with an escape  character.

**Format String**  : The expression to be written to the Event ID field is written.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/8/image4-9.png)

The subsequent logs are  mapped either to an existing event or by creating a new QID. A new Event ID is created by pressing the + button on the “Event Mappings” screen.  

Event ID and Event Category values are determined and “Choose QID...” is selected to determine the QID.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/8/image4-10.png)

A new QID value is created by selecting “Create New QID Record” on the screen that opens.  

**Name**  : QID Name  

**Log Source Type**  : Log source type is selected.

High Level Category and Low Level Category options are selected.

**Severity**  : Level is determined.

It is saved with the Save button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/8/image4-11.png)

The created QID name and QID value are checked and the OK button is pressed.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/8/image4-12.png)

On the screen that opens, the values are checked and the mapping is created by pressing the "Create" button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/8/image4-13.png)

Next, parse the fields in the log. Available fields are available on the Properties screen. If we are going to assign it to an existing field, we can directly select  that field or recreate it if it does not exist. For example, since there is no field name for the Alert Category in the Suricata log, we create a new one.  

Properties -> + button is pressed.  

Alert Name, Field Type and Description fields are filled in.  

**Enable for use in Rules, Forwarding Profiles and Search Indexing**  : Select and press the "Save" button in order to search for the relevant field.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/8/image4-14.png)

From the Properties  section, the newly added "Alert Category" property is selected and  parsing is performed with regex in the Expression section.  

To read the Classification value in the log:  

A regex is written as  \[Classification\:\s+(.*?)\] Here, the Classification expression is “:”  after the [ character and “\s+” for space.

(.*?)\] is the value up to the square brackets to be taken.  

**Note**  : The places in parentheses are the part that is extracted/extracted from the parsed data.  

As seen below, the “Potentially Bad Traffic” part is parsed.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/8/image4-15.png)

For Source IP, which is  one of the existing Properties, "Source IP" is selected from the  Properties section and the relevant regex is written by selecting  "Overwrite system behavior". $1 allows writing the extracted data in the log to the relevant field.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/8/image4-16.png)

For Destination IP, which is one of the existing Properties, "Destination IP" is selected from  the Properties section and the relevant regex is written by selecting  "Overwrite system behavior". $1 allows writing the extracted data in the log to the relevant field.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/8/image4-17.png)

Similarly, parsing is applied and saved in the same way for the “Source Port” and “Destination Port” options.  

You can see that the  incoming logs are parsed by going to the Log Activity screen and  filtering the relevant source as Log Source.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/8/image4-18.png)

The situation when looking at the details of the log:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Collection+and+Parsing/8/image4-19.png)

Parsing can be done this  way with QRadar. With this method, log sources that are not parsed by  QRadar are parsed, making it possible to write more meaningful analyzes  and rules/correlations.  

In this part of the training, how to perform log parsing with IBM QRadar is mentioned.

### Question

1 - Which tool can we use to edit the logs that are transmitted to QRadar but not parsed?

> **Answer:** **DSM Editor**

2 - What expression is included in the “Low Level Category” section for logs belonging to log sources  that are transmitted to QRadar but not parsed?

> **Answer:** Stored



























































































