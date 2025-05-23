# SIEM 101

What do SOC Analysts need to know about SIEM?

**Table of content:**

- [SIEM Introduction](#siem-introduction)

- [Log Collection](#log-collection)
- [Log Aggregation and Parsing](#log-aggregation-and-parsing)
- [Log Storage](#log-storage)
- [Alerting](#alerting)

## SIEM Introduction

Security information and event management (SIEM) is a security solution  that collects and interprets data within the organization and then  detects potential threats. Thanks to SIEM, security threats can be  monitored in real-time. In this training, we will explain how a SIEM  works in general. Without going too deep, we're going to provide you  enough information for the SOC analyst to understand what's going on  behind the scenes. At the end of the training, you will have a general  understanding of the following topics:

How does SIEM work? 

How does SIEM collect logs? 

Log storage 

Creating alerts

### **SIEM Products**

There are many SIEM solutions on the market. According to the Gartner 2021 report, the most successful commercial SIEM solutions are as in  the image below.

![siem products](https://ld-images-2.s3.us-east-2.amazonaws.com/SIEM+101/images/siem-gartner.png)

### **SIEM and SOC Analyst**

Potential threats detected with SIEM are reviewed by SOC analysts.  For example, you can think of the alerts on the LetsDefend Monitoring  page as alerts created by SIEM.

## Log Collection

First of all, we need data for the SIEM solution to detect threats. That's  why the log collection process is one of the most important parts of the SIEM architecture, because without the log SIEM would be useless.

### **What is Log and Logging?**

In computing, a log file is a file that records either events that  occur in an operating system or other software runs, or messages between different users of a communication software. Logging is the act of  keeping a log. In the simplest case, messages are written to a single  log file. *definition: wikipedia.org*

It contains a basic log, time, source system and a message. For example, when we look at the content of the "/var/log/auth.log" file on an  Ubuntu server, we can see the source, time and message information.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/SIEM+101/images/authlog1.png)

Our goal at this point is to transfer logs from various places (Hosts,  Firewall, Server log, Proxy, etc.) to SIEM. Thus, we can process all  data and detect threats at a central point. Logs are generally collected in the following 2 ways:

- Log Agents
- Agentless

### Log Agents

In order to implement this method, a log agent software is required.  Agents often have parsing, log rotation, buffering, log integrity,  encryption, conversion features. In other words, this agent software can take action on the logs it collects before forwarding them to the  target. For example, with the agent software, we can divide a log with  "username: LetsDefend; account: Administrator" into 2 parts and forward  it as:

message1 = "username: LetsDefend"

message2 = "account: Administrator"

**Pros of the method**

It is a tested, and a working application by the developers

Has many additional features like automatic parsing, encryption, log integrity, etc.

**Cons of the method**

As the additional features are activated,  resource consumption increases. That requires  the system's resources  such as CPU, RAM to be increased, so the cost increases.

**Syslog**

It is a very popular network protocol for log transfers. It can work  with both UDP and TCP, and can optionally be encrypted with TLS. Some  devices that support syslog: Switch, Router, IDS, Firewall, Linux, Mac,  Windows devices can become syslog supported with additional software.

You can have your log agents transfer logs with Syslog. For this, you must first parse your logs in syslog format.

**Syslog Format:** 

 Timestamp - Source Device - Facility - Severity - Message Number - Message Text 

![syslog log format](https://ld-images-2.s3.us-east-2.amazonaws.com/SIEM+101/images/09fig02.gif)

Also, the maximum packet size that can be sent with Syslog UDP is 1024 bytes. For TCP it is 4096 bytes.

**3rd Party Agents**

Most SIEM products have their own agent software. 3rd party agents  have more capabilities than syslog because of the features they support. Some agents:

Splunk: universal forwarder

ArcSight: ArcSight Connectors

These agents are easy to integrate into SIEM and have parsing features.

**Popular open source agents:**

- Beats https://www.elastic.co/beats/
- NXLog https://nxlog.co/

### Agentless

Agentless log sending process is sometimes preferred as there is no  installation and update cost. Usually, logs are sent by connecting to  the target with SSH or WMI. For this method, the username and password of the log server are  required, therefore there is a risk of the password being stolen. Easier to prepare and manage than the agent method. However, it has  limited capabilities and credentials are wrapped in the network.

**Manual Collection**

Sometimes there are logs that you cannot collect with existing agent  software. For example, if you cannot read the logs of a cloud-based  application with the agent, you may need to write your own script.

### Summary

As you can see, there are various ways to collect logs. These are agents and agentless. In cases where the agents on the market are not  sufficient, you should write your own scripts.

### Questions

1 - What is the best method for those who do not want to manage agent software?

> **Answer:** Agentless

2 - “Universal Forwarder” is the agent software of which product?

> **Answer:** splunk

## Log Aggregation and Parsing

The first place where the generated logs are sent is the log aggregator. We can edit the logs coming here before sending them to the destination.  For example, if we want to get only status codes from a web server logs, we can filter among the incoming logs and send only the desired parts  to the target.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/SIEM+101/images/aggregator1.jpg)

<iframe src="https://letsdefend.org/log-parser/" style="width:100%; height:500px;"></iframe>

### Aggregator EPS

**What is EPS?**

EPS is an event per seconds. The formula is Events/Time period of  seconds. For example, if the system receives 1000 logs in 5 seconds, EPS would be 1000/5 = 200. As the EPS value increases, the aggregator and storage area that should  be used also increases.

**Scaling the Aggregator**

More than one aggregator can be added so that the incoming logs do  not load the same aggregator each time. And sequential or random  selection can be provided.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/SIEM+101/images/aggregator2.jpg)

**Log Aggregator Process**

The log coming to the Aggregator is processed and then directed to  the target. This process can be parsing, filtering, and enrichment.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/SIEM+101/images/aggregator3.jpg)

**Log Modification**

In some cases, you need to edit the incoming log. For example, while  the date information of most logs you collect comes in the format  dd-mm-yyyy, if it comes from a single source as mm-dd-yyyy, you would  want to convert that log. Another example, you may need to convert UTC + 2 incoming time information to UTC + 1.

**Log Enrichment**

Enrichment can be done to increase the efficiency of the collected logs and to save time. Example enrichments:

- Geolocation
- DNS
- Add/Remove

**Geolocation**

The geolocation of the specified IP address can be found and added to the log. Thus, the person viewing the log saves time. It also allows  you to analyze location-based behavior.

**DNS**

With DNS queries, the IP address of the domain can be found or the IP address can be found by doing reverse DNS.

### Questions

1 - Which one is not the skill of a log aggregator?

- -filtering
-  -parsing
-  -analysis
-  -enrichment

> **Answer:** analysis

2 - What is the EPS of a SIEM system that receives 150000 logs per minute?

> **Answer:** 2500

## Log Storage

In our previous articles, we talked about logs and log aggregators. The next step is to store incoming logs.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/SIEM+101/images/storage1.jpg)

One of the common mistakes made in SIEM structures is to focus on  storage size. High-sized storage is important, as well as the speed of  accessing this data. For example, let’s say we collect all the logs such as WAF, Firewall, Proxy, etc. and imagine that it takes 15 minutes to  make a search in these logs. In a situation where it is so difficult to  access data, the studies will not be very productive. For this reason,  the speed of data access should also be considered in storage. 

When we look at the popular storage technologies in the market (Example: mysql), we see that it is focused on adding, editing, and deleting  data. But our focus is on indexing the data, we do not intend to edit  the stored log later. Our purpose is to access data as quickly as  possible. For this, WORM (write once read many) based technologies are  more suitable to be used in SIEM. 

More info about worm, write once read many: https://en.wikipedia.org/wiki/Write_once_read_many

The result of the first query was quite slow, while the second query  returned results instantly. While minor delays during investigation or  processing of new incoming data are acceptable, excessive delays can be  risky.

### Questions

1 - Is data update (change value, delete value etc) very important for SIEM data storage?

Answer Format: Y/N

> **Answer:** N

2 - Which one is the most important for SIEM storage?

- -Speed
- -Features
- -Price

> **Answer:** Speed

## Alerting

We have collected, processed and stored logs up to this point. Now, we  need to detect abnormal behavior using the data we have and generate  alerts.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/SIEM+101/images/alerting1.jpg)

Timely occurrence of alerts varies depending on our search speed. For a  log created today, we want to create a warning immediately instead of  generating an alert after 2 days. Therefore, as we mentioned in our  previous article, a suitable storage environment should be created. The alarms we will create for SIEM will usually be suspicious and need  to be investigated. This means that the alert must be optimized and not  triggered in large numbers (except in exceptional cases). Here are some ways to create an alert:

By searching stored data

Creating alarms while taking logs

Example alerts that can be created:

New user added to global administrator

15 Login failed in 3 minutes with the same IP address

In order to create a quality alert, you must understand the data you  have. Some of the techniques for making better log searches are  blacklisting, whitelisting and long tail log analysis.

### Blacklist

It can be used to catch undesirable situations. For example, we can  collect the prohibited process names (Example: mimikatz.exe) and write  them to a list. Then, if a process in this list appears in the logs, we  can create an alert. Similarly, an alert can be generated when there is a device that creates and accesses a banned IP list. It is easy to manage and implement, but very easy to bypass. For  example, if the name mimikatz2.exe is used instead of mimikatz.exe, no  alert will occur.

### Whitelist

Unlike blacklist, it is used for desired situations. For example, a  list of IP addresses with normal communication can be kept. If  communication is made with an address other than this list, we can  generate an alert. This method is highly effective but difficult to manage. The list needs  to be constantly updated.

### Long Tail Log Analysis

This method assumes that the behaviors that occur constantly are  normal. In other words, if an "Event ID 4624 An account was successfully logged on" log is constantly occurring on a device, with this method we should take it as normal and approach the least occurring logs with  suspicion.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/SIEM+101/images/alerting2.jpg)

picture: https://respond-software.com/ 

Good post about long tail log analysis: https://threatpost.com/long-tail-analysis-hope-cybercrime-battle/155992/ You can catch suspicious situations and create alerts using these 3 methods.

### Questions

1 - I have 2 IP addresses that are certain to be malicious. I want to create an alert when these are accessed. Which method should I use?

- -whitelisting
- -blacklist
- -long tail

> **Answer:** blacklist

2 - "The whitelist method is not only very effective but also very easy to manage." Is that true or false?

> **Answer:** false