# Security Solutions

Get familiar with Firewall, IPS/IDS, Antivirus, EDR and more!

**Table of content:**

- [Introduction to Security Solutions](#introduction-to-security-solutions)

- [Intrusion Detection System (IDS)](#intrusion-detection-system-ids)
- [Intrusion Prevention System (IPS)](#intrusion-prevention-system-ips)
- [Firewall](#firewall)
- [Endpoint Detection and Response (EDR)](#endpoint-detection-and-response-edr)
- [Antivirus Software (AV)](#antivirus-software-av)
- [Sandbox Solutions](#sandbox-solutions)
- [Data Loss Prevention (DLP)](#data-loss-prevention-dlp)
- [Asset Management Solutions](#asset-management-solutions)
- [Web Application Firewall (WAF)](#web-application-firewall-waf)
- [Load Balancer](#load-balancer)
- [Proxy Server](#proxy-server)
- [Email Security Solutions](#email-security-solutions)

## Introduction to Security Solutions

Many  products and technologies are used to protect digital devices and  networks within a large institution or small business. A single method  or product is insufficient to provide security against attackers and  detect security breaches. Security can be achieved with many products  and technologies. SOC analysts and cyber security department managers  are the human resources that are effective and necessary in providing  cyber security. The element that provides cyber security outside of  human resources or together with human resources is cyber security  products. There are cyber security products with many different tasks to detect and prevent corporate security breaches.

In this training, it is mentioned what the hardware and software used as cyber security products are, what features they have, and for what  purpose they are used. Although it is theoretical, this training  contains essential information about cyber security products. It is  recommended that everyone working in the cyber security sector,  especially SOC analyst candidates, complete the topics in this training  without skipping.

## Intrusion Detection System (IDS)

### **What is IDS?**

An Intrusion Detection System (IDS) is hardware or software used to  detect security breaches and attacks by monitoring a network or host.

### **Types of IDS**

There are many different types of IDS products:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image.png)

### **Network Intrusion Detection System (NIDS)**

Network Intrusion Detection System (NIDS) is used to detect whether  there is traffic suitable for attacker behavior by passing all traffic  on the network through it. When abnormal behavior is observed in the  traffic, an alert can be generated and the administrator can be  informed.

### **Host Intrusion Detection System (HIDS)**

The Host Intrusion Detection System (HIDS) works on a specific host  in the network. It tries to detect malicious activities by examining all network packets coming to this device and all network packets going  from this device. Detected malicious behaviors are reported to the  administrator as an alert.

### **Protocol-Based Intrusion Detection System (PIDS)**

A protocol-Based Intrusion Detection System (PIDS) is a type of IDS  that examines the traffic between a server and a client in a  protocol-specific way.

### **Application Protocol-based Intrusion Detection System (APIDS)**

An Application Protocol-Based Intrusion Detection System (APIDS) is a type of IDS that tries to detect security breaches by monitoring  communication in application-specific protocols.

### **Hybrid Intrusion Detection System**

A hybrid Intrusion Detection System is a type of IDS in which two or more violation detection approaches are used together.

### **Functions of IDS**

- Detecting security breaches according to the detection methods used by the IDS product is the main task of the IDS product.
- When IDS detects a security breach, the administrator is informed, and/or this information is sent to the SIEM product.

**Note:** For detailed information about “SIEM”, you can refer to the “SIEM 101” training. You can access it from the link below:

**SIEM 101:** https://app.letsdefend.io/training/lessons/siem-101

### **Importance of IDS for Security**

IDS is a product developed to detect malicious behavior. It can be  said that security is lacking in a network without IDS. Because IDS is  one of the products that has reached a certain technological maturity.  Due to its task, it is very important to detect security breaches. It is recommended to be used with other security products rather than alone.  Since the IDS product does not have the ability to take action, it will  be more effective to use it with a security product that has the ability to take additional action.

Some popular IDS products used in the cybersecurity industry are as follows:

- **Zeek/Bro**
- **Snort**
- **Suricata**
- **Fail2Ban**
- **OSSEC**

### **What log sources does the IDS have?**

During its operation, IDS detects security violations according to  previously established rules. Therefore, it is very important how much  the written rule defines the attack. If the written rule cannot detect  the attack or detects the normal behavior as an anomaly, the rule should be changed or the incoming alerts should be reviewed by the analyst.  Among the IDS logs examined by the analyst, there is information in the  network packets regarding the security breach.

**Note:** For detailed information about IDS logs, you  can refer to the "Network Log Analysis" training. You can access it from the link below:

**Network Log Analysis:** https://app.letsdefend.io/training/lessons/network-log-analysis

### **Physical Location of the IDS Device**

The location of the IDS device in the network may vary depending on  which type of IDS it is. For example, a NIDS-type device must pass all  packets coming into the network over it. Therefore, it is more suitable  to be positioned close to the network devices that provide access to the external network. A HIDS-type device, on the other hand, should be  positioned close to the host in the network because it only examines the network packets coming to and leaving a certain host.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-1.png)

(Image Source: https://www.comodo.com/ids-in-security.php)

In this part of the training, what the IDS device is, its types,  tasks, and its importance for security were discussed. In the next part  of the training, the subject of **“Intrusion Prevention System (IPS)”** will be explained.

### Questions

1 - How many of the following are tools in the IDS type?

1. Snort
2. Volatility
3. OllyDbg
4. Suricata
5. Zeek/Bro
6. REMnux

**Answer Format:** X 

**Sample Answer:** 7

> **Answer:** 3

2 - According to the Snort IDS log, what is the IP address from which the response came? 

  ![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/question-2.png)

**Answer Format:** X.X.X.X 

**Sample Answer:** 192.168.1.100

> **Answer:** 4.2.2.3

3 - Check the Snort IDS log, according to the OSI model, which layer 7 network protocol does it belong to?

**Note:** Enter the abbreviation of the Protocol name. 

**Answer Format:** XXX 

**Sample Answer:** FTP

> **Answer:** DNS

**NOTE:** You can use the machine to solve the questions from the hands-on section above. 

4 - What is the HTTP request method according to the given Zeek IDS HTTP log? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\zeek-http.log.zip 

**Answer Format:** METHOD 

**Sample Answer:** HEAD

> **Answer:** GET

5 - What is the FTP command used for file transfer according to the given Zeek IDS FTP log? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\zeek-ftp.log.zip 

**Answer Format:** XXXX 

**Sample Answer:** LIST

> **Answer:** RETR

## Intrusion Prevention System (IPS)

### **What is IPS?**

An Intrusion Prevention System (IPS) is hardware or software that  detects security violations by monitoring a network or host and prevents security violations by taking the necessary action.

### **Types of IPS**

There are many different types of IPS products:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-2.png)

### **Network-Based Intrusion Prevention System (NIPS)**

Network-based intrusion prevention system (NIPS) is a type of IPS  that detects security violations and eliminates security violations by  monitoring all incoming traffic to the network it is in.

### **Host-Based Intrusion Prevention System (HIPS)**

Host-based intrusion prevention system (HIPS) is software that monitors and analyzes suspicious activities for a host.

### **Network Behavior Analysis (NBA)**

Network Behavior Analysis (NBA) is a type of IPS that detects and  blocks unusual traffic flows and Denial of Service (DoS) attacks on the  network.

### **Wireless Intrusion Prevention System (WIPS)**

A Wireless Intrusion Prevention System (WIPS) is a type of IPS that  monitors and analyzes wireless network protocol traffic of wireless  devices in a network.

### **Functions of IPS**

- IPS is responsible for preventing malicious behavior by detecting security breaches.
- It notifies the relevant authorities of the security breach encountered during monitoring as an alert.

### **The Importance of IPS for Security**

IPS is an important security product that should be included in an  organization. Having the ability to take action against the security  breach it has detected makes a great contribution to ensuring security.  As with any security solution, it must be used and configured correctly. It is not recommended to be installed and left to work without constant control by the personnel. It must be followed by the cyber security  personnel whether the IPS product is working or not and whether it takes the right action.

Some popular IPS products used within the cybersecurity industry are as follows:

- Cisco NGIPS
- Suricata
- Fidelis

### **What log resources does IPS have?**

The IPS device has log content similar to the IDS device. In terms of their duties, IDS and IPS have similar features at one point. Some of  the information that can be included in the IPS logs is as follows:

- Date/Time Information
- Message About the Attack
- Source IP Address
- Source Port
- Destination IP Address
- Destination Port
- Action Information
- Device Name

**Note:** For detailed information about IPS logs, you  can refer to the "Network Log Analysis" training. You can access it from the link below:

**Network Log Analysis**: https://app.letsdefend.io/training/lessons/network-log-analysis

### **Physical Location of IPS Device**

The location of the IPS device in the network may vary depending on  which type of IPS it is. In general terms, it should be placed at  whatever point it needs to be located in the network due to its task.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-3-1024x723.png)

(Image Source: https://study-ccna.com/firewalls-ids-ips-explanation-comparison/)

In this part of the training, what the IPS device is, its types,  tasks, the importance of security, and the information that can be found in the logs of the IPS device were discussed. In the next part of the  training, the topic of **“Firewall”** will be explained.

### Questions

**NOTE:** You can use the machine to solve the questions from the hands-on section above.

1 - According to the given Suricata IPS log, has the command been run successfully?

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\suricata1.log.zip 

**Answer Format:** Y/N

> **Answer:** Y

2 - What is the name of the SSL vulnerability that is attempted to be exploited in the given Suricata IPS log? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\suricata2.log.zip

> **Answer:** POODLE

3 - What is the name of the scanning tool that triggers the creation of the given Suricata IPS log? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\suricata3.log.zip

> **Answer:** nmap

## Firewall

### **What is Firewall?**

A firewall is a security software or hardware that monitors incoming  and outgoing network traffic according to the rules it contains and  allows the passage of network packets or prevents the passage of packets according to the nature of the rule.

### **Types of Firewall**

A firewall is divided into many different types according to its features:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-4.png)

### **Application-Level Gateways (Proxy Firewalls)**

Application-Level Gateways (Proxy Firewalls) are a type of firewall  that functions at the application layer between two end systems. Unlike  basic firewalls, it captures and analyzes packets in the application  layer according to the OSI model. In this way, it works as an additional security measure on the application layer.

**Note:** For detailed information about the “OSI  Model”, you can refer to the “Network Fundamentals-2” training. You can  access it from the link below:

**Network Fundamentals-2** : https://app.letsdefend.io/training/lessons/network-fundamentals-ii

### **Circuit-Level Gateways**

Circuit-Level Gateways are a type of firewall that can be easily  configured, has low resource consumption, and has a simplified  structure. These types of firewalls verify TCP connections and sessions  and operate in the session layer of the OSI model.

**Note:** For detailed information about “TCP Sessions”, you can refer to the “Network Protocols” training. You can access it  from the link below:

**Network Protocols** : https://app.letsdefend.io/training/lessons/network-protocols

### **Cloud Firewalls**

Cloud Firewalls are the type of firewall used when the institution  receives firewall service over the cloud as a service. Another name is  "FWaaS" (firewall-as-a-service). There are some advantages to using a  cloud firewall. For example, cloud firewalls have no physical resources, so they can be easily reconfigured based on demand or traffic load.  Additional capacity can be added to accommodate increased traffic.

### **Endpoint Firewalls**

Endpoint Firewalls are a type of host-based firewall installed on  devices. It is a type of firewall that is often difficult to manage. It  is an important component that must be used to ensure security. For  example, the "Windows Defender Firewall", which comes pre-installed in  Windows, is an example of this type of firewall.

**Note:** For detailed information about “Windows  Defender Firewall”, you can refer to the “Windows Fundamentals”  training. You can access it from the link below:

**Windows Fundamentals** : https://app.letsdefend.io/training/lessons/windows-fundamentals

### **Network Address Translation (NAT) Firewalls**

Network Address Translation (NAT) Firewalls are a type of firewall  designed to access internet traffic and block unwanted connections. Such firewalls are used to hide the IP addresses in the internal network  from the external network. In other words, it is the firewall where NAT  is applied.

**Note:** For information about “Network Address  Translation (NAT)”, you can refer to the “Network Fundamentals”  training. You can access it from the link below:

**Network Fundamentals** : https://app.letsdefend.io/training/lessons/network-fundamentals

### **Next-Generation Firewalls (NGFW)**

Next-Generation Firewalls (NGFW) are a type of firewall that combines the features of different firewalls available under the conditions of  that day on a single firewall. These firewalls have a deep-packet  inspection (DPI) feature. This type of firewall is designed to block  external threats, malware attacks, and advanced attack methods.

### **Packet-Filtering Firewalls**

Packet-Filtering Firewalls are the most basic type of firewall. It  has a feature that monitors network traffic and filters incoming packets according to configured rules. A packet-Filtering firewall blocks the  destination port if the incoming packet does not match the rule set.  This firewall is one of the quick solutions that can be used without  many resource requirements. But there are also some disadvantages. For  example, it lacks the ability to block web-based attacks.

### **Stateful Multi-Layer Inspection (SMLI) Firewalls**

Stateful Multi-Layer Inspection (SMLI) Firewall is a type of firewall capable of both packet inspection and TCP handshake verification. With  these features, it stands out from other firewalls. It also has the  feature of tracking the status of established connections.

### **Threat-Focused NGFW**

Threat-Focused NGFW has all the features of an NGFW-type firewall. In addition, it has advanced threat detection features. Thanks to this  feature, it can react quickly to attacks. It helps to provide security  more effectively thanks to the rules written with a threat focus. Since  it monitors every malicious activity from beginning to end, it runs the  process faster by shortening the time from the first time it detects the threat to the cleaning phase.

### **Unified Threat Management (UTM) Firewalls**

Unified Threat Management (UTM) Firewalls are a special type of  stateful inspection firewalls with antivirus and intrusion prevention.

### **How Firewall Works**

Although there are many types of firewall devices, they basically  work with the same logic. Some rules are needed for a firewall to work.  The firewall rule is the part that is checked to decide whether to allow or block the passage of network packets coming to the firewall. For  example, firewall rules can be created to prevent two departments from  accessing each other's network within an organization. In this way, a  kind of network segmentation is provided and security is increased by  interrupting the communication of devices that do not need to  communicate with each other. The working principle of a Firewall is  basically as follows:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/1-da7107e73b.gif)

(Image Source: PowerCert Animated Videos Youtube Channel, https://www.youtube.com/watch?v=kDEX1HXybrU)

How the firewall manages network packets by rules is shown below: 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/1-278f8be9ea.gif)

(Image Source: PowerCert Animated Videos Youtube Channel, https://www.youtube.com/watch?v=kDEX1HXybrU)

As can be seen above, the passage of incoming packets is allowed or  the passage of packets is blocked according to the details in the rules.

### **Importance of Firewall for Security**

A firewall is one of the most basic security solutions that should be included in a network. It would not be right to talk about the complete security of a corporate network without a firewall. In addition to  being in the existing network, it is also very important that the  firewall is correctly configured and managed. It is not possible to  protect the network or related host from attacks using only a firewall.

Some popular Firewall products used in the cybersecurity industry are as follows:

- Fortinet
- Palo Alto Networks
- SonicWall
- Checkpoint
- Juniper
- pfsense
- Sophos

### **What log resources does Firewall have?**

Firewall products have logs about network flow because they do  network-based filtering. For example, below is some information from  firewall logs:

- Date/Time information
- Source IP Address
- Destination IP Address
- Source Port
- Destination Port
- Action Information
- Number of Packets Sent
- Number of Packets Received

### **Physical Location of Firewall Device**

Firewall devices can be located in different places in the network  according to their types. For example, the host-based firewall is used  to filter inbound/outbound traffic in front of that host. If we consider a corporate network in general terms, a firewall should be located at  the interfaces of the institution that go to the internet or at the  external interface. The device that will meet the packets coming from  the internet even before they come to the IDS / IPS devices is the  firewall device.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-5-1024x487.png)

(Image Source: https://www.geeksforgeeks.org/types-of-firewall-and-possible-attacks/)

In this part of the training, what the Firewall device is, its types, the working logic of the firewall, its importance for security, and the information that can be found in the logs of the firewall device were  discussed. In the next part of the training, the subject of **“Endpoint Detection and Response (EDR)”** will be explained.

### Questions

**NOTE:** You can use the machine to solve the questions from the hands-on section above.

1 - What is the action taken according to the given firewall log?

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\firewall.log.zip 

> **Answer:** deny

2 - What is the source IP address according to the given firewall log? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\firewall.log.zip 

**Answer Format:** X.X.X.X 

**Sample Answer:** 192.168.1.100

> **Answer:** 192.168.68.12

3 - What is the destination port number according to the given firewall log? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\firewall.log.zip

**Answer Format:** XXX 

**Sample Answer:** 111

> **Answer:** 143

4 - According to the given Windows Defender Firewall log, what is the IP  address that sends the TCP segment whose source port is 5421?

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\pfirewall.log.zip 

**Answer Format:** X.X.X.X 

**Sample Answer:** 192.168.1.100

> **Answer:** 192.168.1.9

5 - According to the given Windows Defender Firewall log, which network  protocol do the logs associated with the "8.8.8.8" IP address belong to? 

**Note:** Enter the abbreviation of the Protocol name. 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\pfirewall.log.zip 

**Answer Format:** XXXX 

**Sample Answer:** DHCP

> **Answer:** ICMP

## Endpoint Detection and Response (EDR)

### **What is EDR?**

Endpoint Detection and Response (EDR) is a security product that is  installed on endpoint-qualified devices, constantly monitors the  activities in the system, tries to detect security threats such as  ransomware & malware, and takes action against malicious activities.

### **Endpoint Devices**

Examples of endpoint devices are:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-7.png)

### **EDR Core Components**

EDR products can perform many different operations on the endpoint  device. These are the processes that support each other to ensure the  security of the device. EDR core components are as follows:

- Endpoint data collection agents
- Automated response
- Analysis and forensics

### **Functions of EDR**

The duties of EDR products are generally as follows:

1. Monitoring and collecting each process on the device that may identify a security threat
2. Analyzing the behavior of threat actors according to the data collected on the device
3. Informing the relevant analyst by taking the appropriate security  action against the threat actor obtained from the collected data.
4. Allow forensic analysis on the device to conduct in-depth investigation of suspicious activities

### **The Importance of EDR for Security**

Ensuring the security of the devices that EDR products need to  protect has become an essential element to be considered today. Because  attackers aim to gain access to the network by turning to weak devices  in terms of security. After gaining access to the network through an  endpoint, the attacker tries to access more critical systems. In this  way, if there is an endpoint that does not have an EDR product installed and is not sufficiently secure, it can be used by the attacker for  initial access.

Some popular EDR products used within the cybersecurity industry are as follows:

- SentinelOne
- Crowdstrike
- CarbonBlack
- Palo Alto
- FireEye HX

### **What log sources does EDR have?**

EDR product keeps some information as a log by monitoring the system  on which it is installed. The processes running on the system are  monitored and the names of the files accessed by the programs and their  access information are recorded by EDR as logs. It records which  programs are run, which files the run programs read, or which file they  make changes to. Each EDR can obtain various information through the  system. In general, it can be said that the EDR product monitors and  logs the sections deemed necessary in terms of security.

For example, in the image below, it is seen that the endpoint security product lists the processes on the device:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-6-1024x672.png)

Endpoint security product provides some information about the  processes it lists to the user. Some of this information is size  information, hash information, and path information, as seen in the  image above.

In this part of the training, what EDR is, its duties, EDR  components, and the importance of EDR for security were discussed. The  next part of the training covers the topic of **“Antivirus Software (AV)”**.

### Questions

**NOTE:** You can use the machine to solve the questions from the hands-on section above.

1 - What is the name of the powershell script that is tried to be downloaded according to the given Crowdstrike EDR log? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\edr1.log.zip 

**Answer Format:** XX-XX 

> **Answer:** Invoke-Mimikatz

2 - According to the given Crowdstrike EDR log, what is the name of the MITRE technique used by the attacker? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\edr1.log.zip 

**Answer Format:** XXX XXX XXX

> **Answer:** OS Credential Dumping

3 - According to the given Crowdstrike EDR log, what is the name and  extension of the file that the attacker is trying to download onto the  system? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\edr2.log.zip 

**Answer Format:** XX-XX.XX

> **Answer:** Get-System.ps1

4 - What is the severity of the alert based on the given Crowdstrike EDR log?

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\edr2.log.zip 

> **Answer:** High

## Antivirus Software (AV)

### **What is Antivirus Software (AV)?**

Antivirus Software (AV) is security software that detects malware on  devices and blocks and removes malware from the system before it harms  the device.

### **Types of Antivirus Software**

Antivirus software is generally responsible for scanning the system  for security. Antivirus software can be divided into subtypes according  to scanning methods:

### **Signature-Based Scanning**

In the signature-based scanning method, the antivirus software scans  the system to detect malware with a digital signature, and if there is a matching signature, it marks the file it scans and matches as malicious and clears the file from the system. In this method, digital signatures are kept on the system in the database and must be constantly updated  with up-to-date malware signatures. It is a method that has been used  from the past to the present and is effective in detecting known  malware. Although it does not catch every single malware, it can detect  most of them.

### **Heuristic Scanning**

The heuristic scanning method is a very different malware detection  method than the previous signature-based scanning method. Instead of  detecting by signature, it monitors the accesses and behaviors of the  examined file. In this way, the probability of detecting malicious  activities is much higher. For example, this behavior is flagged as  suspicious if the executable file that the antivirus tracks is trying to read or modify a system file it shouldn't be able to access. Even if  its signature is not in the antivirus database as malicious, it may be  executable malware. This situation is logged by the antivirus.

### **Functions of Antivirus Software**

- To detect malware in the system by constantly scanning the system
- Protecting the system against external threats
- Cleaning detected malware from the system

### **Logic Behind How Antivirus Software Works**

The working logic of antivirus software is shown as follows:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image1.gif)

(Source: https://www.youtube.com/watch?v=jW626WMWNAE)

### **The Importance of Antivirus Software for Security**

Antivirus software, which has a long history, is of great importance  in terms of security. Periodic security scans on systems are one of the  most basic security procedures to be performed. Antivirus software is  one of the most effective ways to detect known malware and quickly clean it from the system. If an institution does not have antivirus software, it means that security is weak at some point. Using antivirus software  with an up-to-date malware signature database is necessary to ensure  security today.

Some popular Antivirus products used in the cybersecurity industry are as follows:

- McAfee
- Symantec
- Bitdefender
- Eset
- Norton

### **What log sources does Antivirus Software have?**

Antivirus software keeps logs of the findings it obtains in its  periodic scans or a special scan of a specific file. These logs contain  information about the detected malware. For example, information such as the size of the file, the name of the file, its signature, and the type of malware can be included in the logs. Thanks to these logs,  information on retrospective scans and malware detections can be  obtained.

In this part of the training, what Antivirus software is, its types,  tasks, working logic, and importance for security were discussed. In the next part of the training, “**Sandbox Solutions**” will be explained.

### Questions

**NOTE:** You can use the machine to solve the questions from the hands-on section above.

1 - According to the given Windows Defender log, what is the type of malware named “executable.8180.exe”? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\win-defender.log.zip

> **Answer:** Trojan

2 - According to the given Windows Defender log, what is the name of the file belonging to the "Backdoor" type malware? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\win-defender.log.zip

> **Answer:** program1

## Sandbox Solutions

### **What is Sandbox Solutions?**

Sandbox is a technology used to run/open and examine executable files or file types with different extensions (pdf, docx, and xlsx, etc.)  that are thought or known to be malware in an isolated environment.  Thanks to the Sandbox, precautions are taken against the problems that  may arise when the file is run/opened on a live system.

### **The Benefits of Sandboxing**

- It does not put hosts and operating systems at risk.
- Detects potentially dangerous files.
- Allows testing of software updates before they go live.
- It allows fighting against 0-day vulnerabilities.

### **The Importance of Sandboxes for Security**

Malware types encountered in the past are now trying to access  systems with more different and advanced methods by designing themselves in a better way. Therefore, technologies that provide security against  advanced attack tools and malware are also created. Sandboxes should be  used to see malware behaviors and take precautions accordingly. Here's  how a sandbox works:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-8.png)

Some popular Sandbox products used in the cyber security industry are as follows:

- Checkpoint
- McAfee
- Symantec
- Trend Micro
- Proofpoint

### **What data sources do sandboxes have?**

Each sandbox product holds its unique data. However, it can be said  that the information that sandboxes can keep in the data presented to  the user due to their duty is about the analysis they make. For example, when the sample.exe file is run in the sandbox environment, information such as the run time of this file, the files the program accesses after running, its behavior, the date/time information of these operations,  and the hash information of this file may be included in the data  provided to the user by the sandbox product.

In this part of the training, what Sandbox is, its benefits, and its  importance for security were discussed. In the next part of the  training, **“Data Loss Prevention (DLP)”** will be explained.

### Questions

1 - According to the sandbox analysis result in the URL given below, for which domain address was the DNS request made? 

**URL:** https://app.any.run/tasks/2d2ca664-521c-48bf-9748-722cbf34bcea/ 

**SHA256 Hash:** 4a24048f81afbe9fb62e7a6a49adbd1faf41f266b5f9feecdceb567aec096784 

**Answer Format:** www.XXX...XXX.com

> **Answer:** www.xmlformats.com

2 - What is the name and extension of the file that performs the malicious  activity on the system according to the sandbox analysis result in the  URL given below? 

**URL:** https://app.any.run/tasks/73db6760-6ca1-42fc-bd8d-dd6425d7acea 

**SHA256 Hash:** dcbd77ad65145ab5aa64b8c08608991a6cc23daabf02cf0695f2261da3ec5b7d  

**Sample Answer:** malwr.exe

> **Answer:** DotSetupSDK.dll

## Data Loss Prevention (DLP)

### **What is Data Loss Prevention (DLP)?**

Data Loss Prevention (DLP) is a technology that prevents sensitive and critical information from leaving the institution.

### **Types of DLP**

DLP products fall into several types:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-10.png)

### **Network DLP**

Network DLP is responsible for taking security actions related to  leaving critical and sensitive information on the network outside the  organization. For example, the DLP product may block a connection that  is attempted to upload a file to an FTP server, request it to be  audited, or forward it as a log to the relevant security solution. The  action to be taken by the DLP product varies according to its  configuration. Additionally, it can report suspicious activity to the  administrator.

### **Endpoint DLP**

Unlike Network DLP, Endpoint DLP monitors activities on a particular  device rather than packet flow within the network. The Endpoint DLP  product is installed on the device and after installation, it manages  suspicious activities on the device. Endpoint DLP is essential for  protecting critical and sensitive information on the devices of remote  personnel. For example, an Endpoint DLP product can see whether  sensitive information is kept in encrypted form in the device.

### **Cloud DLP**

Cloud DLP is used to prevent sensitive data from leaking over the  cloud by working with certain cloud technologies. It is responsible for  ensuring that corporate personnel can use cloud applications comfortably without data breaches or loss.

### **How does DLP work?**

When DLP detects data in the right format according to the rules  defined for it, it blocks the action taken or tries to ensure the  security of the transmission by encrypting the data. For example, credit card numbers have a certain format, and when the DLP product in the  email content sees the credit card number per this format, it will take  the relevant action. The following image shows how DLP works in a basic  sense:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-9-1024x532.png)

(Image Source: https://bbes-group.com/bbes-group-solutions/data-loss-prevention/)

### **The Importance of DLP for Security**

Today, critical information disclosure is a frequently encountered  situation in organizations. It is one of the factors that should be  considered, as this situation can have many bad effects. The DLP product is one of the security products that should be used for institutions  with critical information, just like other security solutions.

Some popular DLP products used within the cybersecurity industry are as follows:

- Forcepoint
- McAfee
- Trend Micro
- Checkpoint
- Symantec

In this part of the training, what DLP is, its types, its working  logic, and its importance for security were discussed. In the next part  of the training, the subject of **“Asset Management Solutions”** will be explained.

## Asset Management Solutions

### **What is Asset Management Solutions?**

Asset Management Solutions is software that can implement all asset  management operations such as monitoring the operating status of assets  in the corporate network, maintaining them, and removing them when  necessary.

### **Benefits of Asset Management Software**

- It facilitates the implementation of standards.
- It helps with documentation.
- It improves the working performance of assets.
- Provides inventory control.
- Provides strategic decision-making support.

### **Types and Components of IT Asset Management**

The four main managed IT assets are:

1. Software
2. Hardware
3. Mobile devices
4. The Cloud

(Source: https://cio-wiki.org/wiki/Information_Technology_Asset_Management_(ITAM)#Types_and_Components_of_IT_Asset_Management.5B5.5D ) 

### **The Importance of Asset Management Software for Security**

Today, there are many devices that act as security products or  network products in a corporate network. The increase in the number of  devices in the network makes it difficult to manage the devices.  Therefore, the things to follow about the devices may cause the details  to be overlooked. Asset Management Tools are used to prevent this  situation. It is very important that Asset Management tools do their  jobs accordingly. Thanks to Asset Management Tools, outdated software  can be easily detected and managed. For example, quick action is  critical when a security update arrives that patches an important  vulnerability in a firewall device. Because as time passes, there may be malicious activities aimed at critical vulnerabilities. Thanks to Asset Management Tools, you can be notified about security updates quickly  and updates are made quickly.

Some popular Asset Management Tools used in the cybersecurity industry are as follows:

- AssetExplorer
- Ivanti
- Armis
- Asset Panda

In this part of the training, what Asset Management Tools are, their  benefits, and their importance for security were discussed. In the next  part of the training, **"Web Application Firewall (WAF)"** will be explained.

## Web Application Firewall (WAF)

### **What is a Web Application Firewall (WAF)?**

Web Application Firewall (WAF) is security software or hardware that  monitors, filters, and blocks incoming packets to a web application and  outgoing packets from a web application.

### **Types of WAF**

There are several types of WAF products:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-11.png)

### **Network-based WAF**

Network-based WAF is a security product that is hardware-based on the relevant network. It needs staff to write rules on it and to maintain  it. Although it is an effective WAF product, it is more expensive than  other WAF products.

### **Host-based WAF**

Host-based WAF is a cheaper product than network-based WAF. It is a  WAF with more customization possibilities. Considering that it is a  software product, it consumes the resources of the server it is on. It  may be more difficult to maintain and the systems on it must be securely hardened.

### **Cloud-based WAF**

Cloud-based WAF is a much more convenient and easy-to-apply security  solution than other WAF products purchased as an external service. Since the maintenance and updates of the WAF product belong to the service  area, there are no additional costs such as cost and maintenance.  However, it is a matter to be considered that the cloud-based WAF  product that is serviced has sufficient customizations suitable for you.

### **How does a web application firewall (WAF) work?**

A WAF manages inbound application traffic according to existing rules on it. These requests, which belong to the HTTP protocol, are either  allowed or blocked per the rules. Since it works at the application  layer level, it can prevent web-based attacks. In the image below, the  working logic of the WAF product is shown in a basic sense:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-12.png)

Before going to the web application, HTTP requests from users are met in the WAF product. According to the rule set on the WAF product, as  shown in the image below, some requests are not allowed to pass, and  thus requests that create malicious traffic are blocked. Here, it is  very important how the rules on the WAF define the attack, otherwise, it is possible to block incoming normal requests even though they do not  show malicious behavior. This shows that the WAF product is not used  efficiently and correctly, so it may result in not being able to prevent the attack at some points.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-13-1024x395.png)

The image above, it is shown how an action is taken on the WAF product against normal and malicious requests.

### **The Importance of WAF for Security**

Today, applications in almost every sector are available in local  networks or open to the Internet. Ensuring the security of web  applications, which are widely used in the IT world, is of critical  matter. Serious data leaks or security breaches can occur on unsecured  web applications. To prevent all these security breaches, WAF products  are placed in front of web applications. Even the presence of the WAF  product in front of the web applications is not sufficient to ensure  application security, while the absence of the WAF product is not  recommended at all.

Some popular WAF products used in the cybersecurity industry are as follows:

- AWS
- Cloudflare
- F5
- Citrix
- Fortiweb

In this part of the training, what WAF is, its types, its working  logic, and its importance for security were discussed. In the next part  of the training, the subject of **“Load Balancer”** will be explained.

### Questions

**NOTE:** You can use the machine to solve the questions from the hands-on section above.

1 - According to the given AWS WAF log, a request for SQL_Injection attack  was blocked. What is the IP Address that sent this request? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\aws-waf.log.zip 

**Answer Format:** X.X.X.X 

**Sample Answer:** 192.168.1.100

> **Answer:** 185.220.101.35

2 - According to the given Cloudflare WAF log, an HTTP request was sent to  the IP address 185.220.102.244 . Which HTTP method does this HTTP  request use? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\cloudflare-waf.log.zip

> **Answer:** GET

## Load Balancer

### **What is a Load Balancer?**

Load Balancer is a hardware or software used to distribute the  traffic to the servers in a balanced way and is placed in front of the  servers.

### **Benefits of Load Balancer**

Load Balancer is an important tool for the IT sector with many  advantages. The benefits of the load balancer device, which plays a  critical role in the distribution of network traffic, are shown below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-16.png)

### **Logic Behind How Load Balancer Operates**

The load balancer detects the most suitable target using some  important mathematical algorithms while performing the load-balancing  process and directs the network packets to the appropriate target. In  this way, the overloading of a server behind the load balancer is  prevented. For example, the possible traffic flow when no load balancer  is used is as follows:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-15-1024x524.png)

(Image Source: https://www.cloudflare.com/learning/performance/what-is-load-balancing/)

As can be seen in the image above, as an undesirable situation,  “server1” has become overloaded and cannot process packets. This  situation causes a delay that the user or the client device using the  server does not want. To prevent this situation, a load balancer should  be used. For example, the following image shows the possible traffic  flow when the load balancer device is used:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-14-1024x495.png)

(Image Source: https://www.cloudflare.com/learning/performance/what-is-load-balancing/)

As seen in the image above, the resources of the system and servers  are used much more effectively with balanced load distribution,  preventing delays and loss of access.

### **The Importance of Load Balancer for Security**

The load balancer is a very important component of an organization  due to its duty. Continuing the services of the organization  uninterrupted can be very critical for the organization. Therefore, for  access security, load balancer devices/software should be placed in the  necessary parts and correctly configured and monitored. Otherwise, the  services of the organization may be interrupted, causing the  organization to experience a loss of prestige or financial loss. For  example, if we consider that DoS/DDoS attacks are aimed at preventing  the services of the organization, we can more easily understand the  importance of load balancers in this sense.

**DoS (Denial of Service):** It is called attacking to  render the service inoperable by sending more network traffic than the  target system can handle. In short, it can be said to cause disruption  of the service provided by consuming resources towards the target.

Some popular Load Balancer products used in the cyber security industry are as follows:

- Nginx
- F5
- HAProxy
- Citrix
- Azure Traffic Manager
- AWS

In this part of the training, what a Load Balancer is, its benefits,  its working logic, and its importance for security were discussed. In  the next part of the training, the **“Proxy Server”** will be explained.

### Questions

**NOTE:** You can use the machine to solve the questions from the hands-on section above.

1 - What is the User-Agent in the HTTP request in the given AWS load balancer log? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\aws-loadbalancer.log.zip 

**Answer Format:** XXXX/X.XX.X

> **Answer:** curl/7.46.0

## Proxy Server

### **What is Proxy Server?**

A proxy Server is hardware or software used for many different purposes and acts as a gateway between client and server.

### **Types of Proxy Servers**

There are many types of Proxy Servers:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-17.png)

### **Forward Proxy Server**

Forward Proxy Server is the most widely used proxy server type. It is used to direct requests from a private network to the internet with a  firewall.

### **Transparent Proxy Server**

A transparent Proxy Server is a proxy server that directs requests  and responses to the target without making changes to incoming/outgoing  requests and responses.

### **Anonymous Proxy Server**

Anonymous Proxy Server is a proxy server that enables anonymous browsing on the internet.

### **High Anonymity Proxy Server**

A high Anonymity Proxy Server is a proxy server that makes it  difficult to track the client with higher confidentiality without  sending the proxy server type and client IP address information in the  request.

### **Distorting Proxy Server**

A distorting Proxy Server is a proxy server that tries to hide its  identity by defining itself as the proxy server of a website. By  changing the real IP address, the confidentiality of the client is tried to be ensured.

### **Data Center Proxy Server**

Data Center Proxy Server is a special proxy server that is used as a  proxy server that is not connected to the ISP (Internet Service  Provider) by getting service over data centers. It is a proxy server  that is insufficient to provide anonymity. It has a quick response  feature.

### **Residential Proxy Server**

A residential Proxy Server is a proxy server that passes all requests made by the client. Thanks to this proxy server, unwanted and  suspicious advertisements can be blocked. It is more secure than other  proxy servers.

### **Public Proxy Server**

A public Proxy Server is a free proxy server available to everyone.  It is ideal for those looking for a cost-free proxy server by  sacrificing security and speed. It's insecure because it's accessible to everyone, and it's also slow.

### **Shared Proxy Server**

A shared Proxy Server is a proxy server that can be used by more than one person at the same time. It is preferred for fast connection and  cost-free use. The disadvantage of this proxy server is that it is used  by many people at the same time, so the activity of any user can affect  another. For example, after the activity of one of the users, the IP  address of this proxy server may be blocked by a server. In this case,  access to the blocking server cannot be provided by all persons using  the proxy server.

### **SSL Proxy Server**

SSL Proxy Server is a proxy server in which the communication between client and server is provided in a bidirectional encrypted manner. It  can be said to be safe because it provides encrypted communication  against threats.

### **Rotating Proxy Server**

A rotating Proxy Server is a proxy server where a separate IP address is assigned to each client.

### **Reverse Proxy Server**

A reverse Proxy Server is a proxy server that validates and processes transactions so that the client does not communicate directly. The most popular reverse proxy servers are "Varnish" and "Squid".

### **Split Proxy Server**

A split Proxy Server is a proxy server that runs as two programs installed on two different computers.

### **Non-Transparent Proxy Server**

A non-Transparent Proxy Server is a proxy server that works by  sending all requests to the firewall. Clients using this proxy server  are aware that requests are sent over the firewall.

### **Hostile Proxy Server**

A hostile Proxy Server is a proxy server used to eavesdrop on traffic between client and target on the web.

### **Intercepting Proxy Server**

Intercepting Proxy Server is a proxy server that allows using proxy server features and gateway features together.

### **Forced Proxy Server**

A forced Proxy Server is a proxy server where blocking and allowing policies are applied together.

### **Caching Proxy Server**

Caching Proxy Server is a proxy server that has a caching mechanism  on it and returns a response in accordance with this caching mechanism  in response to the requests sent by the clients.

### **Web Proxy Server**

A web Proxy Server is a proxy server that works on web traffic.

### **Socks Proxy Server**

A socks Proxy Server is a proxy server that prevents external network components from obtaining information about the client.

### **HTTP Proxy Server**

HTTP Proxy Server is a proxy server with caching mechanism for HTTP protocol.

### **Benefits of Proxy Server**

- Private browsing
- Increases user security.
- Allows the client's IP address to be hidden.
- It allows to manage network traffic.
- Together with the caching mechanism, it saves bandwidth.
- It can provide access to places with access restrictions.

### **How Does a Proxy Work?**

Since the proxy server is a network component that is responsible for forwarding the requests from the client to the target address, it  functions by taking place between the two communicating parties.  Basically, how the proxy server works is shown below.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-18.png)

As seen in the image above, the requests sent by the client must pass through the proxy server before going to the destination. In this way,  it is ensured that all requests sent by the client pass through the  proxy server, which is an intermediary network component. Proxy server  directs incoming requests to the target in accordance with its intended  use.

The proxy server keeps some log records of its transactions. If  necessary, some details about network communication can be seen by  looking at these log records. The log activity on the proxy server is  roughly as follows:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image3.gif)

(Image Source: https://www.youtube.com/watch?v=5cPIukqXe5w)

### **The Importance of Proxy Servers for Security**

Proxy Server can take on important tasks at some points, although it  varies according to the purpose of use. For example, since the IP  address field in the request sent by the client is changed with the IP  address belonging to the proxy server on the proxy server, the IP  address of the proxy server appears in the destination instead of the IP address of the client. In this case, the IP address of the client is  hidden and security is provided.

As SOC Analysts, we need to pay attention to the traffic coming from  the Proxy while analyzing the servers. Because the source IP address we  see does not belong directly to the person concerned, it belongs to the  proxy server. What we need to do is to find the real source IP making  the request to the proxy server and continue the analysis with these  findings.

Another issue is that only some types of proxy servers support  encrypted traffic. In terms of security, it is very important to  transmit the traffic as encrypted. It can be said that proxy servers  with this feature are more secure.

Some popular Proxy Server products used in the cyber security industry are as follows:

- Smartproxy
- Bright Data
- SOAX
- Oxylabs

In this part of the training, what Proxy Server is, its types,  benefits, working logic, and importance for security were discussed. In  the next part of the training, the subject of **“Email Security Solutions”** will be explained.

### Questions

**NOTE:** You can use the machine to solve the questions from the hands-on section above.

1 - According to the given Squid Web Proxy Server log, to which port of the "letsdefend.io" address was the request sent? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\squid-proxy.log.zip

> **Answer:** 443

2 - According to the given Squid Web Proxy Server log, how many different web addresses are there to send HTTP GET method requests? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\squid-proxy.log.zip

> **Answer:** 5

## Email Security Solutions

### **What is Email Security Solution?**

Email Security Solutions is one of the security solutions that  provides security against threats that may come via e-mail. It can be  software or hardware-based products.

### **Functions of Email Security Solution**

- Ensuring the security control of the files in the email
- Ensuring security checks of URLs in the email
- Detection and blocking of spoofed emails
- Blocking known harmful emails
- Blocking email addresses with malicious content detected
- Transmitting information about harmful e-mail content to the relevant product or manager as a warning

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Security+Solutions/image-19-1024x368.png)

(Image Source: https://www.proofpoint.com/au/threat-reference/email-security)

### **The Importance of Email Security Solutions for Security**

Phishing, which is the most popular attack method today, is a major  threat to corporate and individual users. The consequences of phishing  attacks, which aim to collect information about organizations or  individuals by using the vulnerability of the human factor, or to harm  the target, can sometimes be very severe. Therefore, threats that may  come via email should never be taken lightly. It is necessary to verify  that the files and links sent in the email are secure, and not  malicious. At this point, the importance of email security solutions  that offer comprehensive security measures emerges. Like other security  products, email security solutions are not enough to provide security  alone, but they are an important component in ensuring security. Its  main purpose is to prevent malicious emails from reaching the end user  by automatically analyzing incoming emails.

**Note:** To have information about the analysis and  details of phishing attacks using email, you can refer to the "Phishing  Email Analysis" training:

**Phishing Email Analysis:** https://app.letsdefend.io/training/lessons/phishing-email-analysis

Some popular Email Security Solutions products used within the cyber security industry are as follows:

- FireEye EX
- IronPort
- TrendMicro Email Security
- Proofpoint
- Symantec

In this part of the training, what Email Security Solutions are and their importance for security were discussed.

### Questions

**NOTE:** You can use the machine to solve the questions from the hands-on section above.

1 - According to the email security solution log, what is the email address of the recipient of the email? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\email.log.zip 

**Answer Format:** user@domain.io

> **Answer:** jonas@letsdefend.io

2 - What is the type of threat according to the email security solution log provided? 

**File Location:** C:\Users\LetsDefend\Desktop\QuestionFiles\email.log.zip

> **Answer:** malware