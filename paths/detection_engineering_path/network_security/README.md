# Network Security

During  this course section, we'll explore the intricacies of network security,  focusing on practical security strategies and techniques to enhance your ability to protect digital systems effectively.

**Table of Contents:**

- [Introduction to Network Security](#introduction-to-network-security)
- [Network Types](#network-types)
- [Network Topology](#network-topology)
- [Network Devices](#network-devices)
- [Network Devices Syslog & SNMP Settings](#network-devices-syslog--snmp-settings)
- [Protocol and Services](#protocol-and-services)
- [Network Traffic Capture & Analyze](#network-traffic-capture--analyze)
- [Network Troubleshooting](#network-troubleshooting)
- [Top Network Attacks & Mitigation](#top-network-attacks--mitigation)

**Evaluate Yourself with Quiz**

- [Network Security](https://app.letsdefend.io/training/quiz/network-security)

## Introduction to Network Security

Network Security is a set of measures and applications used to protect computer networks from  unauthorized access, abuse, interruption, or changes. Various  technologies, policies, and procedures are employed to safeguard network infrastructure, data, and resources from potential threats.

Let's explore the fundamentals of network security by breaking it down into the following categories:

### **Firewalls**

The firewalls regulate  and screen the flow of incoming and outgoing network traffic, blocks  potential threats, and prevents unauthorized access. It can be  considered one of the fundamental building blocks of network security.

### **Access Control and Authentication** 

Verifying the identities  of users and devices is crucial in controlling access to the network.  You can use username/password and multi-factor authentication (MFA) as  methods of authentication.

### **Encryption** 

Encrypting data ensures  that it remains secure and inaccessible to unauthorized individuals. The encrypted transmission or storage of sensitive data increases data  security.

### **Network Segmentation**

Network segmentation  involves logically dividing the network into distinct segments, thereby  isolating traffic within these segments. This limitation on the spread  of attacks enhances network security, as it narrows down the potential  attack surface.

**Intrusion Detection and Prevention Systems (IDPS)**

IDPS detect and block  attacks by monitoring network traffic. They are capable of identifying  known attack types and detecting abnormal network traffic.  

### **Patch/Update Management**

Maintaining and keeping  systems and software up-to-date on the network helps to address known  security vulnerabilities. Regularly applying security patches and  updates is crucial for ensuring network security.

### **Network Monitoring and Logging**

Monitoring network  traffic and events is essential for detecting and responding to security threats. By analyzing network logs, attacks or abnormal activities can  be identified and addressed promptly.

### **Physical Security**

It is critically  important to ensure the physical security of the network infrastructure. Physical access points such as server rooms, network devices, and data  centers should be protected at all times.

### **Education and Awareness**

Educating and raising  users' awareness about security is crucial. It is important to employ  password policy like to encourage users to use strong passwords, or  increase their awareness against phishing emails and keeping them  up-to-date on how to identify those phishing emails, as well as keep the users adhere to security policies is critically important.

### Questions

1 - What type of security is the security of server rooms?

> **Answer:** Physical Security

## Network Types

Understanding network  types is crucial for security engineers to effectively configure,  manage, and secure their networks. When a structure is installed with  sufficient knowledge of network types, it enables the resolution of  various issues, including proper network design, network management  (such as lan-wan-dmz configurations), network security, and network  performance management, all achieved by adhering to best practices. 

As a security engineer,  mastering the network types within the structure you are responsible for developing a robust security strategy tailored to this topology. By  understanding the network types, you can effectively identify and  evaluate risks, determine the attack surface, and address specific  issues that may arise. Familiarity with definitions like wan-to-lan and  lan-to-wan is crucial when examining logs to identify events promptly.  This knowledge accelerates the understanding of incidents.

## Network Topology

Network topology refers  to the way that the systems and connections on a network are organized  and configured. It is crucial for security engineers to understand and  evaluate network topology as it facilitates the development and  implementation of network security strategies.

Security engineering  demands a profound comprehension and expertise in network topology to  effectively recognize security vulnerabilities, assess the attack  surface, implement segmentation and isolation, conduct audits, ensure  compliance, manage access controls, and establish redundancy measures,  among other essential aspects.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-security/3/image3-1.png)

### Questions

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-security/image1.png)

1 - What is the network topology in the image above?

> **Answer:** Star Topology

## Network Devices

Network devices serve as  the foundational tools for security engineers to ensure and manage the  network security. Network professionals can effectively manage network  devices and safeguard overall network security only by identifying  devices and configuring security measures properly.

A Security Engineer should be familiar with the following topics related to network devices. 

### **Firewalls** 

Firewalls act as monitors and controllers for network traffic. They play a vital role in  filtering incoming and outgoing data, preventing harmful or unwanted  traffic. Serving as a critical security measure, they defend against  external attacks on the network and constitute one of the fundamental  building blocks of network security. Next-generation firewall devices  can even provide security at the application layer (L7) level.

### **Web Application Firewalls**

These devices provide security for web applications by filtering harmful web traffic and detecting and blocking malware.

### **Network Access Control Systems(NAC)**

The system assesses the  security status of devices connected to the network and regulates access based on compliance policies. It verifies the authentication, updates,  and adherence to security requirements for each device. Depending on  these evaluations, it decides whether to grant network access to the  device.

### **Intrusion Detection and Prevention Systems (IDS/IPS)**

These are the systems  used to detect and prevent attacks on the network. By monitoring  anomalies and suspicious requests, they can detect attacks and take the  necessary measures.

### **Virtual Private Network (VPN) Devices**

VPN devices are utilized  to establish secure, encrypted connections for remote access and  site-to-site connections. They guarantee the secure transmission of data and prevent unauthorized network access. Typically, it is added as a  module on firewall devices.

### **Data Loss Prevention (DLP) Device** 

It is a security device  used to prevent sensitive data from leaving the network without  permission. Detects and prevents data leakage.  

### **SSL/TLS Decryptor** 

It allows for analyzing  encrypted traffic and its content. In this way, we can detect harmful or unwanted activities in encrypted communication. 

### **NDR (Network Detection and Response)**

This security solution is designed to detect and prevent threats quickly, and respond to  incidents in real-time within the network. NDR efficiently identifies  abnormal or malicious activities, analyzes security incidents, and  promptly intervenes by monitoring network traffic. By detecting attacks, malware, and data leaks occurring on the network, this solution  enhances network security while also aiding in monitoring network  performance and providing valuable network-related threat intelligence.

### Questions

1 - What is a network device that authenticates users and devices on the network and controls network access?

> **Answer:** NAC

2 - What provides secure communication by encrypting traffic on the network?

> **Answer:** VPN

## Network Devices Syslog & SNMP Settings

### What is Syslog & what is it used for?  

Syslog is a standard  protocol used to record logs and events generated by an operating system or network device. Logs are records of a system's actions and their  timing. This information is particularly useful for identifying problems and conducting analysis in case of errors. Furthermore, logs play a key role in detecting security breaches.

Syslog stands out with  its ability to collect log records from multiple devices in one place.  This offers a network-wide overview and facilitates the swift tracking  of particular events. Its ability to collect logs from different devices and operating systems makes it a flexible log management solution.  

Logs sent via Syslog  adhere to a standardized format that includes specific details such as  timestamp, source IP address, event level, and event details. Adopting  this standard enables analysis and processing tools to process logs  easily. For more detailed information about the standards, you can check out the "syslog rfc standards".  

The Syslog protocol  provides information about the priority and source of logs. This  information is categorized into two main sections known as "facility"  and "severity," respectively.

The facility identifies  the source of the message and is usually an operating system component  or a network device. You can see the general "facility" codes below.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-security/table-1.png)

Severity indicates the significance of the message. The following are the general "severity" levels:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-security/table-2.png)

Each Syslog message is  assigned a priority by combining both categories. This priority is  typically displayed in the "<facility.severity>" format. For  example, if a displayed message's priority appears as "<3.6>", it  indicates that the system daemon (facility 3) sent an informational  message (severity 6).

You can find the sample output about syslog settings from a Linux system below. 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-security/5/image5-1.png)

Based on the example  above, you can add the following line at the bottom of the  /etc/rsyslog.conf file on a Linux (RHEL-based) system to send only  security logs to the syslog server. 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-security/5/image5-2.png)

In order for the relevant settings to be active, it is necessary to restart the “rsyslog” service on the linux system. 

### What is SNMP, and what is it used for? 

Simple Network Management Protocol (SNMP) is a standard internet protocol used for controlling  and managing network devices. SNMP enables the monitoring of the status  and activity of various network components, including routers, switches, servers, printers, and firewalls. 

SNMP's main goal is to  enable network administrators to monitor device status and diagnose  network issues. It collects device information and allows configuration  when needed. Moreover, SNMP is a crucial tool for optimizing network  performance, enhancing reliability, and swiftly diagnosing network  problems.

SNMP versions; 

**SNMPv1 (SNMP Version 1):**   It is the first version  of SNMP and offers basic network management features. Nevertheless, the  security of the system is limited since the network traffic remains  unencrypted. This poses a risk of potential leakage or modification of  traffic information sent from/received to the network.  

**SNMPv2 (SNMP Version 2):**   This version provides  performance improvements and additional features in contrast to SNMPv1.  Two minor versions, v2c and v2u, exist. However, it has not gained  widespread acceptance and is not in general use.  

**SNMPv3 (SNMP Version 3):**   This is the latest  version of SNMP and provides major security improvements.SNMPv3 offers  authorization and privacy features to encrypt network traffic, thereby  reducing the risk of information being tracked or modified.

For example, when the  corresponding SNMP settings are made on a Linux server, you can remotely obtain data from the system related to SNMP.   

The information retrieved from the "dockerio" server via SNMP using the "snmpwalk" command on a  Linux system includes the hostname ("centosvm"), kernel version, server  date, and timezone. The server's IP address is 192.168.1.100. The  "snmpwalk" command has been used to obtain this data.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-security/5/image5-3.png)

Information on the parameters to be used with the 'snmpwalk' command;

-v: SNMP version information

-c: the password set to retrieve data via SNMP.

-O: output information type, e="print enums numerically”

In this part of our  training, we have covered the importance of syslog and SNMP services on  the network devices, the types of outputs they generate, and how to  interpret these outputs effectively.

### Questions

1 - According to the given PCAP file, what is the IP address of the device to which SNMP requests are sent?(snmp.pcap)

> **Answer:** 192.168.216.131

2 - According to the given PCAP file, what is the SNMP version used?(snmp.pcap)

> **Answer:** 1

3 - According to the given PCAP file, what is the name of the target Linux distribution to which SNMP requests are sent?(snmp.pcap)

> **Answer:** ubuntu

4 - What is the latest SNMP version?

> **Answer:** 3

5 - What is the protocol that allows network administrators to receive information from network devices?

> **Answer:** SNMP

## Protocol and Services

Network protocols and  services allow computers to communicate with each other as well as other devices on the network. Security engineers are expected to have a  thorough understanding of these protocols and services in order to  address issues effectively such as data privacy and integrity,  authentication, monitoring and managing network traffic, and detecting  malicious activity. 

Understanding protocols  and services from a security perspective is important because they play a vital role in ensuring the security of networks and systems for the  reasons mentioned below.

**Identifying Security Vulnerabilities** 

Gaining a comprehensive  understanding of protocols is essential for recognizing potential  vulnerabilities and the methods by which they can be exploited. Both  protocols and services are susceptible to vulnerabilities, which can  manifest as holes or bugs. These weaknesses can serve as entry points  for unauthorized attackers to gain access to the system or disrupt  services. Being well-versed in these vulnerabilities is crucial for  addressing them and enhancing the overall security of the system.

**Security Patch Management** 

The most popular services and applications are usually updated regularly, and these updates  usually contain important security fixes and patches. Getting to know  these services and applications allows you to understand which systems  need to be patched and which security updates need to be applied.

**Using the Right Applications**   

Understanding the  security features and limitations of a particular protocol can help you  determine which protocols are best for which situations. For example, it is important to know that a secure protocol such as HTTPS should be  preferred when transferring sensitive information.

**Penetration Testing and Threat Hunting**   

Security professionals  should have an understanding of the protocols in cybersecurity  procedures such as penetration testing and threat hunting. Knowing the  functioning of these protocols enhances your ability to detect abnormal  network traffic and identify potential security threats.

**Creating Security Policies and Guidelines** 

By comprehending  protocols, organizations can establish robust security policies and  guidelines. For instance, determining the appropriate protocols for data transfer and identifying their suitable usage in various situations can significantly enhance overall security measures.

**Enhancing the Security Posture Continuously** 

Acquiring knowledge and  comprehension of protocols empowers you to consistently assess and  elevate the existing security landscape. This involves incorporating new versions, patches, and updates, addressing vulnerabilities, and overall enhancing network security.

**Risk Assessment** 

Every network protocol  and service possesses unique vulnerabilities, which bring along specific risks that can impact your systems. By understanding the inner workings of these protocols and services, you can identify existing risks,  implement appropriate measures, and effectively manage these risks to  safeguard your systems.

**Responding to Cyber Incidents**    

In the event of a  cybersecurity incident, having a grasp of protocols and services can  help tremendously in identifying the root cause and understanding its  triggers. Armed with this knowledge, you can effectively respond to the  incident, mitigate its impact, and implement necessary improvements.

**Understanding the Goals**   

Cybercriminals usually  target the most common services and applications, because this provides  them with the widest pool of potential victims. Having knowledge about  these services and applications helps you understand the aims and  intentions of cybercriminals and determine which areas should be  prioritized for protection.

**Resilience and Restoration**   

When facing a potential cyberattack, your familiarity with commonly used services and  applications can expedite the process of mitigating its effects and  restoring normal operations. This involves comprehending the critical  systems, prioritizing data recovery, and identifying essential services  that need immediate restoration to minimize downtime and ensure a swift  recovery.

For more detailed information about Protocol and Services, you can see the following courses. 

- [Network Protocols](https://app.letsdefend.io/training/lessons/network-protocols)  
- [Network Protocols 2](https://app.letsdefend.io/training/lessons/network-protocols-2)  

### Questions

1 - What is the protocol that automatically assigns IP addresses to devices on the network?

> **Answer:** DHCP

2 - What is the protocol used for name resolution of devices on the network?

> **Answer:** DNS

3 - What is the technology used to ensure the security of network protocols, provide end-to-end  encryption, and prevent eavesdropping on network traffic?

> **Answer:** VPN

## Network Traffic Capture & Analyze

It is a fundamental topic in network security that almost every role related to security should  be familiar with. Among the basic applications used in this context are  tools like Wireshark and TCPdump.

The most important issues to consider when capturing traffic are as follows;  

- Whether the traffic is  encrypted or not; when analyzing encrypted traffic, we cannot see the  contents of outgoing/incoming packets in a clear format.  
- The size of the traffic and the saved files; analyzing high-size files can be difficult when  transferring these files to a different location later or capturing them with an analysis tool.   
- Performance criteria;  it is important that the captured application fully captures the  traffic. The situation can be monitored through the drop rate ratios on  the interface.  
- Meaningful data  capture; As an example, if an analysis is to be performed on the web  traffic, there is no need to capture all the traffic. We can capture the traffic belonging to the relevant protocol and service only.  

Traffic capture and  analysis play a crucial role in network security and management. It is  essential to grasp the basics for several reasons, including: 

**Debugging and Troubleshooting** 

Traffic capture serves as a valuable tool to identify packets and data flowing through a network, making it an invaluable resource for detecting and resolving network  issues. For instance, it can be used to investigate the cause of a  network connection slowdown, diagnose malfunctions in applications, or  determine the reasons behind service inaccessibility.

**Security Analysis** 

Traffic analysis is also  used to detect suspicious or malicious activities. For instance, it can  help identify network intrusions by determining if an attacker has  gained access, detect malware infections on devices, or recognize DDoS  attacks when they occur. 

**Performance Monitoring** 

Traffic capture and  analysis are used to understand network performance and capacity. For  example, they can be used to determine which applications use the most  bandwidth, which services cause the most network traffic, and how  overall network usage is trending.  

**Compliance with Regulations**   

Compliance with industry  standards and government regulations often necessitates monitoring and  reporting specific types of network traffic. Traffic capture and  analysis are utilized to ensure adherence to these regulations and  standards. 

**Identification of New Threats**   

Traffic analysis is  instrumental in identifying both new and established threats. Such  threats are typically detected by observing abnormal network activity or traffic that deviates from known good patterns. For instance, to create an IPS/IDS signature for a new attack vector, it is crucial to possess  the knowledge and skills for traffic capture and analysis.  

**Verifying compliance with agreements and policies** 

Organizations are  typically required to adhere to certain network policies and protocols.  Capturing and analyzing traffic can be used to verify that these  policies and protocols are being followed.

**Forensic Analysis**   

When there is a security  breach, traffic capture, and analysis tools are often an integral part  of the investigation and response process. It is also used to understand past events and how events evolved. 

**Detection of Information Leakage**   

Traffic analysis is used  to investigate if sensitive information is being transmitted over the  network. For instance, it can help identify whether sensitive files or  data are being sent to external sources through traffic monitoring and  analysis.

**Provision of High-Quality Services** 

Traffic analysis can be  used to monitor network performance and improve service quality. For  example, to improve the quality of services such as VoIP, network  traffic analysis can be used to make the necessary adjustments.

**Optimization of Software and Systems**   

Traffic analysis is used  to understand how services and applications operate on a network. This  provides valuable information for optimizing performance and making the  network more efficient. It has especially critical importance in  industries such as the financial sector where the speed of communication is critical.

## Network Troubleshooting

Network troubleshooting  is a process used by Network and Security Engineers to detect, monitor  and solve network problems. This process helps to optimize network  performance and security, ensure business continuity, and minimize  service interruptions. Network troubleshooting capabilities require a  thorough knowledge of protocols, services, network hardware, and  software. In addition, effective network troubleshooting usually  involves the use of diagnostic tools such as ping, traceroute, and  network analysis tools such as Wireshark, and TCPdump. Since the  previous courses provided detailed information on the relevant protocol, application, and analysis tools, these topics will not be covered in  this course. 

We will explain the topic in 3 basic headings.   

- Most Commonly Used Network Troubleshooting Tools;  
- Scenarios Requiring Network Troubleshooting;  
- Examples of Network Troubleshooting  

### Most Commonly Used Network Troubleshooting Tools  

**Ping:** Ping is a tool used to  test the health of a network connection. It sends and receives packets  from one system to another and measures the duration of this process. It can also detect packet loss.  

**Traceroute (tracert):** Traceroute shows how a packet gets from one point to another. It helps to determine the path a packet takes across a network.

**Nslookup / Dig:** These tools are used to test and resolve DNS queries. They resolve IP addresses into domain names or vice versa.

**Netstat:** Netstat is used to display network connections, routing tables, and network interface  information. This is useful for understanding what network connections a system has.

**Wireshark:** Wireshark is a powerful  tool used to analyze network traffic and detect network problems. It can display all network traffic and analyze packets.

**TCPDump:** TCPDump captures and  analyzes network traffic. It usually works via the command line  interface and provides detailed information about network traffic.

**IPerf:** IPerf is a tool used to assess the bandwidth of a network connection by measuring the data transfer rate between two systems.

**Nmap:** Nmap is a network  discovery and security auditing tool. It detects what devices are active on the network and what services are running.

**Advanced IP Scanner:** It is a free network  scanning tool that quickly scans and analyzes all systems on a network.  It provides comprehensive information, including IP addresses, users,  network shares, and other details, and also enables remote access and  control of specific systems.

### Scenarios That Require Network Troubleshooting

**Internet Connection Problems**   

If a user cannot connect  to the Internet, the first step is usually to check and restart the  modem and/or router. If this does not resolve the problem, a more  detailed troubleshooting process may be required. This may include  checking IP settings, investigating DNS issues, and/or contacting the  Internet Service Provider (ISP).

**Slow Network Connections**   

When a network is running slowly, several tools can be used to determine the source of the  problem. These include the use of network monitoring tools, which are  typically used to monitor bandwidth usage, analyze network traffic, and  identify systems or services that may be slowing down.

**Service Access Problems** 

When a user faces  difficulty accessing a specific service or application, such as a  website or email server, it often suggests potential issues with the  network configuration or the service itself. To address such problems,  it is usually necessary to review the network configuration settings,  check the status of the service, and investigate any potential obstacles arising from firewalls or network policies.

**Network Security Issues** 

If there are signs of a  security breach on the network (for example, unknown traffic, unexpected system behavior, etc.), this usually requires a more thorough  troubleshooting process. This may include actions such as capturing and  analyzing network traffic, examining system logs, and detecting and  removing potentially malicious software.

### Examples of Network Troubleshooting

**Situation:** An office employee cannot access shared files in the office.

**The Solution Process:** First, we need to check the employee's network connection. We can use the “ping” command to see  if the computer is connected to the network or not. If this is not the  reason, we can check the file-sharing services. The problem may be  caused by an incorrect configuration of the shared files or an error in  the access permissions.  

**Situation:** A web server slows down unexpectedly or stops responding.

**The Solution Process:** Initially, we assess the  server for possible overload by checking the the server resources,  including processor usage, RAM usage, and disk usage. If resource  utilization exceeds normal levels, further analysis is essential to  identify the services responsible for the excessive resource consumption or any services that need to be limited or suspended.  

**Situation:** The Internet connection drops unexpectedly for all users.

**The Solution Process:** In this case, the first  step is usually to check the network hardware. We check if there is a  fault with the modem, router, or other network devices. If any part of  this hardware is defective or faulty, we can consider restarting the  device or replacing it if necessary. It may also be useful to check for  connection problems with your Internet Service Provider (ISP). 

**Situation:** Employees who connect to your company's VPN experience delays in accessing network resources.

**The Solution Process:** In this case, it is  important to check the performance of the VPN server. If the server is  overloaded, we can consider adding more resources. We also need to make  sure that the VPN is configured correctly and follows the necessary  security protocols. If the problem persists, we can use Wireshark or a  similar tool to analyze network traffic and identify potential  bottlenecks.

### Questions

1 - According to the output below, which protocol is causing the access problem?  

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-security/image1+(1).png)

> **Answer:** DNS

2 - What protocol does the "tracert" command use to check the paths a packet takes to reach its destination in the window?

> **Answer:** ICMP

3 - What protocol is used by  the traceroute command in Linux distributions to check which paths a  packet uses to reach its destination?

> **Answer:** UDP

## Top Network Attacks & Mitigation

Network Attacks occur  when individuals or groups attempt to gain unauthorized access to an  organization's network systems. The objectives of these attacks  typically involve data theft, system damage, or service disruption.  Among the types of attacks are DDoS attacks, Man-in-the-Middle attacks,  IP spoofing, ARP spoofing, SQL injection, Cross-Site Scripting (XSS),  phishing, malware attacks, brute force attacks, and zero-day attacks.  Each of these threats poses a significant network security and privacy  challenge, and an effective network security strategy requires the  ability to protect against and proactively respond to these threats.

### DDoS Attacks (Distributed Denial of Service)

DDoS attacks are usually  carried out using a botnet network consisting of a large number of  systems and aim to consume the resources of a targeted server, service,  or network and thus make the service unusable. DDoS attacks are usually  of three types: 

**Volume-Based Attacks:** These attacks are  designed to consume the target's network bandwidth. UDP flood (user  datagram protocol) and ICMP flood (internet control message protocol)  are examples of such attacks.

**Protocol Attacks:** These attacks target and consume the system resources (processors, firewalls, etc.) of the target. One example of such attacks is the SYN flood (synchronization).

**Application Layer Attacks:** These attacks focus on a specific application of the target. An example of such attacks is HTTP flood attacks.

Several strategies and  tools can be used to prevent DDoS attacks. These include utilizing DDoS  protection services, enhancing network capacity, implementing proper  network configurations, and continuously monitoring traffic behavior.  However, it is crucial to treat DDoS attacks seriously and offer  appropriate training to recognize the signs of such attacks as they are  often used as distractions to mask other security breaches. 

### Man in the Middle (MitM) Attacks

Man-in-the-Middle (MitM) attacks occur when an attacker intercepts or decrypts communications  between two parties. To execute these attacks, the attacker typically  gains control over network traffic and misrepresents themselves as a  trusted agent or service.   

To safeguard against MitM attacks, we should be using secure communication protocols (e.g.,  SSL/TLS) and virtual private network for connections, meticulously  validating security certificates, and relying on known secure DNS  servers. Additionally, we should be extra cautious when connecting to  public WiFi networks and only be using trusted networks, as public WiFi  is often a prime target for MitM attacks.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-security/9/image9-1.gif)

  Source:  https://heimdalsecurity.com/blog/man-in-the-middle-mitm-attack/

### ARP Spoofing/Poisoning Attacks 

ARP Spoofing (Address  Resolution Protocol Spoofing) or ARP Poisoning, is a Man-in-the-Middle  (MitM) attack executed on a network. ARP is a protocol responsible for  converting an IP address into its corresponding hardware address (MAC  address). In an ARP Spoofing attack, the attacker manipulates the ARP  table by injecting misleading ARP responses, redirecting the flow of  traffic as dictated by the attacker.

This type of attack  allows an attacker to monitor, decrypt, or even exchange data packets  between devices on a network. In this way, the attacker can steal  private data, disrupt services, or perform other malicious actions.

There are several methods to prevent or mitigate ARP Spoofing attacks. These include utilizing  static ARP tables, implementing security tools to detect ARP Spoofing,  and employing network segmentation. Furthermore, adopting secure  communication protocols like SSL and HTTPS can make it challenging for  attackers to intercept or manipulate traffic.  

However, we should know  that these measures may not always offer complete protection. To ensure  comprehensive security, an overarching network security strategy,  regular network monitoring, and constant monitoring of potential  security threats are also critical.

  

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/network-security/9/image9-2.jpeg)

  Source: https://www.opensourceforu.com/2014/10/use-wireshark-to-detect-arp-spoofing/

### IP Spoofing Attacks

IP Spoofing is a network  attack where an attacker deceives the network or systems by using a  counterfeit IP address. This type of attack is often utilized to evade  the network's security measures, execute denial-of-service attacks, or  engage in identity theft by impersonating another user.  

The decryption of traffic entering your network, and specifically egress filtering (controlling  traffic leaving your network), are some the major techniques to prevent  IP spoofing. Egress filtering verifies that the source IP addresses of  all packets leaving your network match the IP address of your network.  This prevents your network from being part of a DDoS attack. 

### DHCP Starvation Attacks  

A DHCP Starvation attack  is a network attack that targets the resources of a dynamic host  configuration protocol (DHCP) server on a network, aiming to disrupt the network's stability. The primary objective is to deplete the available  IP addresses on the network, thereby preventing other users from  acquiring valid IP addresses.  

A DHCP server  automatically allocates IP addresses to systems on a network. In a DHCP  starvation attack, the attacker sends multiple spoofed DHCP requests,  causing the server to "reserve" IP addresses temporarily, making them  unavailable for legitimate users. If enough spoofed requests flood the  server, all available IP addresses may become "reserved," preventing  real users from obtaining new IP addresses.  

This attack usually leads to a network being taken out of service (DoS - Denial of Service)  because new users cannot connect to the network or existing users' IP  addresses cannot be renewed. In some cases, attackers can use this type  of attack when trying to add a malicious DHCP server to a network. This  provides them with the ability to control the traffic of systems on the  network and steal potentially sensitive data.

There are ways to protect your network against DHCP Starvation attacks, and you can do that  easily by enabling MAC address Decryption, DHCP snooping, and port  security.

### DHCP Spoofing Attacks

A DHCP spoofing attack  targets the DHCP (Dynamic Host Configuration Protocol) protocol, which  dynamically assigns the IP addresses of systems on a network. This type  of attack usually allows an attacker to take control of the network and  monitor traffic on the network.

To understand how a DHCP  spoofing attack works, it is important to understand how the DHCP  protocol works first. When a system connects to a network, the DHCP  protocol applies, and a DHCP server on the network assigns an IP address to the system. This process is usually automatic and does not require  user intervention.

In a DHCP spoofing  attack, the attacker typically pretends to be a DHCP server and assigns  fake IP addresses to systems connecting to the network. This allows the  attacker to control and monitor network traffic. For example, an  attacker can monitor the entire Internet traffic of a user by routing it through a proxy server.

Several methods can be  employed to prevent such attacks. For instance, enabling the DHCP  snooping feature on a switch allows it to accept DHCP responses solely  from trusted ports, preventing attackers from posing as fake DHCP  servers and assigning fake IP addresses to connected systems.  Additionally, safeguarding against such attacks involves compelling  systems on the network to utilize reliable DNS servers and encrypting  traffic.

### Phishing

Phishing is a type of  online fraud in which an attacker impersonates a person or organization, usually through an email, text message, or social media message. The  attacker's goal is usually to steal the target's personal information,  financial information, or login information.

Phishing attacks usually occur in the following ways:

**Email Phishing:** The attacker sends  deceptive emails that mimic reputable entities such as banks, social  networks, e-commerce sites, or other trusted organizations. These emails often demand urgent actions and prompt the user to visit a website and  provide their personal information. However, the website is typically a  counterfeit one, and any data entered by the user is directly  transmitted to the attacker.

**Spear Phishing:** This is a type of phishing attack that is particularly targeting a specific person within  the management of an organization. The attacker creates a customized and convincing message using the personal information of the target.

**Whaling:** Similarly to the spear phishing, whaling attacks target the high-profile management personnel within the C-level management. 

There are several  effective strategies to prevent phishing attacks. These include  educating users about recognizing and responding to suspicious emails  correctly, employing automated email scanning tools to identify  potential phishing threats, and implementing additional security  measures like multi-factor authentication (MFA). Furthermore, it is  essential to verify the security of a website at all times (e.g.,  ensuring the URL starts with "https" and trusting the site) before  disclosing personal and financial information.

### Malware Attacks 

Malware is a term that  stands for "malicious software" and typically refers to software  designed to harm computer systems, gain unauthorized access, or steal  personal and sensitive information. Malware can take various forms,  tailored to the attacker's objectives, and often operates covertly,  evading detection.

Malware attacks usually occur in the following ways:

**Viruses:** It is a piece of malware and usually requires a user to run a file or open a plugin. Viruses  usually infect and spread to system files.

**Trojans (Trojans):** It is software that  looks harmless but contains malicious code. It often misleads users and  provides access to the user's system.

**Worms (Worms):** They are self-contained malware that can spread from one system to another over networks. They require no user interaction.

**Ransomware:** It takes the target's data hostage by locking down a computer system or the user's files, usually demanding a ransom.

**Spyware:** It monitors the user's activities by infiltrating a computer system and usually steals personal information or credentials.

**Adware:** Adware is typically  software that displays or redirects unwanted advertisements. While some  adware may be harmless, others can be malicious and cause system  slowdowns or even steal personal information.

Protection against malware attacks typically involves several measures, such as using  up-to-date antivirus software, keeping the operating system and  applications current, avoiding downloads from unknown or suspicious  sources, and being vigilant against phishing attacks. Additionally,  making regular backups and implementing multi-factor authentication  offer extra layers of protection against such attacks.

### Brute Force Attacks

Brute Force attacks are a form of cyberattack where an attacker attempts all possible  combinations to guess a target's password. This is often achieved  through automated software tools. The attacker makes multiple attempts  on the system to determine if a specific password is correct.

Brute Force attacks usually occur in two ways:

**Full Brute Force Attacks:** In such attacks, the  attacker tries all possible combinations of characters. This usually  takes a considerable amount of time and requires sophisticated computer  hardware. However, short and weak passwords can be decrypted relatively  quickly.

**Dictionary-Based Brute Force Attacks:** In such attacks, the  attacker usually uses a dictionary file (a list of commonly used or  guessed passwords). This is usually faster than full brute force attacks because fewer attempts are made.

There are several ways to protect against Brute Force attacks. These include using complex and  long passwords, using multi-factor authentication, setting account  lockout policies (automatically locking the account after a certain  number of failed login attempts), and using security systems that  monitor and block multiple login attempts from IP addresses or user  accounts.

### Zero-Day Attacks

Zero-Day attacks are cyber attacks that exploit unknown and unpatched vulnerabilities in  software (zero-day vulnerabilities). These vulnerabilities are  particularly risky since they have not yet been identified or fixed by  the software's manufacturer. When attackers discover these weaknesses,  they capitalize on the opportunity to harm their targets, steal data, or gain unauthorized access to systems by launching a zero-day attack.

Zero-day attacks come to  an end when security researchers or manufacturers identify the  vulnerability and release a patch. However, during the period before the patch is available, attackers can cause significant harm. These attacks are particularly utilized against critical infrastructures or  high-value targets.

Protecting against  Zero-Day attacks is challenging since they exploit vulnerabilities that  are unknown and unpatched. Nonetheless, there are some general  strategies:

**Keeping the Software Up to Date:** Software manufacturers  regularly release updates to fix security vulnerabilities. Implementing  these updates quickly can reduce the impact of a zero-day attack.

**Using Security Tools:** Some security tools can  provide a certain level of protection against zero-day attacks. For  example, advanced threat protection (ATP) solutions can use behavioral  analysis to identify and block an attack.

**Safety Training:** Educating users,  especially about the techniques that attackers commonly employ to  execute zero-day attacks, such as phishing and social engineering  tactics, is of utmost importance.

**Network Segmentation and the Principle of Least Privilege:** Restricting cross-system access and providing users with only the necessary privileges can  effectively curtail an attacker's access to the system and reduce  potential damage.

**Regular Backup:**   Regular backup of systems and data can help prevent data loss in the event of an attack.

In this part of our  training, We have covered network attacks and their corresponding  solutions. Networking is significantly important within the  cybersecurity and this training will empower you to enhance your network security and effectively counter potential threats. By maintaining an  up-to-date and secure network infrastructure, you can strengthen your  network defense significantly against cyber attacks.

### Questions

**File Location:** /root/Desktop/QuestionFiles/bruteforce.pcap

1 - According to the given PCAP file, which protocol was used in the brute force attack?(bruteforce.pcap)

> **Answer:** FTP

2 - According to the given PCAP file, which user is the brute force attack directed against?(bruteforce.pcap)

> **Answer:** bro

3 - According to the given PCAP file, what is the IP address of the target  device where the brute force attack was performed?(bruteforce.pcap)

> **Answer:** 192.168.56.101

4 - According to the given PCAP file, how many attempts were made in the brute force attack?(bruteforce.pcap)

> **Answer:** 30































