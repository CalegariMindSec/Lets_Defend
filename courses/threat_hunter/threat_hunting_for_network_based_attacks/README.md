# Threat Hunting for Network-Based Attacks

In the "Threat Hunting for Network-Based Attacks" course, participants  will embark on a journey to understand the intricacies of identifying,  analyzing, and responding to network-based threats. This course is  designed to bridge the gap between theoretical knowledge and practical  application, diving deep into the methodologies that skilled threat  hunters use to protect organizational networks. With a hands-on  approach, interactive tutorials, and real-world case studies, learners  will gain valuable insights into various threat hunting techniques and  tools to recognize early signs of malicious activities, ensuring a  robust defense against cyber threats.

**Table of Contents:**

- [Introduction]()
- [Common Network-Based Attack Vectors]()
- [Techniques for Network-Based Attacks]()
- [Abnormal Traffic Hypothesis]()
- [Port Scanning Activity Hypothesis]()
- [Practical Lab 1]()
- [Practical Lab 2]()
- [Practical Lab 3]()

Evaluate Yourself with Quiz

- [Threat Hunting for Network-Based Attacks](https://app.letsdefend.io/training/quiz/threat-hunting-for-network-based-attacks)

## Introduction

Network-based attacks  are cyberattacks where attackers aim to gain access to systems,  databases, or devices through an organization's network. These attacks  can be carried out using various techniques, such as man-in-the-middle  (MiTM) and port scanning. Additionally, DDoS attacks are also among the  network-based threats that cause service disruptions. Network-based  attacks pose serious risks to businesses, leading to service outages,  data breaches, and financial losses. Therefore, network security is  considered a fundamental component of modern cybersecurity strategies.  

Through threat hunting, a proactive defense strategy can be developed against network-based  attacks. Network traffic and logs are analyzed in depth to identify  anomalies and attack indicators that traditional security measures may  miss. This process enables the early detection and prevention of  attacks, strengthens network security, and minimizes potential damage.  Threat hunting makes defense dynamic and effective against the  ever-evolving cyber threat landscape.  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Network-Based+Attacks/1.Introduction/image1_1.png)

(**Image Source**: https://www.wallarm.com/what/what-is-a-cyber-attack)  

This lesson provides an introduction to the topic. The next lesson will cover "Common Network-Based Attack Vectors".  

## Common Network-Based Attack Vectors

Network-based attacks  are considered one of the most significant threats in cybersecurity.  These attacks use techniques such as DDoS, Man-in-the-Middle (MitM), and Port Scanning to disrupt network traffic, steal data, or gain  unauthorized access to systems. In the threat hunting process, it is  critical to develop proactive strategies to detect and prevent these  attacks. These strategies include methods such as network traffic  analysis, monitoring abnormal activities, and strengthening security  controls. A successful threat hunting process ensures the early  detection of network-based attacks and minimizes their impact.  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Network-Based+Attacks/2.Common+Network-Based+Attack+Vectors/image2_1.png)

(**Image Source**: https://www.educba.com/types-of-attack/)  

### Port Scanning  

Port Scanning is an attack method used to identify open ports and vulnerabilities on a  target system. This technique allows attackers to determine which  services are running on the target system and discover potential attack  points.  

- **How It Works:** The attacker scans  the ports on the target system to identify which ports are open and then launches attacks through these open ports.    
- **Example:** An attacker using the nmap tool to scan open ports on a target system.    
- **Prevention:** Close unused or unnecessary ports using firewall rules and detect port scans using network monitoring tools.    
- **Threat Hunting Process:** Analyze network traffic and firewall logs to detect port scans and monitor suspicious IP addresses.    

### Zero-Day Exploits  

Zero-Day Exploits are attacks that exploit previously unknown vulnerabilities in software.  These attacks are highly dangerous because the vulnerabilities are not  yet known or patched by software vendors.  

- **How It Works:** The attacker discovers the vulnerability and uses it to infiltrate the system.    
- **Example:** Exploiting a newly discovered browser vulnerability.    
- **Prevention:** Regularly apply updates and patches, and harden applications to reduce the attack surface.    
- **Threat Hunting Process:** Monitor abnormal system behavior and unexpected software errors, and use threat intelligence to detect Zero-Day Exploits.    

### Spoofing Attacks  

Spoofing Attacks  involve attackers hiding their identity or source and presenting fake  information. These attacks can be carried out using various methods such as IP address spoofing, DNS spoofing, and ARP spoofing.  

- **How It Works:** The attacker deceives the target system using fake credentials or a fake IP address.    
- **Example:** An attacker conducting a phishing attack using a fake email address.    
- **Prevention:** Use trusted source verification methods on the network and deploy IDS/IPS systems to detect spoofed traffic.    
- **Threat Hunting Process:** Analyze network traffic to detect authentication errors and monitor spoofed IP addresses or DNS requests.    

### Code Injection  

Code Injection is the  execution of malicious code injected into an application. This attack  exploits vulnerabilities in the application, allowing the attacker to  execute code.  

- **How It Works:** The attacker inputs malicious code into user input fields, and this code is executed on the server.    
- **Example:** Injecting malicious JavaScript code into a web form.    
- **Prevention:** Strictly validate user inputs and implement security controls.    
- **Threat Hunting Process:** Review web application logs to detect suspicious code injection attempts and monitor abnormal behavior.    

### DDoS Attacks  

DDoS (Distributed  Denial of Service) Attacks aim to overwhelm a target system, causing  service disruptions. These attacks are typically carried out using  traffic sent from multiple devices.  

- **How It Works:** The attacker sends a large volume of traffic to the target system from multiple sources, rendering the system unresponsive.    
- **Example:** A website getting crashed by sending thousands of fake requests.    
- **Prevention:** Use load balancers and traffic filtering systems to reduce attack traffic.    
- **Threat Hunting Process:** Monitor network traffic to detect abnormally high traffic and identify early signs of DDoS attacks.    

### Brute Force Attacks  

Brute Force Attacks  involve systematically guessing a user's credentials using  trial-and-error methods to crack passwords. These attacks often target  accounts with weak passwords.  

- **How It Works:** The attacker uses automated tools to try a series of password combinations.    
- **Example:** Attempting to log into an SSH server using consecutive password attempts.    
- **Prevention:** Enforce strong password policies and use multi-factor authentication (MFA).    
- **Threat Hunting Process:** Review security logs to detect suspicious login attempts and monitor multiple failed login attempts from the same IP address.    

### Buffer Overflow  

Buffer Overflow is an  attack where the buffer space in an application's memory is exceeded,  allowing malicious code to be executed. These attacks often target  programs with weak memory management.  

- **How It Works:** The attacker overflows the buffer memory, overwriting commands and executing malicious code.    
- **Example:** Executing code by overflowing the buffer memory on a web server.    
- **Prevention:** Use secure coding practices and memory management techniques to prevent such vulnerabilities.    
- **Threat Hunting Process:** Monitor system errors and crashes, and investigate anomalies in memory usage.    

### Man-in-the-Middle (MitM) Attacks  

Man-in-the-Middle (MitM) Attacks involve an attacker secretly intercepting or altering  communication between two parties. These attacks are used to steal or  manipulate user data.  

- **How It Works:** The attacker intercepts and manipulates traffic between two parties.    
- **Example:** Stealing credit card information over an unencrypted Wi-Fi network.    
- **Prevention:** Use encryption protocols like SSL/TLS and isolate traffic through network segmentation.    
- **Threat Hunting Process:** Monitor network traffic to detect unusual traffic redirections and traffic manipulation attempts.    

### Worms and Viruses  

Worms and Viruses are self-replicating malicious software. While viruses typically spread  through user actions, worms can spread automatically over a network.  

- **How It Works:** The malicious software replicates from one device to another, affecting the system.    
- **Example:** A virus sent via email infecting multiple devices.    
- **Prevention:** Use antivirus software and increase user awareness.    
- **Threat Hunting Process:** Monitor security software logs and network traffic to detect signs of malware spread.    

### Trojan Attacks  

Trojan attacks involve  malicious software that is disguised as a legitimate program. Users  unknowingly download and run Trojans, allowing attackers to gain access  to the system.  

- **How It Works:** The attacker presents the malicious software as a legitimate application, and users download and execute it.    
- **Example:** A fake software update sent as an email attachment.    
- **Prevention:** Only download software from trusted sources and educate users about suspicious files.    
- **Threat Hunting Process:** Use endpoint security software to monitor malicious software and detect suspicious file downloads and executions.    

This lesson discussed common network-based attack vectors. The next lesson will cover "Threat Hunting Techniques for Network-Based Attacks".  

## Techniques for Network-Based Attacks

To conduct an effective threat hunting process against network-based attacks, it is essential  to have specific knowledge and technologies. The following is an outline of the key skills and technology needed for the process:  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Network-Based+Attacks/3.Threat+Hunting+Techniques+for+Network-Based+Attacks/image3_1.png)

### Knowledge Requirements  

- **Network Protocols**: Understanding basic network protocols such as TCP/IP, HTTP, DNS, and SSL/TLS is critical to monitoring and analyzing network traffic. Understanding these protocols is necessary to detect and respond to attacks using these protocols.    
- **Attack Techniques**: It is important to  understand common network attack techniques such as DDoS,  Man-in-the-Middle (MitM), port scanning, and spoofing. This knowledge  will help determine what indicators may signal an attack.    
- **Security Standards:** Familiarity with  security standards and frameworks such as OWASP and MITRE ATT&CK  helps in understanding attack vectors and developing defense strategies.    
- **Understanding Network Architecture:** Understanding an  organization's network topology, segmentation, and firewall policies is  critical to determining where to focus threat hunting efforts.    

### Required Technologies and Tools  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Network-Based+Attacks/3.Threat+Hunting+Techniques+for+Network-Based+Attacks/image3_2.png)

(**Image Source**: https://www.fortinet.com/br/resources/cyberglossary/threat-hunting)  

### IDS/IPS (Intrusion Detection/Prevention System)  

- **Purpose:** IDS detects attack  attempts, while IPS blocks these attacks. These systems monitor network  traffic to recognize attack signatures and stop malicious activities.    
- **Threat Hunting Process:** IDS/IPS can be used for the immediate detection and prevention of network-based threats such as port scanning and DoS attacks.    

### Network Traffic Analysis Tools (NTA)  

- **Purpose:** These tools analyze  network traffic in depth to detect abnormal behavior. They monitor and  analyze data packets, enabling anomaly detection.    
- **Threat Hunting Process:** It is used to detect threats such as abnormal traffic patterns and data exfiltration attempts.    

### SIEM (Security Information and Event Management)  

- **Purpose:** It collects,  analyzes, and correlates logs from various sources to detect attacks.  SIEM is used to monitor anomalies in network traffic, suspicious login  attempts, and unusual system behavior.    
- **Threat Hunting Process:** SIEM plays a central role in detecting abnormal events and identifying attack attempts in a timely manner.    

### EDR (Endpoint Detection and Response)  

- **Purpose:** It monitors and  blocks abnormal activities on endpoints (servers, user computers). EDR  systems provide immediate response capabilities against threats.    
- **Threat Hunting Process:** It enables rapid detection of threats such as brute force attempts and malware on endpoints.    

### Threat Intelligence Platforms  

- **Purpose:** It collects and  analyzes up-to-date threat information (IoC, TTP). These platforms  provide insights into attackers' methods, helping to develop defense  strategies.    
- **Threat Hunting Process:** It is used to stay updated about current threats and integrate this information into defense mechanisms.    

### Vulnerability Scanners  

- **Purpose:** It identifies  vulnerabilities in networks and systems and provides guidance for  mitigation. These tools are used to assess the security posture of  systems.    
- **Threat Hunting Process:** Regular scans are conducted to detect potential vulnerabilities and prevent their exploitation by attackers.    

### Packet Capture Tools (Wireshark, tcpdump)  

- **Purpose:** It captures and analyzes network traffic. These tools are used for detailed inspection of data packets.    
- **Threat Hunting Process:** Detailed network traffic analysis is essential to detect suspicious packets and abnormal traffic patterns.    

### Deception Technologies (Honeypots, Honeynets)  

- **Purpose:** These tools deceive attackers and analyze their methods. Honeypots and honeynets divert attackers' attention from real systems.    
- **Threat Hunting Process:** They help to analyze attackers' techniques and tools and develop defense strategies.    

### Network Access Control (NAC) Solutions  

- **Purpose:** They manage and  control network access permissions. NAC solutions ensure that only  authorized devices and users can access the network.    
- **Threat Hunting Process:** They are used to detect and block unauthorized access attempts to the network.    

### Conclusion  

Proper and effective  use of these technologies can help detect, prevent, and strengthen  defenses against network-based attacks. The integration and proper  configuration of these tools into the threat hunting process is the  foundation of a successful security strategy.  

This lesson discussed  the technologies and tools used in the threat hunting process to detect  network-based attacks. The next lesson will cover the “Abnormal Traffic Hypothesis”.  

## Abnormal Traffic Hypothesis

### Hypothesis

A specific internal IP address may be sending an abnormally high volume  of traffic to external IP addresses using unexpected network protocols  (such as ICMP or UDP). This could indicate a data exfiltration attempt  or be part of a DDoS attack.

### Data Sources

- **Firewall Logs:** Internal and external network traffic, connection attempts using specific  protocols, and records of failed and successful connection attempts.
- **SIEM Logs:** Centralized collection of logs from firewalls, IDS/IPS, and other security devices.
- **Network Flow Analysis:** Protocol-based examination of network traffic data and monitoring of connection flows.
- **IDS/IPS Logs:** Logs from systems that detect and record suspicious or malicious activities.
- **NetFlow/Sflow:** Monitoring and analysis of network traffic flows on a protocol basis.

### Analysis Steps

- **Data Collection:** Firewall logs, NetFlow data, and logs from other network security devices are  forwarded to a centralized log management system or SIEM solution.
- **Establish Normal Traffic Patterns:** Identify the protocols typically used on the network and the typical traffic volume associated with these protocols.

### Anomaly Detection

- Analyze activities that deviate from the normally used protocols (e.g., unexpected ICMP or UDP traffic).
- Examine high-volume connection attempts from a specific internal IP address using these protocols.

### Correlation Analysis

- Correlate firewall logs, IDS/IPS logs, and NetFlow/Sflow data to identify the source of abnormal activities.
- Investigate the relationship between detected anomalies and other security events.

### Identify Attack Vectors

- Determine the external IP addresses targeted by the attacker and potential attack vectors based on the detected abnormal protocol usage.

### Incident Verification and Monitoring

- Collect additional data to verify the incident and determine the stages of the attack attempt.
- Monitor suspicious activities and track potential related connections in the long term.

### Expected Results

- An abnormal amount of traffic is detected using unexpected network  protocols (e.g., ICMP, UDP) from a specific internal IP address.
- Analysis of firewall logs and NetFlow data confirms that this traffic is abnormal and potentially malicious.
- Correlation analysis with SIEM and other security logs determines whether this  activity is indicative of a data exfiltration attempt or a precursor to a DDoS attack.

This lesson discussed a hypothesis about anomalous traffic using unexpected network protocols. The next lesson will cover the "**Port Scanning Activity Hypothesis**".

## Port Scanning Activity Hypothesis

### Hypothesis

A particular external IP address may suddenly send a large number of  connection requests to the internal network. This could be an indication of port scanning activity or a vulnerability scanning attempt.

### Data Sources

- **Firewall Logs:** Internal and external network traffic, connection attempts, and records of successful and failed connections.
- **SIEM Logs:** Centralized collection of logs from firewalls and other security devices.
- **IDS/IPS Logs:** Logs from systems that detect and record suspicious or malicious activities.
- **Network Flow Analysis:** Monitoring and analysis of connection flows.

### Analysis Steps

- **Data Collection:** Logs from firewalls, IDS/IPS, and other network security devices are  forwarded to a centralized log management system or SIEM solution.
- **Establish Normal Traffic Patterns:** Determine the normal volume, source, and target ports of connection requests to the network.

### Anomaly Detection

- Analyze sudden and high-volume connection requests from external IP addresses.
- Examine the ports targeted by these connection requests and the frequency of connection attempts.
- Specifically, analyze continuous connection attempts to different ports (port scanning).

### Correlation Analysis

- Correlate firewall logs, IDS/IPS logs, and network flow analysis to identify the source of abnormal activities.
- Investigate the relationship between detected anomalies and other security events.

### Identify Attack Vectors

- Evaluate whether the detected abnormal connection requests represent potential attack vectors.
- Investigate whether there is evidence of port scanning or vulnerability scanning activities.

### Incident Verification and Monitoring

- Collect additional data to verify the incident and determine the stages of the attack attempt.
- Monitor suspicious activities and track potential related connections in the long term.

### Expected Results

- A high volume of connection requests from a specific external IP address to specific ports is detected.
- Analysis of firewall and IDS/IPS logs confirms that this traffic is part of port scanning activity.
- Correlation analysis with SIEM and other security logs determines if this activity  is indicative of a vulnerability scanning attempt.

### Summary

These analysis steps provide strategies for detecting abnormal traffic  activity associated with port scanning. Firewall logs, NetFlow data, and IDS/IPS logs are critical data sources for monitoring and identifying  such activity. Early detection of anomalies plays an important role in  ensuring network security and proactively preventing potential attacks.  This process allows analysts to quickly identify anomalous activity on  the network and then take timely action.

## Practical Lab 1

### Hypothesis

**Note**: The questions in this section are prepared for Threat Hunting based on the following hypothesis:

**Hypothesis:** Attackers might attempt to execute commands by launching OS command injection  attacks against web applications, and conduct lateral network scans.

### Threat Hunting Lab Environment

- Firewall Traffic Events
- IPS/IDS Events (FortiIPS)
- EDR Events (Sysmon)
- SIEM (Wazuh)
- Web Access Logs (Microsoft IIS)

### Lab Notes

- Analyze the logs between "Aug 19, 2024 00:00 - Aug 23, 2024 00:00" to answer the questions below.
- Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

### Questions

**Note:** Analyze the logs between "Aug 19, 2024 00:00 - Aug 23, 2024 00:00" to answer the questions below.

**Note**: Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

1 - What is the IP address that carried out the "OS.Command.Injection.Attempt" attack that was reported by the IPS?

> **Answer:** 124.31.2.92

2 - What is the firewall action taken against the "OS Command Injection" attack reported by the IPS?

> **Answer:** alert

3 - What is the command executed remotely in the "OS Command Injection" attack reported by the IPS?

> **Answer:** whoami

4 - In the previous stages of the threat hunting process, the "OS Command  Injection" attack reported by the IPS was identified. According to EDR  logs, what is the parent process of the process that executed the  command?

> **Answer:** C:\\Windows\\System32\\apache.exe

5 - In the previous stages of the threat hunting process, the "OS Command  Injection" attack reported by the IPS was identified. Subsequently, the  parent process of the process that executed the command during this  attack was found. What is the name of a different Windows lolbin process executed by this parent process?

**Note**: This attack might have eluded IPS's detection.

**Answer Format**: cmd.exe

> **Answer:** certutil.exe

6 - In the previous stages of the threat hunting process, the "OS Command  Injection" attack reported by the IPS was identified. Subsequently, the  parent process of the process that executed the command in this attack  was found. What is the name of the file downloaded using a different  Windows lolbin tool executed by this parent process?

**Answer Format**: test.zip

> **Answer:** PSTools.zip

7 - In the previous stages of the threat hunting process, an "OS Command  Injection" attack reported by the IPS was identified. According to EDR  logs, a process other than the web service process on this endpoint  device established a network connection. What is the name of this  process?

**Answer Format**: cmd.exe

> **Answer:** psping.exe

## Practical Lab 2

### Hypothesis

**Note**: The questions in this section are prepared for Threat Hunting based on the following hypothesis:

**Hypothesis:** Attackers may manipulate DNS queries on the corporate network by launching DNS  hijacking attacks to redirect users to fake websites.

### Threat Hunting Lab Environment

- Vulnerability Detection Events (Nessus)
- IPS/IDS Events (Suricata Network IDS)
- Windows DNS Audit Events
- SIEM (Wazuh)
- Firewall Traffic Events

### Lab Notes

- Analyze the logs between "Aug 19, 2024 00:00 - Aug 23, 2024 00:00" to answer the questions below.
- Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

### Questions

**Note:** Analyze the logs between "Aug 19, 2024 00:00 - Aug 23, 2024 00:00" to answer the questions below.

**Note**: Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

1 - What is the CVE for the critical vulnerability detected on the DNS Server?

**Answer Format**: CVE-2022-1133

> **Answer:** CVE-2020-1350

2 - What is the date when the critical vulnerability on the DNS Server was detected?

**Note**: It is the @timestamp value.

**Answer Format**: Jan 27, 2024 @ 22:16:37.124

> **Answer:** Aug 19, 2024 @ 17:28:39.956

3 - What is the "data.alert.signature" of the IPS or IDS event generated by a  signature pointing to the critical vulnerability detected on the DNS  Server?

> **Answer:** ET EXPLOIT Microsoft Windows DNS Server SIG Record Parsing RCE Attempt (CVE-2020-1350)

4 - What is the source IP address of the IPS or IDS event generated by a  signature pointing to the critical vulnerability detected on the DNS  Server?

> **Answer:** 92.8.100.23

5 - In the previous stages of the threat hunting process, the source IP  address of the IPS or IDS event pointing to the critical vulnerability  on the DNS Server was identified. According to the CTI platform ([Threat Intel LetsDefend Platform](https://app.letsdefend.io/threat-intelligence-feed)), which APT group does this IP address belong to?

> **Answer:** APT-M070

6 - What is the record deleted by the "Record Delete" event on the DNS Server?

> **Answer:** ghsprofessional.company.local

7 - What is the record added by the "Record Add" event on the DNS Server?

> **Answer:** ghsprofessional.company.local

8 - What is the record type of the new entry added by the "Record Add" event on the DNS Server?

﻿**Answer Format**: MX

> **Answer:** A

9 - What is the corresponding IP address for the new record added by the "Record Add" event on the DNS Server?

> **Answer:** 147.23.7.30

10 - In the previous stages of the threat hunting process, the corresponding IP address for the new record added by the "Record Add" event on the DNS  Server was identified. How many different IP addresses are communicating with this IP address?

> **Answer:** 4

11 - In the previous stages of the threat hunting process, the corresponding IP address for the new record added by the "Record Add" event on the DNS  Server was identified. What is the firewall action for the accesses to  this IP address?

> **Answer:** deny

## Practical Lab 3

### Hypothesis

**Note**: The questions in this section are prepared for Threat Hunting based on the following hypothesis:

**Hypothesis:** The "APT-BN42" APT group, as reported by the CTI service, may have  compromised XYZ Software's update servers and altered the update  packages. Institutions that received these software updates may be  communicating with the APT group's command and control (C2) server.

### Threat Hunting Lab Environment

- Firewall Traffic Events
- IPS/IDS Events (Suricata Network IDS)
- EDR Events (Sysmon)
- SIEM (Wazuh)
- CTI Events ([Threat Intel LetsDefend Platform](https://app.letsdefend.io/threat-intelligence-feed))

### Lab Notes

- Analyze the logs between "Aug 19, 2024 00:00 - Aug 23, 2024 00:00" to answer the questions below.
- Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

### Questions

**Note:** Analyze the logs between "Aug 19, 2024 00:00 - Aug 23, 2024 00:00" to answer the questions below.

**Note**: Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

1 - What is the IP address reported on the CTI platform ([Threat Intel LetsDefend Platform](https://app.letsdefend.io/threat-intelligence-feed)) belonging to the “APT-BN42” APT group?

> **Answer:** 23.11.98.133

2 - What is the destination IP address in the IDS alert related to the Anydesk software associated with the "APT-BN42" APT group?

> **Answer:** 172.16.5.16

3 - What is the source IP address in the IDS alert generated during the same  time period for the Anydesk software affected by the "APT-BN42" APT  group?

> **Answer:** 19.68.100.23

4 - What is the hash value for the "APT-BN42" APT group, as reported on the CTI platform ([Threat Intel LetsDefend Platform](https://app.letsdefend.io/threat-intelligence-feed))?

> **Answer:** 4986659HGFYRFM232BE450E124A34439D67

5 - What is the IP address of the system for which the CTI platform ([Threat Intel LetsDefend Platform](https://app.letsdefend.io/threat-intelligence-feed)) reported a hash for the "APT-BN42" APT group?

> **Answer:** 172.16.5.16

6 - What is the process name for the hash reported for the "APT-BN42" APT group on the CTI platform ([Threat Intel LetsDefend Platform](https://app.letsdefend.io/threat-intelligence-feed))?

> **Answer:** anyupdate.exe



































