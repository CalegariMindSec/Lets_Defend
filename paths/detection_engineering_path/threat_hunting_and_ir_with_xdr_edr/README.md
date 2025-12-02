# Threat Hunting and IR with XDR/EDR

The  "Threat Hunting and Incident Response with XDR/EDR" course provides  comprehensive training on utilizing Extended Detection and Response  (XDR) and Endpoint Detection and Response (EDR) technologies for  effective threat hunting and incident response strategies in the  cybersecurity domain. Participants will learn advanced methodologies and best practices for proactive threat identification and rapid incident  handling.

**Table of Contents:**

- [What is Threat Hunting?](#what-is-threat-hunting)
- [Purpose and Methods of Threat Hunting](#purpose-and-methods-of-threat-hunting)
- [Threat Hunting Techniques with EDR/XDR](#threat-hunting-techniques-with-edrxdr)
- [Incident Response with EDR/XDR](#incident-response-with-edrxdr)

Evaluate Yourself with Quiz

- [Threat Hunting and IR with XDR/EDR](https://app.letsdefend.io/training/quiz/threat-hunting-and-ir-with-xdr-edr)

## What is Threat Hunting?

### What is Threat Hunting?

Threat hunting is a  security approach that is carried out proactively, not in response to  security incidents, but to identify, isolate and prevent these incidents ahead of time. The goal is to actively investigate these threats,  assuming they may have infiltrated the organization's network. This is  done by analyzing many data sources such as network traffic, log files  and endpoint data. The concept of threat hunting has the following  features.  

**Proactive Approach**

Cyber threat hunting actively searches for potential threats rather than waiting to identify them.  

**In-Depth Data Analysis**

Hunters deeply examine data from log files, network traffic, and other data sources.  

**Use of Specialized Tools and Techniques**

Threat hunters often use specialized tools and techniques beyond standard security tools to better detect threats.

**Human-Focused**

While automated security  tools can assist in this process, cyber threat hunting relies heavily on the analytical capabilities of experienced security professionals.  

### Why is Cyber Threat Hunting Necessary?

Cyber threats are  constantly evolving and attackers keep developing new infiltration  techniques. While traditional security tools work based on known threat  signatures, cyber threat hunting uses analytical and heuristic  approaches to detect attacks that have not yet been “signatured” or are  customized. This better protects organizations against advanced  persistent threats (APTs) and unknown threats such as zero-day attacks.

Traditional security  solutions are effective at detecting known threats, but in the  ever-changing and evolving cyber threat landscape, this is only the  first step. Here are some key reasons why cyber threat hunting is so  essential:  

**Evolving Threat Landscape**

Cyber attackers are  constantly finding new ways to bypass traditional security solutions.  This is mainly achieved through zero-day infiltration methods, advanced  persistent threats (APTs) and specialized malware.  

**Proactive Approach**

Traditional security  tools have a reactive approach; They react when a threat is detected.  However, threat hunting aims to actively find threats before they have  an impact.  

**Comprehensive Visibility**

Threat hunting often  includes techniques such as in-depth network analysis, endpoint  monitoring and log analysis. This helps organizations monitor every  corner of their IT infrastructure.  

**Closing Gaps**

The ability to find threats that traditional security tools cannot detect. It helps closing security gaps.  

**Human Factor**

Cyber threat hunting  relies on the analytical and problem-solving abilities of experienced  security professionals that go beyond automated tools and alerts. The  human factor is critical for detecting certain patterns of behavior that computers may miss.  

**Reduction of the Damage**

An active hunting  approach can significantly reduce how long attackers operate on a  network (dwell time). This means reducing potential damage and cost as  well.  

**Risk Management**

Active threat hunting helps organizations better understand and manage their risks. This  provides more effective protection of their most valuable assets against threats.  

Ultimately, cyber threat  hunting is a critical process that complements traditional security  approaches and protects organizations against unknown and ever-changing  threat landscape. This is especially important today, when the cyber  threat landscape is constantly evolving and attackers are using more  sophisticated and targeted attack methods.  

In this part of the  training, we have covered what threat hunting is, the features of threat hunting, and why cyber threat hunting is necessary in today’s world. In the next part of our training, we will learn abou the "Purposes and Methods of Threat Hunting" topic.

### Questions

1 - Which process is an  approach to security that is not in response to security incidents, but  proactively identifies, isolates and prevents them?

> **Answer:** Threat Hunting

2 - The active approach of threat hunting can reduce how long attackers operate in a network. What is this period called?

> **Answer:** dwell time

## Purpose and Methods of Threat Hunting

Threat hunting is a  proactive cybersecurity approach and was developed not as a reaction to a specific security incident, but to detect and respond to such incidents in advance. Threat hunting actively investigates computing networks and systems to detect, analyze, and take action against potentially  dangerous and suspicious activities.  

### Purposes of Threat Hunting

**Proactive Defense**

Traditional security  approaches are generally reactive, meaning they take action after a  security breach occurs. The primary goal of threat hunting is to adopt a proactive defensive posture in which threats are detected and blocked.  By actively searching for potential threats in systems and networks, it  ensures that these threats are detected and blocked before they turn  into real harm.  

**Reducing Attacker's Residence Time**

Attackers usually have a residence time after taking over a network or system. During this time,  they may engage in data theft, spreading malware, or other malicious  activities. By reducing this dwell time, threat hunting limits  attackers' activities and minimizes potential damage.  

**Protection Against Advanced Threats**

Today's threats are  becoming increasingly sophisticated to bypass traditional security tools and solutions. Threat hunting actively scans computing networks and  systems to detect specialized and targeted threats such as Advanced  Persistent Threats (APTs).  

**Security Posture Improvement**

Threat hunting helps  security teams identify vulnerabilities and potential risks in their  networks. This information can be used to create a more robust security  architecture and strengthen existing security protocols.  

In summary, threat  hunting helps organizations take a proactive security approach. This  approach ensures that attackers are detected early and dealt with effectively, preventing potential harm and minimizing security risks.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Threat+Hunting+and+IR+with+XDR-EDR/2/image2-1.png)

(Image Source:   [https://www.crowe.com/cybersecurity-watch/hunting-the-hunters ](https://www.crowe.com/cybersecurity-watch/hunting-the-hunters)  )

### Methods of Threat Hunting

**Hypothesis-Based Hunting**

This approach is a method in which security experts develop a hypothesis on a particular threat  or suspicion of malicious activity. For example, if an expert suspects  that a particular type of malware may have infiltrated the company  network, he or she initiates an in-depth investigation into that  hypothesis.  

**Machine Learning and Analytics Hunting**

In this approach, a baseline is created on the normal network traffic and user behavior.  Anomaly hunting detects deviations or anomalies from this norm. These  deviations may be indicative of a threat or malicious activity.  

**Signature-Based Hunting**

This approach uses  signatures of pre-defined malicious activities or malware samples.  Malicious activities have certain “signatures” and this method aims to  find potential threats by detecting these signatures.  

**TTP Based Hunting (Tactics, Techniques, and Procedures)**

It is carried out based on the tactics, techniques and procedures used by attackers. CTI (Cyber  Threat Intelligence) reports and other intelligence sources help hunters understand what types of TTPs attackers are using.  

**Automation and Triage**

Making an initial assessment of suspicious events using tools configured for automatic threat detection.  

Each of these methods  focuses on a different aspect of threat hunting. For example,  hypothesis-based hunting is often used in situations where a hunter has a specific idea or intuition about a specific threat vector or tactic,  while analytical hunting is often used to analyze large amounts of data  and detect specific behavioral patterns or anomalies.  

In this part of the  training, we have covered the purposes and methods of threat hunting. In the next part of our training, we will learn about the “Threat Hunting Techniques with EDR/XDR” topic.

## Threat Hunting Techniques with EDR/XDR

Even though EDR/XDR tools are the most important resources for threat hunting process and they  may not be enough to achieve the goal because it requires many other  resources. Other tools and technologies required for threat hunting are  SIEM, XDR/EDR, CTI, network-based threat detection technologies (NIDS,  NDR, etc.) and Sandboxes.  

### Threat Hunting Techniques with EDR/XDR

EDR and XDR technologies are invaluable tools to support threat hunting activities. Thanks to  these technologies, security professionals can proactively investigate  and respond to potential threats. The main hunting techniques are as  follows:  

**Indicator-based Hunting**

Indicator-based Hunting  is a threat hunting method that detects potential threats using  previously known markers or indicators of malicious activity. These  indicators are generally obtained from previously detected events,  public sources, private intelligence sources or sector-specific shares.

For example; A security  report states that a malicious botnet was controlled from a specific IP  address. This will help cybersecurity analysts to search for this IP  address in their organization's network traffic to check whether there  is any interaction with those IPs and to be on the alert.  

**Behavioral-based Hunting**

Behavioral-based Hunting  is a proactive threat hunting approach that detects potential threats by monitoring typical behavior of systems, users, or networks, rather than relying on static indicators of known malicious activity. This method  is based on predefined behavioral characteristics and analytics.  

For example; Such as a  user without administrative rights unexpectedly running administrative  tools on the system, or a standard user running "PowerShell" or "Command Prompt" with administrative rights.  

**Heuristic Hunting**

Heuristic Hunting is a  threat hunting method that uses general behavioral characteristics and  rules to detect potential threats without relying on specific threat  signatures or known behaviors. This approach is often used to detect new and unknown threats.

For example; You see a  constant and rapid port scanning activity on your network which is like a device on your internal network scanning thousands of ports in a few  seconds.  

### Threat Hunting with SentinelOne

SentinelOne offers  numerous features for threat hunting. One of the major characteristics  of SentinelOne is that the wide range of telemetry data it collects.  Using SentinelOne's “Deep Visibility” feature, you can query all  activity associated with a specific IP address, domain, URL or hash  value.

To perform threat hunting with SentinelOne, the "Hunting" menu opens on the "Visibility" screen.

- By opening more than one new tab on this screen, you can run different hunting queries in different tabs.  
- By default, threat hunting data is kept for 14 days in SentinelOne.  
- You can access ready-made queries (basic, advanced, etc.) on this screen.  

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Threat+Hunting+and+IR+with+XDR-EDR/3/image3-1.png)

You can type your query  in its search bar labeled as "Start Hunting" which has the autocomplete  feature. You can specify a field name or value etc. Similar field names  and values to yours will automatically be listed at the bottom as you  type. For example, if we are going to search for an event type, we can  press the "TAB" key to list the event types we can search down.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Threat+Hunting+and+IR+with+XDR-EDR/3/image3-2.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Threat+Hunting+and+IR+with+XDR-EDR/3/image3-3.png)

Additionally, SentinelOne displays all the data collected on the hunting screen in different tabs according to certain categories. The main ones are Processes, Cross  Process, Indicators, Files, Network Actions, DNS, URL, Registry,  Scheduled Tasks, Logins, Driver Load, Command Scripts.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Threat+Hunting+and+IR+with+XDR-EDR/3/image3-4.png)

The "Indicators" tab in  the "Hunting" section of SentinelOne can be thought of as a tool that  allows you to investigate specific threat indicators and identify  potential threats on your systems based on these indicators. This tab is used to search and analyze signs of malicious activity. This is a  proactive security approach which scans your network based on known  signs of malware and helps you identify potential threats.

For example, when we look at the Indicator detail below, it is reported that the "cmd.exe" opened by the "admin" user was run via a shortcut, not as a direct incident,  but as a potential suspicious activity. This situation points to the  Mitre T1204 technique.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Threat+Hunting+and+IR+with+XDR-EDR/3/image3-5.png)

When we look at another  Indicator detail, we see that the case reported as “Different Original  Filename” was actually run by the “C:\python27\excel.exe” application,  which imitates excel.exe, one of the Microsoft Office applications, but  this exe was reported because it is not the original Excel application.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Threat+Hunting+and+IR+with+XDR-EDR/3/image3-6.png)

### Conclusion/Summary

Threat hunting is an  approach used by cybersecurity professionals to proactively investigate  and respond to potential threats. EDR/XDR technologies are invaluable  tools to support threat hunting activities. These technologies are used  to detect and analyze potential threats using data collected from  endpoints, networks, and other sources.

In this part of the  training, we have covered threat hunting techniques and how threat  hunting can be conducted via SentinelOne. In the next part of the  training, we will be learning about the “Incident Response with EDR/XDR” topic.

### Questions

1 - Which tab in SentinelOne's "Hunting" section is used to search for and analyze indicators of malicious activity?

> **Answer:** Indicators

## Incident Response with EDR/XDR

Incident management is a process that helps for detecting, investigating, responding and  remediating a cyber attack or other security incidents. Incident  management is key to maintaining the organization's cybersecurity  posture and minimizing the impact of an attack.

The incident management process includes the following stages:  

**Incident detection**

The incident response  team uses a variety of tools and techniques to detect potential threats. These tools include firewalls, network detectors, endpoint security  solutions, and EDR/XDR technologies.  

**Incident investigation**

The incident response  team uses a variety of tools and techniques to investigate detected  incidents. These tools include incident management tools, security  analysis tools, and threat intelligence sources.  

**Incident response**

The incident response  team uses a variety of tools and techniques to respond to incidents that are detected and investigated. These tools include endpoint security  solutions, firewalls, and network detectors.  

**Incident remediation**

The incident response  team uses a variety of tools and techniques to determine the causes of  detected and responded to incidents and prevent future attacks. These  tools include incident management tools, security analysis tools, and  threat intelligence sources.  

EDR/XDR technologies can  help make incident management more effective. EDR/XDR technologies are  used to detect and analyze potential threats using data collected from endpoints, networks, and other sources. This data can help incident  managers detect and respond to incidents faster and more accurately.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Threat+Hunting+and+IR+with+XDR-EDR/4/image4-1.png)

(Image Source:   [https://www.blumira.com/incident-response-guide-malware-infections/ ](https://www.blumira.com/incident-response-guide-malware-infections/)  )

## How to Relate EDR/XDR to Incident Response?

**Early Threat Detection**

EDR and XDR technologies  continuously monitor organizations' networks, endpoints and cloud  infrastructures. In this way, abnormal or unusual behavior, malware or  signs of threats can be detected quickly. This early detection allows  attacks to be addressed in their early stages and helps limit potential  damage.  

**Rapid Response Capacity**

EDR/XDR technologies are  equipped with automation and fast response mechanisms. In this way, when a threat is detected, automatic response mechanisms can involve to take action. For example, when a malicious file is detected, responses such  as quarantining this file or isolating the system from the network  access can be carried out automatically. This rapid response helps  prevent the spread of attacks and minimize their impact.  

**Detailed Analysis and Diagnosis**

EDR and XDR technologies  have the capacity to analyze attacks in detail. These analyses may  include details such as how the attack occurred, what steps were  followed, and which systems were affected. These analyses are critical  to better understand the causes and consequences of the event.  

**Identifying the Chain of Events**

EDR/XDR technologies can  detect how attacks occur step by step. This is important to determine  the attack chain and understand what stages the attack went through.  This information helps develop strategies to predict and prevent similar attacks in the future.  

**Provide Visibility**

While EDR technologies  monitors activities at endpoints, XDR can also monitor network and  cloud-based activities. This holistic visibility is critical for  detecting and blocking threats across platforms. Thanks to the  integration of data from different sources, the entire threat can be  better understood.  

**Automation and Efficiency**

EDR/XDR technologies  reduce human error and speed up the response process thanks to their  automation capabilities. Tasks that people must implement manually are  automated, so response times are faster and teams can work more  efficiently.  

**Data Collection and Storage**

EDR/XDR solutions can  store data collected during the attack for analysis and use when  necessary. This data is important for analyzing the attack, determining  the source of the threat and preventing attacks. It can also be used to  extract lessons learned to improve future incident response processes.  

**Learning and Improvement**

The use of EDR/XDR  technologies provides an opportunity to learn from experiences gained  from real attacks and incidents. These experiences help improve future  incident response processes. Improvement opportunities are identified  and security defenses are strengthened.  

**Integration of Various Data Sources**

XDR provides more  comprehensive visibility by integrating different data sources. This  makes it easier to evaluate and detect attacks from different  perspectives.  

**Data Based Decision Making**

EDR/XDR tools deliver  data-driven analysis and reports, enabling teams to make better  decisions. Thanks to decision-making based on this data, more effective  strategies are developed.  

In conclusion, EDR and  XDR technologies strengthen the organization’s security defenses,  helping them responding to cyber attacks faster, detect threats more  effectively, and be ready for future attacks. These technologies make  the Incident Response process more effective and efficient.































































