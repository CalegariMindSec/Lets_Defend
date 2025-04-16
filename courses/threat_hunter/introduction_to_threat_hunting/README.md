# Introduction to Threat Hunting

This course offers a comprehensive introduction to the world of threat  hunting within cybersecurity. Through practical lessons and real-world  scenarios, you will learn to identify, investigate, and mitigate  potential security threats effectively. Designed for both beginners and  those looking to refresh their skills, the course covers key techniques  and tools used in threat detection and response. By the end of the  course, you'll be prepared to proactively protect networks and systems  from emerging cyber threats, with a solid foundation in modern  threat-hunting methodologies.

**Table of content:**

- Introduction

- Threat Hunting Team and Competencies
- Threat Hunting Methodologies
- Hypothesis-Driven Approach
- IoC-Based Approach
- Threat Hunting Life Cycle

## Introduction

Threat hunting is the  proactive process of searching for hidden threats within an  organization's information systems and networks. The process is designed to identify complex and sophisticated attacks that cannot be detected  by existing security measures. Threat hunting typically involves  cybersecurity professionals performing activities such as data  collection, analysis, and threat identification.

Cybersecurity is the set  of technologies, processes, and controls implemented to protect an  organization's information assets. Threat hunting is a critical  component of this framework as it helps uncover threats that may not be  detected by traditional security measures. Threat hunting proactively  improves an organization's security posture and ensures preparedness  against potential attacks.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Introduction+to+Threat+Hunting/1.Introduction/image1_1.png)

### Why Are Reactive Security Measures Not Enough?

Traditional security  measures often take a reactive approach, taking action after an attack  has occurred. These measures rely on technologies such as antivirus  software, firewalls, and intrusion detection systems (IDS). However, in  an environment where new and advanced threats are rapidly evolving,  these approaches can become inadequate. Reactive security measures are  only effective against known threats and are vulnerable to unknown,  zero-day vulnerabilities.

### The Importance of Proactive Security Approaches

Proactive security  approaches involve continuous processes such as monitoring, analysis,  and threat hunting to detect and prevent potential threats. These  approaches enable organizations to identify and respond to threats in  their early stages. Proactive security means identifying potential  threats in advance and taking necessary action before attacks occur,  allowing organizations to respond more quickly and effectively to  security incidents.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Introduction+to+Threat+Hunting/1.Introduction/image1_2.png)

  (  **Image Source**  :   https://www.crowdstrike.com/cybersecurity-101/indicators-of-compromise/ioa-vs-ioc/  )

### The Threat Landscape and the Role of Threat Hunting

### Threat Landscape

Today's cyber threat  landscape is highly dynamic and complex. Cybercriminals are constantly  developing new techniques and tools to circumvent security measures.  Advanced Persistent Threats (APTs), ransomware, spyware, and many other  types of threats pose significant risks to organizations. In addition,  cyber-attacks can target not only large enterprises, but also small and  medium-sized businesses. 

### Benefits of Threat Hunting Against Threats

Threat hunting provides  an effective defense against these complex and advanced threats. Threat  hunters continuously scan systems and networks for anomalous behavior  and potential threats. So that they can prevent attackers from  infiltrating systems and causing damage. Threat hunting also helps  organizations respond more quickly to security incidents and minimize  damage. Additionally, threat hunting processes enable organizations to  continuously improve their security posture and become more resilient to future attacks.

This lesson introduced the concept of threat hunting. The next lesson will cover “**Threat Hunting Team and Competencies**.”

### Questions

1 - What is the proactive process of searching for hidden threats in an organization's information systems and networks?

> **Answer:** threat hunting

## Threat Hunting Team and Competencies

  The Threat Hunting Team  is an interdisciplinary group made up of experts with different  competencies. Each member takes on a specific role and contributes to  achieving the team's overall objectives.

### The Structure of a Threat Hunting Team

The roles within a threat hunting team are as follows:

- **Threat Hunter**: It is the primary  individual responsible for actively hunting and analyzing threats,  planning and executing the threat-hunting process, and reporting  findings.  
- **Incident Responder**: It is the person who  responds swiftly and effectively to detect threats, coordinating  incident management processes and restoring systems to normal.  
- **Malware Analyst**: It is the individual  who analyzes malware, understands its behavior, and develops strategies  to defend against new and complex threats.  
- **Forensic Analyst**: It is the person who  conducts digital forensics, collecting and analyzing evidence to  identify the source and methods of attacks.  
- **Security Analyst**: It is the individual  who monitors the security of networks and systems, identifies  vulnerabilities, and collects cyber threat intelligence.  

### Positions and Responsibilities within the Team

- **Junior Threat Hunter**: It is a less experienced team member who handles basic tasks such as fundamental analysis and data collection.  
- **Senior Threat Hunter**: It is an experienced expert who manages complex operations and provides guidance to other team members.  
- **Threat Intelligence Analyst**: It is the individual  who collects and analyzes threat intelligence, providing insights into  threat actors, techniques, and tools.  
- **Red Team Member**: It is the person who  simulates attacks from an adversarial perspective, identifying security  vulnerabilities and recommending mitigation strategies.  

### Required Competencies and Skills

#### Threat Analysis and Intelligence Competencies

- Understanding the behavior and techniques of threat actors.  
- Conducting threat analysis using frameworks like MITRE ATT&CK.  
- Evaluating and interpreting threat intelligence sources.  

#### Network and System Knowledge

- Deep knowledge of network protocols and topologies.  
- Understanding system and application security principles.  
- Using security devices and software (IDS/IPS, firewalls, antivirus).    

#### Analytical Thinking and Problem-Solving Skills

- Analyzing complex data sets and drawing meaningful conclusions.  
- Identifying abnormal behaviors and potential threats.  
- Solving problems quickly and effectively.    

#### Communication and Reporting Competencies

- Communicating effectively with both technical and non-technical stakeholders.  
- Reporting findings and results clearly and understandably.  
- Collaborating with both internal and external teams.  

### Certifications and Training

#### Certifications

**Certified Threat Hunting Professional (eCTHP)**: Security professionals  must improve their proactive threat detection and response capabilities  to earn this certification, which validates knowledge and skills in  threat hunting methodologies, techniques and tools.

**eCTHP:** https://security.ine.com/certifications/ecthp-certification/

**GIAC Certified Incident Handler (GCIH)**: It is a certification that recognizes expertise in incident response and threat hunting.

**GCIH:** https://www.giac.org/certifications/certified-incident-handler-gcih/   

**Certified Threat Intelligence Analyst (CTIA)**: It demonstrates that the analyst has knowledge of techniques for gathering and analyzing threat intelligence.

**CTIA**: https://www.eccouncil.org/train-certify/certified-threat-intelligence-analyst-ctia/   

**Certified Ethical Hacker (CEH)**: It demonstrates knowledge of offensive tactics and defensive strategies.

**CEH**: https://www.eccouncil.org/train-certify/certified-ethical-hacker-ceh/

**Certified Information Systems Security Professional (CISSP)**: It validates comprehensive knowledge of information security management.

**CISSP**: https://www.isc2.org/certifications/cissp  

### Resources for Continuing Education and Growth

- **Online Platforms**: Courses on platforms such as LetsDefend, Udemy.  
- **Webinars and Conferences**: Events such as Black  Hat, DEF CON, SANS which provide opportunities to learn about the latest cybersecurity trends and techniques.  
- **Professional Communities**: Continuing professional development and networking opportunities through communities such as ISACA, (ISC)².  

### Conclusion

The Threat Hunting Team  is a multidisciplinary team of experts with diverse skills that provides proactive defense against cyber threats. Members of the team have  specific roles: Threat Hunters analyze and report threats, Incident  Responders rapidly respond to incidents, Malware Analysts investigate  malware, Forensic Analysts gather digital evidence, and Security  Analysts monitor network security. Positions within the team have a  variety of responsibilities, including junior and senior threat hunter,  threat intelligence analyst, and red team member. Essential skills  include threat analysis, network and systems knowledge, analytical  thinking, problem solving, and communication. Team members are also  supported through certifications and training resources such as CEH,  CISSP, GCIH, and CTIA.  

This lesson discussed the structure of the threat hunting team, the positions within the team,  and the competencies and skills that team members should possess. The  next lesson will cover “**Threat Hunting Methodologies**”.

### Questions

1 - What primary role on the threat hunting team actively hunts and analyzes threats?

> **Answer:** threat hunter

2 - What role in the threat hunting team responds quickly and effectively to detected threats?

> **Answer:** Incident Responder

## Threat Hunting Methodologies

Threat hunting methodologies encompass various strategies and techniques used  in the threat detection and analysis process. These methodologies offer  different approaches to handling cyber threats and help organizations  build a more resilient security posture. From adversary-centric methods  to hypothesis-driven approaches to indicator of compromise (IoC)-based  methods, a variety of methodologies enable threat hunters to detect  complex and sophisticated threats. This lesson and the following lessons discuss the basic principles and implementation of each methodology.

### Adversary-Centric Approach

Adversary-centric approaches focus on understanding the attacker's perspective and  analyzing their behavior. The goal is to identify the tactics,  techniques, and procedures (TTPs) used by attackers, which can help  identify vulnerabilities and potential attack methods. Adversary-centric threat hunting is a critical approach to understanding the complexity  and sophisticated nature of cyberattacks.

### TTPs (Tactics, Techniques, and Procedures)

- **Tactics:** These are the general strategies that attackers use to achieve their goals.  For example, information gathering or phishing are broad categories of  attack tactics.
- **Techniques:** These are the specific methods used to execute the tactics. For example,  using open source intelligence (OSINT) to gather information is a  technique under the tactic of information gathering.
- **Procedures:** These are the detailed steps used to execute the techniques. For example, the steps involved in using a particular OSINT tool would be considered a  procedure.

Understanding TTPs is essential for recognizing how attackers infiltrate systems and  execute attacks. This information helps threat hunters identify the  stages at which the attacks can be detected.

**Implementation:** Identifying TTPs requires analysis of threat intelligence and historical attack  data. Frameworks such as MITRE ATT&CK are used to categorize and  analyze adversary TTPs. The tools and techniques used by attackers must  be continuously monitored to stay current.

### MITRE ATT&CK Framework

The MITRE ATT&CK (Adversarial Tactics, Techniques, and Common  Knowledge) framework is a comprehensive knowledge base that categorizes  adversary behavior and provides guidance to threat hunters. The MITRE  ATT&CK Framework helps cybersecurity teams better understand  attacker actions by detailing various attack vectors and techniques.

**Content:**

- **Tactics:** These are high-level objectives that attackers strive to achieve, such as initial access, execution, and persistence.
- **Techniques:** These are specific methods used to achieve tactics, such as phishing or remote file copying.
- **Sub-techniques:** These are more specific variations of techniques. For example, email attachments or malicious links under phishing.

**Implementation:** Threat hunters use the MITRE ATT&CK Matrix to predict what techniques an  attacker might use and to develop defensive strategies to counter those  techniques. When developing defenses for a specific attack, they analyze the techniques the attacker will use and how to detect them. The MITRE  ATT&CK framework helps threat hunters understand what stage of an  attack they are in and predict the attacker's next move.

### Case Study: APT Attack

- **Scenario:** A state-sponsored group of attackers is conducting an advanced persistent threat (APT) attack in order to steal critical information from a  specific organization.
- **Tactics:** Phishing emails are used to gain initial access. After gaining access, various  backdoors are placed in the target systems to maintain persistence.
- **Techniques:** Phishing emails containing malicious attachments are sent. After successfully  infiltrating the network, attackers use lateral movement to compromise  other systems.
- **Procedures:** Information is collected using specific malware and sent to servers under the attacker's control.

**Detection and Response:**

- **TTP Analysis:** The TTPs of the attack are examined to determine the techniques used by the attacker.
- **Use of MITRE ATT&CK:** Identifies the stage of the attack and the techniques used. For example, phishing email detection and malware analysis.
- **Defense strategies:** Training users against phishing attacks, using security software that detects  malware, and monitoring the network are defense strategies that should  be applied in this scenario.

### Conclusion

Adversary-centric approaches allow threat hunters to understand attacker behavior by  thinking from the attacker's perspective and preventing attacks.  Analysis of TTPs and the use of frameworks such as MITRE ATT&CK  enhance the effectiveness of these methods. These methods provide a  proactive defense against cyberattacks, strengthen an organization's  security posture, and enable early detection of potential attacks.

This lesson discussed threat hunting methodologies, specifically the  Adversary-Centric approach. The next lesson will cover the "**Hypothesis-Driven Approach**".

### Questions

1 - What is the comprehensive methodology that categorizes attacker behaviors and guides threat hunters?

> **Answer:** MITRE ATT&CK Framework

## Hypothesis-Driven Approach

The Hypothesis-Driven  approach is a systematic process in which threat hunters develop and  test assumptions about a specific threat or attack. This method makes  threat hunting activities more focused and efficient, as threat hunters  work on a specific hypothesis and search for signs of particular attacks or threats.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Introduction+to+Threat+Hunting/4.Hypothesis-Driven+Approach/image4_1.png)

  (**Image Source:**  https://medium.com/@sqrrldata/the-hunting-loop-10c7d451dec8)

### Creating a Hypothesis

**Definition:** Hypothesis generation is  the process of developing assumptions about a specific threat or attack  scenario based on existing data and threat intelligence. These  assumptions are based on how attackers might use certain methods to  compromise systems.

**Importance:** Hypotheses allow threat hunters to focus on a specific threat and take a more targeted approach rather than searching randomly.

**Application:** For example, if abnormal  traffic is observed on a network, a hypothesis is created to determine  if it is an indicator of an attack. The hypothesis might suggest that  this abnormal traffic indicates the presence of a specific piece of  malware.

### Hypothesis Testing

**Definition:** Hypothesis testing is the process of collecting data, analyzing it, and drawing conclusions to  determine if the hypothesis is correct. This process involves systematic steps to verify the hypothesis or identify it as incorrect.

**Importance:** Hypothesis testing  increases the accuracy and effectiveness of the threat hunting process.  False hypotheses are quickly discarded, while valid ones allow for more  effective threat detection.

**Application:** For example, to validate  an anomalous traffic hypothesis, you can examine network traffic logs,  analyze anomalous activity, and determine whether that activity is  malicious.

### Using Analytical Models

**Definition**: Analytical models are  mathematical and statistical techniques that help extract meaningful  information from large data sets. These models play a critical role in  hypothesis testing.

**Importance**: Analytical models  enable threat hunters to analyze large amounts of data and detect  anomalies, validating or disproving hypotheses.

### Case Study: Hypothesis-Based Threat Hunting

**Scenario**: A company notices an  unusual increase in network traffic over a specific period. They suspect this could be an indication of a potential attack.

**Hypothesis**: "The abnormal increase  in network traffic may be a sign of a DDoS attack." This hypothesis is  based on past threat intelligence and current data analysis.

**Data Collection**: Network traffic logs are thoroughly examined.

**Analysis**: Machine learning  algorithms are used to detect anomalies. These algorithms learn normal  network traffic patterns and identify deviations from those patterns.

**Conclusion**: The analysis reveals  high volumes of network traffic coming from specific IP addresses. This  traffic is considered evidence of a DDoS attack.

**Intervention**: Measures are taken  against the network traffic identified as a DDoS attack. For example, IP addresses of the attack sources are blocked, and network security  measures are strengthened.

### Conclusion

The hypothesis-based  approach enables more focused and effective threat hunting. By creating  and testing hypotheses about specific threats, threat hunters can  systematically identify and analyze potential risks. This process helps  extract meaningful insights from large data sets and detect anomalies  using analytical models. As a result, threat hunters can make accurate  and rapid decisions, strengthening the defense against cyber attacks. 

This lesson has covered the hypothesis-based threat hunting methodology. The next lesson will focus on the **“IoC-Based Approach”**.

### Questions

1 - What is the systematic approach by which threat hunters develop and test a hypothesis about a specific threat or attack?

> **Answer:** Hypothesis-Driven Approach

## IoC-Based Approach

The IoC-based approach is a methodology used in the threat hunting process  to identify, track, and analyze evidence of a specific breach or attack. IoCs are distinctive indicators used in the cybersecurity world to  detect the presence of an attack or security breach. These indicators  include the paths taken by attackers, the tools they use, and the traces they leave behind.

### Indicator of Compromise (IoC)

**Definition**: An Indicator of Compromise (IoC) is a digital trace or evidence  indicating that a security breach has occurred in a system or network.  IoCs include attacker activities, malware used, abnormal network  traffic, or suspicious files in the system.

**Importance**: IoCs are critical for detecting and tracking cyberattacks. They enable  early detection of attacks, allowing for rapid intervention.

### Types of IoC

- **File-based IoCs**: Malware or suspicious file changes.
- **Network-based IoCs**: Abnormal network traffic, connections to unknown IP addresses.
- **Host-based IoCs**: Abnormal changes in system logs or the registry.
- **Email-based IoCs**: Phishing emails or suspicious email attachments.

### Identifying IoCs

- **Threat Intelligence:** Identifying IoCs begins with up-to-date threat intelligence. It is essential for  understanding new techniques and tools employed by attackers.
- **Analysis and Logging:** IoCs are identified by analyzing system and network logs. Any abnormal activity or suspicious behavior is recorded as IoCs.
- **Automation and Tools:** Automated threat detection tools and Security Information and Event Management (SIEM) systems are used to detect and track IoCs.

### IoC Databases

**Definition:** IoC databases are repositories that store and continuously update known  IoCs. These databases help threat hunters stay informed about current  and past attacks.

**Importance:** IoC databases are critical for threat hunters to quickly and accurately  identify threats. Up-to-date and comprehensive IoC databases are  essential for tracking new techniques and tools used by attackers.

### Key IoC Databases

- **OpenIOC:** An IoC standard developed by Mandiant, which is open for sharing.
- **STIX (Structured Threat Information Expression):** A format used to structure and share threat intelligence.
- **TAXII (Trusted Automated Exchange of Indicator Information):** A protocol used for sharing IoCs in STIX format.
- **VirusTotal:** A platform that provides information and analysis of malicious software.

### Using IoC Databases

- **Integration:** IoC databases are integrated into threat hunting processes. Security tools use these databases to detect and report IoCs.
- **Updates and Maintenance:** IoC databases are continuously updated and maintained. New threats and IoCs are regularly added.
- **Analysis and Reporting:** IoCs are analyzed to determine the specifics of attacks, and these  findings are reported. The reports are used to take preventative  measures against future threats.

### Case Study: IoC-based Threat Hunting

- **Scenario:** An organization's security team notices suspicious activity on its  systems, including abnormal network traffic and suspicious file  modifications.
- **IoC Identification:** Threat hunters analyze system logs and network traffic data. Anomalous  activity is logged as IoCs. It is detected that a malware has  established a connection to a specific IP address. The IP address is  logged as an IoC.
- **Using the IoC Database:** The identified IoCs are checked against the OpenIOC and STIX databases to  see if they match any known threats. Analyze suspicious files using  VirusTotal to detect the presence of malicious software.
- **Response:** Based on the identified IoCs, block connections to the suspicious IP  addresses. Remove malware and remediate systems. Implement additional  security measures to prevent and detect similar attacks in the future.

### Conclusion

The IoC-based approach is an effective methodology for detecting traces of  specific attacks during threat hunting. Identifying, tracking, and  analyzing IoCs enables threat hunters to detect attacks early in their  lifecycle. The use of IoC databases enhances the effectiveness of threat hunting processes, helping security teams make quick and accurate  decisions. This methodology offers a proactive defense strategy in the  cybersecurity world, strengthening an organization's cybersecurity.

This lesson has discussed the nature of IoCs, their types, IoC databases,  and the IoC-based threat hunting approach. The next lesson will cover  the topic of “**Threat Hunting Life Cycle**.”

### Questions

1 - What are digital traces or evidence that a system or network has been breached?

﻿**Note**: Enter the abbreviation of the answer.

> **Answer:** IOC

2 - What is the IoC standard developed by Mandiant which can be shared?

> **Answer:** OpenIOC

## Threat Hunting Life Cycle

The Threat Hunting  process is a proactive approach used by organizations to identify hidden threats within their information systems and networks. This process  typically consists of five main stages:

- Preparation and Planning  
- Data Collection and Analysis  
- Threat Hunting Process  
- Findings and Reporting  
- Remediation and Optimization  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Introduction+to+Threat+Hunting/6.Threat+Hunting+Life-Cycles/image6_1.png)

  (**Image Source:** https://medium.com/@fahriiyesill/hunting-the-hunters-how-threat-hunting-enhances-cybersecurity-ad8f3c1c5bce)

### Preparation and Planning

### Identifying Resources and Objectives

- **Definition:** The first step in the  threat hunting process involves defining the resources and objectives  for the hunt. This includes deciding which systems, networks, and data  will be investigated.  
- **Importance:** Clearly defining  objectives enhances the effectiveness of the threat hunting process and  prevents unnecessary resource allocation.  
- **Application:** For example, focusing  on a specific department or network segment allows threat hunters to  conduct a more detailed investigation of a particular attack surface.  

### Selecting Tools and Methods

- **Definition:** Choosing the appropriate tools and techniques to be used during the threat hunt directly influences the success of the process.  
- **Importance:** Selecting the right tools and methods increases the likelihood of detecting threats.  
- **Application:** Tools like Security  Information and Event Management (SIEM) systems, network monitoring  tools, and analytical software are commonly used during the hunting  process.  

### Data Collection and Analysis

### Identify and Integrate Data Sources

- **Definition:** In this step, you  identify the data sources to be used in the threat hunting process and  integrate them into an appropriate format for analysis.  
- **Importance:** Integrating different data sources allows for a more comprehensive analysis of threats.  
- **Use:** Collect and integrate data sources such as system logs, network traffic, user activity, and threat intelligence for analysis.  

### Data Collection and Analysis

- **Definition:** Analyzing the collected data is critical for detecting threats.  
- **Importance:** Accurate and effective data analysis enables early detection of threats.  
- **Application:** Machine learning algorithms and analytical models can be employed to analyze the data.  

### Threat Hunting Process

### Active Threat Hunting Techniques

- **Definition:** Threat hunting techniques are the active techniques used during the threat hunting process.  
- **Importance:** Active hunting techniques help identify the presence of attackers within systems.  
- **Application:** Techniques such as  anomaly detection, lateral movement analysis, and user behavior  analytics can be used to uncover malicious activities.  

### Continuous Monitoring and Analytical Methods

- **Definition:** Systems and networks are constantly monitored, and analytical methods are applied to detect threats.  
- **Importance:** Continuous monitoring allows for early detection and rapid intervention when threats are identified.  
- **Application:** Use Security  Information and Event Management (SIEM) systems and Endpoint Detection  and Response (EDR) systems for continuous monitoring.    

### Findings and Reporting

### Documentation of Findings and Results

- **Definition:** This stage involves documenting the findings and results obtained during the threat hunting process.  
- **Importance:** Proper documentation helps in understanding the threats and serves as a reference for future hunts.  
- **Application:** Threat reports, event details, and analysis results should be documented for further review.  

### Reporting to Management and Relevant Stakeholders

- **Definition:** The findings and results should be reported to management and other relevant parties.  
- **Importance:** Reporting ensures that threats are understood and necessary actions can be taken.  
- **Application:** Share reports with management, relevant departments, and external stakeholders when necessary.  

### Remediation and Optimization

### Taking Action Against Identified Threats

- **Definition:** This step involves taking measures and carrying out interventions against the identified threats.  
- **Importance:** Quick and effective intervention minimizes the impact of the threats.  
- **Application:** Patch vulnerabilities, clean up compromised systems, and enhance security measures.  

### Continuous Improvement of Processes and Methodologies

- **Definition:** The threat hunting processes and methodologies must be reviewed and improved all the time.  
- **Importance:** Continuous improvement boosts the effectiveness of threat hunting and strengthens defenses against future threats.  
- **Application:** Actions like gathering feedback, evaluating performance, and developing strategies against  emerging threats contribute to improving the process.  

This lesson has discussed the lifecycle of threat hunting and its components.