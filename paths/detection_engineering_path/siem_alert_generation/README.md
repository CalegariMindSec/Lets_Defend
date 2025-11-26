# SIEM Alert Generation

The  "SIEM Alert Generation" course focuses on providing specialized training for creating robust and effective alerts within Security Information  and Event Management (SIEM) systems. It emphasizes the development of  skills necessary to configure alerts tailored to detect and respond to  potential threats, contributing to a stronger cybersecurity posture  within organizations.

Table of Contents

- [SIEM and Rule/Correlation](#siem-and-rulecorrelation)
- [Basic Components of the Correlation Rule](#basic-components-of-the-correlation-rule)
- [Creating Rules/Correlation](#creating-rulescorrelation)
- [Sample Rule/Correlations](#sample-rulecorrelations)
- [Creating Alarms](#creating-alarms)

Evaluate Yourself with Quiz

- [SIEM Alert Generation](https://app.letsdefend.io/training/quiz/siem-alert-generation)

## SIEM and Rule/Correlation

Fighting against today's  sophisticated cyber threats requires organizations to continually  strengthen their security measures. Therefore, security teams are  looking for an effective approach to monitor their networks and systems, detect and respond to potential threats. This is where SIEM systems and the rule/correlation relationship come into play. The real power of  SIEM comes from the rules and correlation capabilities used when  analyzing this data.

The basic rules that the  SIEM system uses to detect certain events or situations are called  rules. For example, a rule might be triggered if a particular user has  multiple failed login attempts, or if there is an unexpected increase in traffic on a particular port. However, complex and advanced threats  often occur not in a single event, but as a result of multiple events  simultaneously occurring. Here's where correlation plays a role.

Correlation enables the  detection of a potential threat by cross-analysis of different events  and data points. Specifically, it is used to describe a possible threat  that may arise from a series of events occurring together. For example, a combination of events, such as a user making many unsuccessful login  attempts, or trying to pull sensitive data from another device, can  trigger a correlation rule. This goes beyond isolated incidents and  helps detect more complex threats.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Generation/1/image1-1.jpeg)

(Image Source:   [https://www.pratum.com/blog/122-benefits-of-log-consolidation-in-a-siem-environment ](https://www.pratum.com/blog/122-benefits-of-log-consolidation-in-a-siem-environment)  )

SIEM and the  rule/correlation relationship enhance organizations' ability to defend  against cyber threats by enabling them to detect and respond to security incidents more quickly and effectively.  

### Rules-Based Threat Detection

Rule-based threat  detection is a security approach that involves defining specific rules  and patterns within a security system and identifying events or  activities that conform to these rules.

Rule-based threat  detection relies on a specific set of rules when monitoring events and  activities occurring within an organization's security infrastructure.  These rules are used to assess compliance with the organization's  security policies, recognize potential threats, and detect specific  security events or patterns.

Rules used for rule-based threat detection represent a combination of one or more conditions.  Each rule contains a condition or pattern that describes a particular  event or activity. An example rule might be: "If a user enters an  incorrect password three times consecutively, generate a security  alert."

Rules-based threat  detection begins with applying rules to events or activities collected  from data sources. If an event or activity contains a condition that  complies with one or more rules, that rule is triggered. Triggering the  rule may lead to the generation of a security alert or the execution of a specific action.

Rule-based threat  detection is used in many security areas such as network, application,  data, and system security. For example, network traffic monitoring and  rule-based threat detection are commonly used to detect malicious  network traffic and unwanted activities.

Rule-based threat  detection provides effective defense against specific and known threats. However, this method also has disadvantages including potential  limitations in detecting unknown or advanced threats and the possibility of generating false positive alarms.

For up-to-date and  effective rule-based threat detection, rules need to be reviewed and  updated regularly. Current rules must adapt to both the security needs  of the organization and the evolving threat landscape.

Rule-based threat  detection is a powerful tool for monitoring security incidents in  organizations and automatically detecting events that comply with  certain rules. However, because of its limitations, organizations often  combine rule-based detection with other advanced security approaches and threat intelligence.  

### Correlation-Based Threat Detection

Correlation-based threat  detection monitors an organization's network security and detects  threats by analyzing security events and data. This approach goes beyond isolated events and involves evaluating multiple events and data points together.

Correlation refers to the process of identifying meaningful relationships between events and  data. In particular, it aims to detect a possible threat as a result of  the combination of many separate events or activities. This approach  typically includes data from different sources, such as network traffic, system logs, user behavior, and threat intelligence.

Scenarios that use  correlation include detecting abnormal activities on the network,  monitoring malware attacks, detecting data leaks, and detecting advanced threats. For instance, you can use correlation to identify multiple  users attempting to access sensitive data simultaneously or to recognize a certain malware showing similar behavior on different systems.

Correlation-based threat  detection is implemented using specialized correlation engines or  security solutions such as SIEM systems. Correlation engines analyze  data using specific rules and algorithms and try to identify potential  threats. Correlation engines can be customized to lower false alarm  rates and identify genuine risks.

Advantages and Disadvantages of Threat Detection with Correlation:  

**Advantages:**

- Ability to detect advanced threats.  
- Understanding relationships between data points.  
- High customization ability.  

**Disadvantages:**

- It can be complicated and time-consuming.  
- It May lead to False Positive results (risk of missing real threats).  

Correlation-based threat  detection helps organizations develop a more effective defense strategy  against more complex and advanced cyber threats. This method allows  organizations to be better prepared against potential threats by  conducting a more thorough analysis of security incidents.

In this part of the training, we have discussed what correlation is, its significance, its  relationship with SIEM, and rule/correlation-based threat detection. In  the next part of the training, the subject “Basic Components of the Correlation Rule” will be explained.

### Questions

1 - Which approach is used to identify a possible threat by combining multiple events?

> **Answer:** Correlation

## Basic Components of the Correlation Rule

While the core components of the correlation rule aim to detect complex cyber threats, it  includes several important components for this purpose. First, Events  and Source of Data form the basis of these components. Security events  and data are collected from the organization's networks and systems.  These sources include security infrastructure such as network logs,  system event logs, application logs, and security devices.  

The second important  component of the correlation rule is the Fundamental Principle of the  Correlation Rule. This principle defines the conditions under which a  correlation rule is triggered when certain conditions or events occur.  The correlation rule helps the organization be better prepared against  security threats by analyzing meaningful relationships between security  events and data.

Another critical  component of the correlation rule is the Conditions and Match  conditions. This component contains the conditions and match conditions  required to create and trigger the rule. For example, a specific  security event or activity can trigger the rule if certain conditions or requirements are met. These conditions are determined in accordance  with the organization's security policies and threat model.  

Finally, one of the  components that makes the correlation rule work is triggering the rule.  This means that when events and data are analyzed, the rule detects that a particular situation has occurred. A triggered rule signals the  presence of a specific security event or threat and initiates an  appropriate response. This component enables the organization to respond to security threats quickly and effectively.  

### Source of Events and Data

A key component of the  correlation rule involves the sources of security events and data. This  component plays a critical role in setting up the correlation rule and  ensuring it works effectively.  

**Security Events and Data**

The main elements used  when creating the correlation rule are security events and data that  come from the organization's security infrastructure. These may include  network logs, system event logs, application logs, data generated by  security devices, and threat intelligence.

**Source of Incidents**

The source of security  incidents is the organization's network and systems. For instance,  network logs may contain information about traffic and connections on  the network while system logs capture events related to the operating  system and applications.

**Source of Data**

The source of the data  used when creating the correlation rule is also crucial. These resources come from security infrastructure components such as firewalls,  intrusion detection and prevention systems (IDS/IPS), antivirus  software, and SIEM systems.

**Data Types**

The data types used when  creating a correlation rule can vary. For example, IP addresses, user  IDs, port numbers, timestamps, file names, and more may be examples of  these data types.

**Threat Intelligence**

Threat intelligence can  also be used to increase the effectiveness of the correlation rule by  providing information about new threats and malicious activities that  the organization needs to know. This is important for updating  correlation rules and being better prepared for new threats.

**Collecting and Storing Data**

Collecting and storing  this data is a critical step for analyzing security incidents and  applying correlation rules. Organizations often store this data using  log management and storage systems.

The source of events and  data is a fundamental building block for the correlation rule to work  effectively. Accurately identifying these resources increases the  ability to detect security incidents and provides organizations with  greater visibility. When creating the correlation rule, we should  consider which data sources will be used and what type of data will be  analyzed in accordance with the security needs of the organization.

### Basic Principle of Correlation Rule

The basic principle of  the correlation rule describes how the rule works to detect a specific  security threat or event by analyzing security events and data. This  principle helps organizations monitor and respond to cyber threats more  effectively.  

More on the basic principle of the correlation rule:

**Correlation of Security Events**

The main purpose of the  correlation rule is to identify relationships between security events  and data. These relationships are created according to the  organization's security policies and threat model. Specifically, it  identifies scenarios where certain security events or activities combine to create a threat.

**Timestamp of Events**

A part of the basic  principle of the correlation rule involves timestamping events. This  identifies situations where the order and timing of events are  important. For example, events such as a user repeatedly entering an  incorrect password and then attempting to access a sensitive data file  may require a specific sequence and timing.

**Triggering the Correlation Rule**

As a result of the basic principle, the correlation rule is triggered when it detects a  combination of certain conditions or events. This provides the security  team with an opportunity to identify potential threats or anomalies. It  is particularly used for detecting complex threat scenarios.

**Appropriate Response**

Triggering the  correlation rule leads the organization to provide an appropriate  response. This response can take various forms, such as alerts,  notifications, or automated responses to the security team. Thanks to  the correlation rule, threats can be responded to more quickly and  effectively.

**Customization and Improvement**

The basic principle of  the correlation rule can be customized and improved to suit  organizations' security policies and requirements. This allows  organizations to become more susceptible to security threats.

The fundamental principle of the correlation rule provides a basic guide for organizations to  strengthen their security operations and help them detect more complex  threats. Thanks to this principle, organizations can better understand  security incidents and respond more effectively. 

### Conditions and Matching Conditions

One of the key components of the correlation rule is defining the conditions and match conditions necessary for the rule to be triggered. This component is an important  element that directs the operation of the correlation rule and links  security events or situations to specific characteristics. Here are more detailed descriptions of these components:

**Definition of Conditions**

A correlation rule contains conditions that define a particular security event or  condition. Each condition is determined in accordance with the  organization's security objectives and threat model. For example, a  condition might be "A certain user accidentally deleting a file more  than once."

**Matching Conditions**

The circumstances in  which certain conditions or events come together for the correlation  rule to work are called matching conditions. These conditions determine  when the rule will be triggered. For example, a match condition can be  defined as "If Condition 1 AND Condition 2 AND Condition 3 match,  trigger the rule.”

**Binding Operators**

Binding operators are  used to combine matching conditions and create complex correlation  rules. The most common binding operators are "AND" and "OR" operators.  The "AND" operator means that all conditions must match at the same  time, while the "OR" operator means that at least one condition must  match.

**Priority and Ordering**

Organizations often have  more than one correlation rule. The priority level of each rule is set  to determine the situations in which that rule is primarily applied.  This determines which rule takes precedence and is applied in cases  where multiple rules are triggered at the same time.

**Customization and Improvement**

The conditions and  matching conditions of the correlation rule can be customized, regularly reviewed, and improved to fit the security needs of the organization. This is important to enhance the accuracy and effectiveness of the  correlation rule.

Conditions and matching  conditions are the basic building blocks of the correlation rule.  Correctly identifying these components increases organizations' ability  to detect specific threat scenarios and reduces false alarms. When  making a correlation rule, we should plan the selection of conditions  and matching conditions carefully, considering the organization's  security policies, threat intelligence, and security objectives.

### Triggering the Correlation Rule

One of the key components of the correlation rule involves the mechanism by which the rule is  triggered when certain conditions or events come together. This helps  organizations detect and respond to cyber threats more effectively.  Here's more information on how the correlation rule is triggered:

**Match of Conditions**

Triggering of the  correlation rule occurs when the conditions of the rule or match  conditions are met. This means that during the analysis of security  events and data, the rule detects a specific threat or anomaly. For  example, events such as a specific user entering an incorrect password  into a system and then attempting to access sensitive data may meet the  conditions of the rule.

**Event Timestamp**

Triggering the correlation rule also includes situations where the order and timing of  events are important. Specifically, it describes scenarios where events  must follow a specific order and timing. This allows organizations to  analyze sequential events or events that occur over a period of time.

**Analysis of Events**

Triggering the  correlation rule involves in-depth analysis of events and data. The rule aggregates security events and evaluates whether these events comply  with the organization's security policies, threat model, and customized  rule conditions.

**Response Trigger**

A triggered correlation  rule allows the organization to initiate an appropriate response. This  response can be in the form of alerts, notifications, or automated  responses to the security team. In particular, it helps the organization quickly respond to potential threats.

**Trigger Priority**

Organizations often have  more than one correlation rule. The triggering priority of the  correlation rule is defined in a certain order. This determines which  rule will be applied first in cases where more than one rule is  triggered at the same time.

The triggering mechanism  of the correlation rule is an important component that helps  organizations detect and respond to security threats more quickly and  effectively. When creating the correlation rule, the conditions and  trigger mechanism to be used should be carefully planned, taking into  account the specific threat scenarios and security policies of the  organizations.

In this part of the  training, some issues about the basic components of the correlation rule are mentioned. In the next part of the training, the topic “Creating Rules/Correlation” will be explained.

### Questions

1 - Which operator means that all conditions must match at the same time?

> **Answer:** AND

2 - Which operator states that matching at least one condition is sufficient?

> **Answer:** OR

## Creating Rules/Correlation

SIEM collects security  events and data in a central location and helps detect potential threats by analyzing this data. Rules and correlations are the key components  that make SIEM work effectively. Creating rules and correlations  increases the SIEM's capacity to detect and respond to security  incidents using its powerful analytics capabilities. These processes  help organizations manage security operations more effectively and  provide better protection against cyber threats.

### Creating Rules

**Determining Goals and Objectives:** 

Before creating rules, it is important to determine the security goals and objectives of the  organization. Information such as what types of threats should be  detected and which systems or network areas need to be protected are  considered in this process.

**Defining Rule Conditions**

Identifying the  conditions that define a particular security event or condition is  critical when creating a rule. For instance, you can specify conditions  such as a particular user deleting a file or network traffic following a certain pattern.

**Determining Trigger Match Conditions**

We should define the  match conditions required for the rule to trigger. These conditions  determine the circumstances under which certain conditions or events  come together. For example, a matching condition such as "If Condition 1 AND Condition 2 Match" could be used.

**Defining Warning or Response Actions**

We should determine what  kind of response will be received if the rule is triggered. This may  include alerts, notifications, or automated responses to the security  team.

**Customization and Improvement of the Rule**

The created rule can be  customized to fit the needs of the organization and improved by regular  review. This is important to improve the accuracy and effectiveness of  the rule.

### Creating Correlation

**Defining Correlation Relationships**

Correlation rules define  relationships between multiple security events or data. For example, we  can define relationships such as a user making multiple unsuccessful  login attempts within a certain period followed by an attempt to access  sensitive data.

**Determining Correlation Rule Conditions**

Conditions are determined in a similar way for correlation rules. However, these conditions  require the combination of multiple security events or data.

**Defining the Conditions for Triggering the Correlation Rule**

The correlation rule is  triggered when it detects that multiple events or data occur in a  certain order or timing. This enables the organization to detect more  complex threat scenarios.

**Defining Correlation Rule Responses**

A triggered correlation  rule initiates an appropriate response. This response allows the  organization to respond quickly and effectively to potential threats.

### Creating Rules/Correlation with IBM QRadar 

To write a new rule  correlation on IBM QRadar, open the QRadar -> Offenses -> Rules  -> Actions -> “New Event Rule” menu on the interface and the rule  wizard screen opens.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Generation/3/image3-1.png)

With the “Rule Wizard”, first, we determine the criteria on which we will create a rule/correlation.  

**What kind of criteria are there**   :

- **“when the event matches this search filter”**: Searching for events that match the search filter.  
- **“when the source IP is one of the following IP addresses”**: When the source IP address is one of the filtered IP addresses.  
- **“when these rules match at least this many times in this many minutes after any of these rules match”**: When the selected  rules are matched in the specified number of times after any of these  rules are matched for the specified number of minutes.   
- **“when the event QID is one of the following QIDs”**: When the event QID matches one of the selected QIDs.  
- **“when the event category for the event is one of the following categories”**: When the event category matches one of the selected categories.  
- **“when the event severity is greater than 5”**: When the severity is greater than 5.  

By typing filter in the  search field, click on the "+" button at the beginning of the "when the  event matches this search filter" option.  

### Determine the Rule Name.

By clicking “this search filter”, determine the filter that is required to create an offense.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Generation/3/image3-2.png)

Select the field for  creating the search criteria. The 'Event Category' below has been  selected. After selecting the category, click on the “Add+” button and  “Submit”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Generation/3/image3-3.png)

After the filter required for the rule is created, select the group information, and press the “Next >>” button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Generation/3/image3-4.png)

The screen that opens consists of 4 parts.

**Rule Action:** The actions to be taken when an event triggering this rule occurs are specified.

**Rule Response:** What should be done when this rule is triggered by an event is determined.

**Response Limiter:** The frequency of this  rule's response is configured, preventing the same offense from  occurring again for a certain period of time after its initial  occurrence.

**Enable Rule:** Enable this option if you want this rule to start tracking events immediately.  

Also :

**Dispatch New Event:** This action aims to create a new event when a specific rule or event is triggered.

**Ensure the dispatched event is part of an offense:** Ensure the dispatched event is part of an offense.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Generation/3/image3-5.png)

In the last stage,  summary information about the written rule/correlation is presented and  if the information is correct, the rule is activated by clicking the  "Finish" button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Generation/3/image3-6.png)

The activity determined  to test the created rule is created in the relevant system and the  resulting offense falls on the QRadar -> Offenses page.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Generation/3/image3-7.png)

We have seen how to write a rule/correlation on QRadar. Writing rules and correlations in QRadar  gives your security team the ability to detect and respond to threats on your network. Creating the right rules and correlations means better  security and risk management. Therefore, QRadar users should pay  attention to this issue and keep it constantly updated.  

In this part of the  training, the rule/correlation creation process has been explained  through IBM QRadar. In the next part of the training, the topic “Sample Rule/Correlations” will be explained.

### Questions

1 - What is the name of the wizard used when creating rules/correlations in QRadar?

> **Answer:** rule wizard

## Sample Rule/Correlations

In this part of the training, rule/correlation examples regarding  important log sources for SIEM will be discussed. Based on these  examples, different rules/correlations can be developed for the relevant sources.

### Common Rules

Common rules are a sample rule pool that can be created jointly for log  sources such as firewall, operating systems, VPN, and VM platform.

### Rule/Correlation Examples:

- **Rule Name**: Failed Login Attempts
- **Conditions**: Consecutive failed login attempts in security logs.
- **Trigger Condition**: Trigger when consecutive failed login attempts are detected.



- **Rule Name**: Login activity during non-business hours.
- **Conditions**: Login activity to critical systems during non-business hours.
- **Trigger Condition**: Trigger on login activities that are not included during non-business hours.



- **Rule Name**: New User Account Created
- **Conditions**: Creation of a new user account in security logs.
- **Trigger Condition**: Trigger when a new user account is created.



- **Rule Name**: Account Deletion
- **Conditions**: Deletion of a user account in security logs.
- **Trigger Condition**: Trigger when a user account is deleted.

### Firewall

Firewall logs are critical for network security. By analyzing firewall logs,  SIEM detects abnormal activities on network traffic and can create  trigger rules to protect the organization against possible threats.  Integrating firewall logs with SIEM enables rapid detection and response to security incidents.

### Rule/Correlation Examples:

- **Rule Name**: Illegal Port Scans
- **Conditions**: Attempts to access prohibited or unauthorized ports in firewall rules.
- **Trigger Condition**: Trigger when multiple prohibited port access attempts are detected from the same IP address within a certain period of time.



- **Rule Name**: Illegal Country Resources
- **Conditions**: Traffic from illegal or unknown countries in firewall logs.
- **Trigger Condition**: Trigger when traffic from illegal countries is detected within a certain period of time.



- **Rule Name**: Critical Port Accesses
- **Conditions**: Access to critical ports (3389, 1433, 1521, 3306, etc.).
- **Trigger Condition**: Trigger when access to critical ports is detected.



- **Rule Name**: Adding Any Access Rule
- **Conditions**: Adding values such as source_IP_address or destination_IP_address as “any” in newly added or edited firewall rules.
- **Trigger condition**: Trigger if such a rule is added and the existing rule is edited.

### IPS/IDS

IPS/IDS systems help detect and prevent attacks on the network. SIEM collects  and analyzes events detected by IPS/IDS and monitors their compliance  with the organization's security policies. In this way, dangerous events can be quickly identified and countermeasures can be taken.

### Rule/Correlation Examples:

- **Rule Name**: Abnormal Traffic Behavior
- **Conditions**: Abnormal traffic behavior in IDS/IPS logs over a period of time.
- **Trigger Cond**
- **ition**: Trigger when abnormal traffic behavior is detected.



- **Rule Name**: Critical Vulnerability Attacks
- **Conditions**: Attack attempts against known critical vulnerabilities.
- **Trigger Condition**: Trigger when attack attempts against critical vulnerabilities are detected.



- **Rule Name**: Harmful Content Downloads
- **Conditions**: Downloading files containing malware in IDS/IPS logs.
- **Trigger Condition**: Trigger when downloading files containing malware is detected.

### WAF

WAF is used to keep web applications secure. SIEM monitors and protects  against web application attacks detected by the WAF. Integrating WAF  logs with SIEM increases web application security and enables instant  detection of attack attempts.

### Rule/Correlation Examples:

- **Rule Name**: SQL Injection Trials
- **Conditions**: SQL Injection attempts in WAF logs.
- **Trigger Condition**: Trigger when SQL Injection attempts are detected within a certain period of time.



- **Rule Name**: XSS Attacks
- **Conditions**: XSS (Cross-Site Scripting) attacks in WAF logs.
- **Trigger Condition**: Trigger when XSS attacks are detected.



- **Rule Name**: CSRF Attacks
- **Conditions**: CSRF (Cross-Site Request Forgery) attacks on WAF logs.
- **Trigger Condition**: Trigger when CSRF attacks are detected.



- **Rule Name**: Bot Traffic Detection
- **Conditions**: Automatic bot traffic detection in WAF logs.
- **Trigger Condition**: Trigger when a high amount of bot traffic is detected.

### Windows

Windows servers and operating systems form a large part of organizations. SIEM  tracks important information such as authentication, file access, and  event logs by monitoring Windows logs. This is necessary to detect  potential threats and security breaches.

### Rule/Correlation Examples:

- **Rule Name**: Log Deletion
- **Conditions**: Log deletion events in Windows security logs or system logs.
- **Trigger Condition**: Trigger when log deletion events are detected.



- **Rule Name**: New Member Added to Domain Admins Group
- **Conditions**: Adding a new member to the "Domain Admins" group in Windows security logs.
- **Trigger Condition**: Trigger when a new user is added to the "Domain Admins" group.



- **Rule Name**: Member Deleted from Domain Admins Group
- **Conditions**: Deletion of a member from the "Domain Admins" group in Windows security logs.
- **Trigger Condition**: Trigger when a user is deleted from the "Domain Admins" group.



- **Rule Name**: Members of Domain Admins Group Changed
- **Conditions**: Changing the members of the "Domain Admins" group in Windows security logs (added or deleted members).
- **Trigger Condition**: Trigger when members of the "Domain Admins" group are changed.



- **Rule Name**: New Member Added to Enterprise Admins Group
- **Conditions**: Adding a new member to the "Enterprise Admins" group in Windows security logs.
- **Trigger Condition**: Trigger when a new user is added to the "Enterprise Admins" group.



- **Rule Name**: Member Deleted from Enterprise Admins Group
- **Conditions**: Deletion of a member from the "Enterprise Admins" group in Windows security logs.
- **Trigger Condition**: Trigger when a user is deleted from the "Enterprise Admins" group.



- **Rule Name**: Members of Enterprise Admins Group Changed
- **Conditions**: Change of members of the "Enterprise Admins" group in Windows security logs (added or deleted members).
- **Trigger Condition**: Trigger when members of the "Enterprise Admins" group are changed.



- **Rule Name**: Suspicious Account Access
- **Conditions**: Suspicious account access in Windows security logs.
- **Trigger Condition**: Trigger when suspicious account access is detected.



- **Rule Name**: Remote Access Attempts
- **Conditions**: Remote access attempts via Windows RDP (Remote Desktop Protocol).
- **Trigger Condition**: Trigger when remote access attempts are detected.



- **Rule Name**: Attempt to Create a User Account Without Permission
- **Conditions**: Unauthorized user account creation attempts in Windows security logs.
- **Trigger Condition**: Trigger when unauthorized user account creation attempts are detected.

### Linux

Linux servers and operating systems are also a part of the infrastructure of  organizations. SIEM analyzes important data such as network traffic, log files, and system events by monitoring Linux logs. Integration of Linux logs with SIEM enables organizations to centrally monitor multiple  platforms and manage security incidents.

### Rule/Correlation Examples:

- **Rule Name**: High Privilege Transactions
- **Conditions**: Detection of highly privileged operations (privilege escalation) in Linux system logs.
- **Trigger Condition**: Trigger when high-privilege transactions are detected.



- **Rule Name**: Unauthorized Root Access Attempts
- **Conditions**: Root access attempts in Linux security logs.
- **Trigger Condition**: Trigger when unauthorized root access attempts are detected.



- **Rule Name**: SSH Access Monitoring
- **Conditions**: Monitoring SSH access in Linux security logs.
- **Trigger Condition**: Trigger when suspicious activity related to SSH access is detected.



- **Rule Name**: Direct Root Access
- **Conditions**: Direct login activity with root user
- **Trigger Condition**: Trigger if the root user logs in by any means.



- **Rule Name**: Critical File Change
- **Conditions**: Changes in critical files (/etc/passwd, /etc/shadows etc.)
- **Trigger Condition**: Trigger if changes are detected in critical files.

### Network Devices (Router, Switch etc.)

Network devices are the foundation of organizations' communication  infrastructure. SIEM monitors logs generated by network devices and  provides information about network traffic, access attempts, and network performance. This helps detect network security and performance issues.

### Rule/Correlation Examples:

- **Rule Name**: Use of Insecure Protocols
- **Conditions**: Use of insecure protocols (e.g. Telnet) on network devices.
- **Trigger Condition**: Trigger when the use of insecure protocols is detected.



- **Rule Name**: Configurations Incompatible with Security Policies
- **Conditions**: Configurations of network devices that do not comply with security policies.
- **Trigger Condition**: Trigger when configurations that do not comply with security policies are detected.



- **Rule Name**: Critical Port is Down
- **Conditions**: Certain critical ports are down
- **Trigger Condition**: Trigger if a down log occurs on ports specified as critical.

### Endpoint Security

Endpoint security solutions protect the organization's endpoints (computers,  mobile devices, etc.). SIEM protects against malware, spyware, and other threats by analyzing data from endpoint security solutions.

### Rule/Correlation Examples:

- **Rule Name**: Files Quarantined by Antivirus
- **Conditions**: Files quarantined by Endpoint security (antivirus).
- **Trigger Condition**: Trigger if files quarantined by the antivirus are detected.



- **Rule Name**: Threats Detected by the EDR System
- **Conditions**: Dangerous behavior or threats detected by the Endpoint Detection and Response (EDR) system.
- **Trigger Condition**: Trigger if dangerous activities are detected by the EDR system.



- **Rule Name**: Transactions Blocked by the EPP System
- **Conditions**: Malicious processes or applications blocked by Endpoint Protection Platform (EPP).
- **Trigger Condition**: Trigger if malicious activities blocked by the EPP system are detected.

### VPN

VPNs are widely used to provide remote access and secure communications.  SIEM tracks authentication and access attempts by monitoring VPN logs,  thus providing information about security events that occur over the  VPN.

### Rule/Correlation Examples:

- **Rule Name**: Anomaly Activity After VPN Access
- **Conditions**: Access by the same user account outside normal business hours or normal usage patterns.
- **Trigger Condition**: Trigger when abnormal activity is detected after successful VPN login.



- **Rule Name**: Suspicious VPN Access
- **Conditions**: Same user account, consecutive login attempts from different geographical locations.
- **Trigger Condition**: Trigger when fast login attempts are detected from different geographical locations with the same user account.



- **Rule Name**: Suspicious VPN Traffic
- **Conditions**: Detection of certain malware or application signatures within VPN traffic.
- **Trigger Condition**: Trigger when unauthorized software or application is detected in VPN traffic.

### VM Platform

Virtual machines help organizations use resources effectively. SIEM monitors  logs from virtual machine platforms and ensures the security of the  virtualization environment.

### Rule/Correlation Examples:

- **Rule Name**: High Access Authority Changes
- **Conditions**: High access privilege changes on the VM platform.
- **Trigger Condition**: Trigger if high access privilege changes are detected.



- **Rule Name**: Not Taking VM Backups Regularly
- **Conditions**: Not taking regular backups on the VM platform.
- **Trigger Condition**: Trigger if it is detected that VM backups are not taken regularly.



- **Rule Name**: VM Deletion
- **Conditions**: Deletion of a VM on the VM platform.
- **Trigger Condition**: Trigger if deletion of a VM is detected.



- **Rule Name**: VM Creation
- **Conditions**: Creating a new VM on the VM platform.
- **Trigger Condition**: Trigger if the creation of a new VM is detected.

### Vulnerability Management

Vulnerability management solutions help organizations detect and remediate security  vulnerabilities. The logs of these solutions contain information about  potential vulnerabilities and vulnerability scanning results. By  analyzing these logs, SIEM identifies priority vulnerabilities and  provides a rapid response.

### Rule/Correlation Examples:

- **Rule Name**: Rapid Patching of Critical Weaknesses
- **Conditions**: Detection of a critical vulnerability by the Vulnerability Management system.
- **Trigger Condition**: If a critical vulnerability is detected, trigger it to be patched quickly.



- **Rule Name**: Monitoring High Score Weaknesses
- **Conditions**: Detection of high-risk (high score) vulnerabilities by the Vulnerability Management system.
- **Trigger Condition**: If high-risk vulnerabilities are detected, trigger these vulnerabilities to be monitored.



- **Rule Name**: Warnings from Weakness Parties
- **Conditions**: Weaknesses detected by the Vulnerability Management system based on vulnerability scanning results.
- **Trigger Condition**: Trigger the detected vulnerabilities based on the vulnerability scan results to be communicated to the SIEM side.



- **Rule Name**: Failure of Vulnerability Scanning Operations
- **Conditions**: Failure or blocking of vulnerability scanning by the vulnerability management system.
- **Trigger Condition**: Trigger if vulnerability scanning processes are detected to be unsuccessful or blocked.

### Conclusion/Summary

The sample rules and correlations discussed in this lesson help SIEM  systems better monitor organizations' security infrastructure and  respond quickly to potential threats. By monitoring data from different  technologies such as Firewall, IPS/IDS, WAF, Windows, Linux, network  devices, endpoint security, VPN, VM platforms, and vulnerability  management, they offer security teams a critical advantage in  identifying abnormal activities and blocking threats.

These rules and correlations cover different security areas such as network  security, system security, access control, and vulnerability management. For example, by examining firewall logs, unauthorized port access  attempts can be detected and a rapid response can be provided.  Additionally, correlations with endpoint security solutions play an  important role in avoiding malware detection.

All these examples help organizations strengthen their cybersecurity  strategies and minimize security vulnerabilities. However, it is  important to remember that every organization has unique needs and  security policies. Therefore, it is recommended to customize these  sample rules and correlations to suit one’s own needs and technologies.

In this part of the training, sample rules for Firewall, IPS/IDS, WAF,  Windows, Linux, Network Devices, Endpoint products, VPN, virtual  systems, and Vulnerability Management products are mentioned. In the  next part of the training, the subject of “Creating Alarms” will be explained.

### Questions

1 - Which logs does SIEM analyze and detect abnormal activities on network traffic?

> **Answer:** firewall

## Creating Alarms

Alarming with SIEM allows organizations to quickly react to security events. This helps identify  when hackers or threat actors are trying to penetrate or cause harm. To  raise alarms, SIEM monitors many security events or log entries where  certain conditions are met. For example, events such as a failed login  attempt, virus detection, or network traffic anomalies can be defined as alarm conditions.  

When creating an alarm with SIEM, the following basic steps are followed:  

- **Defining Rules and Correlations:** SIEM admins determine  which events or log entries should trigger an alarm. For example,  conditions can be defined as “a certain number of consecutive failed  login attempts”.
- **Alert and Notification:** When an alarm is  triggered, instant notifications are sent to the security team or  relevant persons. These notifications help the organization react  quickly.  
- **Determining the Actions to be Taken:** The actions to be taken  when the alarm is triggered are determined. These actions may include  notifying the security team, automatically isolating the incident or  other responses. At this stage, SOAR technology also comes into play.  

In summary; Various alarm types can be created for the rules/correlations created. Each SIEM  solution has different alarm creation capabilities. The most commonly  used alarm creation methods are:

- **Email Notifications:** SIEM can send automatic  email notifications to the security team or other relevant individuals  when a specific alarm is triggered. This helps ensure quick response to  security incidents.
- **SMS Notifications:** Some SIEM solutions offer the ability to send SMS notifications on critical security events. In  this way, the security team can be quickly notified in cases of  emergency.
- **Web-Based Notifications:** Sending web-based  notifications through the SIEM console provides the security team with  quick access to alerts. Alerts typically appear when users log in to the SIEM console.
- **Mobile App Notifications:** SIEM applications may  have the ability to send alarm notifications to security teams via  mobile devices. This allows security professionals to receive alerts on  the go.
- **Webhooks and API Integrations:** SIEM can send  notifications to other applications or messaging platforms (e.g. Slack,  Microsoft Teams) via webhooks and API integrations. This allows the  security team to receive information using different communication  channels.
- **Dashboard and Console Notifications:** The SIEM console visually displays many alerts and security events. The security team can monitor the alarm status by monitoring the console regularly.

These mechanisms enable  the security team to react quickly and effectively to security  incidents. Businesses generally optimize security alarm management by  configuring these mechanisms in a way that suits their organization. 

### IBM QRadar Alarm Creation

The steps to create alarms for the rules/correlations you define on IBM QRadar SIEM are as follows:  

The step of creating an  alarm on IBM QRadar is determined during the rule/correlation writing  phase. You can reach this step by following the steps below.  

Within the QRadar ->  Offenses -> Rules -> Actions -> 'New Event Rule' screen,  determine/create the rule response in the second step in the 'Rule  Response' section.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Generation/5/image5-1.png)

To create an email alarm, select the Email option, and write the email address to which the notification will be sent.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Generation/5/image5-2.png)

With the Send to Forwarding Destinations option, you can forward the resulting offense to a different target (via syslog, etc.).

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Generation/5/image5-3.png)

The Notify option creates a notification in the QRadar interface regarding the offense.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Generation/5/image5-4.png)

You can write the  information contained in the resulting offense to the reference set by  clicking "Add to Reference Set", and use this reference set with  different rules.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Generation/5/image5-5.png)

With the Execute Custom Action option, you can run your own scripts after the offense occurs.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Generation/5/image5-6.png)

QRadar's rule response  options provide a powerful set of tools to personalize and optimize  security incident detection and response capabilities. These options  help the security team respond quickly to threats and reduce potential  risks. QRadar's flexible and customizable structure allows organizations to improve their security strategies. Therefore, security teams should  learn to use QRadar's rule response options effectively.  

### Conclusion/Summary

Alarming with SIEM is vital for organizations to monitor their security status and respond  quickly to threats. In this way, security vulnerabilities or malicious  activities can be detected more quickly and precautions can be taken.  Additionally, SIEM-generated alerts help the security team use their  resources more effectively.  

In this part of the  training, the basic steps to be followed when creating an alarm with  SIEM and how to create an alarm on IBM QRadar have been mentioned.

























