# XDR/EDR Threat Analysis & Custom Rule

The  "XDR/EDR Threat Analysis & Custom Rule" course is designed to  empower participants with advanced skills in threat analysis and the  creation of custom rules within Extended Detection and Response (XDR)  and Endpoint Detection and Response (EDR) platforms. It focuses on  practical hands-on experience to enhance cybersecurity capabilities.

**Table of Contents:**

- [Fundamentals of Threat Analysis](#fundamentals-of-threat-analysis)
- [Threat Detection and Classification with EDR/XDR](#threat-detection-and-classification-with-edrxdr)
- [Threat Management and Analysis](#threat-management-and-analysis)
- [Data Collection and Analysis with EDR](#data-collection-and-analysis-with-edr)
- [Creating Custom EDR Rules and Policies](#creating-custom-edr-rules-and-policies)

**Evaluate Yourself with Quiz**

- [XDR/EDR Threat Analysis & Custom Rule](https://app.letsdefend.io/training/quiz/xdr-edr-threat-analysis-custom-rule)

## Fundamentals of Threat Analysis

Threat analysis is a method that the cybersecurity experts use extensively. It is a process  that evaluates potential threats that an organization or systems may  face and tries to understand how these threats may affect the  organization or systems.

We will deep dive into the details of "Basics of Threat Analysis" under the following headings: 

### Definition of Threat

Threat refers to any  malicious activity, actor or event in the world of information  technologies that may cause potential harm to the digital assets of an  organization or individual. These threats can range from cyber espionage activities of national governments to cybercriminals seeking financial  gain to hacktivists acting for social or political reasons.  Additionally, organizations may also be exposed to insider threats.  Insider threat refers to the potential risks posed by individuals within an organization who have authorized access to sensitive information or  resources and may use that access to cause harm or compromise the  security of the organization wittingly or unwittingly.    This means that the human factor is a potential risk. Threat definition is a step towards  understanding the nature, source, and potential impact of a threat,  which is the cornerstone of creating an effective cybersecurity  strategy.  

### Threat Actors

Threat Actors is a term  used in the context of cybersecurity to describe individuals, groups, or organizations that have the potential to intentionally cause harm to  digital assets or networks. These actors may include advanced persistent threats (APTs) supporting nation-states, cybercriminals, hacktivists,  and even careless or malicious employees who pose insider threats. Each  threat actor has a specific motivation, capabilities and tools available they leverage. While actors supporting nation-states have often highly  sophisticated tools and capabilities, individual cybercriminals may  operate with simpler methods. Understanding threat actors helps  organizations assess the risks to them and develop effective defense  strategies against these threats.  

### Threat Vectors

Threat vectors are the  ways that attackers use to gain access to or damage a system, network,  or device. These vectors can include malicious attachments sent via  email, vulnerabilities exploited in web browsers, physical devices such  as USB sticks, or even human-based attack routes such as social  engineering techniques. Recognizing and understanding threat vectors  helps security experts predict how attackers may infiltrate into systems and take defensive measures accordingly. Modern cybersecurity  strategies take a proactive approach in an environment where threat  vectors are constantly evolving, so recognition and analysis of vectors  is of critical importance.  

### Asset Evaluation

Asset evaluation is the  process of identifying, classifying and determining the value of all  digital assets owned by an organization. These assets may include  valuable information such as servers, devices, software applications,  databases, network structures, and even intellectual property or trade  secrets. Asset evaluation allows an organization to know what its most  valuable and critical elements are. This helps them understand which  assets may be most impacted by potential threats. This information plays a critical role in prioritizing security measures and creating risk  management strategies. In summary, for an effective cybersecurity  approach, it is important to know what the assets are exactly, where  they are and how valuable they are. 

### Threat Probability

Threat Probability refers to the probability that a threat will occur on a particular asset or  system. This probability is evaluated to understand how likely a  particular threat is and how that threat could affect an asset or  system. Many factors can affect the likelihood of a threat. Some of  these factors include the existing security measures, the capabilities  of threat actors, and the criticality of the targeted system or asset.  An effective threat analysis helps organizations allocate and prioritize security resources and strategies to the right places by accurately  determining the likelihood of threats. This not only focuses on the  highest risk threats, but also enables more effective decisions about  the overall risk profile.  

### Impact Assessment

Impact Assessment is the  evaluation of the potential damage or consequence that a threat will  cause on an asset or system if it occurs. This evaluation is made based  on factors such as the material and moral value of the lost data, costs  that may occur due to interruption of business processes, damage to  brand reputation and potential legal liabilities. Impact assessment  helps an organization identify its most valuable assets, its most  critical systems, and the greatest threats to those assets or systems.  This way, they can make conscious decisions about security strategies  and how to allocate and prioritize resources most effectively. Impact  assessment is a critical step in risk management and is an integral part of threat analysis.  

### Threat Vulnerability Relationship

Threat Vulnerability  Relationship considers how potential threats may interact with specific  vulnerabilities of an organization or systems. Not every threat poses a  real risk unless it targets and exploits an existing vulnerability. For  example, a malware attack might target a vulnerability in a specific  version of the software. If the organization is not using this version,  it does not pose a direct risk for this threat. However, if this  vulnerability exists and the threat is active, the magnitude of the risk increases. Therefore, accurate matching of threats and vulnerabilities  is of critical importance in risk assessment and management processes.  Threat analysis guides us to understand this relationship of threats and vulnerabilities in depth so that we can take the accurate security  measures.  

### Threat Rate

Threat Rate represents  the frequency of threat events over a given time period. This rate helps determine how often a particular threat may occur to an organization or system. A high threat rate indicates that a particular threat occurs  more frequently and therefore poses a higher risk. During the threat  analysis process, determining the threat rate is critical to  prioritizing potential risks and deciding where resources should be  allocated most effectively. The threat ratio is calculated based on data obtained from both internal and external intelligence sources and is  tailored to the organization's risk profile. This allows security teams  to better understand which threats are most likely to occur soon and  with the highest probability.  

### Preventive and Mitigation Strategies

Preventive and Mitigation Strategies are one of the critical results of threat analysis. Threat  analysis reveals how vulnerable an organization is to potential threats; however, it has only theoretical value unless it is combined with  appropriate strategies. Preventive strategies aim to prevent threats  from starting or entering a system. This may include a variety of  technological solutions such as firewalls, authentication mechanisms, or proactive network monitoring. Mitigation strategies, on the other hand, are put in place to limit the impact of a threat or minimize potential  damage. If the threat has already infiltrated a system, mitigations can  help shorten the organization's recovery time by minimizing the impact  of such threats and responding to them quickly. Both types of strategies must work together for a complete cybersecurity as a whole to be robust and effective.  

### Conclusion/Summary

The threat analysis process helps organizations effectively direct their security strategies in the ever-changing cybersecurity environment. Cyber threat analysis  is a critical component of a cybersecurity strategy, and an effective  cyber threat analysis plays a major role in reducing the risk of the  organization.  

In this part of the training, we have covered the fundamentals of threat analysis and we will be learning about the “Threat Detection and Classification with EDR/XDR” topic in the next chapter of our training.

### Question

1 - In cyber security, what do we define as malicious activities that can damage an organization's digital assets?

> **Answer:** Threat

## Threat Detection and Classification with EDR/XDR

EDR and XDR technologies  play a critical role in detecting advanced threats, especially those  that traditional signature-based antivirus solutions cannot detect. It  is also carried out with the capacity to detect malicious behavior in  real time, respond to the incident and stop malicious activities with  advanced analysis techniques. It also classifies threats, allowing  organizations to understand which threats pose the highest risk and  provide a prioritized response accordingly.  

### EDR/XDR Endpoint Threat Detection

Although EDR/XDR  solutions have different threat detection mechanisms, most of them can  be grouped under the following titles. Although they all focus on  different functions their threat detection mechanisms exhibit similar  approaches.  

**Machine Learning and Artificial Intelligence**

Advanced EDR/XDR  solutions leverage ML and AI algorithms to detect malicious activities.  These algorithms identify threats more accurately by learning from large data sets.  

**Behavioral Analysis**

Aims to detect anomalies  or deviations compared to the normal activity of an endpoint. If a user  or process behaves in an unexpected or unusual way, it may indicate a  potential threat.  

**Heuristic Analysis**

Detects potential threats without recognizing the signature of a specific malware. Instead, it  looks for certain characteristics or behaviors for suspicious or  potentially harmful activity.  

**Signature-Based Detection**

Involves detecting  malware based on its recognized “signatures” or characteristics. This  approach is highly effective against known threats.  

**Fileless Threat Detection**

Advanced threats can use  fileless techniques to bypass traditional file-based signature  detection. To detect such threats, mechanisms that monitor behavior in  memory are required.  

**Execution in a Virtual Environment**

Some EDR/XDR solutions  attempt to determine the true nature of suspicious files by running them in an isolated virtual environment. This approach allows malicious  activities to be detected before they occur in a real system.  

**Network Traffic Analysis**

XDR solutions can  integrate additional threat detection methods such as network traffic  analysis. This is used to detect suspicious or malicious activity in  network traffic.  

**Integrated Threat Intelligence**

EDR/XDR solutions can  integrate with external threat intelligence sources to stay up to date  on the latest threats detected around the world.  

Each of these mechanisms can help an organization detect and respond to cybersecurity threats  faster and more accurately. However, the effectiveness of these  mechanisms depends on their correct configuration and constant updating.

### EDR/XDR Endpoint Threat Classification

EDR and XDR solutions are used to detect, analyze and respond to threats to an organization's IT  infrastructure. In classifying these threats, EDR/XDR solutions are  based on certain criteria and features. EDR/XDR uses a set of features  and technologies to identify, analyze and classify threats.

Basically, threat classification can be examined under the following titles:  

**Classification by Threat Type**

It aims to categorize the cyber threats faced by an organization or individual according to their specific characteristics. This classification can be made according to  the source of threats, their impact or the method used. For example;  malware, ransomware, exploit, phishing, lateral movement.  

**Classification by Threat Source**

Focuses on who or which  groups create or spread cyber threats. Threat actors' motivations,  capabilities, and goals are important in determining the source of  attacks. For example; APT groups, insider threats, hacktivists.  

**Classification by Target**

Focuses on specific industries, systems, or applications where cyber threats are created or  targeted. This classification highlights which resources or assets the  attacks target. For example; Attacks targeting SCADA systems, financial  infrastructure systems, and systems containing personal information.  

**Classification by Attack Purpose**

Examines why cyber  attacks are carried out and what these attacks aim to achieve. Every  attacker has a specific purpose or reason for performing an action. For  example; data leakage, denial of service (DOS), espionage, loss of  reputation, etc.  

**Classification According to Threat Complexity**

Evaluates and shows  sophistication level of the cyber threats and technical knowledge of the attackers. The complexity of threats often varies depending on the  attacker's capabilities, resources, technical knowledge and the target  of the attack. For example, low, medium and high complexity threats.  

### Threat Detection and Classification with SentinelOne

Specific details about  how exactly SentinelOne does threat classification are hidden in the  company's internal documentation and technological details, but in  general such solutions detect and classify threats with behavioral  analysis, static analysis, artificial intelligence, machine learning and other techniques.

In general, SentinelOne or other EDR/XDR products classify threats under the following titles:  

**Malware** stands for malicious  software and refers to any software that is designed to harm or gain  unauthorized access to computers, servers or networks.  

**Ransomware** is a type of malware that blocks access to data on a computer system, and it the attackers take  the advantage of it by demanding a ransom to from the system owners to  access their data again.  

**A virus** is a type of malware that operates as part of a computer program or piece of code and can infect  other programs, a computer or a network by copying itself.  

**Hacktool** generally refers to software or hardware tools used to gain unauthorized access to computer systems or bypass security measures.

**Infostealer** is a type of malware designed to access and collect sensitive information or personal data on a computer system.  

**Potentially Unwanted Applications** (PUA) refers to software  that are potentially unwanted or harmful to users. These software are  generally not malicious, but they can perform unwanted actions such as  showing unwanted ads or reducing system performance.  

**A Trojan** is malware that, after  infecting a computer, creates backdoors that allow the attacker to  access the system. It has the ability to disguise itself and appear as  an innocent software.

**Packing** is the process of replacing a malware's original code with compression or encryption techniques to make it harder to detect.

**A rootkit** is a set of malware that  burrows deep into a computer system and is often used to make other  malware difficult to detect or to conceal unauthorized access.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/2/image2-1.png)

SentinelOne uses various  engines to detect known and unknown threats. These engines are  specifically designed for different threat vectors and attack tactics.  Details about these detection engines and threat classes are as follows.

### Reputation Engine

Reputation Engine helps  evaluate the reputation of files, applications and other objects  automatically. Essentially, it uses a large database of threat  intelligence to make a quick decision on whether a file or process is  malicious or not.

This engine provides  access to a database containing information about known malware,  malicious URLs, IP addresses, and other threat indicators. If a file or  process is marked as malicious in this database, the engine immediately  triggers an alert and can take appropriate protection action.

One of the main  advantages of Reputation Engine is that it provides fast and automatic  protection against known threats, although this is not enough to protect against zero-day attacks. It is especially effective for stopping  attacks related to known malware.

However, Reputation  Engine is only part of the SentinelOne platform. SentinelOne is capable  of detecting unknown and advanced threats using behavioral analysis,  artificial intelligence and other advanced detection techniques. This  engine basically works integrated with Threat Intelligence resources  such as SentinelOne Cloud, Recorded Future, and Virustotal, etc.

For example, you try to  download a known malware (mimikatz.exe) to a system with the SentinelOne agent installed. If your policy is in protection mode, the malicious  executable will be caught by the Reputation Engine and the kill &  quarantine action will be applied before it is written to the disk.

In the image below, it is reported that this malware was detected by the “SentinelOne Cloud” engine.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/2/image2-2.png)

### Static AI

SentinelOne Static AI  Engine is part of the SentinelOne platform and protects against known  and unknown malware. This engine uses artificial intelligence (AI)-based models to determine whether a file is malicious or not. Static AI  analyzes the contents of the file without running or opening it,  providing fast and effective protection against zero-day threats.

One of the biggest  advantages of the “Static AI” is that threat detection time is almost  instantaneous. This means malware can be detected and blocked before it  takes effect. This feature of SentinelOne uses complex learning  algorithms to hunt for threats and analyze misleading file behavior. In  this way, it can detect new and advanced threats that traditional  signature-based solutions cannot detect.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/2/image2-3.png)

### Static AI - Suspicious

It is one of the  artificial intelligence-based analysis engines that SentinelOne uses to  detect malicious activities. However, this particular engine is designed to detect less obvious and precise malicious behavior. Static AI  Suspicious Engine analyzes files without executing or interacting with  them. This allows malware to be detected in advance before it risks  causing potential harm or infecting a system. Suspicious Engine can  detect incidents where it is unclear whether a file is potentially  harmful or not. Therefore, when a particular file or process is marked  as "suspicious", this means that it is not necessarily malicious, but  should be taken seriously and files or processes marked as "suspicious"  should be further analysed and may be quarantined to ensure the network  security. This allows security teams to more closely evaluate potential  threats. SentinelOne's Static AI Suspicious Engine constantly learns and adapts due to the ever-changing nature of the threat landscape.

In short, SentinelOne's  Static AI Suspicious Engine helps organizations take a proactive  security approach by detecting subtle malicious behavior and potential  threats. This provides an additional layer of protection, especially  against zero-day threats and unknown malware.  

### Behavioral AI - Executables

SentinelOne's Behavioral  AI detection engine detects malicious activities based on behavior in  the processes and systems where these activities occur. This engine,  unlike traditional signature-based solutions, does not look for specific "signatures" or hashes of malware. Instead, it focuses on behavioral  characteristics to determine whether a process or activity is malicious.

This approach increases  the ability to detect previously unknown threats, including zero-day  attacks. Behavioral AI can monitor the activities of a malicious process in real time (i.e. trying to modify system files, performing in-memory  attacks, interfering with other processes, etc.) and automatically stop  that process.

However, the nature of  this approach also carries the risk of increasing the false positive  rates (misclassification of a legitimate process or activity as  malicious).  

### Documents, Scripts

SentinelOne's "Documents, Scripts" engine is part of the SentinelOne platform and is primarily  aimed at detecting cyber threats in documents and scripts. Attackers  often distribute their malware or commands by embedding them in popular  document formats such as Office documents. SentinelOne's "Documents,  Scripts" engine analyzes such documents and detects indicators for  malicious activities. Scripts (i.e. PowerShell, VBScript, JavaScript)  are frequently used by attackers because they often have powerful  functionality and the ability to make changes to the system. By  analyzing the behavior of these scripts, the engine detects and blocks  suspicious or malicious activities.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/2/image2-4.png)

### Lateral Movement

SentinelOne is a platform that provides end-to-end protection and offers many threat detection  and response capabilities. "Lateral Movement" engine is a feature  designed to detect movements within the network. Lateral movement refers to the process by which an attacker attempts to infiltrate other  systems in the organization's network by using the system he/she first  compromised. Engine can detect an attacker's attempts to infiltrate  other systems within the network. This is critical to track down the  attacker and disrupt his movement.  

### Anti Exploitation/Fileless Engine

SentinelOne's "Anti  Exploitation/Fileless Engine” plays a critical role in the endpoint  protection process. This engine is designed to detect fileless attacks  and attacks using software exploits, in addition to specific file-based  threats. Fileless attacks operate without writing any files to the hard  disk and are typically implemented through code running in memory,  scripting engines, or other built-in tools with the right capabilities.  SentinelOne detects and responds to such attacks using software exploits and these attacks occur when untrusted data is unexpectedly processed  in the target software. SentinelOne can detect exploitation of such  vulnerabilities.  

### Potentially Unwanted Applications

SentinelOne's  "Potentially Unwanted Applications (PUA)" engine is used to detect  unwanted software which are not necessarily malicious often. PUAs refer  to software that is installed without the user's knowledge or in a  misleading manner and often exhibits undesirable behavior. While these  programs are not as harmful as malware, they can still behave in  unwanted manners, disrupt user experience, cause privacy issues, and  consume system resources. Engine can detect adware, browser hijackers,  unwanted toolbars and other potentially unwanted applications.  

### Conclusion/ Summary

In this lesson, We have  provided in-depth information on how EDR/XDR solutions detect and  classify threats. In this way, we learned both attack types and attack  classes. Additionally, we have coverd the engine types on the  SentinelOne EDR/XDR product and their functionalities. In the next part  of the training, we will learn about the “Threat Management and Analysis with EDR/XDR” topic.

### Question

1 - What is the abbreviation for potentially unwanted software?

> **Answer:** PUA

2 - What is the name of SentinelOne's module that detects and prevents attackers from advancing laterally?

> **Answer:** Lateral Movement

## Threat Management and Analysis

EDR and XDR technologies  are important security tools that stand out in today's ever-changing  cyber threat environment. These technologies give cybersecurity  professionals the ability to monitor potential threats in real time,  detect unusual movements through behavioral analysis, and take automatic or semi-automatic interventions against these threats. This allows  organizations to take a proactive rather than reactive approach to cyber attacks.

EDR/XDR threat management and analysis processes have become a critical process in many  organizations as traditional antivirus solutions fall short of detecting increasingly sophisticated threats. Threat management and analysis with EDR/XDR solutions basically consists of the following steps.  

### Threat Management and Analysis Steps

**Detection**

EDR solutions  continuously monitor endpoint activities. These can include file  behaviors, system calls, network traffic, and more. Advanced analysis  techniques are used for anomaly detection, which detects known and  previously unknown threats and malware.  

**Investigation**

When a threat is  detected, analysts initiate an in-depth investigation to determine the  nature, source, and potential impact of the threat. This is critical to  understand the origin of the attack, the files affected, the methods  used, and the general behavior of the threat.

**Response**

Once a threat is  confirmed, a response strategy is immediately created. This may include  removing malware, isolating affected systems, or initiating a broader  response strategy. EDR solutions can provide automated responses or  facilitate manual intervention.  

**Remediation**

At this stage, the focus  is on repairing the damage caused by the attack. This may include  restoring systems to their original state, recovering lost data, and  implementing additional protections against future attacks.  

**Learning**

In the final stage of  this process, an in-depth analysis is made to know how the incident  occurred and what vulnerabilities or weaknesses were exploited. This  information is used to develop strategies to protect against similar  threats in the future.  

**Threat Hunting**

Some EDR solutions  support threat hunting, a proactive approach. Analysts hunt for  potential threats and look for malicious activity that has not yet been  detected on the network.  

These processes work  together to maximize the success of an EDR/XDR solution. However, how an EDR/XDR solution works and what features it provide may vary depending  on the chosen EDR/XDR platform.  

### Threat Management and Analysis with SentinelOne

SentinelOne carries out  the threat management and analysis process with a customized approach. Threats detected by SentinelOne appear under 2 different tabs (Threats,  Alerts) under the “Incidents” menu. 

- **Threats:** This tab displays the threats detected and reported by SentinelOne's existing engines.  
- **Alerts:** This tab display where activities that triggers the custom rules (Star Custom Rule) on SentinelOne.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/3/image3-1.png)

When you want to view the details of a threat, you can click on the down arrow button and expand  the threat and the details about the threat will be displayed.

You can see the following details when you expand the threa on this screen;  

- **Endpoint Name:** Provides the hostname of the endpoint tha the relevant threat occurs.  
- **File Path:** The full path to the file from which the threat originates or is associated. This usually  indicates where a malicious file is located on the system. It helps you  understand where the malicious file is located and how to find it.  
- **Command Line Arguments:** These are the command  line arguments that the malicious file or process receives when it is  run. It helps you understand how the file is run and what commands are  used.  
- **Signer Identity:** This shows the  organization which signes the file or transaction. It helps you  understand who created and signed the file. It often provides  information about the identity of the actor behind the malware.  
- **Classification:** This field shows the  classification of the file associated with the threat. This helps you  understand what type of threat the file is (i.e. Ransomware, Trojan,  etc.).  
- **Originating Process:** The main process or  application that initiates or triggers the threat. It helps you  understand where the file detected as a threat came from and how it  started.  
- **Initiated By:** The user or system  account from which the threat was initiated or created. It helps you  understand who started the malicious file.  
- **Engines:** Shows SentinelOne's  engines or modules that detect and analyze the threat. It helps you  understand how the malicious file is detected.  
- **Detection Type:** Information about how the threat is detected (i.e. behavioral analysis, signature-based detection, etc.)  
- **Analyst Verdict:** It is the decision or  interpretation made by the cybersecurity analyst or an automated system  about the threat. This field hows the analyst's decision about the  threat-related file.  
- **Incident Status:** The current status of the incident (threat). (i.e. quarantined, resolved, pending, etc.)  
- **Indicators:** Symptoms or indicators  associated with the threat. This usually relates to certain behaviors or characteristics that indicate or confirm the presence of a threat. It  helps you understand which threats the malicious file indicates.  
- **Notes:** These are notes or  comments added by analysts or system administrators about the event.  This often includes additional information or specific observations  about the threat.  

These fields are critical to understanding the nature, source, and potential impact of a threat.  This detailed information from SentinelOne helps cybersecurity  professionals quickly detect, analyze and respond to threats.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/3/image3-2.png)

For more details and  analysis about the threat, click on the "View Threat Details" button and the threat detail screen consisting of 3 different tabs opens.

The first of these tabs  to open is the "Overview" tab, which displays the information on the  previous screen on an expanded screen. Additionally, there is more  detailed information (such as OS version, policy, domain, IP address)  about the Endpoint where the relevant threat was detected.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/3/image3-3.png)

In the “Explore” tab,  there is a search screen that includes the starting process of the  relevant threat and all processes run after that process. A timeline of  when the event started and ended appears on this screen. A process you  click is displayed as a process tree in the middle of the page. Events  related to other processes you click on in the Process Tree are listed  by category at the bottom of the page. Additionally, details about the  clicked process appear on the right side of the page as “Event Details”  and “Process Summary”.

### Question

1 - Which menu does SentinelOne use to display detected threats?

> **Answer:** Incidents

## Data Collection and Analysis with EDR

Endpoint Detection and  Response telemetry data is a comprehensive and detailed set of  information collected from endpoints such as computers, servers, mobile  devices. This data is a critical component for organizations to be able  to detect, understand, and respond to malicious activities. Telemetry  data can also go into complex analytics and algorithms to detect  malicious or suspicious behavior. These analyzes often include advanced  techniques such as heuristic checks, behavioral analysis, and machine  learning. In short, EDR telemetry data provides a continuous, and  detailed record of activity at an organization's endpoints so security  professionals can quickly detect, analyze and respond to threats.  

Below are the categories of telemetry data typically collected by EDRs and examples of these categories:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/4/edr-data-table.png)

This table provides a general summary of the telemetry data and does not cover all types of  data that can be collected by EDR solutions. Depending on the version,  configuration and features of the EDR solution, collected data details  may vary.  

### Data Collection and Analysis with SentinelOne

SentinelOne's EDR approach focuses on collecting and analyzing telemetry data, enabling  organizations to quickly detect and respond to potential threats and  attacks. SentinelOne collects the telemetry data shown in the table  below.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/4/image4-1.png)

You can access these telemetry data recorded by SentinelOne from the “Visibility” menu on the SentinelOne console.  

**Example1 [Process]**

When we open the  "C:\Python27\python.exe" application on the LABPC endpoint, a record as  shown in the below screenshot will be displayed in the telemetry data on the SentinelOne.

To find this record, you can write a query like this:

EndpointName = "LABPC" AND ObjectType = "process" and SrcProcName = "python.exe"

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/4/image4-2.png)

**Example2 [File]**

A new file was created with the “new-item” function by opening “powershell.exe” on the LABPC endpoint.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/4/image4-3.png)

SentinelOne output of the relevant file movement is as follows. To find this record, you can write a query like this:

EndpointName = "LABPC" and SrcProcName = "powershell.exe" and ObjectType = "file"

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/4/image4-4.png)

**Example3 [Scheduled Task]**

A new schedule task was created by opening “cmd.exe” on the LABPC endpoint and using the “schtasks” command.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/4/image4-5.png)

SentinelOne output of the relevant schedule task creation activity is as follows. To find this  record, you can write a query like this:

EndpointName = "LABPC" and ObjectType = "scheduled_task"

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/4/image4-6.png)

**Example4 [URL]**

Requested to access to “  [https://letsdefend.io” ](https://letsdefend.ip)  URL on the LABPC endpoint using the “mshta” command on the “CMD”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/4/image4-7.png)

SentinelOne output of the relevant access request is as follows. To find this record, you can write a query like this:

EndpointName = "LABPC" and ObjectType = "url" and SrcProcName = "mshta.exe"

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/4/image4-8.png)

SentinelOne offers a  broad security coverage and analytics capabilities using the telemetry  data it collects. This data provides in-depth information not only for  threat detection and response, but also about the endpoint's overall  operations and performance.

Here are some basic operations that can be done with collected telemetry data:  

**Threat Hunting**

Telemetry data helps  security experts investigate the signs of potential threats. For  example, they can manually investigate suspicious activity by detecting  an uncommon transaction or unexpected network traffic.  

**Incident Response**

When a security incident  is detected, telemetry data can be used to determine how the attacker  infiltrated the system, what files or systems were affected, and what  actions the attacker took on the network.

**Forensic**

Following a security  breach or incident, telemetry data can be used in a forensic analysis to understand how and why the incident occurred. This is critical to  determine steps that can be taken to prevent similar incidents in the  future.  

**Risk and Compliance Assessment**

Telemetry data can be  used to assess an organization's overall security posture and compliance with certain standards or regulations. For example, you can use this  data to determine which devices are not updated or which users have too  many privileges.  

**Behavioral Analysis**

Telemetry data can be  used to classify user, application or system behavior into normal and  abnormal activities. This can help train machine learning or artificial  intelligence algorithms to detect potential threats.  

**Network Monitoring and Analysis**

Collected network  telemetry data can help analyze network connections, traffic, and  overall network performance. This can be used to detect potential DDoS  attacks, network theft attempts such as unauthorized access attempts,  theft of digital information or assets attempts or the internet, or  other network threats.  

These examples  demonstrate that the telemetry data SentinelOne collects has a broad  security and operational analysis capability. By using the telemetry  data it collects for these and many other purposes, SentinelOne provides broad security coverage. Analysis of telemetry data allows accurate and timely responses as well as the creation of more effective security  strategies.  

### Conclusion/ Summary

EDR's telemetry data collection and analysis capabilities enable cybersecurity professionals  to quickly respond to incidents, conduct in-depth investigations, and  take proactive measures against potential threats. These capabilities of EDR help organizations stay safe in the modern cyber threat landscape.  

In this part of the  training, we have explained how to collect and analyze telemetry data  using EDR via SentinelOne. In the next part of our training, we will  cover the “Creating Special EDR Rules and Policies” topic.

### Question

1 - From which menu can you access the telemetry data recorded by SentinelOne?

> **Answer:** Visibility

2 - Which option should be enabled in the "Deep Visibility" section for SentinelOne to collect DNS telemetry data from endpoints?

> **Answer:** DNS

3 - Which option should be  enabled in the "Deep Visibility" section for SentinelOne to collect  Login/Logout telemetry data from endpoints?

> **Answer:** Login

## Creating Custom EDR Rules and Policies

One of the prominent  features of Endpoint Detection and Response systems, especially in large and complex IT environments, is the ability to create customizable  rules. This feature allows companies and security professionals to  create more specific responses to their specific needs, policies, and  potential threats.  

### Details on Custom EDR Rule Development

**Why is it necessary to develop a special rule?**

Every organization has  its own applications, workflows, and characteristics of the IT  environment. Standard rules are designed to respond to general threats,  but may not fully suit the specific needs of a particular organization.  Customizable rules fill this gap.

Threat actors and attack  vectors are constantly evolving. Customized rules make it possible to  create more specific responses to certain new threats or threats from a  specific geographical area.

Custom rules allow  security teams to identify risks specific to their organization and  provide more proactive protection against those risks.

Beyond defending against  external threats, organizations can also defend against internal threats (i.e. in-network attacks or insider threats). Customized rules can help detect and mitigate such internal threats as well.

Standard rules generally  target a wide range of threats. Customized rules may be better suited to a particular organization's infrastructure and applications, which can  help reduce false positives.  

**How Should the Rule Development Process Be?**

- **Needs Analysis:** The first step is to  determine what type of rule is needed. This may be based on needs such  as monitoring the behavior of a specific application, controlling  traffic from a specific IP range, or auditing the behavior of a specific file or process.  
- **Rule Design:** After the needs analysis  is done, it is necessary to define how the rule will operate and under  what conditions it will be triggered.  
- **Testing and Implementation:** It is recommended to test the created rule in a test environment to see whether it works  correctly. This step is critical to determine whether the rule triggers  false positives or false negatives.  
- **Monitoring and Improvement:** Rules should be updated and improved over time based on the changing threat landscape.

### Important point that need extra attention

- **False Positives:** When a rule is too strict or covers a broad scope, normal behavior can be falsely flagged as dangerous.
- **Performance Issues:** Too many rules or rules that are too broad can negatively impact system performance or users’ functionalities.  
- **Update and Maintenance:** EDR solutions require regular review and updating of rules as the threat landscape and IT environment change.

As a result, custom rule  development with EDR enables organizations to customize protection and  response mechanisms for specific threats and needs. However, for these  rules to be implemented effectively, careful planning, testing and  ongoing review are required.

### Custom Rule Development with SentinelOne

To develop a custom EDR  rule with SentinelOne, you can convert the query you wrote on the “Visibility” screen into a custom rule with the “+ Custom Rule” button,  or go to the “Star Custom Rules” tab on the “Visibility” screen and  create a custom rule with the “New Rule” button.

For example, let's write a special EDR rule for "cmd.exe" followed by "whoami.exe" execution.

First, we should create  the query on the “Visibility” -> “Hunting” screen. Then start  creating a new rule through the “+ Custom Rule” button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/5/image5-1.png)

In the 2nd step, you  should specify the “Rule Name”, “Description”, “Rule Severity”, “Rule  Type” (temporary or permanent) and click the “Next” button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/5/image5-2.png)

In step 3, "Scope" is selected in which Site or group the rule will be run. If a change is  needed in the query, it can be corrected with the "Edit Query" option in this step. Then, click the “Next” button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/5/image5-3.png)

In the step 4, we will  specify the action that the SentinelOne will take in case of an incident occurs that fits the query we have determined in the previous step. We  can specify whether only an alarm to be generated or whether this  activity to be defined as a threat and "detect" or "block" action to be  taken. We can also add the option of the “Network Quarantine” that  isolates the relevant endpoint from the network.

After the options are selected, continue by pressing the “Next” button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/5/image5-4.png)

In the last step, summary information about the written rule is shown. To make the rule active  immediately, select the “Activate rule immediately after saving” option  and press the “Activate” button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/5/image5-5.png)

To check that the written rule is active and working, you can the status of the rule on the  “Sentinels” -> “Star Custom Rules” tab.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/5/image5-6.png)

To test the written rule, open “cmd.exe” on LABPC and execute the “whoami.exe” command.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/5/image5-7.png)

After the command is run, there goes a suspicious activity alert on the SentinelOne agent UI on  LABPC stating that a "Suspicious Threat" has occurred.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/5/image5-8.png)

When we check the details about the “Suspicious Threat” via the SentinelOne console, you can see  that there is “cmd.exe” -> “whoami.exe” activity.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Threat+Analysis-Custom+Rule/5/image5-9.png)

### Conclusion/Summary

To summarize, customized  EDR rules enable organizations to provide protection that better suits  their specific needs, risk profiles, and security policies. This is the  key to create a more effective and customized security posture.

In this part of the  training, we have covered how to create custom EDR rules and important  points you need to know when creating custom EDR rules on SentinelOne.

















































