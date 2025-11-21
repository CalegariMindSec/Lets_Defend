# XDR/EDR Basics

The  "XDR-EDR Basics" course is an introductory exploration of Extended  Detection and Response (XDR) and Endpoint Detection and Response (EDR)  technologies, focusing on their fundamental principles and applications  within cybersecurity.

Table of Contents

- [XDR/EDR Introduction]()
- [Common XDR/EDR Products]()
- [EDR/XDR Installation and Configuration Process]()
- [Managing Endpoints with EDR/XDR]()
- [Data Collection and Log Integration for XDR]()

Evaluate Yourself with Quiz

- [XDR-EDR Basics](https://app.letsdefend.io/training/quiz/xdr-edr-basics)

## XDR/EDR Introduction

In today's rapidly  digitalizing world, cybersecurity threats have been increasingly  sophisticated and pose a major risk to organizations. At this point, the concepts of Endpoint Detection and Response (EDR) and Extended  Detection and Response (XDR) has come to the scene. While EDR is an  important tool for detecting and responding to cyber threats at  endpoints, XDR offers these capabilities in a broader perspective by  combining data from the network, cloud and other security sources. In  this course, we will examine the role of EDR and XDR in cyber security  strategies and provide information on how organizations can strengthen  their security solutions in today's complex threat landscape.  

### Endpoint Detection and Response (EDR)

EDR is a security  technology used to monitor, detect and respond to cybersecurity threats  that occur at the endpoints of computer networks like computers,  servers, mobile devices, etc. EDR solutions monitor activities on  computers and devices, detect abnormal behaviors and provide rapid  response to possible threats. This helps organizations stay secure by  increasing the capacity to detect, analyze and respond to cyber-attacks.

EDR solutions typically include the following capabilities:

**File and Process Monitoring**

They constantly monitor files and processes on endpoints. In this way, abnormal behavior or signs of malware can be detected.

**Behavior Analysis**

EDR solutions detect  anomalies by identifying normal usage habits. For example, if an  application performs operations, it should not normally do, this can be  captured by behavioral analysis.

**Malware Detection**

Detects and isolates malware. This helps detect threats such as viruses, trojans, ransomware, etc. at an early stage.

**Indicator of Compromise (IOC) Detection**

Uses industry data and  threat intelligence to identify known malicious activity. This is  important for detecting and responding to previously seen threats.

**Event Log Analysis**

Monitors event logs of  endpoint devices and identifies abnormal events or security-related  situations. This is used to better understand potential threats.

**Threat Intelligence Integration**

They can work integrated  with external threat intelligence sources. This provides organizations  with more effective protection by providing up-to-date threat  information.

**Post-Monitoring Action Capabilities**

EDR solutions provide the tools and capabilities needed to respond quickly when threats are  detected. This is important to minimize the impact of threats and  prevent their spread.

**Network Monitoring**

EDR can also offer network traffic and communications monitoring capabilities. In this way, they can detect network-based threats.

**Data Protection and Encryption**

Some EDR solutions can secure data with encryption and protection features.  

EDR solutions are an  important part of organizations' cyber security strategies to gain a  more effective defense and rapid response capability against  cyber-attacks.

### eXtended Detection and Response (XDR)

XDR is a concept that  goes beyond EDR. XDR integrates various security data across the network (such as endpoint, network, cloud) and brings this data together to  provide a more comprehensive threat view. XDR helps analyze and detect  cyber threats from a broader perspective by analyzing data from  different security sources.

XDR solutions typically include the following capabilities:  

**Multiple Data Source Integration**

XDR brings data together  from different sources such as endpoint devices, network traffic, cloud  services, and security logs. This gives organizations a broader  perspective.  

**Threat Correlation and Analysis**

Analyzes data from  different data sources to show how different threats are correlated and  spread. This is often helpful for understanding the entire lifecycle of a threat.  

**Automatic Threat Detection**

XDR solutions detect  abnormal behavior and automatically identify potential threats using  technologies such as artificial intelligence and machine learning.  

**Threat Chain Analysis**

XDR analyzes events and  relationships to examine how a threat progresses and its effects within  the organization. This is important for understanding more complex  threats.  

**Automatic Response Capabilities**

XDR has the ability to  implement automatic responses when it detects threats. This helps  respond to threats quickly without the need for human intervention.  

**Threat Intelligence Integration**

XDR integrates up-to-date threat information from threat intelligence sources and better prepares organizations for potential threats.  

**Incident Management and Analysis**

XDR monitors, analyzes and evaluates different security events in a broad perspective.  

**Comprehensive Reporting**

XDR solutions provide detailed reports and analysis to understand security incidents and threat status.

XDR is an advanced approach that aims to address threats in a more holistic manner by  integrating different security sources. In this way, organizations can  effectively deal with a broader threat landscape.

### Conclusion /Summary

In summary, EDR and XDR  are technological approaches to increase organizations' abilities to  detect and respond to cybersecurity threats. While EDR focuses on  monitoring threats occurring at endpoints, XDR offers a more  comprehensive approach, combining data from different security sources.  Both are important tools for strengthening cybersecurity operations and  countering cyber-attacks more effectively.

In this part of the  training, we have defined what EDR and XDR are and learned about their  capabilities. We will be learning about the “Commonly Used EDR/XDR Products” in the next part of our training.

### Questions

1 - Which approach does the XDR try to extend?

> **Answer:** EDR

## Common XDR/EDR Products

In the digitalizing  world, information security is no longer just about protecting corporate boundaries. It is necessary to detect, evaluate and respond to threats  beyond these borders. In this context, Endpoint Detection and Response  (EDR) and eXtended Detection and Response (XDR) systems come to the  foreground ad they are one of the most advanced systems for defending  against cybersecurity threats and responding to them as well.

Going beyond traditional  antivirus solutions and firewall-type security devices, these systems  increase networks’ capacity to understand and quickly respond to complex threats. Both EDR and XDR tools optimize the effectiveness and speed of security operations while offering a wide range of capabilities from  threat hunting to proactive protection.

In this lesson, we will  talk about the basic information and features of EDR and XDR systems  that are widely recognized and used globally.

### CrowdStrike Falcon

CrowdStrike Falcon is a  cloud-based endpoint detection and response (EDR) platform. It also  offers XDR features. Thanks to its completely cloud-focused structure,  it offers fast deployment and scalability advantages. It provides  comprehensive protection by working through a single light client  software (agent), which minimizes the impact on the endpoint  performance. It is particularly known for its proactive threat hunting  capabilities and extensive threat intelligence network. This provides  organizations with real-time threat information, empowering them to  respond faster and more effectively. It also offers adaptive protection  against unknown threats thanks to its machine learning-based algorithms. CrowdStrike Falcon is suitable for both large-scale organizations and  small businesses, and is considered an EDR solution that stands out in  the industry.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/2/image2-1.png)

[Image Source: https://www.crowdstrike.com/cybersecurity-101/what-is-xdr/](https://www.crowdstrike.com/cybersecurity-101/what-is-xdr/)

### Cybereason

Cybereason is a major  player in the cybersecurity industry and is particularly known for its  endpoint detection and response (EDR) capabilities. It also offers XDR  features. Cybereason is one of the rare solutions that can offer EDR and EPP capabilities on-prem. XDR capabilities are only available on the  cloud platform.

The platform has a system based on artificial intelligence developed to detect, analyze and  respond to cyber threats. This way, organizations can monitor complex  cyber attacks in real time, gain a deeper understanding of threats, and  quickly respond to potential security breaches. Cybereason's  "Operation-Centric" approach enables security professionals to consider  events in a broader context and see the full story of malicious  activity. Cybereason's "Malop" feature is short for "Malicious  Operation" and is a central component of the company's platform. “Malop” is designed to detect threats automatically, visualize and analyze all  components and effects of a malicious operation or attack.

Additionally, the  platform stands out not only for its reactive but also proactive  protection capabilities, so threats can be detected and blocked before  they infiltrate systems.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/2/image2-2.png)

  (Image Source:   [https://www.cybereason.com/platform ](https://www.cybereason.com/platform)  )

### Microsoft Defender for Endpoint

Formerly known as  Microsoft Defender Advanced Threat Protection (ATP), it is a  comprehensive endpoint detection and rResponse (EDR) solution from  Microsoft. However, by expanding Defender ATP overtime and creating  deeper integrations with other security products, Microsoft transformed  its platform into an extended detection and response (XDR) solution and  named it Microsoft 365 Defender. This service, which is fully integrated and built into the Windows operating system, provides advanced  protection against cyber threats. Microsoft Defender uses advanced  algorithms and AI-based analytics to detect complex cyberattacks,  identify their origins, and respond quickly to incidents.

The platform offers  proactive threat hunting capabilities that help identify potential risks and leaks, not just existing threats. Defender ATP's cloud-based  structure ensures that organizations are always protected against the  latest threats with constantly updated threat intelligence.  Additionally, Microsoft Defender for Endpoint can be managed through a  centralized dashboard through Microsoft 365 Security Center, allowing  security professionals to monitor and manage threats more effectively.

To summarize, Microsoft  Defender for Endpoint is a platform that strengthens the cybersecurity  of organizations by providing the tools and capabilities necessary to  tackle the modern threat landscape. Microsoft Defender for Endpoint is  now considered an XDR solution because it provides protection over the  endpoint data, and against potential threats from other sources as well.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/2/image2-3.png)

(Image Source:   [https://www.infusedinnovations.com/blog/secure-intelligent-workplace/budgeting-for-microsoft-defender-xdr-and-zero-trust-security  ](https://www.infusedinnovations.com/blog/secure-intelligent-workplace/budgeting-for-microsoft-defender-xdr-and-zero-trust-security)  )

### Palo Alto Cortex XDR

Palo Alto Cortex XDR is  an extended detection and response (XDR) solution that is a part of Palo Alto Networks' Advanced Cybersecurity Platform. A pioneer in the XDR  category, this platform detects, analyzes and responds to cyber threats  based on many different data sources. It covers a wide range of threat  vectors, from endpoints to networks to cloud services.

Cortex XDR protects  against a complex and ever-changing threat landscape using advanced  artificial intelligence and big data analysis. Unlike classic EDR  solutions, Cortex XDR offers broader and in-depth visibility by  combining information from multiple data sources. This increases the  ability to quickly detect and respond to both known and unknown threats.

The platform is known for its features such as automatic threat hunting, incident response, and  continuous monitoring. It also provides seamless integration with Palo  Alto's other security products and third-party applications, making it  easy to centralize and automate security operations.

To summarize, Palo Alto  Cortex XDR is a comprehensive, extended detection and response platform  designed to help organizations create a more effective and proactive  defense against cyber threats.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/2/image2-4.png)

(Image Source:   https://www.xcitium.com/palo-alto-cortex-xdr/  )

### SentinelOne

SentinelOne XDR is the  extended detection and response (XDR) solution offered by SentinelOne,  one of the leading companies in the cyber security industry. This  platform uses artificial intelligence (AI) and machine learning  technologies to protect companies against both known and unknown  threats.

SentinelOne can detect  and quickly respond to a wide range of threats, starting with endpoints. This combines both static and behavioral analysis to protect against a  broad spectrum of attacks, from malware to zero-day threats.  Additionally, it helps to perform security operations in a simple,  automatic and effective way, with features such as automatic threat  hunting and incident response.

The platform is not only  limited to detection and response, but it also has features such as  automatic attack mapping and incident investigation. This increases the  ability to quickly understand the source and impact of attacks.

Regarding integration,  SentinelOne XDR can easily integrate with other security products and  third-party applications, enabling centralization and strengthening of  security infrastructure.

To summarize, SentinelOne XDR is a leading security platform that helps organizations strengthen  their cybersecurity posture by providing proactive and comprehensive  protection against the modern threat landscape.

In this part of the  training, we have provided a summary about some of the most widely used  EDR/XDR products globally. In the next part of the training, we will be  covering “  **EDR/XDR Installation and Configuration Process**  ”.

### Questions

1 - Which operating systems include Microsoft Defender for Endpoint?

> **Answer:** windows

## EDR/XDR Installation and Configuration Process

**NOTE:** The EDR/XDR application  that will be used in this lesson is “SentinelOne”. The steps specified  may differ for other EDR/XDR solutions.

SentinelOne is one of the leading cybersecurity solutions in the industry and offers both  Endpoint Detection and Response (EDR) and Extended Detection and  Response (XDR) capabilities. However, the installation and configuration processes for such platforms are often quite detailed and may vary  depending on the user's needs, the size of the network, and other  factors.

The first step in the  installation and configuration process of SentinelOne EDR/XDR begins by  entering into a licensing agreement with SentinelOne. After purchasing  the license, you can access the Portal (Management Console) with the  information sent to you by SentinelOne and start using the product.  Since this is a solution that is completely hosted in the cloud  environment, you don’t need to setup any on-prem servers.

After logging in,  SentinelOne starts with a dashboard by default. This dashboard contains  information such as Threats, Infected Systems, Sentinelone Blog Feeds,  Detection Engines where the threats and threat types are detected.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/3/image3-1.png)

### SentinelOne Introduction

After logging into the  SentinelOne interface, you will see the left navigation panel. Let’s go  over the complete interface and navigation menu in detail:

**Dashboard**

"Dashboard" is the main  page where you can see the general information such as general threat  statistics, recent activities, and system health. The dashboard displays a wide range of critical information, from active threats to  quarantined files, from agent status to policy enforcement information.  Graphs that visualize trends in detected threats over time help the user understand the threat landscape. Additionally, summary information on  recent events and alarms allows security professionals to quickly  respond to potential risks. This dashboard enables the organization to  continuously monitor the security status and take proactive measures.

**Visibility**

SentinelOne "Visibility"  feature provides the ability to conduct detailed threat hunting and  incident investigation by thoroughly observing the activities of devices on the network. This feature provides users lots of data on how events  occur, providing in-depth insight into attack vectors, tools used, and  affected systems. The "Visibility" feature helps security professionals  respond to incidents more quickly and effectively, while also enabling  more proactive threat hunting.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/3/image3-2.png)

**Sentinels**

Through the “Sentinels”  menu, you can access pages where you can perform other operations such  as Endpoint Management, Policies, Custom Rules, Blocklists, Exclusions,  Network and Device Control, Agent installation packages and updates, and account information.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/3/image3-3.png)

**Incidents**

The “Incidents” tab  provides a comprehensive summary and analysis of security incidents.  This section identifies, classifies and groups potential security  threats, breach attempts and other suspicious activities automatically.  Using the incidents tab, users can access critical information such as  the source of an incident, the devices it affects, the attack vectors  used, and the overall severity of the incident. It also includes  recommended response actions and automatic response options for each  incident. The "Incidents" menu provides security teams with the ability  to respond to incidents quickly and effectively, strengthening the  organization's security posture against threats.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/3/image3-4.png)

**Applications**

Through the  “Applications” tab, administrators can see detailed information about  the software applications running in their network. This section is  critical for tracking the general health, security status, version  information of the applications, and if they are vulnerable to any  threats. The information provided in the “Applications” tab is critical  to identify and manage potential security risks.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/3/image3-5.png)

**Activity**

The "Activity" menu is  where all activities occurring on the system (threat responses, updates, user actions, etc.) are recorded and accessed. It also tracks a wide  range of activities, from log and file transactions to system changes,  from network traffic to application behavior. Users can research and  access details of events that occurred during a specific time period or  on a specific device. This offers a proactive approach to detect  possible security breaches or suspicious behavior. The "Activity" menu  provides security teams with in-depth visibility, increasing the  capacity to identify and analyze potential threats at an early stage.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/3/image3-6.png)

**Reports**

You can create one-time  or periodic reports according to different criteria and review these  reports through the “Reports” tab. Administrators and security teams  with access to the “Reports” tab has the ability to access and compile  many different types of reports, such as threat summaries, agent status  reports, compliance status reports, detailed incident analysis reports,  and etc. Customizable reporting features allow you to filter and  visualize information for a specific time period, region, device group  or threat type. This helps organizations periodically assess their  security posture, present information to senior management or other  stakeholders, and develop proactive security strategies.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/3/image3-7.png)

**Settings**

Management console  settings, user management, notification settings, syslog settings and  other system settings are located in this section.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/3/image3-8.png)

### SentinelOne First Configuration

After accessing the SentinelOne account you should follow the below steps to configure your tool effectively:  

### Identify Sites or Groups:

SentinelOne is a solution that supports multi-tenant structure. You can create multiple Sites and multiple groups under these Sites within your SentinelOne account. One  of the first steps to be taken is to determine the sites and groups that properly describe your network. Sites or Groups may have different  policies, different inclusions or exclusions, different access  permissions, different notification methods, reporting, and etc.

The order is “Account > Site > Groups”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/3/image3-9.png)

For example, if you have  an international organization, it may have branches in different  countries, and each country location may have its own branches,  accounting, sales, and IT teams, etc. There may be different sections.  Below is a simple table representing such a structure:

  

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/3/edr-table-1.png)

### Set Policies:

In order to avoid  unexpected issues before installing the SentinelOne agent, it would be  helpful to determine the correct policies beforehand. We can make  SentinelOne policies separately for the Account, Site or Groups. Changes that will be made in the upper hierarchical groups (accounts or sites)  will also be active in the sites or groups below. You can optionally  customize the policies of the sites or groups. You can access the policy window via “SentinelOne > Account/Site/Group > Sentinels >  Policy”.

Policy Settings are configured under the titles we mention in detail below.  

### Protection Mode

SentinelOne basically  divides threat types into two: “Malicious Threat” and “Suspicious  Threat”. “Detect” or “Protect” actions can be applied for these threat  types. Additionally, SentinelOne has various “Detection Engines” to call an event Malicious Threat or Suspicious Threat. Now let's go into some  details about these concepts.  

- **Malicious Threat:** A threat or activity that the SentinelOne algorithm definitively identifies as malicious. Items  tagged as malicious may be files, URLs, or processes that exhibit known  harmful behavior or characteristics. These threats should generally be  automatically quarantined and blocked because they can have potentially  harmful consequences when active on an endpoint.
- **Suspicious Threat:** An activity or element of the SentinelOne algorithm that may be potentially malicious, but cannot be definitively identified as malicious. Suspicious tags are often  associated with files or processes that display new or unknown behavior  but have not yet been fully identified as malicious. Automated actions  for suspicious items are generally more moderate and may require a more  in-depth review from a security expert.  
- **Detected Mode:** In this mode, the  platform detects threats and monitors them, but does not intervene  automatically, which does not prevent it from running or quarantine it.  It is often used during the initial phase of a new SentinelOne  implementation so that the system administrators can evaluate how the  platform is performing and monitor for potential false positives.  
- **Protect Mode:** With this mode, it  automatically blocks and/or quarantines malware and behavior. When  threats are detected, action is taken automatically.
- **Kill & Quarantine:** Kill is the action of  terminating an actively running malicious process. It is used to stop  the activity of malware instantly. It isolates a malicious or suspicious file. When this happens, this file will not be able to interact with  other system components, its potentially malicious effects gets blocked.  
- **Remediate:** This function repairs the damage caused by the threat. For example, if a malware changes system  settings, adds users to the system, etc. This function allows reverting  to the original settings.
- **Rollback:** This function rolls back  the changes caused by a threat, allowing the device to return to its  pre-threat state. It is especially effective against ransomware attacks. If a ransomware encrypts files, it may be possible to roll back these  files to their state before they were encrypted, thanks to the  "Rollback" function. It is a feature that can only be used on Windows  operating systems. To achieve this, it uses Windows' shadowcopy service.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/3/image3-10.png)

### Agent

There are a number of  policies that ensure the security of the SentinelOne agent on the  endpoints where it is installed. Here are some of them:  

- **Anti Tamper:** The ability to prevent  the SentinelOne agent from being modified, disabled or removed by  unauthorized users. This feature is designed to prevent malware or  attackers from disabling protection mechanisms. It is generally  protected by an authorization mechanism controlled through the  “uninstaller.exe” provided by the manufacturer or the central management console.  
- **Snapshots:** “Snapshots” are taken by  SentinelOne to keep track of changes to a system. It is used to get a  detailed view of what happened when a threat is detected or a system  event occurs. These snapshots are critical, especially for the ability  to rollback changes caused by a threat. It is a feature that can only be used on Windows operating systems. To achieve this, it uses Windows'  shadowcopy service.  
- **Logging:** SentinelOne can create  detailed logs about system events, threat detections and agent  activities. These logs are extremely valuable for security analysis,  incident response, and auditing needs. Administrators can configure what information is logged and how long these logs are retained.  
- **Scan New Agents:** This feature determines  when and how to first scan a device where a new SentinelOne agent has  been installed. This feature is important for running a full system scan at startup to identify any potential threats present and create a clean starting point.  

You can also set the activities you want to display on the endpoint (notifications, etc.) via the policy screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/3/image3-11.png)

### Deep Visibility

SentinelOne's Deep  Visibility feature allows detailed monitoring of activities occurring in systems to support threat hunting and incident response processes. This feature can save a very large set of data, but exactly which data types it saves may vary depending on the configuration and the version used.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/3/edr-table-2.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/3/image3-12.png)

This table is a  representative summary of SentinelOne's Deep Visibility feature and may  not apply to a particular SentinelOne version or configuration. It is  recommended that you consult SentinelOne's official documentation and  resources for the most up-to-date and detailed information.  

### More Options

SentinelOne's  "Decommissioning" capability allows an agent to be permanently removed  from the SentinelOne platform. Decommissioning is often required when a  device is retired or removed from the organization. If you wish,  SentinelOne can perform this process automatically for endpoints that  are offline on a certain day.

Finally, when you  activate the “Remote Shell” option from the policy, you can access the  relevant endpoints remotely from the command line with administrator  rights. This is access to Powershell on Windows and bash shell on *Nix  systems.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/3/image3-13.png)

### Identify Exclusions

Although this screen is  not under the Policy menu in the current version, it has been added  under this topic because it affects the functioning of the system.

Necessary exclusions must be defined before the agent installation through the   **SentinelOne > Account/Site/Group > Sentinels > Exclusions**   menu.

You can apply exclusions  on this screen manually or from the catalog (the screen where you can  directly select ready-made 3rd party applications).

You can create a new  exclusion by selecting “New Exclusion” > “Create Exclusion” on the  relevant screen. Here you can define exclusions based on the Hash, the  Path, the Certificate, the File Type and the Browser.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/3/image3-14.png)

### Conclusion /Summary

The SentinelOne  installation and configuration process is critical to ensuring  protection against modern cyber threats. This process stands out to  ensure the effective and precise operation of the SentinelOne platform.  Successful installation and configuration allows organizations to  effectively deal with cyber threats, detect malicious activity in real  time and take necessary interventions quickly.  

In this part of the  training, we have covered the installation and configuration of a sample EDR/XDR product via SentinelOne. In the next part of the training, we  will be learning about the “  **Management of Endpoints with EDR/XDR**  ” topic.

### Questions

1 - What is SentinelOne's "Deep Visibility" feature typically used for?

> **Answer:** threat hunting

2 - What is the mode in which Sentinel One automatically blocks and/or quarantines malware and behavior?

> **Answer:** Protect Mode

3 - What is the Sentinel One function that reverts the changes caused by a threat, returning the device to its pre-threat state?

> **Answer:** Rollback

## Managing Endpoints with EDR/XDR

EDR and XDR technologies  play a critical role in our battle against modern threats in  cybersecurity. The effectiveness of these solutions relies heavily on  solid endpoint management. Here are some important criteria regarding  the importance of endpoint management for EDR/XDR:  

**Deployment**

Particularly for  large-scale organizations, one must decide how to deploy EDR/XDR agents  across multiple devices. This can be accomplished through manual  installation, group policy, or remote deployment tools (SSCM, etc.).  Your solution's agent must be downloaded and installed on the target  device. This agent monitors the behavior of the device and helps detect  abnormal or harmful activities.  

**Visibility**

EDR/XDR solutions provide full visibility over all endpoints in the network. This refers to the  capacity to understand the state of each device, the security policies  implemented, and the processes running on the device. Endpoint  management ensures this visibility is continuous and consistent.  

**Threat Detection**

Modern threats are  constantly evolving and becoming more complex. Endpoint management  allows potential threats to be quickly identified. Each device can be a  threat vector on the network; therefore, knowing and managing each is  critical.

**Response and Response**

EDR/XDR solutions can  detect threats as well as respond to them in real time. However, this is possible with effective endpoint management. For example, it may be  necessary to isolate the affected device to prevent the spread of  malware.  

**Policy and Updates**

Endpoint management  ensures that established security policies are correctly deployed to all devices. It also allows security software and operating systems to be  kept constantly updated.  

### SentinelOne Endpoint Management

SentinelOne is a  cybersecurity solution that incorporates endpoint detection and response (EDR) capabilities. This platform monitors and protects devices through a software component called SentinelOne Agent.

You can view and manage existing endpoints through:

**“SentinelOne > Account/Site/Group > Sentinels > Endpoints”**   menu on the SentinelOne Platform.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/4/image4-1.png)

After selecting an  endpoint, you can access many different actions you can take regarding  the relevant endpoint by clicking on the "Actions" menu. You can star  the ones you use frequently, etc. You can find the most frequently used  action menu in the table below:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/4/man-edr-table.png)

Below you can see a sample screenshot of the “Actions” options.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/4/image4-2.png)

### SentinelOne Endpoint Agent Install

Installation package and token information is required to install SentinelOne agent on an endpoint.

You can access the SentinelOne agent installation package via the:

**“SentinelOne > Account/Site/Group > Sentinels > Packages”**   menu in the interface. On this window, you can apply a filter for the operating system ( i.e.  Windows, Linux, MacOS) you are looking for a package. You can also  access token information for the relevant site on the same screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/4/image4-3.png)

The relevant installation package is downloaded to the endpoint where the installation will be  implemented. The installation package is run with admin rights and after the token information is input, click on the "Install" button. After  installation, the endpoint must be rebooted so that all engines can  actively monitor all processes. After installation, you can see the  relevant endpoint in the “Sentinels > Endpoints” section on the  SentinelOne interface.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/4/image4-4.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/4/image4-5.png)

After installation, you can see the details by opening the “SentinelOne Agent” application on the endpoint.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/4/image4-6.png)

### Sentine lOne Endpoint Agent Uninstall

In accordance with  SentinelOne security policy, the "Anti tamper" feature is active by  default. This is the feature, that prevents the users from disabling the endpoint security agent from the endpoint without permission.  Administrators can uninstall the SentinelOne agent by following the  steps below:

SentinelOne agent is  removed from the relevant endpoint by sending the command “Sentinels  > Endpoint > Select the relevant endpoint > Actions >  Uninstall” via the SentinelOne interface.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/XDR-EDR+Basics/4/image4-7.png)

### Conclusion /Summary

In conclusion,  SentinelOne brings together the management and protection of endpoints,  providing organizations with effective security across a complex threat  landscape. Having such comprehensive endpoint protection is critical,  especially in this era where modern threats are constantly evolving.  SentinelOne offers a platform that allows all these operations to be  performed via the central console.  

In this part of the  training, we have covered an endpoint management with a sample EDR/XDR  product via SentinelOne is discussed. The next part of the training will be about the “  **Data Collection and Log Integration for XDR**  ” topic.

### Questions

1 - What is the name of the action that isolates the file?

> **Answer:** quarantine

2 - What is the action of terminating a running process called?

> **Answer:** kill

## Data Collection and Log Integration for XDR

While Extended Detection  and Response (EDR) systems enable extended threat detection and  response, they base much of these capabilities on the information they  collect from a wide variety of data sources. In this context, data  collection and log integration for XDR is of critical importance.  Followings are some of the important points on the data collection and  log integration of the extended detection and response tools.

### Data Sources

**Network Traffic Information**

Network traffic is a  critical data source for detecting abnormal behavior. Information from  IDS/IPS systems, network traffic logs, NetFlow data, and other network  monitoring tools are included in this category.  

**Endpoint Data**

EDR systems provide  detailed information about operating system events, processes, file  activities and other endpoint activities.  

**Application Logs**

Logs produced by applications are especially important to gain insight into targeted attacks or malware activities.  

**Cloud Services Logs**

Many organizations are  migrating to cloud infrastructure, including cloud-based applications  and services. Logs from these services expand XDR's threat detection  capability.  

**Email Logs**

Email logs can help detect phishing attacks, malicious attachments, or other cyber threats.

**Sandboxing & Malware Analysis**

Dynamic analysis of suspicious files or URLs can help us understand the nature and behavior of threats.

 **Threat Intelligence**

Threat intelligence  received from external sources, known malicious IPs, domains, file  hashes, etc. It provides information about and increases detection  capability.  

Information from these  data sources is analyzed by XDR platforms and aggregated to detect  potential threats, abnormal behavior or security breaches. With proper  integration and normalization, these data sources can greatly improve  organizations' cybersecurity postures.

### Log Integration

**Automated Integration**

Most modern XDR solutions offer automatic log integration with popular security products, network devices, and cloud services. These integrations are usually  accomplished through APIs. It is the best way to increase the  effectiveness of XDR systems. This integration enables the XDR platform  to automatically collect and analyze information from data sources. This helps security teams detect threats faster and more accurately, without having to manually collect and analyze logs.  

**Customized Integration**

For custom applications  or custom configured systems, XDR platforms typically support manual  integrations via APIs or customized log senders. Manual integration is  not as efficient as automatic integration, but may be necessary in  special cases. For example, if a security product that your organization is using is not supported by your XDR platform, you may need to  manually integrate its logs.

### Data Enrichment, Storage and Querying

The data collected is  often enriched with additional sources such as threat intelligence  databases, geographic IP information, or user credentials. In this way,  more in-depth analysis, fewer false positives and the ability to respond faster become possible. Ultimately, the effectiveness of XDR depends on the quality of the data collected and how it is enriched.

XDR solutions provide  scalable data storage solutions for storing often large amounts of log  and event data. It also allows for quick and efficient querying of this  data, which is critical for proactive threat hunting and incident  investigation. XDR solutions offer the appropriate infrastructure for  its data storage and handling. For example, Crowdstrike Falcon XDR  maintains and manages its data on the Humio infrastructure.  

### Conclusion/ Summary

In summary, XDR systems  are designed to detect cyber threats earlier and more accurately. These  systems collect information from a wide variety of data sources and  analyze it to detect potential threats. Log integration can greatly  increase the effectiveness of XDR systems. Therefore, when choosing XDR  systems, it is important to ensure that they support all the data  sources your organization needs.  

We have covered data  sources, log integration, data enrichment, data storage and data query  options in this part of our training.

### Questions

1 - From which sources are intelligence data such as known malicious IP addresses and domains provided to EDR/XDR solutions?

> **Answer:** Threat Intelligence









































































