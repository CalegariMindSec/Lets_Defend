# Threat Hunting with CTI

In the "Threat Hunting with CTI" course, you'll delve into the practical  application of Cyber Threat Intelligence to proactively identify and  mitigate potential threats. The course offers hands-on tutorials,  providing you with the techniques and tools needed to effectively hunt  for threats before they materialize into incidents.

This course is designed for security professionals eager to expand their  knowledge in threat detection. You'll explore real-world scenarios,  harnessing CTI to anticipate and counteract cyber threats efficiently.  Whether you're new to the field or strengthening your existing skills,  this course will guide you through every essential step of the threat  hunting process.

**Table of content:**

- Introduction

- CTI Resources
- Threat Hunting Process with CTI
- Phishing Campaign Hypothesis
- Practical Lab-1
- Practical Lab-2
- Practical Lab-3

## Introduction

Cyber Threat Intelligence (CTI) refers to the information collected,  evaluated, and analyzed about cyber threats. It includes how, where, and by whom cyber attacks are carried out, the targets of the attacks, and  the techniques used. CTI helps security teams make informed decisions  about cyber threats, develop defense strategies, and respond more  effectively to cybersecurity incidents.

### Use of CTI

- **Threat Hunting:** CTI is used in threat hunting processes to help identify potential threats. Cybersecurity teams use CTI data to investigate suspicious activities  and identify threats.

- **Security Operations Center (SOC):** SOC analysts use CTI data to monitor and analyze daily security incidents.  Thus, it enables analysts to detect and respond to threats quickly.

- **Malware Analysis:** CTI is used in the analysis and detection of malware. Analysts use CTI data to understand the behavior and propagation methods of malicious  software.

- **Security Policies and Strategies:** CTI contributes to the development of security policies and strategies. By  providing information about the nature and scope of threats, it ensures  that policies are more effective.

- **Risk Assessment:** CTI is used in the assessment of cyber risks. Integrated into risk  management processes, it helps understand the potential impact and  likelihood of threats.

- **Attack Surface Analysis:** CTI helps organizations analyze their attack surface and identify weak  points. This enables the mitigation of vulnerabilities and the  improvement of defense measures.

This lesson has introduced the CTI and its use. The next lesson will introduce and cover "**CTI Resources**".

## CTI Resources

Cyber Threat Intelligence (CTI) resources are critical for detecting and analyzing cyber threats  and developing defense strategies against them. CTI resources include  information obtained from various sources such as open-source  intelligence (OSINT), commercial CTI providers, dark web intelligence,  and threat intelligence sharing networks (ISACs). These resources  provide cybersecurity teams with up-to-date and accurate threat  information, helping them prevent potential attacks and respond to  incidents more quickly. In this lesson, different CTI resources and  their roles in the threat hunting process will be discussed.

### Open Source Intelligence (OSINT)

Open Source Intelligence  (OSINT) is the process of creating threat intelligence using information collected from publicly available sources. It includes data and  documents freely accessible on the internet.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+with+CTI/2.CTI+Resources/image2_1.png)

(**Image Source**: https://www.linkedin.com/pulse/osint-top-15-open-source-intelligence-tools-securetriad/)

### Objectives of OSINT

- **Information Gathering:** To collect information from various open sources to gain a comprehensive understanding of threat actors.  
- **Analysis and Evaluation:** To analyze collected information to assess potential threats.  
- **Early Warning:** To provide early warnings about potential threats and develop security measures.  

### Workflow of OSINT

- **Source Identification:** Identifying reliable and relevant sources on the Internet.  
- **Data Collection:** The process of collecting data from identified sources can be manual or automated.  
- **Data Analysis:** Analyzing the collected data and transforming it into meaningful information.  
- **Reporting:** Reporting the results of the analysis and presenting them to the relevant parties.  

### Sources of OSINT

- **Social Media:** Data from platforms like Twitter, Facebook, and LinkedIn.  
- **Blogs and Forums:** Blogs by security researchers and cybersecurity forums.  
- **News Websites:** Current news about cyberattacks and threats.  
- **Official Publications:** Reports and announcements by government and security organizations.  

### Advantages of OSINT

- **Accessibility:** Freely accessible information provides access to a wide range of data sources.  
- **Cost-Effectiveness:** Threat intelligence is obtained using free or low-cost information sources.  
- **Diversity:** Data from diverse sources enables comprehensive and multifaceted analysis.  

### Disadvantages of OSINT

- **Lack of Accuracy and Reliability:** It can be challenging to verify the accuracy and reliability of information from open sources.  
- **Data Overload:** Large volumes of data can make it difficult to distinguish meaningful information.  
- **Issues of Privacy and Ethics:** Privacy and ethical guidelines must be followed during the information-gathering process.  

In summary, Open Source  Intelligence (OSINT) provides a broad and accessible source of  information about cyber threats. When used with the right sources and  analysis methods, OSINT supports cybersecurity strategies and plays a  significant role in detecting threats.

### Commercial CTI Providers

Commercial CTI providers  are organizations that offer paid services to deliver comprehensive  threat intelligence. Providers analyze data collected from various  sources and present it to their clients.  

### Objectives of Commercial CTI Providers

- **Professional Service:** To provide clients with high-quality and verified threat intelligence.  
- **Risk Mitigation:** To help clients reduce cybersecurity risks.  
- **Incident Response:** To provide necessary information for quick and effective responses to cybersecurity incidents.  

### Workflow of CTI Products

- **Data Collection:** Data collection from multiple sources (open sources, dark web, specialized databases).  
- **Analysis:** Analysis of data by advanced analysis tools and expert analysts.  
- **Reporting and Notification:** Reporting of analysis results to clients.  
- **Integration:** Automation of threat data processing through integration with systems such as SIEM and EDR.  

### Commercial CTI Sources

- **Threat Intelligence Platforms:** Platforms like MISP, ThreatConnect, and Anomali.  
- **Security Companies:** Companies like FireEye, CrowdStrike, and Recorded Future.  
- **Special Reports and Analysis:** Reports on specific threats and attack campaigns.  

### Advantages of Commercial CTI Sources

- **High Quality:** It offers verified and high-quality threat intelligence with analysis.  
- **Time-Saving:** It eliminates the need for clients to collect and analyze data themselves.  
- **Expert Analysis:** It provides in-depth analysis and recommendations provided by security experts.  

### Disadvantages of Commercial CTI Sources

- **Cost:** Commercial CTI services are often expensive.  
- **Privacy Issues:** Clients must ensure the confidentiality of shared information.  
- **Dependency:** Clients may become overly reliant on commercial providers for their security strategies.  

In summary, Commercial CTI providers offer in-depth knowledge and analysis, enhancing  organizations' security capabilities. These services are particularly  critical for organizations facing large-scale and targeted attacks.

### Dark Web Intelligence

Dark Web Intelligence  refers to threat intelligence obtained from activities conducted in the  hidden and restricted areas of the internet (dark web). The dark web is a hub for cybercriminal activities, where transactions are anonymous and  difficult to trace.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+with+CTI/2.CTI+Resources/image2_2.png)

(**Image Source**: https://www.hawk-eye.io/2020/12/dark-web-and-threat-intelligence-darkint/)

### Objectives of Dark Web Intelligence

- **Monitoring Cybercrime:** Monitoring and analyzing cybercriminal activities on the dark web.  
- **Preventive Measures:** Using information from the dark web to take preventive measures against potential threats.  
- **Incident Response:** Quickly detect threats on the dark web and respond to incidents.  

### Workflow of Dark Web Intelligence

- **Access and Monitoring:** Accessing the dark web and collecting data from various sources.  
- **Data Collection:** Collecting data from dark web marketplaces, forums, and other sources.  
- **Analysis:** Analyzing collected data to extract meaningful insights.  
- **Reporting:** Reporting findings and presenting them to relevant teams.  

### Dark Web Intelligence Sources

- **Dark Markets:** Platforms where malware, stolen data, and counterfeit documents are sold.  
- **Hacker Forums:** Platforms where attackers share information and collaborate.  
- **Dark Web Search Engines:** Specialized search engines for finding information on the dark web.  

### Advantages of Dark Web Intelligence

- **Early Warning:** It provides early warnings about activities on the dark web, enabling preparedness for potential threats.  
- **In-Depth Knowledge:** It offers detailed insights into cybercriminal activities.  
- **Preventive Measures:** It enables proactive preventive measures based on dark web intelligence.  

### Disadvantages of Dark Web Intelligence

- **Access Challenges:** Accessing and collecting data from the dark web requires technical expertise and specialized tools.  
- **Lack of Reliability:** Ensuring the accuracy and reliability of collected information can be challenging.  
- **Privacy and Legal Issues:** Privacy and legal concerns may arise during the information-gathering process.  

In summary, Dark Web Intelligence plays a critical role in the early detection and prevention of cybersecurity threats. Monitoring and analyzing activities on the  dark web strengthens organizations' cybersecurity strategies and  prepares them for potential threats.

### Threat Intelligence Sharing Networks (ISACs)

Information Sharing and  Analysis Centers (ISACs) are organizations established to facilitate threat intelligence sharing and collaboration among specific sectors or  regions. ISACs encourage trusted information exchange among members, creating a collective defense mechanism against cyber threats.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+with+CTI/2.CTI+Resources/image2_3.png)

(**Image Source**: https://www.anomali.com/blog/the-power-of-active-collaboration-in-isacs-isaos-and-security-interest-groups)

### Objectives of ISACs

- **Information Sharing:** They facilitate the sharing of information about cyber threats, vulnerabilities, and attack techniques among members.  
- **Analysis and Evaluation:** They analyze collected information to produce sector-specific threat assessments and reports.  
- **Defense Strategies:** They develop tailored security recommendations and defense strategies for members.  
- **Incident Response Support:** They provide support and guidance to members during cybersecurity incidents.  

### Workflow of ISACs

- **Membership:** ISACs are typically sector-based and accept organizations from specific industries as members.  
- **Information Collection and Distribution:** ISACs collect threat information from members and various sources, analyze it, and distribute it back to members.  
- **Collaboration and Coordination:** They encourage collaboration among members, coordinate information sharing, and develop joint defense strategies.  
- **Training and Awareness:** ISACs organize training programs, workshops, and awareness campaigns for members.  

### Examples of ISACs

- **Financial Services ISAC (FS-ISAC):** Threat intelligence sharing for the financial sector.  
- **Health Information Sharing and Analysis Center (H-ISAC):** Threat intelligence sharing for the healthcare sector.  
- **Automotive Information Sharing and Analysis Center (Auto-ISAC):** Threat intelligence sharing for the automotive sector.  
- **Energy Information Sharing and Analysis Center (E-ISAC):** Threat intelligence sharing for the energy sector.  

### Advantages of ISACs

- **Early Warning:** ISACs provide early warning of emerging threats across the industry.  
- **Collective Defense:** ISACs enable you to develop stronger and more coordinated defense strategies through information sharing.  
- **Resource Efficiency:** You can use security resources more efficiently through information sharing and collaboration.  
- **Increased Trust:** You can increase security awareness and collaboration across the industry.  

### Disadvantages of ISACs

- **Lack of Trust Between Partners:** Building trust among members for information sharing might be challenging.  
- **Data Privacy:** Ensuring the confidentiality and proper use of shared information might be challenging.  
- **Coordination Challenges:** Facilitating coordination and collaboration among different organizations.  

Threat Intelligence  Sharing Networks (ISACs) play a critical role in sector-specific  cybersecurity. By promoting trusted information sharing among members,  ISACs create a collective defense mechanism against cyber threats. Networks enhance the cybersecurity capabilities of sectors and provide a more resilient defense.

This lesson has covered  OSINT, commercial CTI providers, dark web intelligence, and threat  intelligence sharing networks (ISACs). The next lesson will introduce  and explain **"Threat Hunting Process with CTI"**.

## Threat Hunting Process with CTI

Cyber Threat Intelligence (CTI) provides critical information for detecting, analyzing, and responding to threats, while threat hunting processes proactively search for potential threats using this information. It plays a vital role in every stage of the threat hunting cycle, from hypothesis creation to  uncovering new threat patterns.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+with+CTI/3.Threat+Hunting+Process+with+CTI/image3_1.png)

  **(Image Source:** https://www.researchgate.net/figure/The-Threat-Hunting-Loop_fig2_344319370**)**

### Create Hypotheses

CTI plays a significant role in creating hypotheses during the threat hunting process. At this stage, it contributes in the following ways:

- **Threat Indicators (IOCs):** CTI provides threat  indicators such as malware signatures, malicious IP addresses, and  domains. These indicators serve as foundational information for creating hypotheses.  
- **Information on Threat Actors:** CTI offers insights into the motivations, capabilities, and targets of specific threat actors. These insights are used to develop hypotheses about how and why  potential threats might occur.  

### Investigate With Tools and Techniques

  CTI provides critical information for the tools and techniques used during the investigation phase. At this stage, CTI offers:

- **Threat Intelligence Integration:** CTI data is integrated into SIEM, EDR, and other security tools to support the threat hunting process.  
- **Advanced Analysis Techniques:** CTI enables deeper  analysis of threats. For example, understanding how specific malware  operates and spreads allows this information to be used in analysis  processes.  
- **Threat Detection and Monitoring:** CTI provides  information on specific threat indicators (IOCs) and attack methods  (TTPs), making it easier for security tools to detect and monitor  threats.  

### Uncover New Patterns and TTPs

  CTI plays a key role in uncovering new threat patterns and attack techniques (TTPs). At this stage, CTI's offers:

- **Data Enrichment:** CTI enriches existing data, enabling the discovery of new threat patterns and TTPs.  
- **Anomaly Detection:** CTI helps identify deviations from normal behavior patterns and anomalies, leading to the identification of new threat patterns.  
- **Continuously Updated Information:** CTI provides up-to-date information on the evolving tactics and techniques of threat actors.  This information helps threat hunters detect new threats more quickly.  

### Inform and Enrich Analytics

  CTI plays a critical role in informing and enriching analytics during the threat hunting process. At this stage, CTI offers:

- **Providing Contextual Information:** CTI helps understand  threats in a broader context. For example, it provides information not  only about a malware file name but also about the threat actor group  using it.  
- **Data Correlation:** Comparing information from multiple data sources with CTI data accelerates the detection of anomalies and threats.  
- **Incident Validation:** CTI data is used to validate detected incidents. For instance, when a security event matches an IOC in the CTI database, the event is verified.  

### Summary

CTI is essential in all  threat hunting stages. From hypothesizing to uncovering new threat  patterns, the information and analysis provided by CTI helps  cybersecurity teams detect and respond to threats more effectively.

This lesson has discussed the importance of CTI in each step of the threat hunting cycle. The next lesson will cover the "**Phishing Campaign Hypothesis**".

## Phishing Campaign Hypothesis

### Hypothesis

There may be a targeted phishing campaign against the employees of your  organization. The campaign could be aimed at stealing employee  credentials, accessing financial information, or installing malware.

### Data Sources

- **Cyber Threat Intelligence (CTI) Platform:** It collects and analyzes information about security threats.
- **Threat Intelligence Feeds:** They provide information on known email addresses, URLs, and IP addresses used in phishing campaigns.
- **SIEM System:** It is a tool for collecting and analyzing logs and security events.
- **Email Gateway Logs:** It monitors incoming and outgoing email traffic.
- **Web Proxy Logs:** It tracks users' internet access records.
- **Endpoint Detection and Response (EDR) Logs:** It monitors endpoint device activities and detects abnormal behavior.
- **User and Entity Behavior Analytics (UEBA):** It analyzes user and entity behavior to identify anomalies.

### Analysis Steps

- Collect logs from SIEM, email gateway, web proxy, and EDR systems.
- Gather data about phishing campaigns from the CTI platform and threat intelligence feeds.
- Compare logs with information from the CTI platform and feeds.
- Match logs with known phishing email addresses, URLs, and IP addresses.
- Identify techniques used in phishing campaigns (e.g., fake websites, phishing  emails) and search for traces of these techniques in the logs.
- Detect emails from known phishing email addresses in email gateway logs.
- Check web proxy logs for user access to phishing URLs.
- Identify abnormal activities on devices of users exposed to phishing attacks in EDR logs.
- Analyze the content of phishing emails and identify social engineering techniques.
- Analyze user behavior to identify users who clicked on phishing emails or accessed fake websites.
- Use UEBA to detect unusual user behavior and potential account compromise attempts.
- Forward detected suspicious emails and web access incidents to the incident response team.
- The incident response team analyzes the details of the phishing campaign and identifies targeted users.
- Based on the findings, isolate affected accounts and devices to prevent further damage.

### Expected Outcomes

- Details and techniques of the targeted phishing campaign will be identified.
- Phishing emails sent during the campaign and fake websites accessed by users will be determined.
- Suspicious behavior and potential account compromise attempts will be detected,  and relevant users will be informed while necessary measures are taken.
- By correlating with CTI data, phishing attacks can be detected earlier and proactive measures can be taken quickly.

### Summary

This hypothesis outlines steps for detecting phishing campaigns on the  network using CTI. In order to strengthen the company's security posture and prevent potential phishing attacks, these steps are critical.

## Practical Lab-1

### Hypothesis-1

**Note:** The questions in this section are designed for threat hunting based on the following hypothesis.

**Hypothesis:** Attackers may use social engineering techniques to deceive employees and deploy malware.

### Threat Hunting Lab Environment

- **Company Name:** RiverKids
- **Company Domain:** riverkidscorp.com
- CTI Events ([Threat Intel LetsDefend Platform](https://app.letsdefend.io/threath-intelligence-feed))
- Email Security ([LetsDefend Platform](https://app.letsdefend.io/email-security))
- SIEM (Wazuh)
- EDR Events (Sysmon)
- Firewall Traffic Events

### Lab Notes

- Analyze the logs between "Aug 1, 2024 00:00 - Aug 7, 2024 00:00" to answer the questions below.
- Subsequent questions require correct answers from previous ones. **Answer all questions strictly in the order they appear.**

### Questions

**Note:** Analyze the logs between "Aug 1, 2024 00:00 - Aug 7, 2024 00:00" to answer the questions below.

**Note:** Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

1 - According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)), what domain was registered with a name similar to the company?

> **Answer:** riverkidscompany.com

2 - According to the email security platform ([LetsDefend - Email Security](https://app.letsdefend.io/email-security)), what is the recipient email address of the email sent to company staff from the domain similar to the company's name?

> **Answer:** mike@riverkidscorp.com

3 - According to the email security platform ([LetsDefend - Email Security](https://app.letsdefend.io/email-security)) what is the sender's email address of the email sent to company staff from the domain similar to the company's name?

> **Answer:** support@riverkidscompany.com

4 - According to the email security platform ([LetsDefend - Email Security](https://app.letsdefend.io/email-security)), what action was taken for the email sent to company staff from the domain similar to the company's name?

> **Answer:** Allowed 

5 - According to the email security platform ([LetsDefend - Email Security](https://app.letsdefend.io/email-security)), what domain is included in the email sent to company staff from the domain similar to the company's name?

> **Answer:** supportcenter.login.vpnccloudd.io

6 - According to the Threat Intel ([LetsDefend](https://app.letsdefend.io/threath-intelligence-feed)) source, what is the category (TAG) of the domain included in the email  sent to company staff from the domain similar to the company's name?

> **Answer:** phishing

7 - What is the IP address of  the endpoint attempting to access the domain included in the email sent  to company staff from the domain similar to the company's name?

> **Answer:** 192.168.16.54

8 - What process on the  endpoint, identified in the previous question, sent the DNS request for  the domain mentioned in the email that was sent to company staff from  the domain resembling the company’s name?

Answer Format: office.exe

> **Answer:** outlook.exe

9 - What is the IP address of the URL contained in the email sent to company  staff from the domain detected as similar to the company name?

> **Answer:** 111.222.111.222

10 - What is the action taken  for the access attempt to the IP address of the URL contained in the  email sent to company staff from the domain detected as similar to the  company name?

> **Answer:** deny

## Practical Lab-2

### Hypothesis-2

**Note:** The questions in this section are designed for threat hunting based on the following hypothesis.

**Hypothesis:** Published indicators of compromise (IoCs) associated with the APT-ENR-88 group  that targets the energy sector may be present in system events.

### Threat Hunting Lab Environment

- **DMZ Server IP Block**: 172.16.8.0/24
- CTI Events ([Threat Intel LetsDefend Platform](https://app.letsdefend.io/threath-intelligence-feed))
- SIEM (Wazuh)
- EDR Events (Sysmon)
- Firewall Traffic Events

### Lab Notes

- Analyze the logs between "Aug 1, 2024 00:00 - Aug 7, 2024 00:00" to answer the questions below.
- Subsequent questions require correct answers from previous ones. **Answer all questions strictly in the order they appear.**

### Questions

**Note:** Analyze the logs between "Aug 1, 2024 00:00 - Aug 7, 2024 00:00" to answer the questions below.

**Note:** Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

1 - According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)), how many different IoCs of the "APT-ENR-88" group were published?

> **Answer:** 3

2 - According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)), what is the IP address of the system that communicated with the IP address listed in the IoCs of the "APT-ENR-88" group?

> **Answer:** 192.168.123.123

3 - According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)) what was the name of the process that communicated with the IP address  listed in the IOCs published regarding the group APT-ENR-88?

**Answer Format:** tester.exe

> **Answer:** netapp0.exe

4 - According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)), what is the IP address of the system where the hash (listed in the IOCs for threat group 'APT-ENR-88') was detected?

> **Answer:** 192.168.123.123

5 - According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)), what is the name of the process in the event where the hash listed in the IoCs of "APT-ENR-88" group was detected?

**Answer Format:** D:\\Apps\\sales\\test.exe

> **Answer:** C:\\Program Files\\App\\app0.exe

6 - According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)), what is the firewall action for the access logs related to the IP address listed in the IoCs of the "APT-ENR-88" group?

> **Answer:** Deny

7 - According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)), what is the access log action for the IP address that the domain (listed in the IoCs of the group "APT-ENR-88") resolved to?

> **Answer:** allow

8 - According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)), what was the target IP address within the organization's network that  received connection attempts from the IP address listed in the IoCs of  the "APT-ENR-88" group?

> **Answer:** 172.16.8.5

9 - According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)), what was the name of the IPS attack event triggered by access attempts  from the IP address (listed in IoCs for the "APT-ENR-88" group) to the  organization's systems?

> **Answer:** Apache.Log4j.Remote.Code.Execution

10 - According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)), what action did the IPS product take against the attack event triggered by access attempts from the IP address (listed in IoCs for  "APT-ENR-88") to organization's systems?

> **Answer:** dropped

## Practical Lab-3

### Hypothesis-3

**Note:** The questions in this section are designed for threat hunting based on the following hypothesis.

**Hypothesis:** A threat actor group might be preparing a Business Email Compromise (BEC) attack targeting this organization.

### Threat Hunting Lab Environment

- **Company Name:** CNCHome
- **Company Domain:** cnchomecorp.io
- **Third-Party Companies:** vertexenterprise.io , universalventures.io , pioneersystems.io
- CTI Events ([Threat Intel LetsDefend Platform](https://app.letsdefend.io/threath-intelligence-feed))
- Email Security ([LetsDefend Platform](https://app.letsdefend.io/email-security))

### Lab Notes

- Analyze the logs between "Aug 1, 2024 00:00 - Aug 7, 2024 00:00" to answer the questions below.
- Subsequent questions require correct answers from previous ones. **Answer all questions strictly in the order they appear.**

### Questions

**Note:** Analyze the logs between "Aug 1, 2024 00:00 - Aug 7, 2024 00:00" to answer the questions below.

**Note:** Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

1 - ﻿According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)), which suspicious domain, suspected to belong to a third-party company the organization works with, was reported?

> **Answer:** universalventures.top

2 - According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)), what is the TAG (CTI category) of the suspicious domain suspected to  belong to a third-party company the organization works with, reported?

> **Answer:** phishing

3 - According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)), what is the email address of the sender of the email sent to the  organization from the suspicious domain suspected to belong to a  third-party company?

> **Answer:** john@universalventures.top

4 - According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)), how many different email accounts in the organization received emails  from the suspicious domain suspected to belong to a third-party company?

> **Answer:** 3

5 - According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)), what is the recipient email address of the successfully delivered email sent from the suspicious domain (suspected to belong to a third-party  company)?

> **Answer:** anna@cnchomecorp.io

6 - According to the CTI Platform ([LetsDefend - Threat Intel](https://app.letsdefend.io/threath-intelligence-feed)), were any emails sent from the organization to the suspicious domain suspected to belong to the third-party company?

> **Answer:** No