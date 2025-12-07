# SIEM Basics, Installation and Configuration

The "SIEM  Basics, Installation, and Configuration" course offers comprehensive  training, focusing on providing an in-depth understanding of Security  Information and Event Management (SIEM) principles. It specifically  emphasizes hands-on instruction for the installation and configuration  of SIEM tools, enabling participants to grasp the fundamental concepts  and practical application of SIEM technology within cybersecurity.

**Table of Contents:**

- [Introduction to SIEM]()
- [SIEM Components]()
- [Common SIEM Products]()
- [SIEM Installation Planning]()
- [SIEM Installation Planning - 2]()
- [SIEM Installation and Configuration]()
- [To-Do List after SIEM Installation]()

Evaluate Yourself with Quiz

- [SIEM Basics, Installation and Configuration](https://app.letsdefend.io/training/quiz/siem-basics-installation-and-configuration)

## Introduction to SIEM

Security Information and  Event Management (SIEM), is a solution that enables companies and  organizations to collect, store, analyze, and generate reports from  security events and data logs.

The main purpose of SIEM  is to centralize and analyze large amounts of log and event information  from organizations' IT infrastructures and to detect and manage security threats using this data. Under this broad purpose, SIEM has several  specific goals:  

### Central Surveillance

Modern IT infrastructures are often dispersed and contain numerous components: servers,  endpoints, network devices, applications, and more. SIEM tools collect  logs and events from these components in a central point, which allows  security experts to monitor the entire infrastructure from a single  location.  

### Threat Detection

SIEM systems quickly  detect abnormal or suspicious activities using correlation rules and  advanced analysis techniques. This is especially critical for detecting  unknown and complex attacks, such as zero-day threats.  

### Compliance Reporting

Many industries require  organizations to comply with certain security standards (e.g. PCI DSS,  HIPAA). SIEM tools store the logs required for compliance with these  standards and creates compliance reports.  

### Forensic Analysis and Incident Response

After security incidents  occur, SIEM tools store detailed log information for forensic analysis.  This information is critical to understanding how an attack occurred and what its impact was.  

### Automation and Integration

SIEM can integrate with  other security tools to respond to security incidents automatically. For example, it can trigger a firewall rules automatically when suspicious  traffic is detected.  

### User and Asset Tracking

SIEM tools detect  abnormal behaviors by creating behavioral profiles of users and IT  assets. This is especially important for detecting insider threats.  

### Operational Efficiency

SIEM tools can improve  overall operational efficiency by providing valuable insights for IT  operations. For example, it can detect system errors, performance  issues, and configuration errors.  

To summarize, the main  purpose of SIEM is to enable organizations to respond to security  threats quickly and effectively, monitor their IT infrastructures  continuously, and meet the compliance requirements. This helps  organizations both protect their digital assets and maintain customer trust.  

In this part of the  training, we have covered the introduction to SIEM tools, its use and  purposes. In the next part of the training, we will be learning about  the subject of “SIEM Components” topic.

## SIEM Components

Security Information and  Event Management (SIEM) systems are complex solutions that include many  components and features. These components enable the SIEM to collect  data from different sources, analyze this data, and eventually detect  and react to security threats. The basic SIEM components can be grouped  under the following headings:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/2/image2-1.jpg)

  (Image Source:   https://www.wallarm.com/what/siem-whats-security-information-and-event-management-technology-part-1  )

### Data collection

It enables SIEM to collect log and event information from devices, servers, and other  systems on the network. Collection methods can be agent-based (via  device-specific software) or non-agent (directly from the device's log  outputs). This collected data helps the SIEM process centrally for  analysis. In summary, data collection is the process of obtaining log  and event data from various devices, servers, applications, and other  sources on the network.

To ensure visibility,  SIEM needs this data to monitor activities within and around the  network. This is crucial for detecting, analyzing, and responding to  potential threats. Furthermore, the SIEM correlation engine analyzes  data from various sources and searches markers for potential security  events.   

Briefly, the most basic data sources are:

- **Network Devices:** Network devices such as routers, switches, firewalls, and IDS/IPS systems.
- **Servers:** Logs of different operating systems.
- **Applications:** Databases, web servers, email servers, and other enterprise applications.
- **Other Resources:** Cloud services, IoT devices, authentication systems and more.

Log collection methods:

- **Agent-Based Collection:** Agents designed specifically for SIEM are installed on source systems and send logs directly to the SIEM system.
- **Agentless Collection:** Collecting logs through central log servers or syslog servers without using an agent.
- **API and Integrations:** Integration via APIs to retrieve data from modern platforms such as cloud services.

In short, data collection process is critical for SIEM to work effectively. This process ensures  that the organization can comprehensively monitor its entire network and react quickly to potential threats. Therefore, choosing the right data  collection strategies and tools is essential. 

### Log and Data Storage

Another important  component of SIEM systems is log and data storage capacity. This helps  the SIEM systems meet compliance requirements besides its capabilities  to monitor, analyze, and report events. SIEM systems collect logs and  event data from network devices, servers, applications, and other  sources. This data is stored for extended periods of time for analysis,  research, reporting, and compliance purposes.

Examining past incidents  is critical for threat hunting and can help identify trends in security  incidents. In many industries, logs must be retained for a certain  period of time. For example, regulations such as PCI DSS may require to  retain certain logs for a year or longer. When security breaches or  other incidents occur, access to old logs is critical to understanding  what happened.

As a result, the log and  data storage capacity of the SIEM system allows a historical review of  events, meeting compliance requirements and better understanding of  potential security threats. Therefore, it is essential to properly  design and manage the storage strategy and infrastructure.  

### Log Normalization

Log normalization is the  process of converting event and log data from different systems,  devices, and applications into a standard format or structure.

Different sources use  different log formats and structures. These differences make it  difficult to consolidate, analyze, and correlate events. Normalization  addresses these challenges by standardizing this data, making it an  essential issue in SIEM projects.

As a working structure,  SIEM systems collect log and event data and apply predefined  transformation rules to this data. These rules know what formats log and event data come in and define what to do to convert them to a certain  standard. As a result, events from different sources are represented in  SIEM in the same format.

Correlation is extremely  important in terms of query, search, report, and performance. In  conclusion, event normalization is a fundamental process that ensures  SIEM systems operate effectively. By converting data from different  sources into a standard format, it facilitates the analysis,  correlation, and reporting of this data.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/2/image2-2.png)

(Image Source:   https://www.logpoint.com/en/what-is-siem/  )

### Log Correlation

One of the key features of SIEM systems is log correlation. Log correlation helps detect a  specific pattern or event by analyzing log information from different  sources. Log correlation is the process of analyzing log entries from  different systems, applications, and devices and combining them to  detect a specific event, security breach, or other potential threat.  Correlation is usually performed automatically, based on predefined  rules or algorithms.  

Features and Functions of Log Correlation:

- **Multi-Source Log Processing:** Correlation is often used to analyze logs from multiple sources. This is critical for detecting  correlated events between different systems.
- **Predefined Rules:** SIEM systems can use predefined correlation rules to detect specific threat scenarios or security events.
- **Automatic Alerts and Notifications:** Correlation can automatically generate alerts or notifications when a specific pattern or event is detected.
- **Advanced Diagnostics:** Through correlation, security professionals can better understand the cause and effect of events.
- **Historical and Real-Time Analysis:** Correlation can operate  on both real-time and historical log data, allowing it to analyze past  events and detect what is happening right now.  

Importance of Log Correlation:

- **Comprehensive Visibility:** Provides an overview of events in an organization's IT infrastructure by combining logs from different systems and sources.
- **Rapid Threat Detection:** Correlation quickly  identifies specific threat patterns, allowing security teams to respond  faster to potential security incidents.
- **Effectiveness and Efficiency:** Automatic correlation allows security teams to save time by automatically detecting threats instead of manually reviewing logs.
- **Fewer False Alarms (F/P):** Proper correlation rules can reduce the number of false positives so teams can focus only on real threats.
- **Forensic Analysis:** Identifying the  chronological order of events and associated events is critical to  understand the root cause and impact of a security incident.  

In short, log correlation is a critical component of modern SIEM systems. This feature is  essential to quickly detect, understand, and respond to security incidents and threats. Correlation gives security teams broader and  deeper visibility so they can make more informed and effective  decisions.

### Real-Time Monitoring and Analysis

Real-time monitoring is the process of keeping an organization's network, applications, users,  and other components under constant and immediate surveillance.  Real-time analysis refers to the automatic evaluation of the data  collected during this monitoring against certain security rules,  algorithms, and other parameters.

The SIEM system collects  logs and events from sources (servers, network devices, security  solutions, etc.). This data is processed, normalized, and stored by the  SIEM tools in real-time. SIEM tools detect threats by applying  predefined rules, correlations, and algorithms to this data.

Real-Time Monitoring and  Analysis is critically important because time is critical for detecting  and responding to security breaches and other critical incidents. We are able to detects threats almost instantly thanks to real-time monitoring and analysis reducing response time. It monitors every single asset in  the organization, ensuring threats are detected when they occur  anywhere.  

### Warning and Alarm

Alerts and alarms are  automatic notifications that indicate a specific security event or a  certain threshold has been exceeded. SIEM systems create these  notifications according to specified criteria. This component instantly  detects potential security breaches, allowing the organization to  respond quickly to the incident. Manually reviewing all logs and events  is a challenging task. Automatic alarms automate this process allowing  you to focus on only important events and keep track of important events on a regular basis.  

Warning and Alarm Types:

- **Predefined Alerts:** Alerts created in response to known threats or specific activities. (i.e. too many failed login attempts)
- **Customized Alerts:** Alerts created based on the organization's specific needs and related to a specific workload, application, or process.  

Alert Creation Process:

- **Data Collection:** Transferring relevant data to the SIEM system.
- **Data Analysis:** Analyzing the collected data and checking whether it meets certain criteria.
- **Correlation:** Combining and analyzing data from different sources.
- **Alert Creation:** Automatic creation of an alert if a certain criterion is met.

Alert Management :

- **Prioritization:** Not all alarms are of equal importance. Prioritization of alarms according to importance and urgency.
- **Verification:** Checking whether the alarm represents a real threat and filtering false alarms.
- **Response:** Responding quickly and effectively to the event/incident.

In short, the alert and  alarm mechanism of SIEM systems allows organizations to quickly detect  potential threats and breaches and respond to them accordingly.  Therefore, it is essential that this mechanism works effectively and is  constantly updated.  

### Reporting 

SIEM reporting involves analyzing and compiling collected log and event data and presenting it  in specific formats. These reports present complex data in an  understandable format, often through graphs, tables, and text.

Reporting Types:

- **Security Reports:** Contains information on security incidents, threat detections, and other security-related issues.
- **Compliance Reports:** Reports on whether organizations comply with certain regulatory standards and regulations.
- **Operational Reports:** Contains information about system performance, user activities, and other IT operations.

Importance of Reporting:

- **Briefing:** Obtaining information about the organization's overall security posture and becoming aware of potential vulnerabilities.
- **Compliance:** Ensuring and monitoring compliance with various regulatory standards and regulations.
- **Decision Making:** Making effective decisions about shaping security strategies and IT investments.
- **Incident Response:** Responding more effectively to similar incidents quicker by obtaining information about past events.  

SIEM reporting capability helps organizations understand their security posture, operational  status, and compliance status. These reports play a critical role in  both daily operations and strategic planning processes. An effective  SIEM reporting process enables organizations to better manage  security-related risks, ensure compliance, and generally make more  informed and proactive IT and security decisions.

### Forensic Analysis

SIEM systems are valuable not only for real-time event monitoring and threat detection but also  for forensic analysis which refers to a detailed examination of the  aftermath of a security incident. This investigation aims to determine  how and why the incident occurred, who carried it out, and what impact  it had.

In terms of the  importance of SIEM in forensic analysis, it is critical to quickly  determine what happened in the immediate aftermath of a security breach. SIEM provides quick access to this information and collects data from  multiple sources, which helps forensic analysts get a complete picture  of the incident. Chronological event tracking and correlation features  help analysts determine how and why events occur. Forensic analysis also includes the collection and preservation of evidence. SIEM ensures that this evidence is verified and preserved.

To summarize, SIEM  systems are a critical tool for forensic analysis. Following a security  incident, the data collection, storage, and analysis capabilities  provided by SIEM help organizations quickly determine what happened,  plan how to respond to the incident, and understand how to prevent  similar incidents in the future.  

### User and Asset Tracking (UEBA)

UEBA learns the normal  behavior of users and assets (servers, devices, applications, etc.) on  the network and is used to detect deviations from this behavior. UEBA  creates a profile of “normal” behavior by analyzing the historical  activities of a particular user or entity. If a user or entity displays  activity that does not fit the normal behavior profile, this is  considered an anomaly, and such activity can be processed as an alarm or warning.  

Importance of UEBA:

- **More In-Depth Threat Intelligence:** UEBA adds an additional  layer to traditional signature-based threat detection, meaning more  in-depth and accurate threat intelligence.
- **Fast Response Times:** UEBA's continuous monitoring and automatic detection capability allows security teams to respond faster to potential threats.
- **Proactive Security Approach:** Behavioral analysis can help take a proactive security approach by detecting potential security incidents at an earlier stage.
- **Comprehensive Internal Threat Protection:** Internal threats are  often more difficult to detect than external threats. UEBA is an  effective tool for identifying such threats.

In short, the UEBA  capabilities of SIEM systems play a critical role in protecting against  modern security threats. This helps organizations take a more effective  and proactive security approach against both internal and external  threats.

In this part of the  training, we have covered the components of the SIEM systems and their  importance. We will be learning about the “Commonly Used SIEM Products” topic in the next part of our training.

### Questions

1 - What is the name of the  security technology that monitors the behavior of users and assets on  the network and detects abnormal activities?

> **Answer:** UEBA

## Common SIEM Products

The SIEM (Security  Information and Event Management) market has a wide range of products  offered by many different manufacturers. These products typically offer  basic SIEM functions such as log collection, analysis, correlation, and  threat detection. However, each stands out with its own unique features. Here are some commonly used SIEM products and features:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/3/image3-1.png)

(Image Source:   [https://www.cyberkach.com/blog/siem-ii ](https://www.cyberkach.com/blog/siem-ii)  )

### Splunk

Splunk is one of the  industry's leading SIEM solutions. Splunk has extensive capabilities in  big data analytics and real-time business intelligence and is used by  many organizations for log management, monitoring, and security  analysis.

**General features:**

- **Data Collection**: Ability to collect log and machine data from different sources (servers, network devices, applications, etc.).  
- **Real-Time Analysis**: Analyzing and visualizing logs and other data in real-time.  
- **Scalability**: Splunk is scalable across a wide spectrum, from small businesses to large organizations.  
- **Visualization and Dashboards**: Visualize data with customizable dashboards, charts, and reports.  
- **Research and Query**: Ability to make detailed queries on data with powerful search functions.  
- **Applications and Integrations**: Leveraging various data sources and technological solutions through pre-configured applications and integrations.  

**Highlighted Features:**

- **Splunk Cloud**: As a cloud-based SIEM solution, this version of Splunk offers the advantage of rapid deployment and scaling.  
- **Splunk IT Service Intelligence (ITSI)**: It is a product developed to monitor and analyze the performance of IT and business services.  
- **Advanced Threat Analysis**: Advanced threat detection and response with AI and machine learning-based analysis.  
- **Threat Hunting**: Provides tools for proactive security analysis and threat hunting.  
- **Advanced Correlation**: Improved event correlation between different data sources.  
- **Splunkbase**: A marketplace with  thousands of pre-made applications and plugins for Splunk. This makes  Splunk easier to integrate into a variety of technologies and use cases.  
- **Broad API Support**: Splunk's APIs make it possible to create customized solutions by integrating with third-party applications.  

Splunk goes beyond being  just a security solution with its general data analysis and business  intelligence features. However, fully evaluating these features requires proper configuration and optimization. Organizations must receive the  necessary training and/or work with experienced experts to use Splunk  effectively.  

### IBM QRadar

IBM QRadar is one of the  industry's leading SIEM (Security Information and Event Management)  products. Below you can find the general and prominent features of  QRadar.

**General features:**

- **Log Management**: Collects, normalizes, stores, and analyzes logs from different sources.  
- **Event Correlation**: Identifies complex security threats by correlating data from various log and event sources.  
- **Network Flow Analysis**: Detects potential threats and performs asset discovery by analyzing network traffic.  
- **Offense Management**: Used to identify, prioritize, and track security breaches and other critical events.  
- **Visualization**: Customizable dashboards, charts, and reporting features.  
- **Scalability**: Provides a scalable structure for large-scale corporate networks.  

**Highlighted Features:**

- **QRadar QFlow**: Deeply analyzes network traffic, collects content data, and displays application activity.  
- **QRadar VFlow**: Captures and analyzes virtual network traffic.  
- **Advanced Threat Intelligence**: Provides up-to-date  threat intelligence and information about well-known malicious IP  addresses through integration with IBM X-Force.  
- **High Customizability**: Allows organizations to create customized correlation rules based on their use cases.  
- **Automatic Incident Responses**: The ability to automatically respond to specific security incidents.  
- **Advanced Search and Query**: A user-friendly search interface to quickly research events and streams.  
- **Detection of Anomalies**: Detects abnormal behavior in the network with AI and machine learning-based analysis.  

QRadar offers a comprehensive SIEM solution for many different industries and sizes of  businesses. However, proper configuration, constant updates, and  training are required to use this system effectively.  

### LogRhythm

LogRhythm is also a well-known industry leader in the field of SIEM market. LogRhythm is  designed to provide advanced protection against modern threats.

**General features:**

- **Integrated Log Management**: Ability to collect, normalize, classify, and analyze logs from various systems and platforms.  
- **Advanced Event Correlation**: The ability to create complex correlations between different data sources.  
- **AI-Based Threat Detection**: Using artificial intelligence and machine learning to automatically identify anomalies and suspicious behavior.  
- **Alert and Incident Management**: Ability to respond quickly and manage security incidents effectively.  
- **Visualization and Dashboards**: Customizable dashboards and charts to quickly gain insight into security status.  
- **Automation and Orchestration**: The ability to automate security operations and coordinate between different security products.  

**Highlighted Features:**

- **Network Monitor**: Provides rich content for threat hunting and internal threat detection by examining network traffic in depth.  
- **CloudAI**: Uses artificial intelligence to identify abnormal behavior by analyzing user and asset behavior.  
- **SmartResponse**: The ability to create automation actions to react to specific threat scenarios automatically.  
- **Case Management**: The ability to organize and document processes for responding to security incidents.  
- **File Integrity Monitoring**: Monitoring and alerting on important file and configuration changes.  
- **Multi-tenancy Support**: Particularly useful for environments that support multiple customers or business units.  
- **Forensic Analytics**: Detailed analysis to detect malicious activities by looking deeper into events.  

LogRhythm offers a comprehensive and customizable SIEM solution for mid to large-sized  organizations. However, using this system with maximum efficiency  requires proper configuration, constant updates, and training.

### ArcSight (Micro Focus)

ArcSight is another  leading SIEM solution provided by Micro Focus and is considered the  industry standard. ArcSight is used to detect, analyze, and respond to  security incidents and data breaches.

**General features:**

- **Log Management**: Collects, normalizes, indexes, and analyzes logs from various devices and applications.  
- **Advanced Event Correlation**: Detects advanced threats and security incidents by correlating events across different data sources.  
- **Real-Time Monitoring**: Monitors real-time data sources such as network traffic, application activity, and user behavior.  
- **Warning and Alarm Mechanism**: Creates automatic alerts for events that meet certain conditions.  
- **Visualization and Reporting**: Customizable dashboards and reports to assess and analyze security status.  
- **Data Storage and Querying**: Stores large amounts of data for a long time and investigates events with fast query capabilities.  

**Highlighted Features:**

- **Effective Correlation Engine**: The ability to detect complex threats and events with a powerful and customizable correlation engine.  
- **Distributed Event Collection**: The ability to collect events from distributed systems in various geographic locations.  
- **ArcSight Data Platform (ADP)**: Provides data collection, enrichment, and normalization functions.  
- **ArcSight Investigate**: High-speed incident investigation and threat-hunting capabilities.  
- **Integration**: Easy integration with various security tools and solutions.  
- **Flexible Architecture**: Thanks to its scalable structure, it can be used in both small businesses and large corporate networks.  
- **Machine Learning and Artificial Intelligence**: AI and ML-based analysis to detect anomalies and suspicious behavior.  

ArcSight is particularly popular for large-scale organizations and has a large community and support infrastructure. However, to use this system at its best, proper configuration, constant updates, and training are required. 

### Microsoft Sentinel

Microsoft Sentinel is  Microsoft's cloud-based SIEM (Security Information and Event Management) and SOAR (Security Orchestration, Automation, and Response) solution.  It runs on the Azure platform and is used to detect, analyze, and  respond to security incidents and data breaches of organizations.

**General features:**

- **Cloud-Based Structure**: Sentinel runs on the Azure cloud, providing scalability and maintenance benefits.  
- **Log Management**: The ability to collect and store logs from various devices, applications, and services.  
- **Advanced Event Correlation**: Detects complex threats and security incidents by correlating events across different data sources.  
- **Real-Time Monitoring**: The ability to monitor security events in real time.  
- **Integration**: Deep integration with other Azure services and Microsoft's security product line.  
- **SOAR Features**: Provides security automation, response, and orchestration capabilities.  

**Highlighted Features:**

- **Comprehensive Visualization Interface**: Ability to visualize events and threats with powerful and customizable dashboards.  
- **AI-Powered Analysis**: Smarter threat hunting and incident detection by leveraging Azure's AI capabilities.  
- **Code-Free Query**: With its easy-to-use query interface, users can perform in-depth analysis without code knowledge.  
- **Playbook Automation**: The ability to create automated playbooks to create automatic responses to specific events.  
- **Integration**: Easy integration with other security products from Microsoft (i.e. Microsoft Defender) and third-party solutions.  
- **Low Cost**: With its cloud-based structure, organizations can pay according to their scale.  
- **Worldwide Data Centers**: Leveraging Microsoft's extensive data center network to meet data storage needs in different geographic regions.  

Microsoft Sentinel is a  very appealing choice, especially for organizations that have existing  integrations with Azure and use other products of the Microsoft  ecosystem. Its cloud-based structure offers great flexibility in scaling and expansion, unlike traditional SIEM solutions.

### Conclusion/Summary

Each of these products  has unique features that may be suitable for different use cases,  organizational requirements, and budgets. When deciding which SIEM  product is the best fit, it is important to consider factors such as  the needs of the organization, scalability requirements, cost, and  support options.

In this part of the training, we have covered commonly used SIEM products and their features. We will be learning about the “SIEM Installation Planning” topic in the next part of our training.

### Questions

1 - What is the name of the module within IBM QRadar that is used to analyze network traffic, one of its prominent features?

> **Answer:** QFlow

2 - Which company provides the SIEM solution ArcSight?

> **Answer:** Micro Focus

## SIEM Installation Planning

SIEM (Security Information and Event Management) installation is a critical step to  meet the organization's information security requirements. This process  requires good planning and careful preparation. Here are the steps to  adhere to and factors to take into consideration when preparing for SIEM installation:  

### Needs Analysis

Needs analysis for SIEM  deployment is often the first and most critical step in determining  exactly what an organization needs and expects from a SIEM solution.  Needs analysis helps in defining the requirements and selecting the most appropriate SIEM solution.

**Evaluation of the Current Situation:**

- **Available Security Tools**: List the security tools you use (Antivirus, IDS/IPS, Firewall, DLP, Proxy, WAF, EDR/EPP, etc.).  
- **Log Sources**: Which devices,  applications, and systems create logs? Determine the formats of these  logs (e.g. Syslog, CEF, Windows Event Logs, JSON).  
- **Available Capacity**: Review your current  storage, computing, and network capacity. This will help you understand  the need to scale the SIEM solution.  

**Determining Security and Compliance Requirements:**

- Determine what regulations and standards you must comply with (e.g. GDPR, HIPAA, PCI DSS).  
- Determine your organization's specific security policies and requirements.  

**Defining Functional Requirements:**

- **Log Storage**: How much data should you store and for how long?  
- **Real-Time Monitoring**: Do you need to monitor security events in real time?  
- **Event Correlation**: Do you need to correlate logs from different sources automatically?  
- **Alerts and Alarms**: Determine the types of events you want to be notified about.  
- **Reporting**: Make a list of what types of reports you need (i.e. compliance reports, daily activity reports).  

**Determination of Technical Requirements:**

- Make sure which protocols and formats are supported, especially for large and complex IT infrastructures.  
- Evaluate the SIEM solution's ability to integrate with other security tools.  

**User and Roles:**

- Determine who will use  the SIEM solution. For example,is it just the security team who will use the system or the whole IT department?  
- Define the users’ permissions levels.  

**Scalability and Future Needs**:

- Consider how the  scalability of the SIEM solution will adapt to your organization's  growth or changes in technology infrastructure.  

**Consider These During Needs Analysis**   :

- **Involve All Stakeholders**: Get input from the IT department, security team, management, and other interested parties.  
- **Be Realistic**: A SIEM solution with all the features and capabilities may be appealing, but focus on the features you really need.  
- **Consider Cost**: Try to find the most  cost-effective solution for your needs. This should include not only the licensing cost but training, management, customer support, and the  maintenance costs as well.  

Needs analysis is a critical step for a successful SIEM deployment.

### Budget and Resource Planning

“Budget and resource  planning” is crucial for the success of the project when preparing for a SIEM installation. Making accurate cost estimates during this planning  process is important to prevent unexpected costs and keep the project  within budget.

**Calculating Total Cost of Ownership (TCO):**

- **License Costs**: Determine one-time, annual, or per-user licensing costs.  
- **Infrastructure Costs**: If you prefer an on-premise solution, consider hardware, storage, and network costs.  
- **Maintenance and Update Costs**: Calculate regular maintenance, update, or license renewal costs.  
- **Training Costs**: Consider the training costs required for your staff to effectively use the SIEM solution.  

**Determination of Operational Expenses:**

- **Staff**: Calculate the work hours, and training requirements for staff who will manage and monitor the SIEM solution.  
- **Third-Party Support and Consultancy**: If you plan to outsource services, consider the costs required for these services.  

**Estimating Implementation and Integration Costs:**

- Initially, determine  which systems, applications, and devices will be integrated into the  SIEM solution. Calculate any custom application development or adapter  costs that may be required for these integrations.  

**Considering Future Scaling and Expansion Costs:**

- Estimate additional costs that you may need to spend as your organization grows or its technological infrastructure changes.  

**Backup and Disaster Recovery Planning:**

- Consider the costs of backing up and recovering SIEM data in the event of a disaster.  

**Creating Budget Flexibility:**

- Leave some flexibility  in your budget for unexpected situations or costs. This will create a  buffer to cover any unexpected costs that may be encountered on the  project.  

**Resource Planning:**

- **Personnel Allocation**: Identify the  necessary roles for a successful SIEM project and the people (i.e.  project manager, security analyst, system administrator) who will hold  these positions.  
- **Training Requirements**: Identify the necessary training for your staff to effectively use the SIEM solution and schedule that training.  
- **Time Frame**: Determine the total time required for SIEM installation, configuration, testing, and full integration.  
- **Technical Resources:**     Determine the necessary hardware, software, and network resources.  

Given that numerous SIEM  solutions use EPS (Events Per Second) for licensing and resource  allocation, and you can estimate your EPS by using the sites you find by searching for "Online EPS Calculator" in search engines.

Planning a SIEM  deployment can be a complex process, especially for large and complex IT infrastructures. Therefore, it is important to plan all the steps  carefully and stick to this plan at every stage of the project.

### Compatibility and Integration

Compatibility and integration in SIEM deployment planning are critical to ensure the new  SIEM solution works properly with the organization's current  infrastructure. Here are the steps you need to consider when planning  for compatibility and integration:

### Compliance Planning

**Evaluation of Current Infrastructure:**

- Determine your current IT infrastructure (operating systems, databases, applications, network devices, etc.) in detail.  
- Create a comprehensive inventory to list current hardware and software versions.  

**Checking the Platforms and Versions Supported by the SIEM Solution:**

- Check the SIEM  product's documentation or technical features to learn about supported  operating systems, applications, and devices.  

**Matching Requirements:**

- Make a mapping of your current infrastructure and the platforms supported by the SIEM solution.  
- This will help you identify possible incompatibilities in advance.  

**Checking Compatibility in the Test Environment:**

- Before installing the SIEM solution directly in the production environment, check  compatibility by installing it in a test environment.  
- In this way, you can detect possible problems in advance.    

### Integration Planning

**Determining Integration Points:**

- Start by listing the systems, applications, and devices SIEM needs to be integrated with.  
- Specifically, identify sources that produce log information and other security event data.  

**Researching Integration Methods:**

- Research the integration methods supported by the SIEM solution (i.e. API, Syslog, agent-based, agent-less, etc.).  

**Determining Special Integration Requirements:**

- Identify systems that require non-standard integration or require a custom integration adapter or module.  

**Testing the Integration:**

- Perform all integrations in the test environment.  
- This way, you can verify whether data collection, normalization, and other processes are working correctly.  

**Considering Data Formats and Normalization:**

- Evaluate data formats from different sources and how to normalize them.  

**Planning Automation and Workflows:**

- Plan how the SIEM solution will integrate with your existing workflows to automatically react to security incidents.  

The integration process  is critical to ensuring the SIEM reaches its full potential. Therefore,  careful and thorough planning during this process will help prevent  potential problems in the long run.

In this part of the training, we have covered the SIEM installation planning process and  some of the most important items that should be taken into consideration when planning for the installation of a SIEM product. We will keep  learning about the "SIEM Installation Planning" process in the next part of our training.

### Questions

1 - What is typically the first step when planning SIEM installation?

> **Answer:** Needs Analysis

## SIEM Installation Planning - 2

### Capacity Planning

Capacity planning is a  critical phase for SIEM installation and implementation. Correct  capacity planning optimizes costs while preventing performance problems  and possible service interruptions. Below you can find steps on how to  do capacity planning for SIEM:

**Determining Daily Data Volume:**

- Perform an assessment  to determine the amount of log data coming from existing log sources.  Measure the total size of logs from different devices, applications, and systems.  

**Evaluation of Data Retention Policy**   :

- Determine your  long-term data retention needs. This may vary depending on regulations,  industry standards, or your organization's internal policies.  

**Calculating Peak Load:**

- Predict peak load on  the system during abnormal situations or security incidents. This  ensures that your SIEM system always has sufficient capacity.  

**Estimating the Number of Concurrent Users:**

- Determine the number of users who will access the SIEM system simultaneously. This may affect  performance and licensing requirements.  

**Planning the Distribution of Components:**

- Plan the SIEM architecture by deciding how components (e.g. collectors, analysis engines, interfaces) will be distributed.  

**Redundancy and Load Balancing Planning:**

- Make redundancy plans  for critical components. Distribute the load using load balancers which  will ensure that the SIEM provides high availability and performance.  

**Planning for Scalability for Future Growth:**

- Design a scalable SIEM architecture for your organization's future growth and changing needs.  

**Establishing the Test Environment:**

- Create a separate environment to test your chosen SIEM solution. This helps you accurately assess performance and capacity.  

**Checking System Requirements:**

- Check the system  requirements of your chosen SIEM product. This may include hardware,  operating system, network, and other technologies.  

**Regular Monitoring and Review:**

- Regularly monitor your SIEM system and adjust it according to changes in capacity needs.  

Capacity planning plays a critical role in ensuring that your SIEM solution operates effectively, consistently, and cost-effectively. Therefore, it is important to  handle this process carefully and thoroughly.

### Implementation Strategy

SIEM deployment requires a customized approach depending on the organization's security  requirements, budget, technical infrastructure, and staff capabilities. The implementation strategy defines the steps to successfully install  and operate the SIEM solution.

Here are some suggestions on how to create an implementation strategy when planning a SIEM installation:

**Due Diligence:**

- Evaluate your current security infrastructure.  
- Get detailed information about log sources, available security solutions, network structure, and endpoint devices.  

**Determining Goals:**

- Clearly define what you expect from the SIEM application.  
- For example; your expectations on using the SIEM could be event monitoring, compliance reporting, or advanced threat hunting.  

**Separation into Phases:**

- Divide the implementation into phases, breaking it down into manageable pieces.  
- Consider starting with critical systems and the most threatened assets.  

**Technology Selection:**

- Choose the SIEM solution that best suits your existing infrastructure and needs.  
- Consider factors such as feature set, cost, scalability, and support.  

**Forming the Project Team:**

- Set up a project team for SIEM implementation.  
- This team may include security experts, network engineers, system administrators, and other relevant stakeholders.  

**Education and Awareness Raising:**

- Provide your team with the necessary training to master the new SIEM solution.  
- Inform the entire organization for general awareness purposes.  

**Testing and Evaluation:**

- Deploy the SIEM solution in a test environment and evaluate its features, performance, and integrations.  

**Transition to Live Environment:**

- Based on the test  results, integrate the SIEM solution into your live environment.  Consider collecting logs from fewer sources initially and testing key  features before rolling it out system-wide.  

**Continuous improvement:**

- Monitor, update, and optimize your SIEM solution regularly.  
- Adjust your application for new threats, technologies, and business needs.  

**Feedback and Revision:**

- Regularly review your SIEM implementation with feedback from users, analysts, and other stakeholders.  

These steps form the core components of the SIEM implementation strategy. However, since each  organization's needs and resources might be different, the strategy must be customized to the specific situation of that organization.

### Education

  To properly install and  use SIEM, it's crucial for staff to have an understanding of using and  maintaining these systems. Here are some specifics on how to approach  the "Education and Awareness" phase while planning the SIEM  installation:

**Determining the Purpose of Education:**

- The purpose of education should be clearly determined.  
- It can range from  training technical staff on how to use the SIEM solution to informing  senior management about the business value of this technology.  

**Defining the Target Audience:**

- It should be determined who will participate in the training.  
- The target audience usually includes security analysts, system administrators, network engineers, and upper management.  

**Preparation of Training Material:**

- Prepare training material on the technical details of the SIEM solution, its usage, benefits, and value to the organization.  

**Practical training:**

- One must go beyond just theoretical knowledge.  
- Give trainees the opportunity to practice with real data on the SIEM platform.  

**Awareness Sessions:**

- Inform the entire organization by making informational presentations about the value and importance of SIEM.  
- It will increase overall security awareness and deepen the understanding of why SIEM is being installed.  

**Utilizing External Resources:**

- SIEM manufacturers often offer training materials and courses for their products.  
- You can train your team members more effectively by using external resources.  

**Routine Training:**

- Threats and technologies in the security field are constantly changing.  
- Routine training sessions should be planned to keep staff constantly updated.  

**Measurement and Feedback:**

- Get feedback to measure the effectiveness of training.  
- You can conduct quizzes or surveys to understand how effective the training is.  

**Awareness Campaigns:**

- Consistently emphasize  the importance of SIEM and the benefits it brings to the organization  through emails, posters, information sessions, and other communication  channels.  

Training and awareness  are processes that must be maintained continuously, not just in the  initial stages of SIEM installation. This approach will strengthen the  organization's overall security posture and help it derive maximum  benefit from its SIEM investment.

### Regular Review and Optimization

Continuous review and  optimization of SIEM systems are essential for long-term effectiveness.  Changes in technology, the growth of the organization, the emergence of  new threats, and changes in business processes require SIEM solutions to be updated over time. Here are some details on how the "Continuous  Review and Optimization" phase can be carried out in planning the SIEM  installation:

**Periodic Reviews:**

- Review the SIEM system  periodically (for example, quarterly, semi-annually, or annually) and  conduct a health check of the complete system. These reviews will  provide an opportunity to identify any performance issues, missing data  sources, or correlation rules in the system.  

**Capacity Review:**

- Data storage needs, amount of traffic, and number of logs processed may increase over time.  
- Therefore, estimate future needs by regularly reviewing the current capacity of the system.  

**Threat Intelligence Integration:**

- Integrate with threat intelligence services to stay aware of new threats and penetration methods.  
- It keeps your SIEM solution constantly up-to-date and effective.  

**Reviewing Correlation Rules:**

- Regularly review existing correlation rules to minimize unnecessary alerts and add new rules to protect against new threats.  

**Documentation and Change Management:**

- Document changes, new rules, and other updates.  
- Change management processes help maintain the stability and reliability of the system.  

**Education and Awareness Update:**

- Schedule additional training to better understand the SIEM system and security threats.  
- Inform staff about newly added features or changes.  

**Performance and Health Checks:**

- Check system performance, hardware health, and network connections regularly.  
- Detect any slowdowns, outages, or other problems at an early stage.  

**Backup and Recovery Strategy:**

- Make regular data backups of your SIEM solution.  
- Also, create a strategy to ensure data is quickly recovered in the event of a problem.  

**Stakeholder Communication:**

- Provide regular feedback to SIEM stakeholders, especially senior management and other  relevant departments, on changes, improvements, and overall performance  of the system.  

The effectiveness of SIEM solutions is directly proportional to continuous review and  optimization. Incorporating these processes from the planning stage  ensures the long-term effectiveness of your SIEM investment.

In this part of the  training, we have covered the some of the most important items that  need to be considered in the SIEM installation planning. We will be  learning about the "  **SIEM Installation and Configuration Process**  " in the next part of our training.

### Questions

1 - As part of the preparation  for a successful SIEM installation, what is included in the planning for personnel responsible for managing the system to learn?

> **Answer:** Education

2 - What is the key planning step to avoid issues with performance and service interruptions, while optimizing costs?

> **Answer:** Capacity Planning

## SIEM Installation and Configuration

The complex cyber threats faced by organizations today necessitate the adoption of advanced  security tools. This is where Security Information and Event Management  (SIEM) systems come into play. SIEM collects and analyzes security event information collected from various sources of the organization at a  central point and alerts for appropriate actions.

Proper installation and  configuration are essential for the SIEM to function successfully.  First, the technical needs (both software and hardware) of the system  must be accurately evaluated. The next steps include properly  distributing the system's data collection agents, integrating log  sources, and normalizing log formats.

Once the SIEM setup is  completed, the main task is to configure the system correctly. Event  correlation, definition of alarms and warnings, reporting, and dashboard configurations are done at this stage. A continuous performance  monitoring and optimization process should also be initiated. This  enables early diagnosis of potential problems in the system and ensures  that the SIEM solution is constantly operating at peak performance.

### About SIEM Installation and Configuration

The SIEM installation and configuration process may vary depending on the needs of the  organization and the SIEM product used. However, by presenting a general approach, the technical steps to be followed in this process and the  topics to be considered can be listed as follows:

**Preliminary**

- Determining the Technical Requirements  
- Compatible Hardware and Software Controls  
- Examining Network Topology  

**Installing SIEM Software**

- Selection of Distribution Models (Centralized vs. Distributed)  
- Applying Necessary Updates and Patches  
- Licensing and Onboarding Settings  

**Data Collection and Integration**

- Identification and Integration of Log Sources  
- Distribution of Collection Agents  
- Data Normalization and Enrichment  

**Configuration**

- Creating Log Correlation Rules  
- Alert and Alarm Settings  
- Reporting and Dashboard Configurations  

**Optimization and Fine Tuning**

- Performance Monitoring  
- Reviewing Alarm Sensitivity Settings  
- Management of System Updates and Patches  

**Backup and Disaster Recovery Planning**

- Periodic Backup Settings  
- Testing Disaster Recovery Scenarios  
- Development of Data Backup and Archiving Strategy    

These steps technically  represent a general approach to installation and configuration. When  using a custom SIEM product, it is important to follow the product's  documentation and best practices. This will make the installation and  configuration process more effective and hassle-free. Additionally,  depending on the specific needs of each organization, some of these  steps can be examined more in depth or the process can be expanded by  adding additional steps.

**Note**: This course will  include a demonstration of SIEM installation, with the IBM QRadar SIEM  solution chosen as the sample SIEM solution.  

### IBM QRadar SIEM Setup

IBM QRadar is an  industry-renowned SIEM solution. Installing QRadar typically involves  several steps, and you must meet certain hardware and software  requirements.  

### Requirements

**Hardware Requirements**

Recommended hardware  specifications for QRadar can be found in IBM's official documentation.  This usually includes adequate CPU, memory, and storage capacity. The  performance of the server on which the installation is made depends on  the amount of logs to be processed. Minimum resource requirements are 8  core CPU, 16 GM RAM, and 300 GB disk. This resource can be virtual or  physical.  

**Software Requirements**

QRadar is designed to run on specific operating systems such as some versions such as Red Hat  Enterprise Linux. Additionally, it is recommended not to have any other  software on the system.  

**Network Requirements**

Proper network  configuration of the QRadar server must be made during installation.  This is necessary for the server to collect data from log sources and  other components.  

### Installation Steps  

After the requirements  are prepared, you can start the installation phase. Hardware  requirements can be physical or virtual. You should prepare the  necessary source, boot the system with the Qradar installation ISO file, and build Qradar on Redhat distribution.  

**Step 1:** Select “Install Red Hat Enterprise Linux 7.9” to start an installation with a graphical display.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-1.png)

**Step 2:** After the installation files are loaded, type “yes” to accept the license and continue by pressing “enter”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-2.png)

**Step 3:** Select the “Software Install” option and click “Next”.  

- **Appliance Install:** An installation option  optimized for pre-configured QRadar devices with custom hardware,  providing an integrated hardware-software solution.
- **Software Install:** A software-based version of QRadar, typically designed for direct installation on virtual machines or existing hardware.  
- **High Availability Appliance:** It is a backup device  that automatically activates to guarantee the continuous operability and data integrity of QRadar in case the primary device fails.  
- **App Host Appliance:** An installation option  specifically designed for additional applications to run on QRadar, thus adding additional functions to the core SIEM functionality.  
- **Data Gateway Appliance:** It is a component designed to collect log and event data from different network segments  or geographical locations and direct it to the main QRadar system.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-3.png)

**Step 4:**   Select “All-In-One Console” and click “Next”.  

- **All-in-one console:** An installation form that combines all the core components of QRadar (acquisition, processing,  and console functions) in a single device. Suitable for small and  medium-sized organizations.
- **Data Node:** Used to store and search large amounts of data. It is added to increase data storage capacity.  
- **Event Collector:** Collects log and event  data from various devices and applications on the network, performs  initial analysis, and sorts this data to transmit it to one or more  event processors.  
- **Event Processor:** Processes collected event data, applies correlation rules, and stores events.  
- **Event/Flow Processor:** A component designed to  process both event and network flow data. This allows QRadar to process  both log and network flow data at a central point.  
- **Flow Collector:** Collects network flow data, performs light processing on this data and routes it to one or more flow processors.  
- **Flow Processor:** Processes the network flow data collected by the Flow Collector, applies correlation rules, and stores the flows.  
- **QVM Processor:** Performs central  processing for the QRadar Vulnerability Manager (QVM). It is used to  identify and analyze vulnerabilities in the system.  
- **QVM Scanner:** Identifies potential vulnerabilities by scanning the network.  
- **QVM Appliance:** A standalone appliance that includes all the functionality of QRadar Vulnerability Manager  providing a central point for vulnerability scans, risk assessments, and vulnerability management.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-4.png)

**Step 5:** Select the “normal” installation option.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-5.png)

**Step 6:** Set the Date and Time or enter the time server IP address.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-6.png)

**Step 7:** Select the country for the time zone.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-7.png)

**Step 8:** Select a City or Region.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-8.png)

**Step 9:** IP version and config settings (if necessary) are selected and set.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-9.png)

**Step 10:** Select Management Interface.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-10.png)

**Step 11:** Enter the hostname, IP address, netmask, gateway, and DNS addresses and click the "Next" button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-11.png)

**Step 12:** Create the admin password of the server.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-12.png)

**Step 13:** Create the root password of the server.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-13.png)

**Step 14:** After the installation is completed, you will be logged into the terminal automatically.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-14.png)

**Step 15:** After the installation is completed, you can access the web interface from the browser with “  [https://[Qradar_IP_ Address\]”](https://qradar_ip_adresi)   and log in with the admin username and password specified during installation.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-15.png)

**Step 16:** After the first login, you need to change the password of the admin user.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-16.png)

**Step 17:** You need to accept the license agreement.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-17.png)

**Step 18:** A default dashboard screen as below will be displayed.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/6/image5-18.png)

In this part of the  training, we have covered a sample SIEM installation via IBM QRadar  SIEM. In the next part of the training, we will learn about the “What to Do After SIEM Installation" topic which describes the SIEM configuration process.

### Questions

1 - Which Linux distribution does IBM QRadar run on by default?

> **Answer:** RedHat

## To-Do List after SIEM Installation

### Licensing

The license key must be added before running QRadar to activate all features of the product.

You can define the configurations via QRadar -> Admin -> System Configuration -> System and License Management screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/7/image5-19.png)

### Defining Log Sources

You should define from which log sources QRadar will receive data (Servers, network devices, security devices, etc.).  

**Note**: We will cover this topic as a separate course. 

You can define the log sources via the QRadar -> Admin -> Data Sources -> Events -> Log Sources screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/7/image5-20.png)

### Data Retention Policies

You should determine how long the log and flow data will be stored.

You can define configurations via 

“QRadar -> Admin -> Data Sources -> Events -> Event Retention (default is 1 month)

QRadar -> Admin -> Data Sources -> Flows -> Flow Retention” screens.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/7/image5-21.png)

### User and Role Management

You should restrict user actions by defining access permissions for different users and roles.

You can make configurations through the QRadar -> Admin -> User Management -> Users and User Roles screens.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/7/image5-22.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/7/image5-23.png)

### Network Hierarchy Definitions

QRadar's Network  Hierarchy feature is a model that reflects the network structure of your organization and helps QRadar accurately classify and analyze events,  flows, and attacks.

You can make definitions via the QRadar -> Admin -> System Configuration -> Network Hierarchy screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/7/image5-24.png)

### Updates and Patches

You should check official releases from IBM regularly to keep your version of QRadar up to date  and to apply all security patches.

You can check the updates via QRadar -> Admin -> System Configuration -> Auto Update screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/7/image5-25.png)

### Email Server Settings

You can follow the steps  below to configure email settings in IBM QRadar. These steps are  required for QRadar to send alarm emails.

SMTP settings can be made via QRadar -> Admin -> Email Server Management screen.

To add a new SMTP server  on this screen, you can define a new SMTP server by clicking the "Add"  button and entering IP/hostname, port, and if necessary user and pass  information.

Since QRadar contains an SMTP Server in its default installation, this SMTP server is used by default.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/7/image5-26.png)

QRadar will now send  alarm emails via the SMTP server configured. These settings help QRadar  quickly report security incidents and provide a timely response to your  security team.  

### Grouping Log Sources

"Log Source Group" in IBM QRadar is a feature used to group and organize security events or log  sources of a specific type or source. This feature enhances the  management and analysis of security events and logs.

Log sources can be defined via QRadar -> Admin -> Data Sources -> Events -> “Log Sources Groups” screen.

Select the source on the  "QRadar -> Admin -> Data Sources -> Events -> Log Sources"  screen and click "Edit" to add the servers to the created groups. You  can then choose the added groups from the group section.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/7/image5-27.png)

Adding a log source to the group:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/7/image5-28.png)

### System Settings

QRadar's "System  Settings" section contains a number of basic system configuration and  management functions. Here's what each of these headings does and what  settings you can make:

- **System Settings**: This is the section where basic system settings are configured. It contains the general configuration and settings of QRadar.
- **Database Settings**: Includes QRadar's  database management. Database-related settings such as database logs,  automation, and performance settings are included here.
- **Ariel Database Settings**: Used to configure QRadar's Ariel database which is a component used to store query events and stream data.
- **SNMP Settings**: Allows configuration of Simple Network Management Protocol (SNMP) settings and enables QRadar  to interact and monitor via SNMP.  
- **Embedded SNMP Daemon Settings**: Contains settings related to the embedded SNMP service (daemon) which is used by SNMP clients. 
- **Console Settings**: Used to configure the user interface allowing users to customize the appearance and behavior of the console interface.
- **WINS Settings**: Allows configuration of Windows Internet Naming Service (WINS) settings. WINS is a service that translates the names of systems on the network into IP addresses.
- **Reporting Settings**: Used to configure  QRadar's reporting functions. Time periods for reports, background  process settings, and other reporting features are set here.
- **Data Export Settings**: Contains the settings used to export QRadar data and makes it easier to transfer data to other systems or storage units.
- **QFlow Settings:** This is used for configuring QFlow features, which are used to collect and analyze QRadar's flow data.
- **QRadar Network Insights Settings**  : Used to configure the QRadar Network Insights component which is used for network traffic analysis and threat detection.
- **Geographic Settings**: Used to configure  QRadar's geographic maps and location information and helps in  geographical tracking of threats on the network.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/7/image5-29.png)

###   Authorized Service Management

Authorize Service  Management section helps you create the token information required by  applications such as Wincollect and Use Case Manager, which are  necessary when using QRadar. The tokens created here will be provided to you upon creation. You must save them because they won't be retrievable within the system once created.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Basics%2C+Installation+and+Configuration/7/image5-30.png)

###   Conclusion

These steps mark just the initial phase of setting up QRadar and getting the most out of it.  However, effective use of QRadar requires constant monitoring, review,  and adjustment.

### Questions

1 - In the IBM QRadar solution, where can you access the 'Geo Location' information on the Admin screen menu?

> **Answer:** System Settings



















































































































































































