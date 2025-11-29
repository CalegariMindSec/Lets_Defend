# SIEM Log Search, Analysis and Reporting

The  "SIEM Log Search, Analysis, and Reporting" course is designed to provide specialized training in leveraging Security Information and Event  Management (SIEM) systems for effective log search, analysis, and  reporting. Participants will acquire skills in searching, analyzing, and reporting log data within SIEM platforms, vital for identifying and  responding to potential cybersecurity threats. This course emphasizes  the practical application of these techniques in bolstering  cybersecurity measures.

Table of Contents

- [Introduction to Log Search and Reporting]()
- [Log Search with SIEM]()
- [Log Search with IBM QRadar](r)
- [Log Analysis with SIEM]()
- [SIEM Reporting]()
- [Reporting with IBM QRadar]()

Evaluate Yourself with Quiz

- [SIEM Log Search, Analysis and Reporting](https://app.letsdefend.io/training/quiz/siem-log-search-analysis-and-reporting)

## Introduction to Log Search and Reporting

Security information and  event management (SIEM) is an important technology that helps  organizations protect complex security infrastructures and quickly  detect security threats. SIEM collects, stores, analyzes and creates  reports regarding security-related logs. This helps security teams  protect their networks and systems while ensuring they meet compliance  requirements. 

### What is Log Search?

Log search is the process by which organizations query and analyze security events and event logs from different sources. Logs come from a variety of sources such as  servers, network devices, security systems and applications. Log search  aims to transform these logs into meaningful information by organizing,  filtering and analyzing them. This helps detect potential security  issues and threats.  

### Log Analysis and Its Importance

Log analysis refers to  the process of examining collected log data and extracting valuable  information. Log analysis performs the following important functions:

**Identifying Abnormal Activity**

Logs help identify normal network and system activity. This makes it easier to detect abnormal activity.

**Threat Detection**

Log analysis is used to  identify potential threats and vulnerabilities. This strengthens the  organization's defenses against threats such as malware, attacks or  unauthorized access.

**Compliance Monitoring**

Many organizations must  meet certain compliance requirements. Log analysis helps monitor these  requirements and prepares for compliance audits.

### Reporting and Benefits

Log analysis results are  presented in reports. Reports provide the following benefits to security teams and organizational managers:

**Security Status Monitoring**: Reports visually  represent the organization's security status. This allows the security  team to understand the security situation at a glance.

**Threat Scanning**: Reports help the  organization examine detected threats and security incidents. This  allows us to better understand and respond to security issues.

**Compliance Reports**: SIEM is used to monitor and report compliance requirements. Reports help the organization  evaluate whether it is meeting the requirements.

In this part of the  training, what log search is, the importance of log analysis, reporting  and its benefits are mentioned. In the next part of the training, the  subject of “Log Search” is explained.

## Log Search with SIEM

### What is Log Search?

Log Search or Log Query  is a SIEM feature used for organizations to review and analyze log data  and detect security incidents. Log Search is used for the following  purposes:

**Monitoring Events:** Log Search helps  organizations track daily security events. This makes it easier to  identify potential threats at an early stage.

**Reviewing Events:** Users can review events  that occurred within a specific time period or a specific event type.  This is necessary for detailed analysis of security incidents.

**Answering Questions:** Users can query log data  to answer a specific question or investigate specific suspicious  activity. For example, they can create queries like "Show all login  attempts from a specific IP address."

**Specify Time Frames:** You can use Log Search to track events that occur within a specific time period. This can help  determine the beginning or end of a particular security breach.

**Data Filtering:** Filtering log data  according to certain criteria makes it easier to eliminate unnecessary  information and focus. Users can use filters such as source IP address,  destination IP address, event type, or time.

**Threat Detection:** Log Search can be used to analyze log data to detect abnormal behavior or potential security  threats. Automatic alerts can be created when certain conditions are  met.

**Reporting:** You can generate security reports based on Log Search results and meet compliance requirements.

### Log Search Steps

To use SIEM Log Search, you can follow these basic steps:

**Identifying Goals:** Identify specific events  or goals you want to examine or track. Clarify what types of security  events you want to monitor or analyze.

**Creating Queries:** Create your log queries  in the SIEM system. These queries can include a specific time period,  sources, targets, and event types. Make your queries as specific as  possible.

**Examine Log Data:** Examine log data using your queries. Review the results and try to identify abnormal activities or security events.

**Analysis and Alerts:** Analyze log data and create automatic alerts when necessary. Identify potential threats and take necessary actions.

**Reporting:** Create reports based on  log search results as needed. These reports can be used to present  security status to senior administrators or compliance audits.

In this part of the  training, the purposes for which log search is used and the steps of log search are mentioned. In the next part of the training, “Log Search with IBM QRadar” is explained.

## Log Search with IBM QRadar

Log search on IBM QRadar SIEM can be done via the IBM QRadar Console -> Log Activity screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/3/image2-1.png)

**Search**: This screen contains  “New Search” and “Edit Search” options and allows you to make a new  search or update your existing search criteria.

**Quick Search**: There are many  ready-made search filters on this screen. Ex. Firewall Deny activities,  Firewall Permit activities, Offenses, Top Log Sources etc.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/3/image2-2.png)

**Add Filter**: Allows searching by specific Parameter, Operator and Value.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/3/image2-3.png)

  There are options such as equal or not in the operator section.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/3/image2-4.png)

**Quick Filter**: Allows quick searching, you can search by directly typing the phrases you are looking for. You  can search for phrases in plain text or with custom phrases.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/3/image2-5.png)

**Advanced Filter**: Ariel Query Language  (AQL) search query can be created to get information about specific  events and flows. For example, you can use the Advanced Filter menu to  perform the following searches.

- Build complex WHERE clauses that contain a combination of AND and OR conditions.  
- Look up and include data from reference sets, tables and maps.  
- Look up and include data, such as asset, user, property, and location, from the asset database in a query.  
- Produce customized column headings.  
- Concatenate two or more fields into a single result field.  
- Use string expressions in the query to filter the query results  
- Calculate complex mathematical expressions.  
- Complete custom time and date formatting or expressions.  

### **Advanced Filter examples**  

**Listing all events from a specific IP address**:

SELECT * FROM events WHERE source_IP='Specific_IP_Address'  

**Sorting events within a specific date range**:

SELECT * FROM events WHERE startswith(logsourceid, 'Linux') AND starttime >= 'Start_Date' AND endtime <= 'End_Date'

**Listing events involving a specific attack type**:

SELECT * FROM events WHERE QIDNAME='Specific_Attack_Type'  

**Sorting logins for a specific username**:

SELECT * FROM events WHERE username='Specific_User_Name' AND eventname='Successful Logon' 

Easier filters can be  applied to the outputs on the Log Activity screen by right-clicking with the mouse and using options such as filter in or out in the menu that  opens.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/3/image2-6.png)

### IBM QRadar Log Search Examples

### Creating a filter based on a specific log source via “Add Filter”

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/3/image2-7.png)

**Creating a filter based on target IP address via “Add Filter”**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/3/image2-8.png)

**Creating a filter based on source IP address and target IP addresses via** “Add Filter” (The following output can be obtained by filtering and adding separately.)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/3/image2-9.png)

**Searching for an IP address directly from the Quick Filter section**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/3/image2-10.png)

**Searching by a specific log source and username from the Advanced Search section**

AQL: SELECT * FROM events WHERE logsourceid='212' and username='Administrator'

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/3/image2-11.png)

As a result, log  searching is an integral part of modern security strategies. An  effective log search process keeps organizations safer and allows them  to act quickly against possible security incidents or breaches.

In this part of the  training, how to search logs on IBM QRadar is explained with examples. In the next part of the training, the subject of “Log Analysis” is explained.

### Question

1 - Which language can you use to create queries with Advanced Filter?

> **Answer:** AQL

## Log Analysis with SIEM

Log analysis is the  process of organizations identifying security threats by examining log  data from various sources. Logs are generated by network devices, servers, applications and other IT components and are used to record  security events, user activities and system status.  

### Importance of Log Analysis

- **Threat Detection:** SIEM quickly detects  abnormal activities and security breaches. Identifying potential threats at an early stage increases the security level of the organization.
- **Ability to Review Logs:** SIEM provides automation  to review and analyze large amounts of log data. It performs this  process, which is difficult to do manually by humans, quickly and  effectively.
- **Monitoring Events:** SIEM allows organizations to monitor security events in real time. This increases the ability to  quickly respond to events and determine their origin.
- **Data Integration:** SIEM brings together log  data from different sources and provides central visibility. This makes  it easier for organizations to holistically monitor security events  across different components.  

### SIEM Log Analysis Steps

You can follow the steps below when performing SIEM log analysis:

- **Data Collection:** The SIEM system collects  log data from different sources. These resources include security  devices, servers, applications, and network devices.
- **Data Normalization:** Collected log data is converted to a standard format. This makes logs from different sources comparable.
- **Automatic Analysis:** SIEM examines log data  using automatic analysis engines. It creates automatic alerts or  triggers when certain conditions are met.
- **Manual Analysis:** The analytics team  performs further detailed analysis by reviewing automated alerts and  reports. At this stage, events are verified and response plans are  created.
- **Incident Response:** When threats are detected, appropriate responses are made according to the organization's security policies. This may include isolating the incident, identifying the origin, and blocking the attack.
- **Documentation and Reporting:** SIEM generates reports on detected threats and responses. These reports are used to present  security incidents and the security status of the organization to  administrators.

SIEM log analysis helps  organizations increase security and respond quickly to potential  threats. This process is an important tool for monitoring and analyzing  security events and has become a critical component for organizations.

In this part of the  training, the importance of log analysis and SIEM log analysis steps are mentioned. In the next part of the training, the subject of “Reporting” is explained.

## SIEM Reporting

SIEM is an important tool used by organizations to monitor, analyze and report security events.  SIEM reporting is used to provide information about security events,  assess the level of security, and meet compliance requirements.

Reporting is the process by which organizations create documents that summarize security events,  activities, and results over a period of time. These reports are used to manage, analyze, monitor and share security events.

### Importance of SIEM Reports

SIEM reporting provides the following key benefits:

- **Visualization of Security Status:** SIEM reports visually  present the security status of the organization. This helps us better  understand security incidents and assess risks.
- **Meeting Compliance Needs:** SIEM reports assist in  ensuring compliance with various regulations and compliance  requirements. For example, you can produce the necessary documentation  to meet regulatory compliance requirements such as PCI DSS, HIPAA, and  GDPR.
- **Threat Analysis:** SIEM reports are used to  analyze the organization's past security incidents and dangerous trends. This helps you be better prepared for future threats.
- **Management and Decision-Making Support:** Reports provide  information about security status to senior managers. This can be  helpful when making decisions such as budget allocation, revising  security policies, and assigning resources.

### SIEM Reporting Steps

You can follow the steps below when doing SIEM reporting:

- **Data Collection:** The SIEM system collects log data from different sources and stores it in a central repository.
- **Data Normalization:** Collected log data is converted to a standard format. This makes logs from different sources comparable.
- **Data Analysis:** SIEM analyzes log data and identifies specific events or trends. This analysis helps you identify security incidents and risks.
- **Report Generation:** The SIEM system generates various reports based on the analysis results. These reports may  include security incidents, compliance status, and other important  information.
- **Report Distribution:** Reports are made  available to specific recipients or groups. This allows relevant  parties, such as the security team, administrators, and compliance  auditors, to review the reports.
- **Report Monitoring and Response:** Reports are monitored regularly and responded to if necessary. This increases your ability to quickly respond to threats.

### SIEM Report Types

The SIEM system can generate various types of reports. These include:

- **Security Incident Reports:** These reports summarize  security incidents and attacks. For example, it may include information  about failed login attempts, malware detections, and malicious activity.
- **Compliance Reports:** These types of reports  evaluate the organization's compliance with a particular regulation or  compliance requirement. For example, there might be a report assessing  PCI DSS compliance.
- **Performance Reports:** Performance reports  monitor the performance of the SIEM system and may include metrics such  as network traffic, resource usage, and event processing rate.
- **User Activity Reports:** These reports track  users' logins, file access, and other activities. Useful for identifying unauthorized access attempts or suspicious activity.

SIEM reporting helps  organizations understand their security posture, manage security  incidents, and meet compliance requirements. Creating accurate reports  and monitoring these reports regularly helps the organization quickly  identify and address vulnerabilities.

In this part of the  training, SIEM reports, their importance, reporting types and report  types are mentioned. In the next part of the training, the topic "Reporting with IBM QRadar" is explained.

## Reporting with IBM QRadar

IBM QRadar is a security  information and event management (SIEM) solution that offers powerful  reporting capabilities. QRadar's reporting features help security  professionals and organizations extract meaningful information from  large datasets.

### Ready Reports

QRadar offers a number of ready-made reports. These reports address various security issues and  help users quickly find important information. For example, there are  ready-made reports for network traffic analysis, authentication events,  threat intelligence, and more.

You can access the ready-made reports that come by default on QRadar via the QRadar -> Reports screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-1.png)

By double-clicking on any report on this screen, you can view, change or manually recreate it.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-2.png)

The layout of the report is determined and Next is clicked.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-3.png)

It is determined which outputs will be in which section.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-4.png)

Report format is selected.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-5.png)

Select options such as downloading the generated report from the Console or sending it via e-mail.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-6.png)

To include the report in a group, if any, and create it as soon as the definition is completed,  select the relevant option “Yes - Run this report when the wizard is  complete” and click Next.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-7.png)

The information on the screen showing the report summary to be created is checked and completed by clicking the Finish button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-8.png)

### Customizable Reports

QRadar allows users to  create reports according to their needs. These customizable reports can  be designed to meet specific requirements and analysis needs. Users can  create reports on specific events, time periods, or threat types.

The report creation wizard opens by selecting QRadar -> Reports -> Action -> Create Report.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-9.png)

It is determined whether the report will be created manually or on a scheduled basis.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-10.png)

The layout of the report is determined and Next is clicked.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-11.png)

It is determined what information will be included in the layout.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-12.png)

Details of the  information to be included in the relevant section are selected. Details about Offense Detail are determined below.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-13.png)

Report format is selected.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-14.png)

Select options such as downloading the generated report from the Console or sending it via e-mail.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-15.png)

To include the report in a group, if any, and create it as soon as the definition is completed,  select the relevant option “Yes - Run this report when the wizard is  complete” and click Next.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-16.png)

The information on the screen showing the report summary to be created is checked and completed by clicking the Finish button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-17.png)

The created report can be downloaded and checked from the Reports screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Log+Search%2C+Analysis+and+Reporting/6/image4-18.png)

### Conclusion/Summary

SIEM is a key component  of security information and event management so organizations can  effectively monitor, analyze and report security events. In particular,  leading SIEM solutions such as IBM QRadar attract attention with their  broad and in-depth reporting capabilities. QRadar has the capacity to  quickly visualize the security status of the organization, meet  compliance requirements, recognize dangerous trends, and provide  strategic information for senior management. It offers users both  ready-made reports and the ability to create customizable reports  according to specific reporting needs. These reports can be easily  prepared thanks to QRadar's user-friendly interface and shared in  different formats when necessary. In summary, QRadar's reporting  features allow organizations to quickly react to security incidents and  develop proactive security strategies.  

In this part of the training, reporting on IBM QRadar is mentioned.

### Questions

1 - On which screen of QRadar can a customizable report be created?

> **Answer:** Reports





















































