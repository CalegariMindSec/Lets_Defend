# Incident Management 101

Learn how to manage incidents and how incident management systems work

**Table of content:**

- Introduction to Incident Management
- Basic Definitions About Incident Management
- Incident Management Systems (IMS)
- Case/Alert Naming
- Playbooks
- What Does the SOC Analyst Do When An Alert Occurs?

## Introduction to Incident Management

In this course; we will talk about how an incident that occurred within  the organization is handled and how the investigation process should be  carried out. While doing this, we will give examples from LetsDefend  from time to time, and sometimes we will talk about the best practices. 

 The National Cyber Security Centre (NCSC) defines a cyber incident as a  breach of a system's security policy in order to affect its integrity or availability and/or the unauthorized access or attempted access to a  system or systems; in line with the Computer Misuse Act. 

 In our previous SIEM 101 training, we talked about how data is collected and converted into alerts within the SOC. If you have not completed  that training yet, we recommend that you complete it by clicking the  link and then continue from here. One of the platforms where alerts on  SIEM are collected and investigated is the “Incident Management System”. 

 In the continuation of this training, we will explain how an Incident  Management System works, and why and how to use these systems as SOC  analysts.

## Basic Definitions About Incident Management

In this section, we will explain the basic concepts that you need to know  about incident management. Since you will encounter these concepts  frequently during your education and your daily work routine, we  recommend that you understand these concepts thoroughly: 

- Alert
- Event
- Incident
- True Positive
- False Positive

**Alert**

We talked about how an alert is created in the SIEM training module. You can click on the link  (https://app.letsdefend.io/training/lessons/siem-101) to access the  training. To briefly recall, an alert is generated as a result of data  collection and processing (parsing, enriching, etc.) in SIEM, as seen in the image below. Then, we start the analysis process by sending the  generated alarms to the Incident Management System. 



![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/siem-alert.png)

**Event**

An event is any observable occurrence in a system or network. Simply,  events are activities like a user connecting to a file share, a server  receiving a request for a Web page, a user sending electronic mail  (e-mail), a firewall blocking a connection attempt, etc. 

**Incident**

The definition of a computer security incident has evolved over time. In the past, a computer security incident was thought of as a  security-related adverse event in which there was a loss of data  confidentiality, disruption of data or system integrity, or disruption  or denial of availability. 

A lot of new types of computer security incidents have emerged since  then, and this necessitated an expanded definition of “incident”.  Generally, an incident is a violation or imminent threat of violation of computer security policies, acceptable use policies, or standard  security practices. *Definitions: NIST Special Publication 800-61*

**True Positive Alert** If the situation to be detected and the detected (triggered alert)  situation are the same, it is a True Positive alert. For example, let's  say you had a PCR test to find out whether you are Covid19 positive and  the test result came back positive. It is True Positive because the  condition you want to detect (whether you have Covid19 disease) and the  detected condition (being a Covid19 patient) are the same. This is a  true positive alert. 

Let’s suppose there is a rule to detect SQL Injection attacks and this  rule has been triggered because of a request that was made to the  following URL. The alert is indeed a “True Positive” as there was a real SQL Injection attack. 

 https://app.letsdefend.io/casemanagement/casedetail/115/src=' OR 1=1 

**False  Positive Alert**

In short, it is a false alarm. For example, there is a security camera  in your house and if the camera alerts you due to your cat's movements,  it is a false positive alert. 

If we look at the URL example below, we see the SQL parameter "Union"  keyword within this URL. If an SQL injection alert occurs for this URL,  it will be a false positive alert because the “Union” keyword is used to mention a sports team here and not for an SQL injection attack. 

https://www.google.com/search?q=FC+Union+Berlin 

In order to better understand the definitions, you can compare the terms and definitions in a single table as follows: 



![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/false-positive-true-positive.png)

*img source:towardsdatascience.com*

### Questions

1 - A web attack alert has occurred because I have logged into the following URL address. Is this alert a false positive or a true positive? 

https://www.w3schools.com/sql/trysql.asp?filename=trysql_select_union3

> **Answer:** false positive

## Incident Management Systems (IMS)

Incident Management Systems is where SOC teams conduct the investigation process and record the actions taken when an incident occurs. For this reason,  SOC analysts spend a significant part of their time at the interface of  these systems. 

An example of IMS is the open-source TheHive project. 
 ![hive dashboard](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/1-hive.png) 

Similarly, "Case Management" on LetsDefend can be given as an example to the Incident Management Systems. 

![case management details](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/2-case-management.png) 

**How Incident Management Systems (IMS) Works?** 

In order to open a record on the Incident Management platform, a data  entry must first be provided here. This data can directly come from the  SIEM or from other security products. After the data flow is  established, a ticket/case is created on the Incident Management System. 

If integrations with “Threat Intelligence”, “SOAR”, and similar  platforms are established data within the case is enriched and this  helps in responding quickly. For example, let's say there is a  suspicious "letsdefend.io" domain in the incident. If there is an  integration between IMS and the threat intelligence platform, the  reputation of the “letsdefend.io” domain address is automatically  queried and provided to the SOC analyst. If there is not a threat  intelligence platform integration, then a manual query from the  open-source platforms such as Virustotal is required. 

In addition, SOAR products also offer integration with other security  products. Many SOAR products can integrate with products such as  Firewall, IPS, WAF, Proxy, Email Gateway, Email Security products. If we are sure that the domain “letsdefend.io” is harmful and we want to  prevent access to this address from within the organization, we can  quickly block this domain via a proxy with the help of SOAR. 

Consider the "Investigation Channel" on the LetsDefend Monitoring page. A new "Case" is created on the "Case Management" when we click the  "Create Case" button here. In other words, a new record is created on  the IMS. 

 ![siem create a case](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/3-monitoring.png)Generally, as we see in the picture below, alert details from SIEM are  transmitted to the Incident Management System and the Incident  Management System works in coordination with the Threat Intelligence and SOAR platforms to process all the data and a new case/ticket is  created. Thanks to Threat Intelligence and SOAR integrations on IMS,  data enrichment and various actions are provided. Finally, the alert is  closed when the operations are complete. 

 ![incident management system details](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/4-ims-system.png)

**P.S.:** As we mentioned before, Incident  Management System (IMS) is one of the platforms where you will spend  most of your time as a SOC Analyst. You can significantly shorten your  investigation time and get rid of your repetitive tasks if you use IMS  platforms effectively. Therefore, you should always take your knowledge  and skills on IMS platforms to the next level.

### Questions

1 - Which button in the “Investigation Channel” should we click to open a record on “Case Management” on the LetsDefend platform? 

> **Answer:** Create Case

2 - Which is not a feature of the Incident Management System

\- Workflow
\- Automation / API access
\- Close, open, edit action
\- Prevention

> **Answer:** Prevention

## Case/Alert Naming

It is important that the ticket/case/records created in the Incident  management system have meaningful title as having unified naming  conventions will help in the retrospective inquiries for quickly finding the relevant record or extracting statistics easily when an  investigation is made. For these and similar reasons, it is necessary to have an idea about the ticket/case just by looking at the title. There are several methods for naming tickets. The naming method in  LetsDefend "Case Management" is as follows.

EventID: {Alert ID Number} - [{Alert Name}]

![siem alert naming](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/alert-naming-siem.png)

Thanks to this naming convention, analysts can quickly access the alarm  details they want to reach, by the alarm ID or Name, while examining the past records. 

![SOAR tickets](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/soar.png)

When we look at real-world examples, we see that the naming format we  described above is a common practice in the industry. In addition,  sometimes the following fields may be included in the title: 

- Alert Category
- Event Source
- Description

### Questions

1 - According to this information, how can the ticket be created for the  alert with ID number 25 and rule name "SOC15 - Malware Detected" be  named?

The case/ticket format in LetsDefend is as follows:

EventID: {Alert ID Number} - [{Alert Name}] 

> **Answer:** EventID: 25 - [SOC15 - Malware Detected]

## Playbooks

There are many different types of alerts (web attacks, ransomware, malware,  phishing, etc.) in the SOC environment. The methods and approaches of  investigating these alerts are different from each other. The workflows  prepared for effective and consistent analysis of alerts created on SIEM or a different security tool are called playbooks. 

For example, when you click the “Create Case” button for an alert on the LetsDefend Monitoring page, a ticket opens on “Case Management” and the system automatically assigns you a playbook. So you can investigate the alert with the right steps by following the instructions there. 

 **Why is Playbook Important?** 

As SOC analysts, we may not always know exactly what to do when handling alerts. We can carry out the investigation process step by step, thanks to the instructions in the Playbook. Playbooks will provide guidance,  especially to analysts who have just started their careers in the SOC  field. 

 ![soc playbook](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/playbook.png)

We mentioned that playbooks guide analysts. Apart from that, it enables  the team to perform analysis at certain standards. For instance,  checking to see whether there is access to C2 sites/IP addresses is  vital after analyzing malware. However, some analysts may not be  checking to see the C2 access all the time, while others do. This leads  to inconsistency in the team's work standards. It is important that  playbooks are created and followed by all the analysts in order to  ensure the same level of analysis standards within the team. 

In the example below, you can see the phishing playbook stream that Microsoft has published. 

![soc playbook](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/ms-playbook1.png)
 

![soc playbook](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/ms-playbook2.png)

## What Does the SOC Analyst Do When An Alert Occurs?

In the previous sections, we talked about how an alert occurs. As a SOC  Analyst, your main task is to detect threats to your organization. You  usually do this task by analyzing the alerts created in SIEM or a  different environment. 

The alerts that occur do not always indicate an actual incident.  Sometimes you will encounter false positive alerts. In fact, you will  spend most of your time dealing with the false positives, so you need to be in constant communication with the team that creates the SIEM rules  and give them feedback all the time. As a SOC Analyst, you need to dig  into the details to understand whether an alert is a false positive.  There is no standard analysis method as there may be different types of  alerts (web, malware, endpoint, etc), and each type has its own specific details. Therefore, it is important to follow the playbooks in the  incident management systems. 

Let's give an example over LetsDefend for better understanding. As seen  in the image below, there are many alerts on the "Monitoring" page. As  analysts, we must decide and start by choosing an alert. 

![SIEM dashboard](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/siem.png)

Although it doesn't matter which alert you start within the simulation  environment, in real life you need to prioritize the alerts with high  severity values. 

You can start working on the alert you have chosen by clicking the “Take Ownership” button. The logic of the working standard is that there are  10 active alerts and you are working on the alert with EventID number  63. Since other team members know that you are working on this alert,  they will choose one of the remaining 9 alerts and continue working.  Thus, teamwork is ensured to avoid duplicate work. 

![take ownership of alert](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/2-take-ownership.png)

P.S.: You work on LetsDefend individually, not as a member of a team. 

After taking ownership of the alert, you will see that the alert has  been forwarded to the "Investigation Channel". This channel has alerts  that are actively being worked on. Click on the alert for details. Our  goal is to determine if this alert actually contains a harmful  situation. In other words, we need to determine whether it is a false  positive or true positive. For this, we can create a record on “Case  Management/Incident Management” by clicking the “Create Case” button and then following the playbook steps. 

 ![create a ticket soar](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/3-create-case.png)

Playbook offers you the steps to follow. After closing the alert, it  helps you to check your analysis results through some questions. 

![SOC Analyst playbook](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/4-playbook.png)

After completing the Playbook steps, you will be redirected to the  Monitoring page again. Now that you are done with the analysis, you now  need to make a final decision. Is this alert a false positive or a true  positive? 

 ![close siem alert](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/5-close-alert.png)

After making the necessary selections and explanations, you can close the alert and view your analysis results. 

P.S.: In real life, you may not be able to verify your analysis results  all the time. Sometimes you can work with a senior analyst and get help  by explaining the steps you have done, but this is not a sustainable  method. Therefore, it is an opportunity to examine the analysis results  of the alerts you have closed in LetsDefend and to learn new methods. 

After the alert is closed, it will be directed to the "Closed Alerts" channel and you will be able to check your answers here. 

 ![check siem analysis](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Management+101/images/6-check.png)

You can access the official walkthrough in the "Editor Note" area, or  you can access the solution methods created by the community in the  "community walkthrough" area. 