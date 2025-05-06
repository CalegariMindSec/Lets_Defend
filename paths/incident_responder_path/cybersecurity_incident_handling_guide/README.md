# Cybersecurity Incident Handling Guide

In this  course, we will cover how to handle cybersecurity incidents properly,  incident response processes with its proper order along with the  recommendations of the "Computer Security Incident Handling Guide".

**Table of content:** 

- Introduction to Incident Handling

- Incident Handling Steps
- Preparation
- Detection and Analysis
- Containment, Eradication, and Recovery
- Post-Incident Activity

## Introduction to Incident Handling

Although we care about cybersecurity and allocate budget and invest  in security systems, it is still possible to get targeted and experience a cybersecurity incident. In order to minimize loss and destructions,  mitigating the exploited vulnerabilities and restoring services after  the incident without any problems, Incident Response Teams should be  formed prior to cybersecurity incidents to manage the incident response  processes.

Accurate planning and resources are required as incident response is a complex process that may cause all incident response processes to be  wasted in case of any inaccurate or overlooked steps.

National Institute of Standards and Technology (NIST) an agency of  the United States Department of Commerce whose mission is to promote  American innovation and industrial competitiveness. The NIST  Cybersecurity Framework helps businesses of all sizes better understand, manage, and reduce their cybersecurity risk and protect their networks  and data.  
 (Source: https://www.ftc.gov/business-guidance/small-businesses/cybersecurity/nist-framework)

In this training, we will cover how to handle cybersecurity incidents properly, incident response processes with its proper order along with  the recommendations of the "Computer Security Incident Handling Guide"  published by the NIST.

Our training has been prepared for:

- Tier 2 SOC Analysts
- Incident Responders
- SOC Team Leaders
- SOC Managers

We supported our training with real-life examples to keep interactive learning.

You can access the resource "**Computer Security Incident Handling Guide**" published by NIST at: https://nvlpubs.nist.gov/nistpubs/specialpublications/nist.sp.800-61r2.pdf

## Incident Handling Steps

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/NIST+-+Cybersecurity+Incident+Handling+Guide/1.png)

(Source: NIST.SP.800-61r2)

According to the recommendations published by NIST, cyber incident  response processes should be handled in 4 steps. These steps are as  follows:

1. Preparation
2. Detection & Analysis
3. Containment, Eradication & Recovery
4. Post-incident activity

In the following parts of our training, we will examine these 4 steps in detail.

## Preparation

The preparation step covers the preparations made before intervening  in cyber security incidents. The preparations to be made in this step  ensure that the cyber incident response is carried out correctly and  smoothly.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/NIST+-+Cybersecurity+Incident+Handling+Guide/2.png)

The above image that shows the Incident Handling steps prepared by  NIST shows that the Preparation is the first and the most important step of the Incident Response process to avoid potential incidents. The last step which is the Post-Incident Activity is also the step before the  Preparation step within the Incident Response Life Cycle. This shows  that the preparation step is always a progressive process and it should  be improved all the time in accordance with the experiences and the  “lesson learned” after each security incident.

The preparation step covers all the preparations related to incident  response processes. It covers many topics like preparation of  plan/procedure/policies for incident response processes, establishment  and the training of the incident response team, installing and  maintaining the security tools like IPS/IDS/EDR properly, preparing  equipments that would be used during incident response, training  employees on social engineering, etc.

As it can be seen from the above examples, the preparation step has  no boundaries. Everything that will facilitate cybersecurity incident  response and everything that will prevent cybersecurity incidents from  occurring is considered as a part of the Preparation step. Let's take a  look at some important categories.

### Communication

Incident responders are in constant communications with different  teams and individuals during the incident response. It is of critical  importance to create a list of point of contacts and their contact  information that may be needed at the time of the incident response as  well as to prepare the documentation that includes the critical  information on who to contact with who and how to contact with these  people.

Since the internal communication network may have also been  compromised at the time of the incident, communications should be  carried out through different channels during the incident response. For this reason, separate telephones and lines to be used by the incident  responders during the incident response process should be prepared in  advance.

When creating contact lists, creating a separate list of external contacts will facilitate your incident response processes.

It is also recommended to create a war room to be used during the  cyber security incident. (War rooms are the rooms where people gather  and strategies and plans are discussed to solve problems.)

### Inventory List

Preparing a properly created and constantly updated inventory list  will directly facilitate your incident response processes. You should  have the information of all the critical systems, especially critical  servers (Web servers, FTP servers, Exchange servers, SWIFT servers etc.) information should be kept updated at all times. Inventory lists that  are not kept updated will impact the incident response processes  critically, cause waste of time and wrong decisions during the incident  response process. By looking at an inventory list that is not kept up to date, you will most probably miss critical inventory that you actually  need to check but is not on the list. For example, if 10.75.11.10 IP  address seems to belong to "Web-Server" according to an outdated  inventory list, but if it actually belongs to a different server, it  will confuse things, cause a waste of time and it will delay the  necessary actions to be taken on time. Keeping the inventory list  up-to-date is a laborious task, and so you should utilize some helpful  solutions to make it easy.

### Documentation

Documentation describing the incident response processes should be  prepared and the incident response team should be familiar with these  documentations. This will ensure that every team member will follow the  plans, procedures, and policies correctly and the incident response  process will go as smooth as possible.

A separate plan, policy, and procedure should be prepared for each  important activity. For example, preparing a separate plan, policy, and  procedure on how to handle cybersecurity incidents, for containment, for clarifying how to communicate with internal and external teams during  the incident response.

It is recommended to create report templates in order to shorten the report preparation processes after incident response.

Prepared documentation should be checked and updated periodically.

### Network Topologies

Network topologies have critical importance to understand the  activities and analyze the attack successfully during incident response.

Network topologies should be kept updated regularly to ensure that  they have the correct network information, diagrams and connections,  etc.

If you want to learn more about network topologies, you can reach our “Network Topologies” lesson at the link below:

[Network Topologies](https://app.letsdefend.io/training/lesson_detail/network-topologies)

### Incident Handling Software and Hardwares

You should prepare the hardware and software that has to be utilized during the incident response in advance.

- Digital Forensics Workstations and/or backup devices
- Laptops
- Blank removable media & hard disks
- Forensics and Incident Handling Software

### Preventing Incidents

The preparation step also includes the preparations for the  prevention of cybersecurity incidents before they occur. Organizations  should make the necessary investments in this regard and provide  multi-layered protection by deploying different security solutions such  as EDR, IPS/IDS, Antivirus, WAF, Firewall, DLP.

You can take a look at our “Security Solutions” course at the  following link to get detailed information about the security solutions  mentioned above:

At the same time, the awareness level of employees against social  engineering attacks should be increased by performing social engineering tests regularly.

Organizations must establish an official incident response capability by law. According to the documentation shared by NIST, this capability  includes the following actions:

- Creating an incident response policy and plan 
- Developing procedures for performing incident handling and reporting 
- Setting guidelines for communicating with outside parties regarding incidents 
- Selecting a team structure and staffing model 
- Establishing relationships and lines of communication between the incident response  team and other groups, both internal (e.g., legal department) and  external (e.g., law enforcement agencies) 
- Determining what services the incident response team should provide 
- Staffing and training the incident response team

Since the preparations step will directly affect the incident  response processes, managers must ensure that these preparations are  implemented correctly. You can test your readiness through tabletop  exercises and improve your preparation before encountering a real  incident.

## Detection and Analysis

The Detection and Analysis is the step in which the cybersecurity incident is detected and investigated in depth.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/NIST+-+Cybersecurity+Incident+Handling+Guide/3.png)

(Source: NIST.SP.800-61r2)

### Detection

Every cybersecurity incident starts with detection.

Cybersecurity events can be transmitted to you through different  channels. For example, it can be through a triggered SIEM rule, an alert triggered by the security products you have installed, the IT team  stating that the system is slowing down, or a notification sent to you  via the contact form of your organization.

### Verification

Things would be even easier if every detection was a cybersecurity  incident, but it is not like that all the time. Instead of diving  directly into the incident response process, first, the detection is to  be verified and evaluated if it is indeed a cybersecurity incident or a  false positive.

A SOC analyst solves hundreds of SIEM alerts (detections) in his/her  daily work routine. Can you imagine each of these being a real  cybersecurity incidents?

As an incident responder, you must first confirm the accuracy of the  detection you receive and whether it is a cybersecurity incident. For  example, you have a detection from your IT team indicating some  abnormalities on the extension of the files on the server. If you assume that it is directly caused by ransomware and the incident response  processes and isolate the server, you may cause some unnecessary service interruption. You must first verify the incoming detection. So, the  first thing you need to do is to verify if the file has indeed an  abnormal extension. Remember that correct detection does not always  prove that it is a cybersecurity incident. Even if the file extension is abnormal, someone with access to the server may have done this by  mistake. What you need to do is to investigate the reason why the  extension of the file is an abnormal extension (For example, to  investigate the Sysmon Logs to be able to understand who modified the  file and what process he/she used to do this). After you complete your  investigation, you may find out that a bored IT personnel may have done  this.

As you can see in our example, before starting the incident response  processes, it is extremely important to confirm the accuracy of the  incoming detection and whether it is really a cybersecurity incident or  not.

If you really think there is a cybersecurity incident, you should  start collecting and recording the evidence. You can use the issue  tracking system to record information, evidence and actions about the  event. The information that should be included in the issue tracking  system recommended by NIST is as follows:

- The current status of the incident (new, in progress, forwarded for investigation, resolved, etc.) 
- A summary of the incident
- Indicators related to the incident
- Other incidents related to this incident
- Actions taken by all incident handlers on this incident
- Chain of custody, if applicable
- Impact assessments related to the incident
- Contact information for other involved parties (e.g., system owners, system administrators)
- A list of evidence gathered during the incident investigation
- Comments from incident handlers
- Next steps to be taken (e.g., rebuild the host, upgrade an application).

Since incident response information contains critical data, it is  necessary to keep this information up-to-date at all times and to limit  the number of the users who can access this information.

### Prioritization

You may be exposed to more than one cybersecurity incident at the  same time. The approach of responding to the cybersecurity incidents on a “first come first serve” basis is not correct. You should prioritize  the incidents from the severity, criticality, impact area, potential  damages, etc. perspective and start handling these incidents according  to this prioritization.

You can use the categories published by NIST when prioritizing cyber security events:

**Functional Impact of the Incident**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/NIST+-+Cybersecurity+Incident+Handling+Guide/t1.png)



**Information Impact of the Incident**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/NIST+-+Cybersecurity+Incident+Handling+Guide/t2.png)



**Recoverability from the Incident**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/NIST+-+Cybersecurity+Incident+Handling+Guide/t3.png)



### Notification

After the verification of the detection, the confirmation of the  cybersecurity incident and prioritization, the relevant authorities  should be informed.

It is extremely important to have a documentation prepared that  describes who to contact with along with their contact information at  the time of cybersecurity incident detection. This will help the  incident response team to act quickly by knowing the correct point of  contacts and contacting them within the short period of time. The sample list is as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/NIST+-+Cybersecurity+Incident+Handling+Guide/t4.png)



The issue of who will be informed varies by the type of the  cybersecurity incident, organization, and and in accordance with the  law.

### Analysis

The analysis step is where the activities of the attacker are  analyzed. In this step, every single detail should be analyzed from the  moment of attacker's first access step to his/her most recent activities on the corporate systems.

### Analyzing the Root Cause

When responding to cybersecurity incidents, our priority should be to detect the attacker's access method and stop this access.

Let's think about a scenario where an attacker gains access to the  system by exploiting a vulnerability that he/she detected in the Web  application. If you try to delete the malicious software leveraged by  the attacker from the servers before finding the attacker's initial  access method, the attacker will exploit the vulnerability in the web  application again and access the server again to install the malware.  For this reason, first of all, the root cause should be detected and  remediated.

After the root cause is detected, we should run the Containment,  Eradication & Recovery step to prevent the attacker from  compromising the systems again during the incident response efforts.  After this step, the attacker's other activities should be analyzed by  going back to the Analysis step.

### Analyzing Other Activities

During the incident response, after eliminating the possibility of  the attacker to access the systems again through the initial access  method, other activities should also be analyzed.

Detection & Analysis and Containment, Eradication & Recovery  steps are in a continuous cycle within themselves. Devices and users  found to be compromised should be isolated from the network quickly.

## Containment, Eradication, and Recovery

The Containment, Eradication and Recovery step includes isolation,  cleaning of the indicators/persistence methods used in the attack and  restoring the systems.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/NIST+-+Cybersecurity+Incident+Handling+Guide/4.png)

(Source: NIST.SP.800-61r2)

### Containment

The containment step is where the attacker is isolated so that they  cannot cause any further damage. Since delaying the containment step is  risky, it should be carried out as soon as the event is detected and  confirmed as a cybersecurity incident.

Containment methods may change depending on the type of the cyber  security incident. Some containment methods that can be applied are:

- Placing the device in an isolated network segment,
- Stopping the affected services,
- Turning off the device,
- Disconnecting the device from the network,
- Disable the user’s account on the corporate network.

Current EDR products come with containment feature. With this  feature, the device on which the agent is installed is separated from  the network and communicated only with the EDR central server. In this  way, while performing live analysis on the device, the isolation of the  device is also ensured.

You should create a complete containment strategy during the preparation phase.

Since you cannot isolate critical servers directly from the network,  it is highly recommended to prepare a separate containment procedure for critical applications/servers.

### Eradication

The eradication step includes activities such as cleaning the  malicious software left by the attacker, disabling the compromised  users, deleting the users created by the attacker.

The most important point that should not be forgotten in this step is that the indicators belonging to the attack are recorded as evidence  before they are deleted. For example, before deleting a malicious  software used in the attack from the server, it is necessary to take a  screenshot of the folder where the malware is located, to save the hash  information of the malware, and to record a copy of the malware in an  isolated environment.

Activities to be done in the eradication step can be listed as;

- Cleaning the files uploaded by the attacker,
- Disabling/deleting Compromised users,
- Deleting users created by the attacker,
- Mitigate the identified vulnerabilities,
- Termination of actively running processes.

**Practice of Eradication Step**

Connect to the device named “NodeServer” by pressing the “Connect”  button in the “Hands-On Practice” section at the bottom of the  training. 

- Remove the file named ua-parser.js from the device.

### Recovery

The recovery phase includes restoring the affected  servers/devices/services to their previous operating state and  confirming their proper functioning.

The recovery phase varies from organization to organization. Make sure your organization has a proper Recovery strategy.

Strategies that can be applied in the recovery phase can be listed as;

- Returning to pre-compromise backup
- Rebuilding systems from scratch
- Replacing compromised files with clean versions
- Installing patches
- Changing passwords
- Tightening network perimeter security

## Post-Incident Activity

The Post-Incident Activity step covers the applications to be carried out after the incident response.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/NIST+-+Cybersecurity+Incident+Handling+Guide/5.png)

(Source: NIST.SP.800-61r2)

### Lesson Learned

Although this step is often skipped, it is one of the most important  steps. The cybersecurity incident should be evaluated from the beginning and what can be done better to avoid or prevent another cybersecurity  incident should be discussed. A cybersecurity incident is inevitable,  but it does not mean that we cannot learn from these incidents and be  more prepared for the next incident.

A Lesson Learned meeting should be held about the cybersecurity  incident with all the teams involved. The points to be discussed in the  lesson learned meetings published by NIST are listed below:

- What happened exactly, and at what times?
- How well did  staff and management perform in dealing with the incident? Were the  documented procedures followed? Were they adequate?
- What information was needed sooner?
- Were any steps or actions taken that might have inhibited the recovery?
- What would the staff and management do differently the next time a similar incident occurs?
- How could information sharing with other organizations have been improved?
- What corrective actions can prevent similar incidents in the future?
- What precursors or indicators should be watched for in the future to detect similar incidents?
- What additional tools or resources are needed to detect, analyze, and mitigate future incidents?

After the incident, a complete incident response report should be  prepared and stored in a safe place. You can access a sample incident  response report at the link below:

[Hijacked NPM Package - Incident Report](https://download.cyberlearn.academy/download/download?url=https://files-ld.s3.us-east-2.amazonaws.com/Alert-Reports/Hijacked_NPM_Package.pdf)