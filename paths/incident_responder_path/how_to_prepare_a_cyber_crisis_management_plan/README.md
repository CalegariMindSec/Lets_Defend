# How to Prepare a Cyber Crisis Management Plan?

**Table of Contents:**

- [Introduction to Crisis Management]()
- [General Preparation]()
- [Tools]()
- [Preparing the Response Units]()
- [Backups]()
- [Alerts and End of Crisis]()

## Introduction to Crisis Management

A cyber-crisis encompasses serious events that have the potential to  suffer a significant financial loss or serious damage to the brand  reputation of the organization. In such cases, actions should be taken  by including C-Level managers (CEO, CFO, COO, etc.) in the plan. It will not be easy to make a healthy decision as the stress level will be very high during the handling of the crisis. We must have a Crisis Managment Plan ready and we should be prepared ahead of time to be able to give  the right decisions and implement them in a timely manner during a  potential crisis. In this way, the right decisions are made easily even  before the incidents occur and the potential state of chaos is minimized if not eliminated at the time of the crisis.

You will be able to learn how to make a detailed plan for task  sharing during a cyber crisis, and what needs to be paid special  attention to stage by stage, and you will be comfortable preparing a  crisis management plan for your own organization.

## General Preparation

The purpose of creating a procedure is to find a guideline on how to manage threats/incidents to the existing organization or business partners in  case they turn into a crisis. It is important to understand that there  is no fixed definition of a cyber crisis. Each organization will define  what a crisis is considering the impact on its production and the level  of the organization’s capability of functioning. There are several  standards related to crisis and security incident management:

- \- NIST SP 800-34: the beginning of the crisis
- \- ISO 27035: ensuring the security
- \- ISO 22301: continuity management system

A cyber crisis will not only impact IT staff and is not necessarily a purely technical issue. Here are some things you should know for such  situations:

When it comes to ransomware in your team, the crisis won't be  resolved in a few hours. You will need certain information to review and it will take a long time to acquire. In some cases, deadlines are  incompressible. If you have to manually intervene on a server in a  remote data center, the travel time is incompressible.

One of the first things to do is to properly prepare for a cyber  crisis ahead of time. Therefore, we will present you with a flow of  various stages.

### Inventory of your resources

It is important to have a list of your available resources in the  event of a crisis, both technical equipment and personnel. While  preparing this list, you need to make sure that it includes the answers  to the following questions:

Do you have dedicated technical personnel for incident response?
Do you have trained staff?
Do the personnel who will be called upon have any requirements?

### Communication channels

If your organization is compromised, it is necessary to provide a secure communication channel apart from your infrastructure.

### Insurance

One of the crucial points often referred to at the end of remediation is insurance. When making the insurance, be sure to pay attention to  the following headings.

### Are You Protected?

The first thing to know is if you are covered for crises of cyber origins. We need to make sure what our coverage is.

### Maximum Support?

As we mentioned above, the most important point to validate with your insurance is to define what is covered. For example, will the insurance pay a ransom for your ransomware-infected systems? The insurance  companies usually cover the costs for a return to normal only and they  do not pay the costs of improvements, special charges (staff overtime,  purchase of equipment), etc.

### Partners

Finally, it is important to know if the insurance company will assign you a dedicated agent dedicated to responde to cyber crises’’.. This is a crucial point, as you will need special attention in such cases and  therefore, we should make sure if our insurance company is providing  such close attention.

### Questions

1 - Which standard would be more appropriate to apply to ensure security?

> **Answer:** iso 27035

2 - “It is important to have incident responders designated under insurance.” Is this statement true or false?

> **Answer:** true

## Tools

In order to respond effectively, it is necessary to have the tools  available (USB key, on a dedicated workstation outside the network).  Here is a list of tools that would help to respond during the  investigation of a crisis.

Note: We have listed the free tools below. You can customize your own list for your organization’s needs.

### CAINE Linux 

Italian live Linux distribution managed by Giovanni “Nanni” Bassetti. The project started in 2008 as an environment supporting digital  forensics and incident response, with several related tools  pre-installed.

### TSURUGI Linux

Tsurugi Linux is a DFIR open source project that is and will be  totally free, independent, without involving any commercial brand. They  state that their main goal is to share knowledge and “give back to the  community”.

### Forensicator 

This script automates the collection of information using tools like “winpmem” and more.

[Go to the tool website.](https://github.com/Johnng007/Live-Forensicator)

### Netstat with Timestamps

This script allows you to see the connections with the indication of the timestamps. A must-have!

[Go to the tool website.](https://github.com/gtworek/PSBits/tree/master/NetstatWithTimestamps)

### Mandiant RedLine 

Mandiant’s free Redline tool enables rapid memory analysis by  integrating indicators of compromise (IOC) performed using Mandiant’s  free IOC Editor tool.

[Go to the tool website.](https://fireeye.market/apps/211364)

### Velociraptor 

Velociraptor is a far too underrated tool. It allows retrieving  information on workstations such as CPU and RAM consumption along with  many others. It is also helpful to carry out investigations from its  interface in order to check the content of prefetches, event log,  extract RAM, etc.

[Go to the tool website.](https://velociraptor.velocidex.com/)

### THOR APT Scanner

A full-featured YARA and IOC scanner to automate compromise assessments

[Go to the tool website.](https://www.nextron-systems.com/thor/)

### Questions

1 - You are preparing a process for crisis management. Which tool would you list to analyze the memory dump? - Mandiant RedLine  - Wireshark - Netstat - Python

> **Answer:** Mandiant RedLine

2 - Should it be stated what workstation it will be used for analysis in the process to be prepared? 

Answer Format: Y/N

> **Answer:** Y

## Preparing the Response Units

As announced at the beginning, a response to a cyber crisis is not only  related to the IT teams and should not exclusively mobilize IT teams.  There should be at least two units in charge; the management unit, and  the operational unit.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Crisis+Management/images/units.png)

### 1. Management Unit

#### 1.1 Role

This unit will decide on the strategic priorities for the response.  It will be the one who will tell the Operational unit what must be  remediated and restored first, as well as decide on the internal and  external communications. It will also be responsible for responding to  the concerns of the various departments and managing the impacts of the  crisis.

#### Examples: 

The production line is at a stoppage point, it is the Management Unit’s responsibility to decide

How the employees will get paid during this time

Who will ensure the payment of overtime for the teams

How to conduct internal communication as well as communication with customers, and the press

How to organize personnel scheduling and rotation

#### 1.2 Members 

If there is a management committee, it will be the best practice to  create a management unit amongst the management committee to speed up  the decision-making process as they work together and know each other

#### 1.3 End of Crisis 

It is this unit that will decide to end the organization’s crisis  based on feedback from the Operational team. This decision may not mean  that everything is resolved but that the company resumes "normal"  operations.

Indeed, it is not possible to operate in a “crisis” over an extended  period, both for the staff (who are under great pressure) and for the  assets of the company (the costs may increase quickly when managing a  crisis).

### 2. Operational unit 

#### 2.1 Role 

This unit will have to manage two main tasks. The reconstruction of a new internal infrastructure for an incident response as well as the  restarting of infrastructure for business recovery, decided by the  management unit.

#### 2.2 Members

This unit will be made up of expert and technical personnel. The  experts may be responsible for investigating the workstations to find  the origin of the attack or even trace the new infrastructure, while the technical personnel may be required to prepare workstations for members of other units.

### Expectations from the Operational unit

#### Identify the source of compromise 

The Operational unit will have the task of finding the entry point of the attacker. It is not a question here of finding whether it is the  “user a” from the accounting department or the “user b” from the  communication department, but of knowing how the attacker entered the  network in order to remediate this vulnerability to prevent the  compromise of the new infrastructure from being subject to the same  vulnerability.

#### Date of initial compromise 

Now that we know how the attacker operates within the infrastructure, we potentially have a date when the threat appeared. It is important to determine the date of compromise as it will make it possible to  determine which backups are compromised and which are still intact and  reliable. Also, knowing when the attacker first got into our network and how long he/she accessed our network is crucial as it will help ease  the whole investigation process.

#### Indicators of Compromise (IOC)

Knowing the attack vector along with the date of initial compromise  will make it possible to generate indicators of compromise (IOC) in  order to verify whether the restored backups are healthy. You can also  scan backups using the IOCs you have. For example, if you have acquired a malicious file with the MD5 hash "ac596d282e2f9b1501d66fce5a451f00",  you can check whether there is an infection by searching this hash in  the backup systems.

#### Rebuild the new infrastructure 

In parallel with the investigation, it is crucial to rebuilding  infrastructure in isolation for the members of the various services.

#### Hardening 

100% security is almost impossible with the emerging technologies and the attacks and compromises we face are signs for us that shows our  hardening was insufficient and our operational team will have to review  and implement more strict hardening.

### Questions

1 - Which unit will have to make decisions about the strategic priorities? Answer format: X unit

> **Answer:** management unit

2 -  Which unit is responsible for determining the IOCs? Answer format: X unit

> **Answer:** operational unit

## Backups

Back-ups allow for a potentially quicker return to normal. back-up management is not a protection measure, on the other hand, a faulty back-up policy  may lead to the end of the business.

Whether you’re backing everything up internally, to external hard  drives, or to the cloud, etc. it is crucial that each back-up be  encrypted and the keys available via a means external to your company’s  IT systems.

### Rule of 3-2-1

The basic rule and the minimum expected for infrastructure, the 3-2-1 rule stipulates that you must:

Have at least three copies of your data

Store your back-ups on two different supports

Including an outsourced off-site back-up

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Crisis+Management/images/3-2-11.gif)

### Three Copies

The principle is to have your data on the server and two back-ups.  This is to prevent a failure from rendering your back-ups inoperative.

### Two Supports

Two supports mean having the back-up of our original data on two  different and unrelated points. So it is possible to have two copies of  the back-up on hard disks if both are not stored in the same data  center, not linked via the same software RAID, etc.

### Offsite back-up 

The idea behind this requirement is to have a back-up stored outside  of your building that contains the main data in order to protect against risks such as fires.

### Rule of 3-2-1-1-0 

This rule is to be applied at least to your company’s critical  resources. Identical to the 3-2-1 rule, it adds two more requirements: 

1 offline copy 

0 error while restoring

### One Offline Copy 

This is about having a back-up that is not tied to your network and  any IT infrastructure. The goal is to avoid that if an attacker has  compromised your network, he can intervene on this back-up.

### 0 Error While Restoring 

This may seem a logical requirement, but it will be a good practice  to test the back-ups regularly and to verify that they are restorable  without error. It will be damaging if, once restored, it is discovered  that a file on the database server is in fact damaged.

### Questions

1 - What is the “3” on the 3-2-1 rule?

> **Answer:** copy

## Alerts and End of Crisis

### Alert the Authorities

Do you know who should be alerted, what is the maximum duration to  alert them, and who is responsible for doing so? The answers to these  questions vary from organization to organization, the standards that the organization must meet, and its location.

### Alert Your Partners

Keep in mind that you are not alone. If your information system is  compromised, you can become a threat to your partners interconnected  with your network. Similarly, perhaps the attacker has come from one of  your partner’s networks and you, being more prepared, has detected it  while your partner failed.

In any case, communicating with your partners is a good practice.

### End of Crisis

#### Destruction or Preservation of Traces 

When the crisis is over, we should run the clean desk policy and any  helpful notes on the post-its, A4 papers, notebooks, on the computer,  etc. about the incident, must be destroyed.

In the case of ransomware, it may be interesting to keep encrypted  files on offline storage in case the encryption keys may be accessed in  the future.

#### Oversight 

At the end of the crisis, the personnel tend to relax after having  been under great pressure. It is therefore essential to supervise both  your new infrastructure and the staff.

#### Service Providers

The service providers who have accompanied you will surely offer you  to stay in contact, to sell you the “loaned” solutions for the  resolution of the crisis, etc. Take the time to reflect.











