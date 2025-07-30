# Writing a Report on Security Incident

Writing a clear report is really important to understand what you did exactly for other people.

**Table of Contents:**

- [Introduction to Technical Writing](#introduction-to-technical-writing)
- [Reporting Standards](#reporting-standards)
- [Reporting Style](#reporting-style)
- [Report Formatting](#report-formatting)
- [Report Templates](#report-templates)

## Introduction to Technical Writing

### Introduction to Technical Writing

One of the most important skills a SOC analyst must possess is the ability  to write technical documents. Let's say you have analyzed an important  ransomware case, you did everything as it should be, you identified the  root cause of the incident, and took the necessary actions. If you  cannot convey this situation to your teammates and management correctly, the process will not be considered complete. Because the rest of the  team members could not master the details of the incident due to  insufficient communication.

Everyone knows how important communication is in teamwork, so we  won't emphasize it again and again. The subject of this training is to  develop your skills in written communication. Some important issues to  consider when writing a technical article/documentation/report:

- Audience
- Flow
- Intelligibility

#### Audience

Knowing who will read the content we will prepare is important to  determine the details of the content. For example, let's say we are  preparing an incident report that the CEO wants to read, your CEO's  cybersecurity technical level may not be as deep as yours. Some details  that are important to you (MITRE techniques, IOC, etc.) may be  meaningless to the target audience. For this reason, it is necessary to  create a report that appeals to people.

#### Flow

Regardless of who will read your report, your report should have a  flow. It would not be appropriate to give some information about the end of the Incident and then explain the beginning and create confusion.  For this reason, it is necessary to prepare a sequential report with a  certain flow. Thus, the reader can create the timeline in his head.

#### Intelligibility

The sentences we use should be understandable to the reader. We  should not complicate the understanding of the report by using complex,  inverted sentences.

If we pay attention to these issues in general, we can say that a successful report will emerge.

### Why Do We Write Reports?

There is no single reason to create a report. Sometimes due to legal  obligations, sometimes due to the request of the administrator, a report can be created. Even if there are no situations that require us as  analysts to write a report, we should write a report of the events we  examine.

Think of an incident you analyzed two months ago. How much detail can you remember about that situation? Assuming you review dozens of alerts every day, you can't remember much. When a new situation arises about  the incident you examined two months ago, you will probably be the  person your manager will want to get details from. However, if you do  not have a written report or note, it will not be easy for you to  respond.

Or imagine making a job change. You have all the information about  the analysis you have done, the team has no idea about these situations. Such situations affect the transfer of information within the team in a negative way.

In short, writing a good report is important and must be written for  the well-being of both the individual and the team. Although it is often seen as a waste of time and neglected, it provides the solution to many problems that may be seen in the future.

## Reporting Standards

The reports we will prepare must have a certain standard. Thus, the reader  can guess whether the information they want is in the report or not,  without reading the report, and can quickly reach the result if they are looking for just one piece of information. For example, an  administrator who is curious about the root cause of the incident can  quickly open and read the relevant section of the report. Otherwise, the entire report should have been read in detail. In this section, we will explain which topics we should pay attention to and touch on in general and technical (cyber security) in order to create a standard while  writing a report.

### Intelligibility

As we mentioned in the Introduction section, content should be  prepared according to the readership of the report. In a report to be  sent to the CEO of the company, it will not be necessary to mention  technical issues such as MITRE techniques and hacking tools used by the  APT group. Therefore, you can create an "Executive Summary" section in  the report and write a summary of the incident without mentioning the  cyber security techniques.

### Timeline

Our report should proceed according to a certain timeline. It should  be stated step by step what the attackers and the SOC team did on what  date. The reader should feel himself in a short film. Thus, such  questions are avoided: What did our team do while the attackers were  doing activity X? When did you block the X.X.X.X IP address? etc.

### Repeatability

The technical details in the report should be written in a way that  can be repeated. Let's say you find malware hidden on the server and add that file to the report that it exists. If you do not specify the  methods and techniques you used to find this hidden file, the person(s)  reading the report cannot perform these activities again. If the same  incident happens again on a different date, the analyst reading the  report will be wasting time because he or she will not be able to apply  the same steps again.

### Focus on a single subject

The subject of your content should be fixed. If you are preparing an  incident report, you should not mention matters unrelated to the  incident. Thus, the subject's integrity is ensured and a more easily  understandable report emerges.

## Reporting Style

### Past Tense Patterns

While preparing the report, you should prepare your sentences using  past tense patterns. The main reason for this is that the event happened in the past.

### Short and Concise Sentences

Your sentences should be clear, short, and concise. As a result, you  are preparing a report, not a novel, and you need to convey the  information to the reader as soon as possible.

For example, instead of saying "Mysterious and frightening hacker  group, whose identity is unknown, made SQL injection attempts on the  team's favorite server, and failed against the security of our server",  you can say "The attacker(s) of unknown origin attempted SQL injection  on the web server and failed". A short and clear sentence can be formed.

### Share Important Details

Do not hesitate to share data that may be necessary when making a  statement about a topic. “We have detected various malware on our  servers.” sentence will not be enough for the SOC team. It is not clear  what type of malware was detected on which server. “Mimikatz.exe  malicious software that is used to capture user passwords has been  detected on our web servers with IP addresses 192.168.10.15 and  192.168.10.16.” When you read this sentence, you can understand exactly  what kind of threat is on which server.

### Focus on What You Do

In the report, you should mention the events that took place. For  example, if you did not perform a memory analysis in the system, there  is no need to specify that there is no memory analysis unless there is a very special situation. If giving this detail is important for the  content of the report, information should be given about why the  transaction could not be performed.

“The data in memory was lost because the operating system was  restarted by the attacker, so memory analysis could not be performed.” A sentence created in this way is meaningful because it depends on the  cause and effect relationship and can be found in the report.

### Be Careful When Using Abbreviations

Too many abbreviations are used in the cybersecurity world. Some of  them are IOC, IDS, IPS, AV, EDR, etc. While these abbreviations may  sound familiar to you, they may be meaningless to others, so you should  specify the explanation when using them for the first time. For example, if you are using IOC for the first time in the report, you should write it as IOC (Indicator of Compromise). This way, the reader will better  understand what you mean.

### Show Consistency in Using Words

For example, when describing a device at the beginning of the report, when using the word "host", instead of using different words such as  "endpoint", "system", or "node" in a different part, it is necessary to  use "host" continuously.

## Report Formatting

When creating a professional report content, it is necessary to set  standards on issues such as date, font, text color, tables, and  references.

### Date and Time

The same format should always be used when writing date information.  For example, after specifying a date with "June 16, 2022", a format like "16/06/2022" should not be used. Standards should be maintained, using  the same format over and over.

In terms of time, timezone information should be shared and the same  timezone value should be used. A timezone value other than GMT+2 should  not be used in the continuation of a report that starts with 06:12  GMT+2. Confusion may occur when used, and various calculations have to  be made to better understand the report.

### Font

It is important to choose a font that is readable and formal. Font  selections such as “Comic Sans” should be avoided even though they are  pleasant but not official. Multiple font selection should not be an  issue as long as consistency is maintained. For example, all the  paragraphs of the report can be written in “Arial” font, while the  headings can be written in “Verdana”.

### Table and Visual Usage

Appropriate use of tables are very important for the reader. If you  want to list more than one content with more than one feature, the  tables will help you. For example, you can show the list of hosts  captured by the attacker with a table. You can also share the hostname  and IP information of the host. Sample:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Writing+a+Report+on+Security+Incident/images/table.png)

### Data Details

If detailed information about the data is to be shared, the same  details should be added for all data. For example, if the SHA256 hash of the “mimikatz.exe” file used by the attacker, file name, creation date, and path information is added to the report, the same data should be  shared for other files used by the attacker.

### Lists

You can use bullet or numbered lists for long lists that you do not want to write in paragraphs. For example:

1. mimikatz.exe
2. nc.exe

- SusieHost
- GitServer
- Web-Server

## Report Templates

In order to prepare consistent reports, reports should follow an ordered  template. This section will talk about the points you need to pay  attention to when preparing an incident report template.

### Table of Contents

This is the section that specifies the content of the report. The  titles and page numbers of the pages are specified. If there is a part  that the reader wants to reach directly, he can use this part.

### Incident Background

This is the section that explains how an Incident is detected, what  is detected first, and what actions are taken. Time information should  also be shared while describing events. It doesn't need to be too long, a few paragraphs of explanation will suffice.

### Findings

This is the section where the findings we detected during the investigation will be explained.

### Recommendations

This is the section where long and short-term recommendations will be shared regarding the incident. For example, for a system affected by  the MS17-010 vulnerability, a quick update may be a short-term  recommendation, while investing in EDR solutions may be a long-term  recommendation. It is a very important section for teams/persons who are not experts in the subject and will take action against this situation.

### Timeline

This is the section in which the event is sorted by time. There is no need to share all the details of the event, just focus on the important parts. The aim is to quickly convey how and at what time the event  occurred in general.

The time formats given in this section should be fixed. While giving a time in UTC format in the first stage, using a format like GMT+3  afterward will cause confusion.

### Appendices

It is often used for long listings. If the list that needs to be  shared is more than one page and affects readability, it can be shared  in the appendix. For example, the IP list the attacker is port scanning.

In general, we talked about which sub-headings/sections should be in a report and their details. Now you have important ideas about what parts you should focus on when preparing a report.























