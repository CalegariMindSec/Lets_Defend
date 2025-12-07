# Threat Hunting for Web Attacks

In today's digital landscape, web applications are prime targets for  cybercriminals employing sophisticated attack methods. Our Threat  Hunting for Web Attacks course is meticulously designed to empower you  with the skills needed to proactively identify and mitigate these  threats. Through a blend of theoretical insights and hands-on tutorials, you'll explore the techniques necessary to uncover hidden threats  within web traffic and infrastructure. This course will guide you  through the entire process of web-based threat hunting, from  understanding the underlying principles to applying advanced analytical  tools and methodologies.

**Table of Contents:**

- [Introduction](#introduction)
- [Common Web Attack Vectors](#common-web-attack-vectors)
- [Threat Hunting Techniques for Web Attacks](#threat-hunting-techniques-for-web-attacks)
- [SQLi-Based Unauthorized Data Access Hypothesis](#sqli-based-unauthorized-data-access-hypothesis)
- [Practical Lab 1](#practical-lab-1)
- [Practical Lab 2](#practical-lab-2)
- [Practical Lab 3](#practical-lab-3)

Evaluate Yourself with Quiz

- [Threat Hunting for Web Attacks](https://app.letsdefend.io/training/quiz/threat-hunting-for-web-attacks)

## Introduction

Web attacks are one of the most common and devastating security threats  businesses face today. Components such as web applications, servers, and APIs have become critical targets for attackers. The "Threat Hunting  for Web Attacks" course aims to outline the fundamental steps for  developing an effective defense against such attacks, understanding the  threat surface, and identifying vulnerabilities. This training focuses  on how a Threat Hunter can proactively monitor and prevent security  threats targeting web applications.

### Understanding the Web Attack Surface

The first step in developing an effective defense against web attacks is  understanding the web attack surface. Web applications, servers, and  APIs are among the critical points attackers may target. Each of these  components harbors potential security vulnerabilities. This section will focus on the scope of the web attack surface and how to analyze it.

### Web Applications

Web applications are the most frequently targeted points due to user  interactions and data processing. Common attack vectors such as SQL  injection, cross-site scripting (XSS), and cross-site request forgery  (CSRF) are often targeted.

Threat hunters use Dynamic Application Security Testing (DAST) tools to detect vulnerabilities in web applications. They perform log analysis to  detect abnormal user behavior. They conduct regular security tests and  code analyses to identify potential vulnerabilities and attack vectors.

### Servers

Web servers are critical systems where applications are hosted and data is  stored. Factors such as configuration errors, security vulnerabilities,  weak password policies, and outdated software can make servers  vulnerable.

The threat hunter periodically reviews server configurations and scans for  security vulnerabilities. They test password policies to detect weak  passwords and defend against malicious attempts. They implement regular  update and audit processes for outdated software and unpatched systems.

### APIs

Modern web applications use APIs (Application Programming Interfaces) to  exchange data with other services. APIs are vulnerable to risks such as  authentication weaknesses and data validation failures.

Threat hunters monitor API calls and responses and analyze logs for  vulnerabilities and anomalous activity. They regularly review API  gateways and security mechanisms to ensure API security. They test  authentication and data validation processes on APIs and identify  potential vulnerabilities.

Threat hunting actions specific to each web component help effectively monitor and manage potential web attack surface vulnerabilities.

### OWASP Top 10

The OWASP Top 10 is a report that identifies the most common and critical  web application security risks. The list, compiled by the Open Web  Application Security Project (OWASP), outlines the top threats and  vulnerabilities that developers and cybersecurity professionals should  consider. The OWASP Top 10 is recognized worldwide as a guide to secure  software development processes, reduce vulnerabilities, and make web  applications more secure. It is regularly updated to include the most  prevalent security risks.

![img](https://lh7-rt.googleusercontent.com/docsz/AD_4nXemwCUjWJyRm5FznmyqpGO1vcHqq84jOFRUrK7jmTdrpBZjYcnBOBVUbiFZ7dbYfewFIu5I99VQWuYC3YSXaRqFIOkPZRLIhIgAXhHOyoZjGgB7QQWcI-bw5GHJ0spITaT4Ku01NM1-PKXTFrdQw6Y?key=N3BZbcSrTGcMk9UQWfn5LOIB)

(**Image Source**: https://www.linkedin.com/pulse/what-should-project-leaders-know-owasp-top-10-niharika-srivastav)

This lesson has provided an introduction to the topic. The next lesson in the training will cover "**Common Web Attack Vectors.**”

## Common Web Attack Vectors

​    Web applications are  one of the most common targets for attacks in the modern digital world.  Therefore, developing proactive defense strategies against web-based  attacks is of critical importance for security teams. In this lesson,  various web attack vectors, mitigation measures and threat hunting  actions will be outlined.  

### SQL Injection  

SQL Injection occurs  when malicious code is injected into database queries through user input in web applications. This attack vector allows attackers to gain direct access to the database, modify, delete, or steal data.  

- **How It Happens:** The attacker injects  SQL code into user input points, such as web forms or URL parameters.  This code is executed on the database server, enabling unauthorized data access.    
- **Example**: SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'password';    
- **Prevention:** Techniques such as  parameterized queries, ORM usage, and input validation at the database  layer can prevent SQL Injection attacks.    
- **Threat Hunting Process:** Analyze SQL logs, detect suspicious query attempts, and investigate anomalous database query activity.    

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Web+Attacks/2.Common+Web+Attack+Vectors/image2_1.png)

(**Image Source**: https://portswigger.net/web-security/sql-injection)  

### Cross-Site Scripting (XSS)  

XSS is an attack vector that involves injecting malicious code (usually JavaScript) into web  pages. This code is executed in the browsers of other users, enabling  session hijacking or phishing attacks through fake forms.  

- **How It Happens:** The attacker injects a malicious script into an input field or URL in the web application.  When executed in a user’s browser, the script can steal user information or perform malicious activities.    
- **Example**: <script>alert('Hacked!');</script>    
- **Prevention**: XSS attacks can be  prevented through proper input filtering and encoding, and the  implementation of a Content Security Policy (CSP).    
- **Threat Hunting Process:** Analyze web application logs to detect unusual JavaScript activities, and investigate unexpected user-generated requests.    

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Web+Attacks/2.Common+Web+Attack+Vectors/image2_2.png)

(**Image Source**: https://portswigger.net/web-security/cross-site-scripting)  

### Cross-Site Request Forgery (CSRF)  

CSRF attacks allow  unauthorized actions to be performed using the identity of an authorized user. The attacker sends requests on behalf of a user who is logged  into a web application.  

- **How it happens:** While the user is  logged in, the attacker tricks the user into clicking a malicious URL  that performs an authorized action without the user's knowledge.    
- **Example**: Transferring funds from a user’s bank account to the attacker’s account.    
- **Prevention**: Prevention: CSRF tokens, Referer header checks, and double-submit validation methods can prevent CSRF attacks.    
- **Threat Hunting Process**: Examine user  requests, detect suspicious requests from different IP addresses, and  investigate unauthorized transaction attempts.    

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Web+Attacks/2.Common+Web+Attack+Vectors/image2_3.png)

(**Image Source**: https://portswigger.net/web-security/csrf)  

### File Inclusion Attacks  

This attack vector  allows attackers to include server files or external resources to harm  the web server or access sensitive data.  

- **Local File Inclusion (LFI)**: Attackers load local files from the server’s file system to exploit the server.    
- **Remote File Inclusion (RFI)**: Attackers load malicious files from external sources to take control of the server.    
- **Prevention**: Input validation, restricting dynamic file uploads, and proper file permissions can prevent such attacks.    
- **Threat Hunting Process**: Analyze file access logs, detect unusual access to local files, and investigate requests from external sources.    

### Brute Force Attacks  

Brute force attacks use trial and error to guess username and password combinations in an  attempt to gain access to a particular account or system.  

- **How It Happens:** The attacker uses automated tools to rapidly try various username and password combinations.    
- **Prevention**: Password complexity policies, two-factor authentication (2FA), and login attempt limits can protect against brute force attacks.    
- **Threat Hunting Process:** Analyze user login  logs, detect multiple failed login attempts from the same IP address,  and investigate account takeover attempts.    

### Path Traversal Attack  

Path Traversal attacks allow attackers to  gain unauthorized access to the file system of a web server. This attack vector typically occurs when user-supplied filenames are not properly  validated.

- **How It Happens**: The attacker uses  directory traversal characters (e.g., ../) to access sensitive files on  the server. For example, reading the /etc/passwd file.    
- **Example**: /../../etc/passwd    
- **Prevention:** Strict input validation and file access permissions can prevent such attacks.    
- **Threat Hunting Process**: Path traversal  attacks allow attackers to gain unauthorized access to the Web server's  file system, and can be carried out if there is a lack of proper input  validation when users enter file names.    

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Web+Attacks/2.Common+Web+Attack+Vectors/image2_4.png)

(**Image Source**: https://portswigger.net/web-security/file-path-traversal)  

### Denial of Service (DoS) and Distributed Denial of Service (DDoS) Attacks  

DoS and DDoS attacks aim to disrupt services by overwhelming the target system or exhausting its resources.  

- **How It Happens**: DoS attacks generate a large volume of traffic to a single system or network. On the other  hand, DDoS attacks use multiple sources to flood the system with traffic simultaneously.    
- **Prevention:** Load balancers,  traffic filtering, Intrusion Detection/Prevention Systems (IDS/IPS), and distributed network architectures can mitigate these attacks.    
- **Threat Hunting Process**: Use network traffic analysis tools to detect abnormal traffic patterns and investigate high-volume requests.    

### Summary  

Understanding Web  attack vectors and developing proactive defenses are fundamental steps  in creating a secure Web environment. The types of attacks listed above  are just a few of the most commonly encountered vectors. Appropriate  threat hunting techniques and defense strategies can minimize the impact of such attacks.  

This lesson has discussed common Web attack vectors. The next lesson will cover "Threat Hunting Techniques for Web Attacks".  

## Threat Hunting Techniques for Web Attacks

Developing an effective defense strategy against web-based attacks requires  advanced threat hunting techniques. We will cover a wide range of  techniques, from log analysis to manual investigation, in Threat Hunting Techniques for Web Attacks. The focus of this course is on best  practices for attack detection, monitoring, and prevention.

### Knowledge Requirements

To conduct effective threat hunting against web attacks, certain knowledge and technologies are essential.

- **Web Attack Vectors:** Web attack vectors include the primary methods and vulnerabilities  exploited by attackers. Deep knowledge of common attack types such as  SQL Injection, XSS, and CSRF is necessary to understand how these  attacks occur, which vulnerabilities they exploit, and how they can be  detected.
- **Network Protocols:** Understanding how network protocols such as HTTP, HTTPS, DNS, and TCP/IP work is  critical to analyzing Web traffic and identifying potential attack  vectors. It plays a key role in threat hunting to understand how  attackers can exploit these protocols.
- **Security standards:** Security standards such as the OWASP Top 10 list the most common web application vulnerabilities and attack vectors. Knowledge of these standards  provides a basic guide for vulnerability identification, assessment, and mitigation.

### Required Technologies and Tools

### Log Analysis (SIEM)

- **Purpose:** SIEM systems collect and analyze logs from various sources on a centralized  platform. SIEM can analyze logs from web servers, applications,  networks, and security devices.
- **Example:** Using SIEM, unusual HTTP requests to web servers can be detected. For  instance, SQL Injection attacks can be identified by specific SQL query  patterns. Rules can be created in SIEM to detect such patterns and flag  SQL Injection attempts.

### Network Monitoring (IDS/IPS)

- **Purpose:** IDS/IPS systems monitor network traffic to detect and block attack attempts.  IDS only detects attacks, while IPS can also block them.
- **Example:** IDS/IPS systems can detect Cross-Site Scripting (XSS) attacks by monitoring  specific JavaScript code patterns in web traffic. They can block certain HTTP requests to mitigate the impact of XSS attacks.

### Web Application Firewall (WAF)

- **Purpose:** WAF monitors and filters malicious traffic targeting web applications. It  provides protection against Layer 7 (application layer) attacks.
- **Example:** A WAF can detect Cross-Site Request Forgery (CSRF) attacks by analyzing  incoming requests and enforcing CSRF protections. It can identify  session hijacking or unauthorized transaction attempts and block them.

### Vulnerability Management (Vulnerability Scanning)

- **Purpose:** Vulnerability scanning tools identify security vulnerabilities in systems and  applications and provide recommendations for remediation.
- **Example:** Tools like Nessus or OpenVAS can detect vulnerabilities such as SQL Injection and Remote File Inclusion (RFI) in web applications. These tools  generate reports to help quickly address security gaps.

### Endpoint Detection and Response (EDR)

- **Purpose:** EDR systems detect, analyze, and automatically respond to abnormal activities on endpoints (servers, computers).
- **Example:** An EDR system can detect credential dumping attempts. For instance, if  an attacker tries to access the LSASS process, the EDR can detect and  block this activity. It can also monitor suspicious file changes and  process execution activities.

### Network Traffic Analysis Tools

- **Purpose:** Network traffic analysis tools examine all data flows on a network to identify abnormal behavior and potential attacks.
- **Example:** Tools like Wireshark can detect Denial of Service (DoS) or Distributed Denial of Service (DDoS) attacks by identifying unusually high traffic volumes and analyzing their sources. This enables timely mitigation measures.

### Integrating Threat Intelligence in Web Threat Hunting

### Using Threat Intelligence for Web Attacks

Threat Intelligence is a critical tool for enabling a more proactive and  effective defense against web attacks. When integrated into web threat  hunting, it provides information on current threat trends, attacker  tactics, techniques, and procedures (TTPs). This knowledge helps threat  hunters anticipate potential attack vectors, identify vulnerabilities,  and prepare for attacks. Threat Intelligence offers deep insights into  the tools, methods, and targets used by attackers, enabling more  effective configuration of security policies and defense mechanisms.

### Collecting and Using Indicators of Compromise (IoCs)

IoCs are critical indicators that show traces of an attack in a system or  network. In web threat hunting, IoCs can include suspicious IP  addresses, malicious file hashes, malicious URLs, and specific file  paths.

These indicators are used to detect and track attacks. IoCs can be collected  from threat intelligence sources (e.g., threat intelligence feeds or  reports) and integrated into security systems for automated detection  and response. Regularly updating IoCs ensures protection against new  threats and helps detect attacks at an early stage.

### Steps to Integrate Threat Intelligence into Web Threat Hunting

- **Identify Threat Intelligence Sources:** Determine reliable threat intelligence providers and ensure continuous updates from these sources.
- **Collect IoCs:** Gather suspicious IP addresses, malware hashes, phishing domains, and other  attack indicators, and integrate them into security systems.
- **Analyze and Correlate IoCs:** Compare collected IoCs with existing system logs and security events, create  correlation rules, and integrate these rules into tools like SIEM.
- **Develop Proactive Defense Strategies:** Use threat intelligence to create and update defense mechanisms for web applications and infrastructure.
- **Continuous Monitoring and Updating:** Continuously monitor and update threat intelligence, integrate new IoCs, and revise security policies based on this information.

Integrating threat intelligence into threat hunting enables faster detection of  attacks and more effective defense strategies. This process helps  maintain a proactive security posture and allows organizations to adapt  to the dynamic threat landscape.

This lesson discussed the technologies and tools used in the threat hunting  process to detect web attacks. The next lesson will cover the "**SQL Injection-Based Unauthorized Data Access Hypothesis**".

## SQLi-Based Unauthorized Data Access Hypothesis

### Hypothesis  

A Web application may  be vulnerable to attempts to gain unauthorized data access through SQL  injection. Attackers may attempt to gain access to the database by  injecting malicious SQL commands into the application's input forms or  URL parameters.  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Web+Attacks/4.SQL+Injection-Based+Unauthorized+Data+Access+Hypothesis/image4_1.png)

(**Image Source**: https://www.secrash.com/2023/08/exploiting-sql-injection-with-sqlmap.html?m=1)  

### Data Resources  

- **Web Server Logs:** Monitoring HTTP requests to the web server, especially for SQL Injection attempts.    
- **Database Logs:** Recording abnormal SQL queries.    
- **WAF Logs:** Logging SQL Injection attempts detected by the Web Application Firewall.    
- **SIEM Logs:** Collecting and analyzing logs on a centralized platform.    

### Analysis Steps  

- Forward web server logs to centralized log management or SIEM solution.    
- Search the log for SQL query patterns associated with SQL exploits (such as ';-- or ' OR '1'='1).    
- Identify suspicious and anomalous SQL queries in database logs.    
- Examine WAF logs to detect blocked or allowed SQL injection attempts.    
- Identify normal traffic patterns and monitor for deviations.    
- Identify potential attack vectors. Correlate with attacker information such as IP addresses and browser details.    
- Take action based on the severity of detected incidents.    

### Expected Results  

- Traces of SQL injection attempts are detected in web server logs and database logs.    
- WAF logs will confirm whether SQL injection attempts have been blocked or bypassed.    
- Based on the correlation analysis in the SIEM, it will be determined whether this activity is indicative of a potential attack.    

### Summary  

These analysis steps  provide strategies for detecting SQL injection attacks. Web server and  database logs are critical data sources for monitoring and identifying  such attacks. Anomaly detection enables early detection of potential  attacks and rapid response. It plays a critical role in ensuring Web  application security and proactive threat management.  

## Practical Lab 1

### Hypothesis

**Note**: The questions in this section are prepared for Threat Hunting based on the following hypothesis:

**Hypothesis:** Attackers could exploit the web application's file upload features to damage the  server or create backdoors by uploading malicious files.

### Threat Hunting Lab Environment

- SIEM (Wazuh)
- WAF Events (FortiWeb)
- Web Access Logs (Microsoft IIS)
- Firewall Traffic Events
- EDR Events (SentinelOne)

### Lab Notes

- Analyze the logs between "Aug 19, 2024 00:00 - Aug 23, 2024 00:00" to answer the questions below.
- Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

### Questions

**Note**: Analyze the logs between "Aug 19, 2024 00:00 - Aug 23, 2024 00:00" to answer the questions below.

**Note**: Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

1 - According to Microsoft IIS logs, what is the IP address of the system that sent the most requests to the "/upload.aspx" URL?

> **Answer:** 122.171.207.121

2 - What is the category of the log (attack log) generated by the WAF related to the requests made to the "/upload.aspx" URL?

> **Answer:** Web Shell Attack

3 - Which IP address appears most frequently in the events generated by the WAF  in relation to requests made to the "/upload.aspx" URL?

> **Answer:** 122.171.207.121

4 - What is the malicious file detected by SentinelOne EDR in the "C:\inetpub\w3svc01\uploads" directory on the web server?

﻿**Answer Format**: abcde.exe

> **Answer:** backdshell.aspx

5 - During previous stages of  the threat hunting process, the malicious file that was uploaded to the  web server was identified. What EPP action was taken regarding this file in the file upload events?

> **Answer:** kill-quarantine

6 - During previous stages of the threat hunting process, the malicious file that  was uploaded to the web server was identified. What is the IP address of the system that uploaded this file?

> **Answer:** 37.77.88.166

7 - During previous stages of the threat hunting process, the malicious file that  was uploaded to the web server was identified. What is the IP address of the system that made a GET request to this ".aspx" extension file (web  page)?

> **Answer:** 145.13.10.110

8 - During previous stages of the threat hunting process, the malicious file that  was uploaded to the web server was identified. What status code did the  web server return for the GET request made to this ".aspx" extension  file?

> **Answer:** 404

## Practical Lab 2

### Hypothesis

**Note**: The questions in this section are prepared for Threat Hunting based on the following hypothesis:

**Hypothesis:** A group of attackers could be trying to delete data by exploiting the SQL injection vulnerability on the organization's website.

### Threat Hunting Lab Environment

- WAF Events (FortiWeb)
- Web Access Logs (Microsoft IIS)
- SIEM (Wazuh)
- CTI Events ([Threat Intel LetsDefend Platform](https://app.letsdefend.io/threat-intelligence-feed))

### Lab Notes

- Analyze the logs between "Aug 19, 2024 00:00 - Aug 23, 2024 00:00" to answer the questions below.
- Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

### Questions

**Note**: Analyze the logs between "Aug 19, 2024 00:00 - Aug 23, 2024 00:00" to answer the questions below.

**Note**: Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

1 - According to WAF logs, what is the IP address of the system that conducted the most SQL Injection attacks?

> **Answer:** 133.171.7.21

2 - In the previous stages of the threat hunting process, the IP address of  the system that performed the most SQL injection attacks according to  WAF logs was identified. Among the events related to these web requests, what is the timestamp of the event where the "data.action" value is  “passthrough”?

**Answer Format**: May 11, 2025 @ 12:41:41.165

> **Answer:** Aug 21, 2024 @ 01:14:15.765

3 - In the previous stages of the threat hunting process, the IP address of  the system that performed the most SQL injection attacks according to  WAF logs was identified. Later, the event with the 'data.action' value  'passthrough' was identified among the events related to these web  requests. In this event, to which web URL was the request made?

> **Answer:** d/r/o/p/ /t/a/b/l/e /u/s/e/r/s;

4 - In the previous stages of  the threat hunting process, the IP address of the system that performed  the most SQL injection attacks according to WAF logs was identified.  Later, the event with the 'data.action' value 'passthrough' was  identified among the events related to these web requests. What is the  web server response code for this event?

> **Answer:** 200

5 - During previous stages of  the threat hunting process, the IP address of the system that performed  the most SQL injection attacks, according to WAF logs, was identified.  Later, among the events related to these web requests, the event with  the "data.action" value "passthrough" was identified. Which other IP  address accessed the web URL that received the request in the previously mentioned event?

> **Answer:** 133.191.71.21

6 - In the previous stages of the threat hunting process, the IP address of  the system that performed the most SQL injection attacks according to  WAF logs was identified. According to the CTI platform ([Threat Intel LetsDefend Platform](https://app.letsdefend.io/threat-intelligence-feed)), which APT group does this IP address belong to?

> **Answer:** APT-W38

7 - In the previous stages of  the threat hunting process, the IP address of the system that performed  the most SQL injection attacks according to WAF logs was identified.  Later, the name of the APT group associated with this IP address was  found via the CTI platform. Among the other IP addresses reported for  this APT group, what is the IP address for which the WAF action is  “blocked”?

> **Answer:** 133.111.17.10

8 - In the previous stages of  the threat hunting process, the IP address of the system that performed  the most SQL injection attacks according to WAF logs was identified.  Later, the name of the APT group associated with this IP address was  found via the CTI platform. Then, among the other reported IP addresses  for this APT group, the IP address for which the WAF action was  “blocked” was identified. What is the attack category for this event?

> **Answer:** Remote Code Execution Attack

## Practical Lab 3

### Hypothesis

**Note**: The questions in this section are prepared for Threat Hunting based on the following hypothesis:

**Hypothesis:** Attackers could be trying to access sensitive data by accessing outdated backup  files (.bak, .zip, .tar, etc.) that were left on the web server.

### Threat Hunting Lab Environment

- Web Access Logs (Microsoft IIS)
- SIEM (Wazuh)

### Lab Notes

- Analyze the logs between "Aug 19, 2024 00:00 - Aug 23, 2024 00:00" to answer the questions below.
- Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

### Questions

**Note**: Analyze the logs between "Aug 19, 2024 00:00 - Aug 23, 2024 00:00" to answer the questions below.

**Note**: Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

1 - According to web logs, what is the IP address that returned the most "response status code 404"?

> **Answer:** 91.121.109.67

2 - According to the CTI platform([Threat Intel LetsDefend Platform](https://app.letsdefend.io/threat-intelligence-feed)), which APT group does the IP address that returned the most "response status code 404" in the web logs belong to?

> **Answer:** APT-Q70

3 - For the IP address that received the most "response status code  404" in the web logs, how many distinct URLs returned a response status  code 200 (success) within the same date range?

> **Answer:** 6

4 - According to web logs, the IP address that most frequently returned "response  status code 404" also returned "status code 200" (success) to various  URLs within the same time frame. What is the name of the file with one  of the “.bak”, “.zip”, “.tar” extensions among those URLs?

> **Answer:** mysql.zip

5 - According to web logs, what is the admin panel login URL for which the IP address that returned the most "response status code 404" returned a status code 200 (success)  within the same date range?

> **Answer:** /admin/login.aspx

6 - Excluding the IP address that received the most 404s, according to web logs, what is the IP address that accessed the zip file with response status code  200 (success) during the same date range as the IP address that returned the most "response status code 404"?﻿

> **Answer:** 121.13.10.17

7 - According to web logs, what is the most frequently used "user-agent" by the IP address that received the most 404s?

> **Answer:** DirBuster-1.0-RC1









































































