# Threat Hunting for Privilege Escalation

This  course is designed to equip cybersecurity enthusiasts and professionals  with the skills needed to identify and respond to privilege escalation  threats. Privilege escalation is a critical security risk where an  attacker gains elevated access to resources that should be restricted.  Through a series of guided tutorials, hands-on labs, and real-world case studies, you'll learn how to spot the subtle signs of privilege  escalation attempts within a network. We will explore various tools and  methodologies employed to detect and neutralize these threats, enhancing your capability to maintain a secure IT infrastructure.

**Table of Contents:**

- [Introduction]()
- [Understanding Privilege Escalation]()
- [Preventing and Detecting Privilege Escalation]()
- [Privilege Escalation Attack Vectors]()
- [OS-Based Privilege Escalation Attacks]()
- [Abnormal User Account Activity Hypothesis]()
- [Practical Lab]()

Evaluate Yourself with Quiz

- [Threat Hunting for Privilege Escalation](https://app.letsdefend.io/training/quiz/threat-hunting-for-privilege-escalation)

## Introduction

Privilege escalation  attacks are considered one of the most dangerous and destructive threats in the cybersecurity world. In such attacks, attackers typically  exploit vulnerabilities in the system to elevate their initial low-level user privileges to higher levels. Successful privilege escalation  allows attackers to gain broader access within the system, access  critical data, and even gain full control of the system.  

Privilege escalation  attacks can have serious consequences, especially in large and complex  systems. Therefore, threat hunting processes are critical to detecting  and preventing such attacks. Threat hunting is the proactive process of  searching for threats within an organization's network and systems, and  plays a critical role in the early detection of privilege escalation  attacks.  

Threat hunters monitor  potential vulnerabilities, suspicious activity, and anomalous behavior  within the system to identify and thwart attackers' privilege escalation attempts. Effective threat hunting strategies create a strong line of  defense to detect and stop attacks, ensuring the security and integrity  of the system. Preventing privilege escalation attacks is not only a  technical necessity, it is also critical to ensuring business continuity and data security.  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Privilege+Escalation/1.Introduction/image1_1.png)

(**Image Source**: https://medium.com/@aisnurrrr/privilege-escalation-a3df9fb040e6)  

This lesson has provided an introduction to the topic. The next lesson will cover "Understanding Privilege Escalation”.  

## Understanding Privilege Escalation

Privilege escalation  occurs when a user gains access to a higher level of privileges than  they were originally granted. It is often accomplished through malicious actors who exploit system vulnerabilities, security flaws, or  misconfigurations. Successful privilege escalation allows an attacker to access critical data, gain administrative privileges, and even take  complete control of the system.  

### Types of Privilege Escalation   

Privilege escalation  (or privilege elevation) is an attempt by an attacker or user to gain  access to the privileges of a more privileged account within a system.  There are two main types of privilege escalation: vertical and  horizontal.  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Privilege+Escalation/2.Understanding+Privilege+Escalation/image2_1.png)

(**Image Source**: https://community.exabeam.com/s/article/Privilege-Escalation-Use-Case-Chapter-1-Introduction)  

Vertical privilege  escalation occurs when a user elevates his or her current privileges to  gain higher-level privileges, such as administrative access. This is  usually accomplished by exploiting system or application  vulnerabilities.  

In horizontal  escalation, the attacker remains at the same privilege level but gains  access to the privileges of another user at the same level. This is  often the result of authentication security flaws or misconfigurations.  

To prevent both types  of attacks, it is important to keep security patches current, implement  strong authentication, and perform regular security scans.  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Privilege+Escalation/2.Understanding+Privilege+Escalation/image2_2.png)

(**Image Source**: https://delinea.com/blog/linux-privilege-escalation)  

### Vertical Privilege Escalation  

Vertical privilege  escalation is a type of attack in which an attacker elevates his or her  initial low-level privileges to higher-level privileges, such as  administrative or root access. In such attacks, attackers typically gain access to a standard user account and then exploit system  vulnerabilities to escalate their privileges.  

### How It Is Carried Out  

- **Vulnerability Exploitation:** Attackers exploit  security vulnerabilities in the operating system or installed  applications to elevate their privileges. For example, a buffer overflow vulnerability may allow an attacker to execute code and escalate their  privileges.    
- **Misconfigurations:** System  misconfigurations can enable attackers to escalate privileges. For  instance, if a file is misconfigured to run with administrative rights,  an attacker can execute it to gain administrative access.    
- **Vulnerable Services:** Some system services, especially those running with low privileges, may contain security  flaws. Attackers can target these services to gain administrative  rights. For example, a vulnerability in a web server application running under a low-privilege account could allow an attacker to escalate to  administrative privileges.    

### Impact  

- **Full System Control:** Once an attacker  gains administrative or root access, they can take full control of the  system. This allows them to access all data, harm other users, or even  disable the system entirely.    
- **Persistence:** Vertical privilege  escalation enables attackers to establish persistence on the system.  With administrative rights, they can install malware, create backdoors,  and maintain access for future attacks.    

### Horizontal Privilege Escalation  

Horizontal privilege  escalation takes place when an attacker gains access to another user's  privileges at the same level without attempting to elevate his or her  own privileges. Instead, the attacker extends their reach within the  system by compromising other user accounts or data.  

### How It Is Carried Out  

- **Credential Theft:** Attackers may use  phishing, brute force attacks, or social engineering to steal another  user's credentials. With these credentials, they can access other  accounts at the same privilege level.    
- **Session Hijacking:** Attackers can hijack  an active user session to gain access to the system using that user's  privileges. This allows them to act as another user without elevating  their own account privileges.    
- **Permission Errors and Misconfigurations:** If a system fails to  properly separate user permissions, attackers can exploit this to access other users' accounts. For example, improperly shared files within a  user group can create opportunities for horizontal privilege escalation.    

### Impact  

- **Data Theft:** Attackers can steal sensitive information by accessinz another user's account and the data they have access to.    
- **Impersonation:** Attackers can  impersonate legitimate users to interact with other system components or users, allowing them to remain undetected and cause further damage.    
- **Bypassing Security Measures:** Horizontal privilege  escalation can assist attackers in bypassing existing security controls. For example, they may use a legitimate user account to bypass security  checks.    

### The Role of Privilege Escalation in Threat Hunting  

- **Vertical privilege escalation:** Threat hunting  focuses on identifying methods attackers use to gain administrative or  root privileges. This includes analyzing vulnerability exploits,  privilege-elevating malware, or files that can be run with  administrative privileges.    
- **Horizontal privilege escalation:** Threat hunting  focuses on identifying lateral movement and credential theft. Unexpected transitions between user accounts, session hijacking attempts, and  credential compromise incidents are key indicators of such attacks.    

This lesson has covered what privilege escalation is, its types, how it is performed, its  impact, and its role in the threat hunting process. The next lesson will cover “Preventing and Detecting Privilege Escalation Attacks”.  

## Preventing and Detecting Privilege Escalation

### Preventing Privilege Escalation Attacks  

In cybersecurity, an  effective attack prevention strategy is always better than having a  disaster recovery plan. Below are the fundamental measures that can be  taken to prevent privilege escalation attacks.  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Privilege+Escalation/3.Preventing+and+Detecting+Privilege+Escalation+Attacks/image3_1.png)

(**Image Source**: https://securitytrails.com/blog/privilege-escalation)  

### Regular System Updates  

- **Explanation:** Keeping systems  protected with the latest patches reduces the risk of known  vulnerabilities in software programs or operating systems being  exploited by threat actors. Therefore, establishing a patch management  strategy is crucial.    
- **Recommendation:** Define regular patch  management processes within your organization and strictly follow them.  You can use automated patch deployment tools to simplify this process.    

### Implementing Strong Authentication Methods  

- **Explanation:** Using two-factor  authentication (2FA) or multi-factor authentication (MFA) can prevent  credential theft and make it harder for malicious actors to gain  unauthorized access.    
- **Recommendation:** Enforce MFA for all  critical systems, especially for high-privilege accounts. This  significantly increases the difficulty of account compromise.    

### Monitoring User Activity  

- **Explanation:** Monitoring user  activity can provide clues that a privileged account has been  compromised. Detecting privilege escalation requires monitoring for  sudden changes in user behavior or unusual activity by system  administrators.    
- **Recommendation:** Use Security  Information and Event Management (SIEM) tools to monitor user behavior.  Set up automated alerts to quickly respond to suspicious activities.    

### Strong Password Security Policies  

- **Explanation:** Password policies  should require users to create secure, complex passwords and update them regularly. This is especially important for large organizations.    
- **Recommendation:** Ensure password  policies mandate passwords of at least 12 characters, including  uppercase and lowercase letters, numbers, and special characters.  Additionally, require passwords to be changed at regular intervals  (e.g., every 60 days).    

### Least Privilege Principle  

- **Explanation:** Apply the principle  of least privilege by ensuring that users have only the privileges they  need to perform their tasks. This will reduce the potential damage if an attacker compromises a user's account.    
- **Recommendation:** Periodically review  user authorization processes and remove unnecessary privileges.  Establish processes to automatically revoke temporary high-privilege  access.    

### Sudo Access Control  

- **Explanation:** In Linux  environments, controlling sudo access can help prevent privilege  escalation incidents. Properly managing sudo privileges and periodically reviewing who can run commands with elevated privileges mitigates this  threat.    
- **Recommendation:** Regularly review sudo users and their privileges. Remove unnecessary sudo privileges and  restrict the use of sudo to specific commands.    

In conclusion, a  strategic combination of strong cybersecurity practices and tools  combined with continuously updated security measures can be effective in preventing privilege escalation attacks.  

### Detecting Privilege Escalation Attacks  

Preventing unauthorized access and protecting system security depend on effective detection  capabilities. Below are various methods organizations can use to detect  privilege escalation attacks:  

### Auditing System Logs  

- **Explanation:** Regularly reviewing  system logs can help detect unusual behavior patterns or suspicious  activities, such as repeated failed login attempts or abnormal command  usage.    
- **Recommendation:** Use log management  tools to automate log review processes. You can filter for specific  keywords or patterns to detect suspicious activities more quickly.    

### Anomaly Detection Tools  

- **Explanation:** Use anomaly detection tools to identify deviations from normal behavior on your network. For  example, sudden changes in user roles may indicate an ongoing privilege  escalation incident.    
- **Recommendation:** Deploy anomaly  detection systems for network traffic and user behavior. Configure these tools to learn your system's typical behavior patterns and detect  deviations.    

### User and Entity Behavior Analytics (UEBA)  

- **Explanation:** UEBA uses machine  learning algorithms to understand typical user behavior patterns and  detect potential privilege escalation attempts. It can alert you when  deviations from the norm occur.    
- **Recommendation:** Train UEBA tools to  learn the typical behaviors of each user and entity in your system. Use  these tools to automatically detect anomalies.    

### Password Monitoring  

- **Explanation:** Implement password  monitoring to alert you when passwords are changed without  authorization. The change could indicate that an attacker is attempting  to maintain elevated privileges over time.    
- **Recommendation:** Use password management tools to monitor password changes and generate automatic alerts for unauthorized changes.    

### Intrusion Detection Systems (IDS)  

- **Explanation:** IDS can scan for  signatures of known privilege escalation techniques, allowing attacks to be detected in their early stages before significant damage occurs.    
- **Recommendation:** Configure IDS systems to recognize common attack techniques in your environment. Ensure the  IDS is continuously updated with the latest attack signatures.    

In conclusion, early  detection of privilege escalation attacks is fundamental to maintaining  system security. The methods and tools outlined above provide effective  strategies for detecting and preventing such attacks. The combination of a trained cybersecurity team and robust detection tools increases the  security of your system and reduces the chances of success for  attackers.  

This lesson has discussed methods for detecting and preventing privilege escalation attacks. The next lesson will cover "Common Techniques for Privilege Escalation”.  

## Privilege Escalation Attack Vectors

Privilege escalation is a technique used by cyberattackers to gain unauthorized access to a  system. It can occur through various attack vectors such as stolen  credentials, misconfiguration, malware, or social engineering.  Understanding and detecting these attack vectors is critical to  effective threat hunting.  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Privilege+Escalation/4.Privilege+Escalation+Attack+Vectors/image4_1.png)

(**Image Source**: https://www.beyondtrust.com/blog/entry/privilege-escalation-attack-defense-explained)  

### Malware  

Attackers often use  malware payloads to attempt to escalate privileges on target systems.  This type of attack typically begins with gaining basic access to the  system, after which the attacker uses a malicious payload to elevate  their privileges within the system.  

### Threat Hunting Process  

- **Signs to Watch For:** Unusual file  modifications, unexpected file executions, or a sudden increase in  process usage on the system before the malware infects it.    
- **Detection Methods:** Use anti-malware  tools and SIEM (Security Information and Event Management) solutions to  monitor suspicious file activities and execution attempts. Continuously  review system events to identify potential privilege escalation  attempts.    

### Credential Exploitation  

Attackers may attempt privilege escalation by exploiting weak user accounts or stealing  credentials. Once they have credentials, attackers can act as privileged users to carry out malicious actions.  

### Threat Hunting Process  

- **Signs to look for:** Unexpected login attempts to user accounts, especially from different IP addresses for the same account.    
- **Detection Methods:** Monitor the behavior  of user accounts using User and Entity Behavior Analytics (UEBA). Set up alert mechanisms to be triggered when suspicious activity is detected.  In addition, enforce strong password policies to make it more difficult  to exploit credentials.    

### Vulnerabilities and Exploits  

A common method of  privilege escalation in Linux and Windows is to exploit software  vulnerabilities. For example, if an application does not comply with the principle of least privilege, it can result in vertical privilege  escalation, allowing an attacker to gain root or administrative  privileges.  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Privilege+Escalation/4.Privilege+Escalation+Attack+Vectors/image4_2.png)

(**Image Source**: https://www.bmc.com/blogs/security-vulnerability-vs-threat-vs-risk-whats-difference/)  

### Threat Hunting Process  

- **Signs to look for:** Outdated software without system updates, scan results for specific vulnerabilities, and attempts to exploit vulnerabilities.    
- **Detection Methods:** Periodically scan for vulnerabilities and use patch management systems to remediate  vulnerabilities. Configure IDS/IPS systems to detect exploitation  attempts against known vulnerabilities.    

### Misconfigurations  

Sometimes system  administrators create an environment that allows horizontal privilege  escalation through misconfiguration errors. These situations can include granting unnecessary sudo access or failing to properly secure  privileged account information.  

### Threat Hunting Process  

- **Signs to Watch For:** Unexpected permission changes, unnecessarily granted high privileges, and misconfigured services.    
- **Detection Methods:** Use configuration  management tools and policies to regularly review misconfigurations.  Conduct frequent privilege audits to remove unnecessary privileges.    

### Social Engineering  

This method relies  heavily on human interaction rather than technical vulnerabilities. In a typical scenario, attackers trick employees into revealing their login  credentials, giving them easy access to secure networks. Detecting  social engineering attacks requires a human-centric approach.  

### Threat Hunting Process  

- **Signs to Watch For:** Unusual requests from employees, unexpected password changes, or account lockouts.    
- **Detection Methods:** Reduce social  engineering attacks through training and awareness programs.  Additionally, use security monitoring tools to detect suspicious account activities.    

In this lesson, we discussed common privilege escalation attack vectors. The next lesson will cover "OS-based Privilege Escalation Attacks”.  

## OS-Based Privilege Escalation Attacks

Privilege escalation attacks can be specific to the operating system. In particular, widely  used operating systems such as Linux and Windows can be targeted in a  variety of ways. The following is a discussion of OS-specific privilege  escalation attacks and how they can be detected by the threat hunting  process.  

### Linux Privilege Escalation Attacks  

The open-source nature  of the Linux operating system can make it vulnerable to certain  privilege escalation attacks. Below are some common Linux privilege  escalation methods and measures to mitigate them.  

### Kernel Exploitation  

Kernel exploitation  involves attackers exploiting vulnerabilities in the Linux kernel to  gain root privileges. These vulnerabilities allow attackers to execute  malicious code and elevate their privileges.  

**Threat Hunting Process**  

- **Signs to Look For:** Unexpected kernel-level processes, missing kernel updates, or abnormal system behavior.    
- **Detection Methods:** Use kernel exploit  scanning tools to detect kernel vulnerabilities and apply updates  regularly. Monitor kernel-level activities using SIEM solutions to  identify abnormal behavior.    

### Enumeration  

Attackers can gather  information about user accounts, network resources, or installed  software on the system to plan their attacks.  

**Threat Hunting Process**  

- **Signs to Look For:** Unexpected system scans, unusual queries targeting user accounts, or attempts to gather information about network resources.    
- **Detection Methods:** Use network  monitoring tools and IDS/IPS systems to monitor network traffic. Set up  automated alerts for unexpected information-gathering activities.    

### SUDO Right Exploitation  

Attackers can exploit  misconfigured sudo privileges. If a user has not carefully managed sudo  privileges, an attacker could use these privileges to gain elevated  privileges on the system.  

**Threat Hunting Process**  

- **Signs to Look For:** Unexpected use of sudo commands, especially by unauthorized users.    
- **Detection Methods:** Review sudo usage regularly. Use log management and SIEM solutions to detect unauthorized sudo usage.    

### Windows Privilege Escalation Attacks  

Windows is a widely  used operating system in the enterprise, making it a common target for  privilege escalation attacks. The following are some common Windows  privilege escalation techniques and mitigations.  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Privilege+Escalation/5.OS-Based+Privilege+Escalation+Attacks/image5_1.png)

(**Image Source**: https://delinea.com/blog/windows-privilege-escalation)  

### Access Token Manipulation  

This technique involves attackers manipulating access tokens of privileged accounts to trick  the system into granting them higher-level access.  

**Threat Hunting Process**  

- **Signs to Look For:** Unexpected access token operations or bypassing authorization controls.    
- **Detection Methods:** Regularly review  Windows Event Logs to monitor access token operations. Use security  tools that detect token manipulation attempts.    

### Bypass User Account Control (UAC)  

An attacker can use  hidden processes to bypass UAC (User Account Control) prompts and make  unauthorized changes. These processes do not trigger UAC warnings,  allowing the attacker to escalate privileges unnoticed.  

**Threat Hunting Process**  

- **Signs to Look For:** UAC bypass attempts or high-privilege operations that do not trigger UAC warnings.    
- **Detection Methods:** Use security software that detects UAC bypass techniques. Regularly monitor and analyze high-privilege processes on the system.    

### Sticky Keys Attacks  

This attack involves  replacing the file "sethc.exe" (Sticky Keys application) with "cmd.exe"  (Command Prompt). This allows the attacker to gain administrative  privileges by pressing the Shift key five times on the login screen.  

**Threat Hunting Process**  

- **Signs to look for:** Unexpected changes to the Sticky Keys file or unexpected use of cmd.exe.    
- **Detection Methods:** Use tools that monitor changes to system files. Check logs regularly for abnormal activity related to Sticky Keys.    

### Summary  

Identifying privilege  escalation attack vectors is an integral part of effective threat  hunting. Understanding common attack vectors such as malware, credential exploitation, software vulnerabilities, misconfigurations, and social  engineering is essential to maintaining system security. For Linux and  Windows systems, understanding these attack vectors is vital to the  threat hunting process. A trained security team equipped with the right  tools can detect and prevent privilege escalation attacks early.  Proactively monitoring these vectors creates a strong line of defense to catch and contain threats early.  

This lesson discussed privilege escalation attacks against Linux and Windows. The next lesson will cover the "Abnormal User Account Activity Hypothesis".  

## Abnormal User Account Activity Hypothesis

### Hypothesis

An unusually high  number of failed login attempts or a sudden increase in authorization  requests on a specific user account may indicate a privilege escalation  attempt.  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Threat+Hunting+for+Privilege+Escalation/6.Abnormal+User+Account+Activity+Hypothesis/image6_1.png)

(**Image Source**: https://github.com/qeeqbox/vertical-privilege-escalation)  

### Data Sources  

- **Active Directory Logs**: User login attempts, authorization requests, failed login attempts, account lockouts.    
- **SIEM Logs**: Active Directory and other security logs collected on a centralized platform.    
- **Endpoint Detection and Response (EDR) Logs**: Activities performed by user accounts on the system.    
- **Application Logs**: User access and usage activities within applications.    

### Analysis Steps  

### Collecting and Reviewing Logs  

- Forward Active Directory logs to a centralized SIEM solution.    
- Monitor user login attempts, authorization requests, and account lockouts periodically.    
- Collect Collex EDR logs and analyze user activity.    

### Identifying Normal Behavior  

- Analyze users' normal login and authorization behaviors to create a baseline.    
- Define threshold values for abnormal activities on specific user accounts.    

### Detecting Abnormal Activities  

- Investigate unexpected increases in failed login attempts on a specific user account.    
- Determine if user accounts are being accessed from unusual times or IP addresses.    
- Check for abnormal increases in authorization requests or authorization errors.    

### Correlation Analysis  

- Correlate Active Directory logs, EDR logs, and SIEM logs to determine if abnormal activity indicates an attempted attack.    
- Compare with other security logs to assess the impact of anomalous activity across the network.    

### Incident Validation  

- Gather additional data to confirm whether detected abnormal activities are signs of a real attack.    
- Contact the owner of  the relevant user account to verify the situation and take necessary  actions to secure the account if needed.    

### Expected Results  

- An unusually high number of failed logon attempts and authorization requests are detected for a specific user account.    
- Login attempts from unusual times or IP addresses are detected.    
- It is determined whether this activity is indicative of a potential privilege escalation attack.    
- Correlation analysis with SIEM and other security logs evaluates whether this activity represents a real attack attempt.    

### Summary  

These analysis steps  provide strategies for detecting anomalous activity on specific user  accounts, as well as potential attempts at privilege escalation. Active  Directory and EDR logs are critical data sources for monitoring and  detecting such anomalies. Detected anomalies allow for early  identification of attacks and rapid intervention. This process plays a  critical role in ensuring the security of user accounts and proactively  managing threats.  

## Practical Lab

### Hypothesis

**Note**: The questions in this section are prepared for Threat Hunting based on the following hypothesis:

**Hypothesis:** Attackers can use "credential dumping" techniques to obtain administrator  credentials and elevate their privileges in a compromised system.

### Threat Hunting Lab Environment

- SIEM (Wazuh)
- EDR Events (Sysmon)

### Lab Notes

- Analyze the logs between "Aug 26, 2024 00:00 - Aug 30, 2024 00:00" to answer the questions below.
- Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

### Questions

**Note**: Analyze the logs between "Aug 26, 2024 00:00 - Aug 30, 2024 00:00" to answer the questions below.

**Note**: Subsequent questions require correct answers from previous ones. Answer all questions strictly in the order they appear.

1 - What is the IP address (agent.ip) of the system where the "Credential Dumping" event occurred?

> **Answer:** 172.16.40.67

2 - What is the name of the process (data.win.eventdata.originalFileName) that  generated the "Credential Dumping" event on the affected system?

> **Answer:** mimikatz.exe

3 - In the system where the "MITRE T1003 Credential Dumping" event occurred,  what is the name of the user that was intended to be created using the  "net user" command in the "MITRE T1087 Account Discovery" event?

> **Answer:** john.ters

4 - What is the name of the group whose members were listed in the "MITRE  T1069.001 Permission Groups Discovery: Local Groups" event on the system where the "MITRE T1003 Credential Dumping" event occurred?

> **Answer:** administrators

5 - What is the username of the account that logged in to the system one day prior to the "MITRE T1003 Credential Dumping" event?

> **Answer:** melissa

6 - In the system where the MITRE T1003 Credential Dumping event occurred, how many failed access attempts (data.win.system.eventID: 4625) were made  to different target systems from this system using the account that  logged in the day before the event? 

> **Answer:** 3

7 - In the system where the "MITRE T1003 Credential Dumping" event occurred,  what is the IP address of the system that was successfully accessed  using the account that logged in one day prior to this event?

> **Answer:** 172.16.40.75

8 - In the system where the "MITRE T1003 Credential Dumping" event occurred,  find the system that was successfully accessed using the account that  logged in one day prior to this event. What is the application  (data.win.eventdata.originalFileName) used for the "MITRE T1033 System  Owner/User Discovery" technique in this system?

> **Answer:** whoami.exe













































