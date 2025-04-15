# Detecting Brute Force Attacks

Learn how to detect brute force attacks against applications and systems

**Table of content:**

- [Introduction to Detecting Brute Force Attacks](#introduction-to-detecting-brute-force-attacks)

- [Brute Force Attacks](#brute-force-attacks)
- [Protocol/Services That Can Be Attacked by Brute Force](#protocolservices-that-can-be-attacked-by-brute-force)
- [Tools Used in a Brute Force Attacks](#tools-used-in-a-brute-force-attacks)
- [How to Avoid Brute Force Attacks?](#how-to-avoid-brute-force-attacks)
- [SSH Brute Force Attack Detection Example](#ssh-brute-force-attack-detection-example)
- [HTTP Login Brute Force Attack Detection Example](#http-login-brute-force-attack-detection-example)
- [Windows Login Brute Force Detection Example](#windows-login-brute-force-detection-example)

**Challenge**

- [Brute Force Attacks](https://app.letsdefend.io/challenge/brute-force-attacks)

## Introduction to Detecting Brute Force Attacks

Brute force attacks are a frequently preferred attack technique by attackers  as they provide direct access to the system if successful. It is  extremely important to be able to detect this attack technique and take  the necessary precautions.

In this tutorial, we will focus on what brute force attacks are and how these attacks can be detected.

Training contents;

- What is brute force attack?
- Brute force attacks types
- Online and offline brute force attacks
- Applications and protocols that are vulnerable to brute force attacks
- Tools used in brute force attacks
- Preventing brute force attacks
- Brute force attack detection examples

## Brute Force Attacks

Brute force attack is the name given to the activity performed to find any  username, password or directory on the web page or an encryption key by  trial and error method. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-1.png)

src: https://www.hackingarticles.in/password-crackingms-sql/

The duration of the attack will vary according to the length of the  sensitive data sought. If attempts are being made for a simple password  or a username, this may take a short time or it may take years for  complex expressions.

We can basically explain brute-force attacks into two categories. 

### **1.1. Online Brute force attacks**

In online brute force attacks, the attacker and the victim are online at the same time and contact each other depending on the situation. It  is also possible to categorize these attacks as Active and Passive. 

#### **1.1.1. Passive Online Brute Force Attacks**

In passive online brute force attacks, the attacker and the victim  are on the same network, but do not have direct contact with each other. Usually, the attacker tries to obtain the password in passive ways  without establishing a one-to-one connection with the victim machine. We can give the following examples of this type of attack.

**Man in the Middle:** In this attack style, traffic  related to the environment and the target machine is listened to and the password etc. is attempted to be captured.

**Sniffing:** Sniffing style attacks are effective if  there is a connection on the same network and a network tool such as a  hub is used in the system because the hub sends a package to all the  ports the whole LAN can see this package. If tools such as switches are  used, then these tools will filter what is to be sent to the target  system, and sniffing is not effective here. 

#### **1.1.2. Active Online Brute Force Attacks**

In active online brute force attacks, the attacker communicates  directly with the victim machine and makes the necessary trials to the  relevant service on the victim machine. For example, user/password  attempts made to a web server, email server, SSH service, RDP service or a database service can be given as an example for this title.

This is a very advantageous method for simple passwords, but it  usually doesn't work for strong passwords in the short term. It may  cause situations such as account lockout and disabling the target  system.

### **1.2. Offline Brute force attacks**

Offline brute-force attacks are used for previously captured  encrypted or hashed data. In this type of attack, the attacker does not  need to establish an active connection directly with the victim machine. Attacker can perform an offline attack on the password file that he/she somehow gained access to. The password information to be attacked can  be obtained in different ways. For example;

- By capturing packets on wireless networks
- Capturing a package with a mitm attack
- Dumping hashes from db with a SQLi weakness
- SAM or NTDS.dit database on Windows systems

Usually, these attacks are carried out in 3 different ways.

#### **1.2.1. Dictionary Attacks**

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image.png)

This is a problem caused by the use of a common password. This is an  attack method that usually occurs as a result of more than one person  using the same password accidentally. First, the attacker creates a  dictionary for himself/herself from the passwords he/she will try.  He/she can find a prepared dictionary on the internet or create it as  he/she wishes. Then, each word in this dictionary is tested on the  target system as a password.

#### **1.2.2. Brute Force Attacks**

Brute force attacks are a method performed by trying all  possibilities in a certain range one by one. For example, if the  password we are looking for consists of up to 5 characters, the attacker tries all the possibilities one by one, including 1 digit, 2 digits, 3  digits, 4 digits and 5 digits (including uppercase and lowercase  letters, digits and special characters). If an attack is made to find a  complex password, the attack time may be quite long depending on the  condition of the hardware used.

#### **1.2.3. Rainbow Table Attacks**

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-1024x576.jpeg)

We should keep in mind that all password possibilities in a certain  range are calculated with the relevant function in a rainbow attack. For example, we should calculate the MD5 values of all possible passwords  up to 4 digits in advance. 

In this attack type, the attacker quickly compares the pre-calculated hash file with the password summary he/she wants to crack and obtains  the password if there is a match. The biggest problem here is to  calculate these hashes or to somehow get access to the calculated form.  For example, high processing power and disk space is needed to create a  rainbow table for a password containing all possibilities up to 8  digits.

### Questions

1 - What is the name of the password cracking method that uses a pre-calculated hash table to crack the password ? 

Answer format: **XXXX XXXX** attack

> **Answer:** Rainbow table attack

## Protocol/Services That Can Be Attacked by Brute Force

Brute force attacks are mostly encountered in the following areas in institutions.

- Web application login pages
- RDP services
- SSH services
- Mail server login pages
- LDAP services
- Database services(mssql,mysql, postgresql, oracle, etc.)
- Web application home directories(directory brute force)
- DNS servers, in order to detect DNS records (dns brute force)

### Questions

1 - What is the name of the attack that the attackers usually made on the  protocol running on port 22 in order to obtain a session on a linux server?

Answer format: **protocol** brute force

> **Answer:** SSH Brute Force

## Tools Used in a Brute Force Attacks

**Aircrack-ng** : aircrack-ng is an 802.11a/b/g WEP/WPA cracking program that can  recover a 40-bit, 104-bit, 256-bit or 512-bit WEP key once enough  encrypted packets have been gathered. Also it can attack WPA1/2 networks with some advanced methods or simply by brute force.

**John the Ripper** : John the Ripper is a tool designed to help systems administrators to find weak (easy to guess or crack  through brute force) passwords, and even automatically mail users alert  them about it, if it is desired. Runs on 15 different platforms  including Unix, Windows, and OpenVMS. 

**L0phtCrack** : a tool for cracking Windows passwords. It uses rainbow tables, dictionaries, and multiprocessor algorithms.

**Hashcat** : Hashcat supports five unique modes of  attack for over 300 highly-optimized hashing algorithms. hashcat  currently supports CPUs, GPUs, and other hardware accelerators on Linux, and has facilities to help distribute password cracking.

**Ncrack** : a tool for cracking network authentication. It can be used on Windows, Linux, and BSD. It was built to help  companies secure their networks by proactively testing all their hosts  and networking devices for poor passwords.

**Hydra** : Hydra is a parallelized login cracker which  supports numerous protocols to attack. It is very fast and flexible, and new modules are easy to add.

Reference: [kali.org/tools/](https://www.kali.org/tools/)

## How to Avoid Brute Force Attacks?

### How to Avoid Brute Force Attacks?

To protect your organization from brute force attack, enforce the use of strong passwords. 

You can find some best practices for passwords below:

- Never use information that can be found online (like names of family members).
- Have as many characters as possible.
- Combine letters, numbers, and symbols.
- Minimum 8 characters.
- Each user account is different.
- Avoid common patterns.

Here are some ways you can protect users from brute-force attacks as administrators of an organization:

**Lock Policy** - After a certain number of failed login attempts, you can lock accounts and then unlock them as an administrator.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-5.png)

**Progressive delays** - You can lock accounts for a limited time after a certain number of failed login attempts. 

**Recaptcha** - With tools such as Captcha-reCAPTCHA,  you can make it mandatory for users to complete simple tasks in order to log on to a system. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-4-1024x520.png)

**Strong Password Policy** - You can force users to define long and complex passwords and force them to change their password periodically.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-3.png)

**2FA** - It is the method where a second verification is required from the user with an additional  verification mechanism (SMS,mail,token,push notification, etc.) after  entering the username and password.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-2-1024x609.png)

### **4.1. Brute Force Attack Detection**

Specific rules are usually defined on SIEM systems to detect brute  force attacks. When defining these rules, we consider how many  unsuccessful login attempts are made by the user within a certain period of time. While analyzing the relevant alarms, the logs of the trial  protocol/application are examined and the necessary inferences are made. Examples of some brute force attacks are given below.

### Questions

1 - After logging in the username and password, what is the name of the  method in which a second verification is made to the user with an  additional verification mechanism (SMS, mail, token,push notification,  etc.)?

Answer format: XXX

> **Answer:** 2FA

## SSH Brute Force Attack Detection Example

Simple passwords used on the server with an SSH brute force attack can be  easily found by the attackers. If such attacks fail, the attacker will  only attempt a certain number of failed passwords. If successful, the  password is entered successfully after a certain number of unsuccessful  login attempts.

In an example SSH brute force analysis, when we view a linux machine  log with the contents of the “/var/log/auth.log.1” file and failed login attempts, we can see who the failed login attempts belong to.

*cat auth.log.1 | grep "Failed password" | cut -d " " -f10 | sort | uniq -c | sort*

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-6-1024x208.png)

A command such as the one below can be used to locate the IP addresses that made these attempts.

*cat auth.log.1 | grep "Failed password" | cut -d " " -f12 | sort | uniq -c | sort*

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-7-1024x170.png)

Users who successfully log in can also be detected with the following command.

*cat auth.log.1 | grep "Accepted password"*

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-8-1024x223.png)

As can be seen here, successful login attempts are seen with two different users from two different IP addresses.

When the previous failed login attempts are compared, it is seen that the "analyst" user did not have an unsuccessful login attempt before  from the ip address he successfully logged in. However, it is clearly  seen that many unsuccessful attempts were made with the "letsdefend"  user at the IP address of 188.58.65.203. This shows us that the attacker successfully logged in with the letsdefend user during the brute force.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-9-1024x317.png)

As seen above, successful and unsuccessful logged in users can be  easily found with basic Linux commands. When these two results are  examined in detail, it is seen that there is a successful entry after  many unsuccessful attempts by the letsdefend user from the 188.58.65.203 IP address.

## HTTP Login Brute Force Attack Detection Example

In HTTP login brute force attacks, the attacker usually tries a password  with a dictionary attack on a login page. In order to analyze this, the  content of the relevant log file should be opened with a text editor and the logs should be examined. 

The following screenshot shows an HTTP login brute force attack. It  is seen that the user found the password by successfully entering the  password after a certain number of unsuccessful login attempts. Here,  the difference between the package sizes in the response returned to  failed login attempts and the package sizes in the response returned to  successful login attempts is clearly seen. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-10-1024x539.png)

## Windows Login Brute Force Detection Example

### **7.1 Windows Login Records**

Considering the general situation, a login activity appears in all  successful or unsuccessful cyberattacks. An attacker often wants to log  into the server to take over the system. For this purpose, it can  perform brute force attack or directly login with the password in hand.  In both cases (successful login / unsuccessful login attempt) the log  will be created.

Let’s consider an attacker logged into the server after a brute force attack. To better analyze what the attacker did after entering the  system, we need to find the login date. For this, we need “Event ID 4624 – An account was successfully logged on”.

Each event log has its own ID value. Filtering, analyzing and  searching the log title is more difficult, so it is easy to use the ID  value.

You can find the details of which Event ID value means what from the URL address below.

https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/default.aspx

Log file for lesson:

[Log_File.zip Pass=321](https://files-ld.s3.us-east-2.amazonaws.com/Log_File.zip) (https://files-ld.s3.us-east-2.amazonaws.com/Log_File.zip)

To reach the result, we open the “Event Viewer” and select “Security” logs.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-1.jpeg)

Then we create a filter for the “4624” Event ID.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-2-1024x585.jpeg)

And now we see that the number of logs has decreased significantly  and we are only listing logs for successful login activities. Looking at the log details, we see that the user of “LetsDefendTest” first logged  in at 23/02/2021 10:17 PM.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-3.jpeg)

When we look at the “Logon Type” field, we see the value 10. This  indicates that you are logged in with “Remote Desktop Services” or  “Remote Desktop Protocol”.

You can find the meaning of the logon type values on Microsoft’s page.

https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4624

In the next section, we will detect the Brute force attack the attacker made before logging in.

### **7.2 Windows RDP Brute Force Detection**

In this section, we will catch an attacker who is in the lateral  movement phase. The attacker is trying to jump to the other machine by  brute force over RDP.

Download log file: Log_File.zip Pass=321

[Log_File.zip Pass=321](https://files-ld.s3.us-east-2.amazonaws.com/Log_File.zip) (https://files-ld.s3.us-east-2.amazonaws.com/Log_File.zip)

When an unsuccessful login operation is made on RDP, the "Event ID  4625 - An account failed to log on" log is generated. If we follow this  log, we can track down the attacker.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-11.png)

After filtering, we see 4 logs with 4625 Event IDs.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-12.png)

When we look at the dates, we see that the logs are formed one after  the other. When we look at the details, it is seen that all logs are  created for the "LetsDefendTest" user.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-13.png)

As a result, we understand that the attacker has unsuccessfully  attempted to login 4 times. To understand whether the attack was  successful or not, we can search for the 4624 logs we saw in the  previous section.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-14.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Brute+Force+Attacks/images/image-15.png)

As can be seen from the results, the attacker succeeded in connecting to the system with the 4624 log after the 4625 logs.

### Questions

1 - What is the event id value that indicates that the user is successfully logged in to a Windows system?

Answer format: XXXX

> **Answer:** 4624