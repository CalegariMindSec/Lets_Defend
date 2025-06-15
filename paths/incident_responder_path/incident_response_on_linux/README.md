# Incident Response on Linux

Elevate your cybersecurity capabilities with our Incident Response on Linux  course. This program provides thorough training on detecting, analyzing, and mitigating security threats in Linux environments. Tailored for IT  professionals, system administrators, incident responders and security  analysts, the course offers practical, hands-on experience to strengthen your incident response skills. By mastering essential tools and  techniques, you’ll be equipped to safeguard networks and protect data  effectively. Join now to boost your expertise and advance your career in cybersecurity.

**Table of content:**

- How to Create Incident Response Plan?

- Incident Response Procedure
- 3 Important Things
- Users and Groups
- Processes
- Files and File System
- Mounts
- Network
- Service
- Crontab
- SSH Authorized Keys
- Bash_rc & Bash_profile
- Useful Log Files

## How to Create Incident Response Plan?

### What is incident response?

Incident response is an approach to managing a security incident  process. An incident response plan is needed to approach security incidents systematically. A successful incident response plan includes  the following 6 stages: 

 1- Preparation
 2- Identification
 3- Scope
 4- Eradication
 5- Recovery
 6- Lessons Learned

### 1- Preparation

**Creating a Central Registration System**

It is important in terms of saving time that all data can be examined  from a single point with a central log collection system that can manage large files. 

**Time Synchronization**

Enabling NTP on all devices in the network is important for matching the time information of the logs collected. 

**User Account Management**

The fact that the user names of different accounts belonging to  personnel are the same and different from other personnel makes it easy  to monitor user activities in the event of an incident. 

**Management of System and Service Accounts**

The administrators of the services and systems used should be appointed  and a document should be created on how to reach these managers if  needed. 

**Asset Management**

Instant access to information such as devices, operating systems, patch versions, and critical status should be available. 

**Secure Communication**

If necessary, the team may need to communicate independently of the  internal network, for such cases mobile phone or secondary emails can be used. 

**Legal Transactions**

The method of who will initiate the judicial process and in which situations should be determined before the incident occurs. 

### 2- Identification

**Review**

For a potential suspicious incident, preliminary information about the  incident should be gathered. Then it must be decided whether the  situation is a suspicious event or not. 

**Assignment**

The first person to examine the incident must be determined. The person should take notes about the review. 

**Using the Checklist**

There should be checklists for the analysis to be made in order to ensure consistent responses to incidents. 

### 3- Scope

**Characterize the event**

Since determining the event will determine the actions to be taken, it  is important to determine the type of the incoming event. EX: DDoS,  malware infection, data leak … 

**Taking Action**

Action should be taken according to the technique used to intercept the  attacker's method quickly. If there is an account that it has captured,  simple measures such as account deactivation and IP blocking should be done quickly. 

**Data collecting**

The image of the volatile memory along with the firewall, network traffic and other logs will be required for the investigation. 

**Isolation**

Unplugging the compromised system  could be a solution, isolating it is a more viable solution. 

After the systems affected by the incident are determined, the  possibility of the attacker's spread in the network is cut and volatile  information is collected, the next step can be passed. 

### 4- Eradication

**Identifying the Root Cause**

With the information obtained in the 2nd and 3rd stages, the root cause  of the event should be determined. The attacker must then be completely  eliminated. 

**Determining Rootkit Potential**

If rootkits are suspected in the system, the disk should be cleaned and a clean backup installed. After the installation, the latest updates of  the existing applications and systems should be installed. 

**Improve Defense**

Operating systems, applications used, network, DMZ etc. The deficiencies of defense in areas should be determined and work should be done on how to make improvement. 

**Vulnerability Scan**

Potential attack points on networks and systems should be identified and corrected by performing vulnerability scans. 

When the necessary arrangements are prepared to prevent the event from recurring, the recovery phase can be started. 

### 5- Recovery

**Verification**

Verify that logging, systems, applications, databases, and other operations work correctly. 

**Restore**

At this stage, the restore operation is coordinated. 

**Monitoring**

Systems should be monitored for recurring events. 

When there is no repetitive harmful situation or unusual activity, the next step is taken. 

### 6- Lessons Learned

**Writing a Follow-up Report**

The report includes the examinations with the expert and the executive,  the stages of good and bad working in the intervention plan, and the  recommendations regarding the process. The report should be written in a way that the manager is sure that the incident has been closed.

## Incident Response Procedure

### How Does the Procedure Proceed?

In a SOC (Security Operation Center) environment, the action taken  against an incident is important. Everyone should not use their own  method they came up with, but methods that have had their frameworks  previously determined should be used so there is consistency and  everything proceeds accurately during a time of crisis. In this section, we will talk about how we can keep the base of consistency in response  to incidents. This section is important to understand the big picture.  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/pro.png)

### Alert

After the logs collected through the EDR, IDS, IPS, WAF, and similar  security tools that are found in the SOC, rule correlation sets are  formed through the SIEM to determine suspicious activity. Thus, in the  case of an unwanted situation, a new alert is created.  

### Analyze

In an ideal SOC environment, there are Tier 1 analysts present to  conduct the preliminary analysis on alerts that come through the  security tools. This analyst analyzes the incoming alert and determines  whether it is a false positive or not. For example, an alert can be  formed after sending a request to a malicious URL address; however, the  URL address is not actually malicious. The Tier 1 analyst controls this  procedure and eliminates incoming alerts. 

### Investigate

After it is determined that the incoming alert is not a false positive,  the investigation procedure begins, and the source of the attack is  investigated. In addition, the amount of progress the attacker has made  since the beginning of the attack is investigated.   

### Assess Impact

The systems that have been affected by the attack are determined and the amount of damage present in the current situation is assessed and  evaluated. For example, a system that has been affected by ransomware  may not have had all its data encrypted. Determinations similar to this  have to be conducted to have an assessment of the current situation.  

### Contain

After determining the systems affected from the attack, it is crucial  that the situation is handled with control and prevented from spreading. Thus, the affected devices must immediately be isolated from the  network. Let’s continue with the ransomware example. A dangerous  ransomware will want to spread itself to other devices. In order to  prevent the interaction with the other devices, the device must be  isolated from the network.  

### Respond

After all the mentioned steps above are completed, the response process  is initiated. At this step, the root cause of the situation is  determined, the present dangers are removed, the systems are brought  back to a working state, and lessons are learned from the situation that has occurred. The main topic of this training will be the details  listed under this title. In future topics, we have showed you how to do  this with details.

## 3 Important Things

When analyzing a system that has been hacked or believed to have been  hacked, regardless of the processing system, there are 3 questions that  must be answered. The responses to these questions may change or end the continuation of the analysis. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/3important.png)

- Is there a malware that is actively in the system?
- Is there any suspicious internal or external communication?
- Is there any persistence?

### Is there a malware that is actively in the system?

If there is anything malicious that is actively running in the system,  you may conduct a backward analysis to investigate how it came there in  the first place. The easiest way to do this is conducting a process  analysis. We will teach you the details of process analysis in the  future. However, to give a short example: a “powershell.exe”  childprocess under an “excel.exe” process is suspicious and must be  investigated.  

### Is there any suspicious internal or external communication?

An attacker must form an interaction with the server in order complete  procedures like controlling the system or extracting data from it. This  interaction will form network traffic. An anomaly determination can be  conducted by analyzing the connections made in that system currently and in the past. For example, in the case of a connection being established with an IP with a bad reputation, or data traffic at rates of large GBs between a certain IP, or connections made between abnormal ports can be cases that should be carefully investigated.  

### Is there any persistence?

When the actions of the attacker until this day are observed, it can  clearly be seen that the attacker aims to be permanently present in the  system that has been taken over. The reason behind this can be the fact  that the attacker may not have been able to complete a certain  transaction quickly and may need to return to complete it later and the  thought that he/she should leave an open door because he/she might need  it in the future again.  

During your analysis, you may not be able to determine an active  malicious presence or suspicious traffic. Maybe the attacker has kept a  backdoor that can trigger itself once a week. Thus, you must know the  procedures used for permanence and you must examine these within the  system.  

Answering the 3 mentioned questions is important. The responses to these questions may change the continuation of the analysis. To answer these  questions, there are certain places you must technically analyze. We  will start talking about these in the upcoming chapter.

## Users and Groups

Users are a must in an operating system. User systems are present in all  operating systems in order to ensure the safety of the system, to  identify the data, and to provide a better user experience. 

In this article, we will examine the user system included in the Linux operating system.

When we examine the APT attack reports, we can observe that cyber  attackers aim to take over the authorized user in order to completely  compromise the domain. In ransomware attacks that have been very popular in today’s world, cyber attackers take over the domain admin accounts  and download ransomware into all devices within the domain. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image1.jpg)

Most system administrators won’t periodically conduct check-up’s  regarding the devices under their responsibility. Thus, when a user is  taken over or a new user is added into the operating system, it is very  rarely recognized. Since the possibility of it being recognized is very  low, attackers frequently choose this method in order to maintain  persistence. 

In addition, since the passwords that are included for users by  default are not changed/forgotten during set-up, attackers can easily  access the operating system. 

If the general anatomy of a cyber attack is examined, attackers  access the system as a result of exploiting the vulnerability on a  service that is open to the Internet, and since these services are  mostly unauthorized service accounts, the attackers compromise the users on the operating system in order to increase their privileges on the  system.

As an incident responder, we must be able to detect the users that  have been taken over, added or removed from the operating system by the  cyber-attackers. 

**“Everything is a file”**

Everything is a file describes one of the defining features of Unix,  and its derivatives—that a wide range of input/output resources such as  documents, directories, hard-drives, modems, keyboards, printers and  even some inter-process and network communications are simple streams of bytes exposed through the filesystem name space. (Wikipedia)

The UNIX file system contains critical files that contain information about users and groups. As an incident responder, it is necessary to  gain the ability to detect the existence of these files, their file  structures, and the anomaly on these files.

The files containing the information of users and groups are as seen below:

**/etc/passwd**

Undoubtedly, one of the most crucial files in UNIX operating systems  is /etc/passwd. This file contains usernames, the user's password  (depracated), UID/GID, the user's home directory and the user's shell  information.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image2.png)

The file named *passwd* belongs to the root user and everyone  has permission to read the file. For this reason, even if the attacker  compromises the user with the lowest privilege in the system, they can  still collect information about the users on the device.

You can read the *passwd* file like any other file with the *cat* command.

cat /etc/passwd

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image3.png)

At first glance, the */etc/passwd* file may seem confusing. However, each line in this file has a specific format.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image4.png)

When we analyze the file format, we can see that:

- The username is written in the beginning of each prior to the first colon,
- The password is written in between the first colon and the second colon  (this part is a legacy and is generally not used anymore.)
- The UID is written in between the second colon and the third colon,
- The GID is written in between the third colon and the fourth colon,
- The comment is included in between the fourth colon and the fifth colon,
- The home directory of the user is written in between the fifth colon and the sixth colon,
- The shell used by the user is written in between the sixth colon and the seventh colon

If a user's shell is "/usr/sbin/nologin" in the passwd file, it means that the user will not be able to login to the operating system.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image5.png)

The fact that the user cannot login to the system does not mean that  the user cannot run commands on the system. For example, the shell of  the www-data user is "/usr/sbin/nologin", however when a web application is compromised, attackers generally execute commands on the system with the www-data user.

**/etc/shadow**

In the shadow file, there are encrypted versions of user passwords.  Thus, it has become one of the most popular files by attackers.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image6.png)

You may think that including user passwords in a file may pose a security risk. The shadow file is readable only by the *root* user and users in the *shadow* group and passwords are kept encrypted. Reading this file doesn't make  any sense on its own. An attacker who wants to discover a user's  password must brute force it to find the password.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image7.png)

Let’s take a look at the shadow file format.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image8.png)

When we analyze the file format, we can see that:

- The username is written in the beginning prior to the first colon,
- The encrypted password is written in between the first colon and the second colon,
- The last password change date is written in between the second colon and the third colon,
- Information about the time needed in order for the user to change the password is  written in between the third colon and the fourth colon, 
- Information about the required password change time is written in between the fourth colon and the fifth colon, 
- Information about when the user will be notified before the password is expired is  written in between the fifth colon and the sixth colon,
- Information about how many days will be provided for the user to change the expired password before the user is disabled is written in between the sixth  colon and seventh colon, 
- Information about when the account will be expired is written in between the seventh and eight colon, 
- The section after the eighth colon is created for future use but is left empty because it is not currently used 

**/etc/group**

The /etc/group file contains the groups and information about which users are included in these groups.

Identifying compromised users is not enough to understand the risk in a cybersecurity incident. User groups should also be checked.

If a special configuration is not made, the *www-data* user is a user with low privilege. However, when determining the risk of a  cyber incident, it would be wrong to adopt a point of view such as "The *www-data* user has been compromised, but the risk is low since the level of privileges is low". If the attacker includes the *www-data* user in an high privilege group, the www-data user can have almost as much privilege as the root user.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image9.png)

The file named *group* belongs to the root user and everyone  has read permission. For this reason, even if the attacker accesses the  system through the user with the lowest privileges, they can still  collect information about the groups on the device.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image10.png)

Let’s take a look at the file format.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image11.png)

When we analyze the file format, we can see that:

- The group name is written in the beginning of each prior to the first colon,
- The password is written in between the first colon and the second colon  (this part is a legacy and is generally not used anymore.)
- The GID is written in between the second colon and the third colon,
- The users and usernames who are group members are written after the third colon

**/etc/sudoers**

The sudoers file contains information about who can run the sudo command under which conditions.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image12.png)

Unlike other files, the *sudoers* file contains comments about the file format by default.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image13.png)

- **User List:** Determines which users will have certain authorizations
- **Host List:** Determines which hosts will have certain authorizations
- **Operator List:** Determines which user the users in <user list> will run commands on behalf of
- **Tag List:** Can have the “*PASSWD*”, “*NOPASSWD*” and “*NOEXEC*” values and determines whether they need passwords to run the command or not
- **Command List:** Contains commands

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image14.png)

**Other Important Files**

Apart from these files, there are also different files that contain information about user logon processes.

- **/var/run/utmp**: maintains a full accounting of  the current status of the system, system boot time (used by uptime),  recording user logins at which terminals, logouts, system events etc.
- **/var/log/wtmp**: acts as a historical utmp
- **/var/log/btmp**: records failed login attempts

### **Incident Response**

### **Analyze**

#### **Determining the Users on the System**

Attackers add new users and modify existing users to ensure  persistence. As an incident responder, it is necessary to identify these users and to remove/edit these users in a way that does not pose a risk during the eradication step.

While controlling the users on the system during the incident  response process, it may be necessary to compare the compromised system  with clean system by obtaining the list of users that should be on the  device from the application/server owner. It will be more accurate to  use snapshots from the pre-cyber incident while obtaining the user list.

In order to make our analysis specific to the users on the system, we first need to identify the users on the system.

By reading the */etc/passwd* file, users defined on the system can be determined.

cat /etc/passwd

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image15.png)

Attackers prefer names such *as support, service, dev, admin and sysadmin* for the users they create in order to prevent themselves from being  detected. We should pay attention to users with these names. 

If the *passwd* file has incorrect permissions, users can be  compromised by editing the passwd file. Attackers can take over users by replacing the "x" value next to their username with the password they  created. For this reason, the information in the password field in the *passwd* file should be carefully checked during the incident response.

In addition, the shell information of the users should be checked.  Shell information of users who should not have shell should be  double-checked.

If the attacker has not cleaned the *auth.log* file, it is possible to detect newly created users via the auth.log file.

tail /var/log/auth.log

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image16.png)

You can find newly created users by searching for the word “useradd” in the auth.log file.

grep useradd /var/log/auth.log

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image17.png)

You can identify users whose passwords have been changed by searching for the word “passwd” in the Auth.log file.

grep passwd /var/log/auth.log

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image18.png)

#### **Identifying User’s Permissions**

As we mentioned earlier in our article, detecting compromised users  is not enough to determine the risk. After identifying the users, the  groups that these users are included in, and the authorizations defined  specifically for these users should also be determined.

A good starting point is to examine the groups that the users belong to and check the permissions of the user.

We have to examine the groups and the users included in the groups through the */etc/group* file. The contents of the group file can be viewed using the cat command.

cat /etc/group

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image19.png)

While conducting our examinations, we must pay attention to the  critical groups and the users included in these groups. Users who should not be included in these groups should be identified. For example, the *www-data* user being included in the sudo group is certainly suspicious. Some of the critical groups are as stated below:

- root
- adm
- shadow
- sudo

Another file that needs to be checked in order to understand the authorizations of users or groups is *“/etc/sudoers”.* There is information on which users and groups can use sudo authority to what extent on this file.

cat /etc/sudoers

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image20.png)

In the sudoers file, unauthorized users and the sudo authorizations  that may cause a system compromise should not be defined. In addition,  incorrect configurations on this file should be determined.

You can list group processes by searching for the words *“groupadd” and “usermod”* in the auth.log file. Listing the group changes in the date range of  the attack will make it easier to track the actions taken by the  attacker.

grep groupadd /var/log/auth.log

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image21.png)

grep usermod /var/log/auth.log

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image22.png)

#### **Identifying Users That Have Logged into the System**

With the help of some tools that are installed by default in most  linux systems, users with an active connection on the operating system  can be listed. We recommend installing as few new tools as possible in  order to preserve the integrity of the device during the incident  response process. There are several different tools that we can use to  detect logon users on GNU/Linux.

The w, who, users and last tools are included by default in  GNU/Linux. With the help of these tools, you can identify users who have logged into the system.

These tools have their own advantages and disadvantages. However,  choosing the "last" tool will speed up the incident response process, as it provides more information and historical data. If no parameter is  given, it will give the login history of all users.

last

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image23.png)

The last command obtains this information from the *"/var/log/wtmp"* file. You can get the same information by reading this file, but the *last* command provides it in a more readable format.

cat /var/log/wtmp

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image24.png)

The /var/log/auth.log file can be examined to detect users logged  into the system via SSH. This file includes successful logins as well as unsuccessful logons. In this way, we can detect brute-force attacks  from within the auth.log file.

You can list the failed login attempts with the following command.

grep "Failed password" /var/log/auth.log

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image25.png)

As an alternative, failed SSH logins can be determined with the journalctl command.

journalctl _SYSTEMD_UNIT=ssh.service | egrep "Failed|Failure"

#### **Identification of Users That Can Conduct SSH**

During the incident response it may be necessary to detect users who  can remotely conduct SSH to the device. You can learn about users who  can conduct RDP on Windows operating systems by listing the users  included in the "Remote Desktop Users" group. However, there is no  similar group on Linux. The following steps should be followed in order  to detect users who can conduct SSH.

1. By reading *the /etc/passwd* file, the users on the system are detected.
2. Users who do not have a valid shell are removed from the list.
3. Users who do not have valid passwords are removed from the list.
4. Users with SSH permissions are detected in */etc/ssh/sshd_config*. If "AllowUsers" is specified in this file, it means that other users cannot use the SSH service.

### **Eradication**

At the end of the incident response, the system must be restored to  its working condition in a way that has not been affected by the  cyber-attack.

Users added by the attacker should be deleted from the system. You  can delete the user and the user's home directory with the following  command.

userdel -r **USERNAME**

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image26.png)

Unauthorized users should be removed from groups with high  authorizations. You can remove the user from the group with the command  below.

gpasswd -d **USERNAME GROUP**

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image27.png)

The sudo authorization given to the user must be removed. You can edit sudo authorizations with the visudo command.

visudo

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image28.png)

Passwords of users that should not be deleted should be changed and their SSH keys should be regenerated. 

You can use the passwd command to change the user's password.

passwd **USERNAME**

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-users-and-groups-image29.png)

In order to regenerate the user's SSH Keys, the old keys must be deleted first. Then a new SSH Key must be created.

## Processes

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image1.png)

Unarguably, the most important piece of an operating system is its  process. As an incident responder, we must have the ability to identify  and analyze the suspicious processes. 

While conducting a process analysis, we can identify the motivation,  goal, and which activities the attacker has conducted in the system.  Undoubtedly, process analysis plays an important role during the  incident response procedure. 

### **What Is Process?** 

Process is a program in the file system that is actively running. 

Let’s say an attacker downloaded malware to the victim machine, this  is called a program. A program is ineffective against the operating  system unless it is executed. When an attacker executes a program, this  is now a process. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image2.png)

Operating systems assign a PID (Process Identifier) value for each  process in order to track each process. Each process has its own unique  PID value. More than one process cannot have the same PID value at the  same time.. However, when the process is terminated, the PID value can  be assigned to another process. 

The “**init**” process is the first process created by the kernel when the operating system is initiated. For this reason, the “**init**” process does not have a parent and always has a PID value of “**1**”. 

The highest PID value that the operating system can assign is located within the “**/proc/sys/kernel/pid_max”** file. By reading this file, you can see the highest PID value that the operating system can assign. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image3.png)

We had mentioned that processes are created after a program is run. However, must a process only be actively running? 

There are 4 different states for a process.

1. **Running**: When a process is running or is prepared to run. 
2. **Waiting**: When a process is waiting for an event or resource. 
3. **Stopped**: When a process is stopped. 
4. **Zombie**: When a process has ended but the “tast_struct” data structure has not been deleted yet for certain reasons. 

### **Process Creation – fork&exec**

A new process creation in UNIX operating systems is conducted with the fork and exec system calls. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image4.png)

Fork creates a new child process by duplicating a running process.

1. The newly created process has a PID value of its own. 
2. The parent of the newly created process is the process that has conducted the fork command. 
3. The newly created process cannot access the memory of the forked process. 

Exec replaces the image of the running process with a new image and ensures that it is run from the entrypoint address.

After the fork and exec commands are completed, the new process is created and running. 

### **Process Tree**

In our articles, we spoke of parent and child processes. However, what are parent and child processes? 

As we have mentioned previously, the “**init**” process  is created first by the kernel. The other processes are created from the init process and according to its needs, each process creates a new  process. 

**Parent Process**

The process responsible for the creation of the process is called the parent process. In UNIX operating systems, all processes have a parent  except the "**init**" process.

**Child Process**

When a new process is created, the newly created process is the child process. All processes outside of the “**init**” process are child processes. 

We must understand the process tree in order to understand the attacker’s goal, motivation, and actions within the system. 

For example, let’s examine the “**pstree**” command output below. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image5.png)

The process named “**sshd**” belongs to the SSH service. It is important to examine the process called sshd in Incident response processes. In this way, it can be determined which shell is logged in  and what kind of activity it performs on the system.

When the child processes of the process named sshd is examined, we  can see that it is running through two different bash shell’s ssh  services. This means that there are two different ssh sessions. When the sshd process above is examined, we can see that the pstree command was  run (since the processes are running when the pstree command is run, it  can list the active processes on the operating system), and when the  sshd process below is examined, we can see that the user has connected  with bash shell and that the user has run the “yes” command. 

### **Incident Response**

### **List Processes**

Before entering the process analysis, the processes running on the  device must be determined. In order to preserve the integrity of the  system as much as possible, we need to use tools that provide the same  functionality and are available by default, besides, installing a new  tool will waste time during incident response. The tools that come by  default will mostly be sufficient for incident response.

**ps**

The “**ps**” command shows the information relating to  the chosen active processes. Without given any parameters, it shows the  information only relating to its own process. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image6.png)

When no parameter is given, the “**ps**” tool will not  be of any use. However, with the help of parameters, the ps tool will be one of the most crucial tools we can use during our process analysis  procedure. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image7.png)

Commonly used parameters are as shown below

- **a:** shows processes for all users
- **u:** displays the process's user/owner
- **x:** shows processes not attached to a terminal
- **-u username**: Only lists processes owned by the specified user
- **-C process_name**: Only lists the processes under the specified process
- **--forest**: Shows the process tree
- **–ppid PPID**: Only lists the processes with the specified PPID values

With the command below, you can see all active processes in the form of a process tree. 

ps aux --forest

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image8.png)

**pstree**

With the **pstree** tool, you can see the active processes in the format of a process tree. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image9.png)

**top**

“**Top**” is one of the tools that help us list active  processes. Its difference from the other tools is the fact that it  allows us to watch the active processes in real time. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image10.png)

In the case of a suspicion of a malicious crypto mining software, we can use the “**top**” tool to watch the processes that are using the most CPU in real time.  When the top tool is run, with the “P” letter you can list the processes according to their CPU usage. 

Some filters that will help us during the incident response procedure are as follows.

- **P:** sort the process list by cpu usage
- **N:** sort the list by process id
- **T:** sort by the running time
- **R:** reverse the sorting order
- **C:** display full command path and arguments of process

### **Analyze**

At this stage, we have the active process list on the device. It is  necessary to make a detailed analysis of the suspects from this list we  have obtained.

If we have a high number of processes to examine, a good point to  start at would be to analyze the processes that have interesting names  like (shell, reverse, miner, etc) and processes that run with service  accounts (www-data).

**/proc**

In the /proc directory, there are details about processes, kernels,  and the Linux system. This directory is a directory that is not actually there and is made up of virtual files. When the content of a file in  the /proc directory is read, the operating system will create the  content of the file and present it for you. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image11.png)

When a new process is created, a new directory is created under the /proc directory for the process. 

**Format:** /proc/PID/

There are virtual files with detailed information about the process  under the /proc/PID directory. With the help of these files, we can get  detailed information about the process. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image12.png)

In this directory, there are certain files that are beneficial to  incident responders. Examples of these files are as stated below.

- **Status**: Contains the status of the process, the user and group identity of the person running the process, the entire  list of group memberships by the user, and the PID and PPID information.
- **Cmdline**: Contains the command line parameters used to initiate the process. 
- **Environ:** The environ file shows the environment variables that are in effect.
- **Fd:** The fd file shows the file descriptors. 

For example, let’s try to learn the command line parameters for the  ssh process. First, we must learn the PID values of the ssh process. For this, we can get help from the tools mentioned in the article. 

ps aux | grep ssh

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image13.png)

Now that we know the PID values of the ssh process, let’s read the file named cmdline located under the /proc directory. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image14.png)

**Binary**

Process image is an executable file required while executing the program. 

Information like the name and which directory the binary is located  in the file system can help us quickly identify the malicious process.  For example, if the executable relating to the process is  “/tmp/reverse”, it has a very high chance of being malicious. 

When analyzing the binary, you can mainly understand whether the file is malicious or not. To analyze the file, you can use the static and  dynamic malware analysis methods. However, quickly checking the  reputation of the file will gain you speed in the incident response  process. 

VirusTotal is one of the greatest tools that has helped analysts that work in the defensive field. You can see whether the file you have  uploaded has been identified by antivirus engines in addition to its  metadata information and the comments that the other users have made. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image15.png)

**Command Line**

The command line parameters relating the process might give you  information on the goal of the process and whether the process is  malicious or not. In general, if the Command Line parameters include  personal information and keywords like *password, login, URL, IP Address, port,* this is a sign that the process should be examined in detail. 

When APT attacks are analyzed, it has been observed that cyber  attackers choose to use tools that are included by default in operating  systems in contrast to custom malicious tools in order to prevent being  identified. For example, when stealing data, it has been observed that  they prefer the “netcat” tool instead of downloading a separate tool to  exfiltrate the data stolen. To access the information about the default  tools that attackers prefer, you can look at the project named  GTFOBins. 

During the incident response procedure while looking into the process lists, we may disregard tools that we may believe to be safe because  they are included in the operating system by default. However, attackers use these tools to their advantage very frequently. It can be  understood whether these tools are being used maliciously or not from  the Command Line parameters. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image16.png)

Considering the image above; find is a tool created for searching,  but the command can be run thanks to the -exec parameter. An attacker  who abuses this feature of the find tool can run commands within the  operating system with the help of the find command. An inexperienced  analyst may not be able to detect the command that the attacker ran  because the find command is included in the operating system by default. However, when the command line parameters are examined, it can be seen  that there is definitely a suspicious situation.

**Memory Analysis**

This section will be explained in more detail under Memory Analysis. However, to quickly take a look, we can use the *pmap* command. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image17.png)

### **Eradication**

In the eradication step of incident response, we must end the processes created by the attacker. 

You can terminate a running process through the tools that come installed by default.

**kill**

The kill tool helps us send a SIGNAL to a process. Its use is as below.

*Usage*: kill SIGNAL PID

kill **SIGNAL PID**

When you send a “SIGKILL” signal to the process you want to end, the process will be terminated. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image18.png)

**killall**

The killall tool will help us end processes based on process name. It can terminate more than one process running under the same name at  once. 

*Usage:* killall PROCESS_NAME

killall **PROCESS_NAME**

During the incident response procedure, we can easily kill more than  one malicious software that is under the same process with the killall  command. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-process-image19.png)

## Files and File System

In a cyber attack event, various files are written to the file system. The attacker writes the malicious software he will use, the information he  collects, the programs he will use to collect information into the file  system at the time of the attack. It also makes changes on the files for purposes such as increasing rights and ensuring permanence.

After the incident response, the device must be restored to its  former working condition. If it will not be restored via snapshot or  base image, the attacker's movements in the file system should be  detected and these files should be cleaned.

Before moving on to our analysis, let’s take a look at the Linux File System.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-files-and-files-systems-image1.png)

- **boot**: Contains all necessary files in order for the operating system to start
- **opt**: Contains the files owned by the software that have been optionally added
- **etc:** Contains the configuration files
- **bin**: Contains the executable files
- **sbin**: Contains the files needed by the Superuser
- **var**: Contains the log files
- **dev**: Contains device files
- **home**: Contains the home files owned by users
- **root**: Is the home file for the root user
- **usr**: Contains the application and library files

### **Incident Response**

### **Find Suspicious Files**

#### **Suspicious Directories**

In order to identify the files the attacker has written into the file system, a good way to start would be to examine the commonly used  directories by attackers. 

The /tmp directory is one of the directories that must be examined  during the time of the incident. The /tmp directory is a commonly used  directory by attackers because it is an directory that every user has  authorization to read and write. In addition, the files located in the  /tmp directory are deleted after a certain amount of time. Thus, a late  incident response means that we lose access to the evidence. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-files-and-files-systems-image2.png)

Another good point to start at would be to examine the directories  that are open to the internet. For example, we may be able to identify  the webshell files by examining the directories owned by the application for a server that serves web services. 

In order to be able to identify directories that are open to the  internet, we must initially need to identify these services. To identify the services open to the internet, we can get help from the **netstat** command. 

For example, we can examine files that we believe look suspicious in the */var/www* directory relating to a server that serves web services. 

#### **Suspicious File Extensions**

We must identify the malicious software, webshell’s, and files that  are able to be run that the attacker has written into the file system.  It is easier to identify these files because they have standard file  extensions. 

With the help of the find command below, we can identify the files  with .sh, .php, .php7 and .elf extensions in the file system. 

```
find / -type f \( -iname \*.php -o -iname \*.php7 -o -iname \*.sh -o -iname \*.elf \)
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-files-and-files-systems-image3.png)

#### **Modification Time**

We can search files within the file system based on their modification time. 

If the time period for the cyber-attack is known, examining the  modified files during this time period would make it easier to find the  files that have been modified by the attacker. 

By using the find tool, we can search for the files within the file  system based on modification time. For example, with the help of the *find* tool below, we can list the files below the /tmp directory that have been  modified between the dates of 10/25/2021 00:00:00 and 10/25/2021  23:59:00. 

```
find /tmp -newermt "2021-10-25 00:00:00" ! -newermt "2021-10-25 23:59:00"
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-files-and-files-systems-image4.png)

Instead of determining a certain time frame, we can also filter by modification date prior to X or after X. 

```
find / -mtime +X
find / -mtime -X
```

#### **Owner**

While searching suspicious files, if we know the compromised users,  conducting an analysis on files owned by compromised users may help you  get quick results. 

It is impossible to identify files modified by X user. However, we can identify files owned by X user. 

By use of the find tool, we can identify all of the files owned by a  certain user. For example, with the help of the command below, the files owned by the www-data user is listed under the /tmp directory. 

find /tmp -user www-data

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-files-and-files-systems-image5.png)

#### **Change Date**

When the ownership of a file, the directories in a file or the  content of a file is changed by the attacker, the Change Date of the  file changes. For various reasons, the attacker may change the  authorizations and ownership of the file. 

With the help of the find command, we can search based on change date. 

```
find / -ctime +X
```

### **Analyze**

When the suspicious files are identified, now these files must be analyzed. 

Before putting the file into a static or dynamic analysis, we must first get more information about the file.

By use of the stat tool, we can get detailed information about the file. 

stat **FILENAME**

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-files-and-files-systems-image6.png)

After getting information about the file, we can move on to static analysis, dynamic analysis and code analysis.

###  **Remediation**

In the remediation step of incident response, the modifications the  attacker has made to the file system must be reverted to its normal  state. The files that the attacker has written into the file system must be deleted and the files the attacker has modified must be reverted to  its normal state. 

If possible, it is healthier to revert the system with a clean image or a snapshot that was taken before the cyber-attack. 

### Questions

1 - The attacker is known to upload webshell. What is the name of this file?

> **Answer:** youcantfindthis.php

## Mounts

In UNIX operating systems, you can mount a different file system to your  own device. Of course, attackers develop methods to use this feature for their own purposes.

Ransomware attacks currently make up a significant number of  cyber-attacks today. Cyber threat actors, by uploading ransomware to all devices located in the network, stop the system from working and by  blocking the owners’ access to important information, force the victims  to pay a ransom. 

When we examine corporate network topologies, we can see that almost  every company has a file share server. During ransomware attacks, file  share servers have become the main targets of attackers. 

Attackers use the file share servers during ransomware attacks for two goals: 

1. Since file share servers generally have critical data,  ransomware is uploaded to these servers to block the owners’ access to  important information and force them to pay a ransom. 
2. By  hosting the ransomware malicious software in the file share servers, to  upload ransomware malicious software through the file share server from  the devices that the attacker has made access to. 

One of the checks that an incident responder must do during a  cyber-attack is to check whether any of the file systems that have been  mounted by the compromised devices has been affected by the  cyber-attack.

Unfortunately, there is no mount/unmount log. Thus, if the attacker  conducted a mount procedure and then unmounted it, we cannot identify  this. However, sometimes, we can see logs regarding mounts within the  dmesg.

```
dmesg | grep mount
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-mounts-image1.png)

Since the mount procedures are not logged, we cannot conduct a  backward search. However, we can still conduct our analysis by  identifying the file systems that are still mounted to the device. 

**Mount**

You can list the mounted file systems with the mount command.

```
mount
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-mounts-image2.png)

**Findmnt**

Findmnt is another tool we can use to list the file systems that have been mounted. Since it is a more visually pleasing output than the  other options, instead of wasting time to understand the other outputs,  we can use the findmnt command. 

```
Findmnt
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-mounts-image3.png)

**Df**

Df is a tool that we can use to get information about disks. With the -aTh parameter we can list the file systems that have been mounted.

```
df -aTh
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-mounts-image4.png)

**/proc/mounts**

In order to identify the actively mounted file systems we can read the /proc/mounts file. 

```
cat /proc/mounts
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-mounts-image5.png)

## Network

The attackers establish a network connection between the systems they have  seized and their own systems, thus ensuring the communication of two  devices. With this connection, the attacker is able to send and receive  data to the system he/she has hacked.

Attackers often prefer to receive a reverse shell over the device,  even if they have Webshell in order to move more easily in the system  they have seized. In addition to being able to move more easily, the  victim device is connected to the attacker's device with a reverse  shell, thus bypassing security products more easily.

As an incident responder, we must identify these connections and analyze the traffic running through these connections. 

### **Listing Active Network Connections**

Due to its ease of use and since it is usually already installed by default, “**netstat**” is probably the most preferred tool. 

You can list all network connection with the “**netstat -a**” command. 

```
netstat -a
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-network-image1.png)

You can only list the network connections of the TCP protocol with  the "netstat -at" command. The "-n" parameter allows you to get faster  results by turning off the reverse DNS lookup.

```
netstat -ant
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-network-image2.png)

In order to maintain persistence in a system, attackers choose to  upload a backdoor in the system. When attackers want to access the  system again, they use the backdoor they have created and can easily  continue to access the system. The easiest way to identify backdoors  like these is to examine the ports that device has listened to. 

With the “netstat -l” command, we can list the ports that the device has listened to. 

```
netstat -l
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-network-image3.png)

During the incident response procedure, we must pay attention to all  ports listened to from all interfaces. A good point to start the  analysis is to analyze the ports that are not used by default by known  applications. 

As can be seen in the image above, by default, there is no information about which processes make these connections.

When we provide the "-p" parameter to the netstat command, the  information about which processes the network connections are made is  also printed.

```
netstat -nlpt
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-network-image4.png)

### **IPTables**

The attacker may have made changes to the firewall rules. These rules must be examined. 

You can list all iptables rules with the “iptables -L” command. 

```
iptables -L
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-network-image5.png)

## Service

Attackers use various persistence techniques in order to be able to access the  compromised system at a later time. One of these methods is to ensure  that the malicious programs, command or codes they have prepared are  activated in the background. 

Since the services are activated in the background, they give the  attackers the option to re-start or activate with a different command in the case of the service not working properly. Thus, it is a commonly  chosen method to ensure persistence. 

Services can have different status according to their activation  status. These status and their explanations are as stated below. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-services-image1.png)

- **Active (running):** The service is running in the background.
- **Active (exited):** Is the case of a service being successfully run but there is no daemon to be monitored. 
- **Active (waiting):** The service is running but is waiting for an event.
- **Inactive:** The service is not working.
- **Enabled:** Service is enabled at boot time.
- **Disabled:** Service is disabled and will not be started at Linux server boot time. 

### Understanding Service Configuration Files

During the analysis procedure, we must be able to identify the  anomalies and malicious behavior relating to suspicious services. For  this reason, we must first understand what kind of a format the service  configuration file has and what these variables mean. 

Configuration files owned by services have the “.service” extension. You can make changes to these files with text editor. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-services-image2.png)

Let’s examine the file structure through an example unit file. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-services-image3.png)

Unit files are made up of sections. The sections are identified  between the “[“ and “]” signs and are valid until the next section or  until the end of the file. 

**[Unit] Section**

The “unit” section is usually used to complete the meta data in the  unit or to configure the connection between the other units. The  directives we will usually come across in the unit section is as  follows: 

- **Description**: Is used to complete the explanations regarding the unit. 
- **Requires**: Contains the other required units in order for the unit to run  successfully. If any of the units identified here are not running  properly, the relevant unit is ended. 
- **Before**: Contains the units that must be run prior to the relevant unit being initiated. 

**[Install] Section**

This section is optional and is used to identify the actions when a  unit is activated or deactivated. The directives you will usually come  across in the install section is as below: 

- **WantedBy:** Is used to identify how the Unit is activated.

**[Service] Section**

This section is used to define the configurations of the service. The directives you will usually come across in the service section is as  below: 

- **ExecStart:** Contains commands and arguments to initiate a service.
- **ExecStartPre:** Contains the commands and arguments needed prior to a service being initiated. 
- **Restart:** Contains information relating to which circumstances the system will restart. 

### **Incident Response**

### **List All Services**

A list of services on the device should be obtained prior to  analyzing the suspicious services. There is more than one method to  obtain the services. 

You may list all services on the device by using the **service** tool.

```bash
service --status-all
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-services-image4.png)

You can also list all of the services on the device by using the systemctl tool. 

```bash
systemctl list-units --type=service
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-services-image5.png)

### **Find Historical Data**

If the attacker will not use the service that he/she has created  again, he/she may have deleted it from the device. In a situation like  this, listing the recorded services might not be enough to identify the  actions that the attacker has conducted on the services. 

If the time frame of the cyber-attack is known, examining the  services executed during this timeframe will help us accurately identify the TTP of the attacker. 

Since we do not know the name of the service, we cannot conduct a  specific search in the logs. At this point, we must evaluate the logs  that have occurred during the attack’s timeframe. 

```bash
sudo journalctl --since "2021-05-07 00:00" --until "2021-05-07 23:59"
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-services-image6.png)

Due to the high number of logs, we may not be able to access the  information we want easily. However, by filtering various words like  unit or service we can continue our analysis with a less number of  logs. 

If we do have the name of the service, we can conduct our research in an easier manner. 

```bash
sudo journalctl -u cron --since "2021-05-07 00:00" --until "2021-05-07 23:59"
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-services-image7.png)

### **Analyze**

Now that we have suspicious services, we can start our analysis.

Initially, we must collect information about the status of the  service. We can access information about the status of the service and  the location of the configuration file with the “**service** ***SERVICE_NAME\*** **status**” command.

```bash
service **SERVICE_NAME** status
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-services-image8.png)

As a result of this command, we can access information relating to  whether the service is actively running, where the configuration file is located, the PID value of the running process and the last couple of  log information of the service. 

We can access the same information through systemctl. 

```bash
systemctl status **SERVICE_NAME**
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-services-image9.png)

After learning the current status of the service and the location of  the configuration file, we can now start to collect information about  the service. 

We can collect information regarding the service by opening the configuration file through any text editor. 

```bash
cat /lib/systemd/system/cron.service
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-services-image10.png)

The sections that we should specifically pay attention to in the  configuration file is in the “service” section. Within the “ExecStart”  directive of this section, the commands and programs that will execute  when the service is activated are present. Attackers can input their own malicious commands into the “ExecStart” directive, and these commands  can run in the background. 

In addition, it is critically important that we identify when the services will run, and which users can run it. 

We can identify when the configuration file for the system has been  edited with the “stat” command. If you suspect that the attacker has  changed a service or has created a new service, you can examine the  information relating to the configuration file. 

```bash
stat /lib/systemd/system/cron.service
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-services-image11.png)

We must examine whether this service has been activated before, and  if it has, we must examine its service logs. In order to view the logs  for the service, we can use the journalctl tool. You can view logs  relating to a specific service by using the “-u” parameter and inputting the name of the unit. 

```bash
journalctl -u **service-name.service**
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-services-image12.png)

If you want to limit your search to a determined time period, you can use the “**--since**” and “**--until**” parameters.

```bash
sudo journalctl -u cron --since "2021-05-07 00:00" --until "2021-05-07 23:59"
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-services-image13.png)

### **Eradication**

In the Eradication step of the incident response, the services  created and changed by the attacker must be deleted and the system must  be restored to its former state.

In addition, we must stop the services created and changed by the attacker. We can stop the service with the commands below. 

```bash
sudo systemctl stop **SERVICE_NAME**
sudo service **SERVICE_NAME** stop
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-services-image14.png)

In order to prevent the service from running automatically when the  system is started, it must be disabled. You can disable the service with the help of the following command.

```bash
sudo systemctl disable **SERVICE_NAME**
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-services-image15.png)

We must remove the configurations and programs relating to the service from the file system. 

```bash
rm **FILE_NAME**
```

The following command must be run for the changed configurations to take effect.

```bash
sudo systemctl daemon-reload
```

### Questions

1 - A cyber attack took place  between 03.11.2021 and 04.11.2021. What is the name of the service that  the attacker created between these dates?

> **Answer:** reverse

2 - Determine whether the service you have detected has been run before. If executed enter "executed", if not enter "not executed".

> **Answer:** not executed

## Crontab

Cron is a tool for scheduling a task in UNIX operating systems. System administrators make frequent use of cron.

This kind of feature is of course abused by attackers to ensure persistence.

Terms like cron, crontab and cronjob are usually mixed up. First, let’s look at the differences in these terms. 

- **Cron**: The name of the tool that ensures the timing of jobs
- **Cron job**: Timed jobs are given the name of cron job
- **Crontab**: Is the configuration file that includes the cron jobs and that identifies when the cron jobs are supposed to work. 

In short; Cron is the tool that executes the jobs (cron jobs) when  they are scheduled and works with the help of the configuration file  named crontab.

### **Understanding Crontab**

Before we start our analysis, let’s look at how a crontab file looks.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-crontab-image1.png)

This crontab file is made up of 6 areas. These are:

1. At what minute the cron job will be executed
2. At what hour the cron job will be executed
3. On which days of the month the cron job will be executed
4. Which months the cron job will be executed
5. Which days of the week the cron job will be executed
6. And finally, the command that will be executed

**Examples:**

If we want a bashscript (for example */root/delete_backup.sh*) to execute at the beginning of every hour, we must add a crontab like the example below.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-crontab-image2.png)

If we want to time the job to execute on the 1st of every month, we must add a crontab like the example below.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-crontab-image3.png)

In devices with a crontab entry like the one below, the bashscript “/root/delete_backup.sh” will execute every 15 minutes.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-crontab-image4.png)

### **Incident Response**

### **List All Cron Jobs**

Since each crontab file is different for each user, in order to  identify all cron jobs, we must examine each crontab file separately. 

#### **Checking the system crontab**

We can first check the system crontab. Since only the authorized  users can edit the system crontab, this file usually has the cron jobs  that will help the system work normally. 

With the help of the command line below, we can see the content of the crontab. 

```bash
cat /etc/crontab
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-crontab-image5.png)

#### **Checking The System Drop-In Directory**

The system’s crontab files are located in the /*etc/cron.d/* directory. To list all of the crontab files in this directory, you can use the command below. 

```bash
cat /etc/cron.d/*
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-crontab-image6.png)

#### **User’s Crontab**

Each user has their own crontab file. To list all cron jobs by all users, you can use the command below. 

```bash
cat /var/spool/cron/crontabs/*
cat /var/spool/cron/*
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-crontab-image7.png)

### **Historical Data**

Detecting only active cron jobs may not be sufficient to detect  attacker cron job activities. In a situation where the attacker deletes  the cron jobs he created because there is no need, it will not be  possible to detect the activities of the attacker through active cron  jobs.

We can list the cron executions from the syslog. With the command  below, we can filter the word CRON in the logs from the syslog. 

```bash
cat /var/log/syslog | grep CRON
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-crontab-image8.png)

With the Journalctl tool, you can detect cron jobs running through the logs of the cron service.

```bash
journalctl -u cron
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-crontab-image9.png)

By using the “**--since**” ve “**--until**” parameters with the journaltcl tool, we can list the Cron executions during the time frame of the attack. 

```bash
journalctl -u cron --since "2021-05-07 00:00" --until "2021-05-07 23:59"
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-crontab-image10.png)

### **Analyze**

After the cron jobs in the system are identified, we can start analyzing these cron jobs. 

First we need to understand when the cron job will run. Crontab files have a specific format. As we mentioned in the "Understanding Crontab"  title, it is possible to schedule a cron job in various ways.

Then the command/script to be run should be examined. Attackers often add the reverse shell command as a cron job. Such commands must be  determined in the crontab.

A good starting point for our cron job examination is to analyze the  cron jobs that have been executed from suspicious locations. For  example, a bash script that is being executed under a /tmp directory is  suspicious. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-crontab-image11.png)

In addition, the names and parameters of the program that will be  executed must be carefully examined. The scripts with names like  “backdoor”, “rev”, or “shell” must be quickly examined. 

After identifying the malicious cron jobs, we must check whether  these cron jobs have been executed before or not. By examining the cron  logs, we can identify whether these cron jobs have been executed in the  past or not. 

We can list cron logs with the commands below. 

```bash
cat /var/log/syslog | grep CRON
journalctl -u cron --since "2021-05-07 00:00" --until "2021-05-07 23:59"
```

### **Eradication**

During the eradication step of incident response, we must delete the  cron jobs added by the attacker and revert the cron jobs that have been  changed by the attacker. 

We can conduct changes on the crontab with the command below. 

```bash
crontab -e
```

To edit a crontab owned by a different user, we can use the “-u” parameter. 

```bash
crontab -u **USERNAME** -e
```

### Questions

1 - What is the IP address of the reverse shell that the attacker has added to the crontab?

> **Answer:** 2.2.2.2

## SSH Authorized Keys

The SSH server allows access to the system with more than one authentication method.

The most commonly used method is to provide authentication with the  username and password pair. However, this method is not more reliable  than other methods. SSH keys are a more reliable and secure  authentication method.

After the user creates the key pairs on his own device, he/she writes the public key to the "~/.ssh/authorized_keys" file on the server that  he/she will access. Thus, the user can now access the server without  using the username-password pair.

This feature is used by attackers to ensure persistence. By adding  their own key to the "authorized_keys" file, the attackers can access  the device whenever they want.

During the incident response procedure, we must identify the SSH keys added by the attacker, and we must delete these keys in order to block  the attacker from accessing the device. 

The *“authorized_keys”* file is located in the “.ssh” directory in the main directory of users. We can use the command below to identify all *“authorized_keys”* files. 

```bash
find / -name 'authorized_keys'
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-ssh-keys-image1.png)

### Questions

1 - Connect to the device you  will analyze with the help of the "Connect" button above. For which user did the attacker add the SSH Auth Key?

> **Answer:** helpdesk

### Bash_rc & Bash_profile

In order to maintain persistence, attackers change the .bashrc and .bash_profile files for their own benefit.

During the incident response procedure, all the methods that the  attackers have made to maintain persistence must be identified. Any  methods of persistence that are not identified will mean that the  attacker can access the system again. Thus, the incident response  procedure will have been unsuccessful. 

Within the .bashrc and .bash_profile files have commands within them  that will run when the shell is activated. Attackers often add reverse  shell commands within these files in order to maintain permanence. 

- **.bashrc**: executed by bash for non-login shells.
- **.bash_profile**: executed for login shells

You can see these files with the cat command or any text editor.

```bash
cat .bashrc
```

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Incident+Response+on+Linux/images/linux-bash_rc-bash_profile-image1.png)

Since each user has different .bashrc and .bash_profile files, all  .bashrc and .bash profile files must be identified and examined. 

### Useful Log Files

As an incident responder, we must know which actions on the system are  recorded, where these actions are stored, and how we can use this  information during our incident response procedure. 

Below, you can find a table that shows commonly used log files during incident response procedures and what information is stored in each  file. 

| **File**     | syslog                                       |
| ------------ | -------------------------------------------- |
| **Location** | /var/log/syslog /var/log/messages            |
| **Contents** | Execution of cron jobs Execution of services |

| **File**     | access.log                                            |
| ------------ | ----------------------------------------------------- |
| **Location** | /var/log/apache2/access.log /var/log/nginx/access.log |
| **Contents** | Web requests                                          |

| **File**     | auth.log                                                     |
| ------------ | ------------------------------------------------------------ |
| **Location** | /var/log/auth.log /var/log/secure                            |
| **Contents** | Logon eventsUser creation eventsGroup eventsUser change events |

| **File**     | lastlog                |
| ------------ | ---------------------- |
| **Location** | /var/log/lastlog       |
| **Contents** | Last logon information |

| **File**     | bash_history                       |
| ------------ | ---------------------------------- |
| **Location** | ~/.bash_history                    |
| **Contents** | Executed commands through terminal |