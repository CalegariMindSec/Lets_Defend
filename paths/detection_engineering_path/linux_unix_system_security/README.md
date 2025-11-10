# Linux/Unix System Security

Explore  the intricate world of Linux/Unix system security in this comprehensive course. Gain hands-on experience in safeguarding your systems against  threats, vulnerabilities, and cyberattacks. From access control and  authentication to encryption and threat detection, you'll develop a deep understanding of security concepts and practical techniques to fortify  your systems. Equip yourself with the knowledge to confidently protect  Linux and Unix environments and bolster your cybersecurity expertise.

**Table of Contents:**

- [Introduction to Linux/Unix System Security](#introduction-to-linuxunix-system-security)
- [Linux Distributions](#linux-distributions)
- [Update & Upgrade on Linux/Unix](#update--upgrade-on-linuxunix)
- [Authentication on Linux/Unix](#authentication-on-linuxunix)
- [Authorization on Linux/Unix](#authorization-on-linuxunix)
- [Password Management on Linux/Unix](#password-management-on-linuxunix)
- [Password Policies on Linux/Unix](#password-policies-on-linuxunix)

**Evaluate Yourself with Quiz**

- [Linux/Unix System Security](https://app.letsdefend.io/training/quiz/linux-unix-system-security)

## Introduction to Linux/Unix System Security

Today, many organizations, including the world's largest data centers and cloud service providers, run their activities on Linux and  Unix-based servers. These operating systems stand out with their  customizability, compatible cost structure and flexibility features.  This wide usage makes Linux systems vulnerable to various security  threats. Linux security includes a set of strategies and tools used to  protect systems against these threats. However, these systems are  complex structures that require attention and knowledge in terms of  security.

However, Linux security is not just about tools and strategies. It  also requires knowledge of the nature and functioning of Linux. Linux  file permissions, user and group management, system and network  services, update, upgrade, log infrastructure are all important aspects  of Linux security, and understanding how they work and how to manage  them is the basis for building a secure Linux system.

In short, Linux security is essential to ensure your overall system  and data security against increasing digital threats. Knowledge and  skills in Linux security are essential for being successful and safe in  today's digital world both for beginners and even for the experienced  professionals.

In conclusion, with this training, we aim to establish a solid  foundation in ensuring Linux/Unix system security. By focusing on both  theoretical knowledge and practical skills, you will become better  equipped to secure systems. By participating in this introductory  course, you can be a part of this journey and increase your knowledge  and skills in Linux system/server security.

We will start learning the “**Linux Distributions”** topic in our next chapter.

## Linux Distributions

Linux is an open-source operating system which means it is open for  anyone to modify a Linux kernel and customize it to fit into their  needs. These customized versions are often referred to as "Linux  distributions" or "distros" for short. In addition to the Linux kernel, a Linux distribution includes applications, libraries, command line  tools, a window system, and often a graphical user interface (GUI).

Linux distributions are classified into several major branches,  usually based on the package management system and philosophy they lead. The two biggest branches are Red Hat and Debian based distributions.  These two branches are the most popular and widely used versions of  Linux, and many other distributions are built on one of these two major  distributions.

### **Debian Based Distributions**

Debian is a Linux distribution that is extremely stable, reliable and has a large software repository. Debian uses the package management  system called APT (Advanced Package Tool) and supports the DEB package  format. Debian-based distributions generally focus on reliability and  stability. Debian also forms the basis of the user-friendly Ubuntu  distribution. Ubuntu, on the other hand, had its own derivatives and  formed the basis of popular distributions such as Linux Mint, Elementary OS, Pop!_OS.

### **Red Hat Based Deployments**

Red Hat is a Linux distribution designed for commercial and  enterprise use. Red Hat uses the RPM (Red Hat Package Manager) package  management system and is generally preferred for server and enterprise  solutions. Red Hat's largest derivative is CentOS, which has no  commercial support and is managed by the community. Alongside CentOS,  Fedora is another popular distribution powered by Red Hat, which is  often used to test the latest technologies and gather feedback from  users.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/2/image2-1.png)

(Image Source: https://nixwindows.wordpress.com/2015/02/09/linux-distros/)

Here are some of the most popular Linux distributions and some of their key features:

### **Ubuntu**

Ubuntu is one of the most popular Linux distributions worldwide. It  is especially recommended for beginners because it has a user-friendly  interface and is supported by a large community. Ubuntu is available for desktops, servers, and cloud environments.

### **Fedora**

Fedora is another popular option, especially for users who want to  try out current open source technologies. One of Fedora's strengths is  that it is a community project maintained and supported by Red Hat Inc.. This allows Fedora to experiment with technologies used in professional systems such as Red Hat Enterprise Linux (RHEL).

### **Debian**

Debian is another popular Linux distribution known for its stability  and high standards. Debian has a very large software repository and is  available for many different computer architectures. This makes Debian  usable in a wide variety of applications.

### **ArchLinux**

Arch Linux allows the users to fully customize the system. This means that the user can install only the software he needs, thus creating a  very light and fast system. However, this flexibility of Arch Linux  requires the user to have more knowledge about Linux and system  administration.

### **CentOS**

CentOS is a clone of Red Hat Enterprise Linux (RHEL) and is therefore often used in server environments. CentOS offers Red Hat's pro-level  features and performance, but without Red Hat's commercial support.

### **Kali Linux**

Kali Linux is an open source Linux distribution used by people who  specialize in cybersecurity and penetration testing. Based on Debian,  Kali Linux offers a wide range of software including many security tools and is preferred by hackers, penetration testers and network security  professionals. Kali Linux provides its users with the necessary tools to detect network vulnerabilities, identify vulnerabilities, and perform  penetration tests.

### **Conclusion**

These distributions are just the beginning. There are hundreds of different Linux distributions available.

The below link is a good source for you to keep up to date with other Linux distributions:

**Linux Distros** : https://distrowatch.com/

Each Linux distribution appeals to a specific user base, a specific  use case, or a specific philosophy. The variety of Linux distributions  is a testament to the power and flexibility of Linux, and every user can find a distribution that meets their needs. Therefore, the best  distribution for a Linux beginner often depends on what the person wants to achieve, what hardware they use, and what level of knowledge they  have.

In this part of the training, we have learned about the Linux distributions. We will cover the “**Update & Upgrade on Linux/Unix**” topic in the next part of our training.

### Questions

1 - What are customized Linux versions called?

> **Answer:** Distro

2 - Which package management system does Red Hat use?

> **Answer:** RPM

3 - What is an open-source Linux distribution used by people who specialize in cybersecurity and penetration testing?

> **Answer:** Kali Linux

## Update & Upgrade on Linux/Unix

Regular and effective updating of every operating system is a  critical part of information security and the Linux operating system is  not exempt from this rule. Linux's 'update' and 'upgrade' commands play a major role in closing potential security vulnerabilities, while keeping your system's software up-to-date and secure.

In Linux operating systems, software updates are usually performed  via the command line, and this is usually done with the update and  upgrade commands. Let's take a closer look at this issue:

### Update

The update command usually tells the package manager to check all  software repositories for new versions and updates. This updates the  list of packages in the repositories, but does not upgrade your existing software versions which means the update command doesn't change or  upgrade anything on your system, it just checks for the presence of new  updates and makes them available for download.

In Debian-based distributions, this is usually done with the "sudo  apt update" command. In Red Hat-based distributions, the "sudo yum  check-update" command is used.

**Ubuntu Update Process**

It checks the list of packages that need to be updated with the "sudo apt update" command and makes them ready for update.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/3/image3-1.png)

**Centos Update Process**

It checks the list of packages that need to be updated with the "yum check-update" command and makes them ready for updating.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/3/image3-2.png)

### Upgrade

The upgrade command upgrades the packages on your system to newer or  the latest versions according to the updated package list. This command  is typically used after running the update command.

This process is performed with the “sudo apt upgrade” command on  Debian-based systems and the “sudo yum upgrade” command on Red Hat-based systems.

These two commands are usually used together, first updating the  package list with update and then upgrading these packages to the newest versions with upgrade. On Debian-based systems these two commands are  often run together:

**Command:** 

```sh
sudo apt update && sudo apt upgrade                
```

These are the basic commands used to manage software updates in  Linux. However, in some cases more complex updates may be required, for  example an operating system upgrade. In this case, more specific  commands are usually used and such updates require more care and  precautions.

**Ubuntu Upgrade Process**

With the "apt upgrade" command, you can update the packages that need to be updated. In order to update the packages, we just need to presss  “Y” key for “YES” for the question asked for upgrade.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/3/image3-3.png)

**Centos Upgrade Process**

You can update the packages that need to be updated with the “yum  upgrade” command. To update the packages, we just need to presss “Y” key for “YES” for the question asked for upgrade.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/3/image3-4.png)

### Conclusion / Summary

In conclusion, regularly updating and upgrading your Linux operating  system is vital to the security of your system. These processes not only keep your system up to date with the latest features and improvements,  but also close potential security vulnerabilities and protect your  systems from cyber threats. However, it is also important to be careful  when performing these operations. Accidentally deleting a critical  system file or creating a problem in the system due to incompatibility  of an update can lead to serious problems. Therefore, it is always best  to test updates first and make backups of important data.

In this part of the training, we have covered the update and upgrade  operations on Linux systems and how they are implemented. We will learn  about the “**Authentication on Linux/Unix”** topic on the next part of the training.

### Questions

1 - Which command is usually used to install, remove or upgrade package in Redhat based distributions?

> **Answer:** YUM

2 - Which command is used to install, remove, or upgrade packages in Debian-based distributions?

> **Answer:** APT

3 - What is the command to  check the list of packages that need to be updated in Ubuntu and make  them ready for updating? (with sudo command: sudo XXX XXX)

> **Answer:** sudo apt update

## Authentication on Linux/Unix

Authentication in the Linux operating system is another important points of the system security and user control.

Authentication refers to the process of verifying who a user is. It  is usually done with a combination of username and password, and this  information is usually managed through PAM (Pluggable Authentication  Modules). Advanced authentication mechanisms include techniques such as  two-factor authentication (2FA), making the authentication process more  secure.

### Authentication

Authentication is the process of verifying who a user is.  Authentication in Linux is usually done with a username and password  combination. This information is checked against the list of users  defined in the system and if correct, the user can access the system.  Users enter a username and password to log into the operating system.  Linux looks for the username in the “/etc/passwd” file and the  corresponding password hash in the “/etc/shadow” file. If the entered  password matches the hash stored in the system, the user can log in to  the system.

**/etc/passwd:** This file contains user account information. Username, user and group ID, home directory and shell  information of each user are stored here.

**/etc/shadow:** This file contains users'  passwords, which are stored by encryption. Keeping passwords separate  from /etc/passwd improves system security.

The below image shows the details of the file contents of “/etc/passwd” and “/etc/shadow”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/4/image4-1.png)

In Linux, the authentication process can also be done via PAM  (Pluggable Authentication Modules) with more advanced capabilities. PAM  standardizes and manages authentication processes between various  services and applications in the system.

PAM achieves this generic and reusable structure by dividing the  verification process into "modules". A module usually represents a  specific authentication mechanism. For example, one module may represent traditional UNIX password authentication, and another module a  network-based authentication service such as LDAP, RADIUS, or NIS. This  allows a system administrator to complexly configure modules to  determine what type of authentication a service should use.

Below you can find some PAM modules:

**pam_unix.so:** Provides UNIX password authentication.

**pam_cracklib.so:** Requires strong passwords.

**pam_securetty.so:** Allows root user to login only from secure terminals.

**pam_nologin.so:** prevents normal users from logging in if the nologin file exists.

You can configure PAM modules in “/etc/pam.d/” or “/etc/pam.conf”  file. These configurations are service-based, meaning you can set  different PAM policies for each service.

Also, there are more secure authentication methods available. For  example, in two-factor authentication (2FA) systems, a user  authenticates not only with username and password information, but also  with another information or device (for example, a phone).

Let's take an example to better understand the capabilities of PAM.  (Example is made on CentOS distribution. Steps may differ according to  distributions.)

**Note**: This process is done separately for each user. In this example, the process will be done for the "root" user.

**Step-1:** Install the "google-authenticator" package with the following command:

**Command** : sudo yum install google-authenticator -y

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/4/image4-2.png)

**Step-2:** The application is opened by running the "google-authenticator" command from the terminal.

After running the command it will be necessary to answer some  questions. First, you will be asked to enable time-based authentication. This is usually answered with “Y”.

It then asks you to generate an emergency passcode (or "key to boot") and whether codes can be used multiple times, whether codes expire  after 30 seconds, and whether a code used within the last 30 seconds  should be rejected. Each of these questions should be answered with "Y"  or "N" depending on your situation.

This action will also generate a QR code. You can scan this code when you install the Google Authenticator app on your phone.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/4/image4-3.png)

**Step-3:** PAM must be configured to use Google Authenticator. This setting is made by editing the sshd PAM  configuration file. Open the “/etc/pam.d/sshd” file with the text editor and add the following line:

```txt
auth required pam_google_authenticator.so                    
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/4/image4-4.png)

**Step-4:** Finally, SSH must be configured to  use 2FA. To do this, the SSH configuration file “/etc/ssh/sshd_config”  is opened with a text editor and the “ChallengeResponseAuthentication”  value in the file is set to “yes”.

**Step-5:** The ssh service is restarted for the settings to be active.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/4/image4-5.png)

**Step-6:** By making an attempt to access with  SSH, it is seen that the 2FA code is requested after the password and  the login is entered after the information is entered.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/4/image4-6.png)

These are the general steps to set up 2FA with Google Authenticator  on CentOS 7. You should be extremely careful when configuring these  settings as an incorrect action may completely block the SSH access.  Always make a backup before making chances and test it first in a test  environment.
In this part of the training, we have covered the  authentication mechanism on Linux and the implementation of the  authentication process with the PAM module. We will learn about the “**Authorization on Linux/Unix**” topic in the next part of the training.

### Questions

1 - What is the UID (user id) value of the "analyst" user on the system you are accessing?

> **Answer:** 1001

## Authorization on Linux/Unix

Authorization in the Linux operating system is another important points of the system security and user control.

Authorization determines what a user can do. A user's powers are  often based on his or her group memberships and the authority levels of  those groups. Linux has authority settings on the file system that  determine who can do what on a particular file or directory.  Authentication and authorization work together to ensure the secure and  proper functioning of Linux systems.

Authorization is the process of controlling what types of actions a  user can perform on the system. Authorization in Linux is the process of granting access to files, directories, or commands to specific users or groups. This process is important to increase the security of the  system, control what users can do, and maintain the integrity of the  data. The issue of authorization will basically be detailed under 2  different headings:

### Sudo authorization

A user's powers are often determined by his or her group memberships. For example, users included in the sudo group usually have root  privileges on the system and gain full control over the system. The  “sudo” (superuser do) tool uses the “/etc/sudoers” file to control which commands specific users or user groups can run and on which systems.

You can check the following elements to determine what users can do with sudo:

**Users:** You can specify which users can use the sudo command.

**Systems:** You can specify which systems they can run the sudo command on.

**Commands:** You can specify which commands they can run with sudo.

The management of sudo authorization is done using the "visudo"  command. This command provides a safe way to edit the "/etc/sudoers"  file. To avoid conflicts, Visudo locks the edit while someone else is  editing the file and checks for syntax errors.

Here are some examples of sudo definitions;

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/5/image4-7.png)

The examples above show how to configure the “/etc/sudoers” file.  This file controls how the “sudo” command is used and is therefore  important for security. An accidental change can result in a user  gaining full control over the system or the sudo command not working.  Therefore, it must be edited using the visudo command.

### File /Directory Authorization

In Linux, the privileges of files and directories are divided into  three categories: owner, group, and other. Each file and directory  belongs to a specific user (owner) and group. Read (r), write (w), and  execute (x) permissions for each can be set separately. These privileges can be managed with the chmod and chown commands.

The chmod, chown, and chgrp commands are commonly used to manage file and directory authorizations in Linux. Some examples of these commands:

**Setting File/Directory Permissions (using chmod):**

- Granting read (r), write (w), and execute (x) permissions to a particular file to user (u), group (g), and others (o):

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/5/image4-8.png)

In this example, for the file named “myfile”, the user reads, writes  and executes; read and run to the group; Other users are given read-only permissions.

- Setting permissions in numeric format:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/5/image4-9.png)

In this example, the file named “myfile” is read, written and  executed by the user (7); read and run to group (5); other users (4) are only given read permission.

**Change File/Directory Owner (using chown):**

- Changing the owner of a file:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/5/image4-10.png)

In this example, the owner of the file named “myfile” has been changed to “newuser”.

- Changing the owner of a directory and its contents:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/5/image4-11.png)

In this example, the directory named “mydirectory” and its contents  have been changed to “newuser” (the -R parameter causes the action to be applied to all subdirectories and files of the directory).

**Changing File/Directory Group (using chgrp):**

- Changing the group of a file:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/5/image4-12.png)

In this example, the group of the file named “myfile” has been changed to “newgroup”.

- Changing the group of a directory and its contents:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/5/image4-13.png)

In this example, the group of the directory named "mydirectory" and its contents has been changed to "newgroup".

Authorization is especially critical to the security of a Linux  system. Incorrect authorization settings can give unauthorized users or  attackers access to important files or services that can compromise the  system.

In this part of the training, we have covered the authorization  mechanism on Linux and how the authorization can be implemented. We will learn about the “**Password Management on Linux/Unix**” topic in the next part of the training.

### Questions

1 - Which user has been given "sudo" authority to run only the "apt" command on the system you access?

> **Answer:** updater

2 - Which user is the owner of the “/usr/bin/whoami” file?

> **Answer:** root

3 - Which user owns the file “/usr/bin/at”?

> **Answer:** daemon

## Password Management on Linux/Unix

Password management in the Linux operating system is a critical  element of system security and protects systems from unauthorized  access. Passwords form the basis of authentication, and control users'  access to the system and various services. However, weak or standardized passwords are easy targets for attackers to exploit. That's why  effective password management has a huge impact on the overall system  security.

The Linux operating system provides a set of tools and policies for  secure password management. Password management is a crucial mechanism  for authenticating a user and preventing unauthorized access. Here are  some details about password management on Linux systems:

### Password Management Tools

There are several tools that help manage the passwords on Linux. For  example, “passwd” is a command-line-based password manager that allows  you to securely store and manage passwords.

Some of the important password management tools are:

**passwd:** This is the most commonly used tool  for managing passwords. With the passwd command, users can change their  passwords and system administrators can reset or change users'  passwords.

**chage:** This tool is used to set the password lifetime of users. The system administrator can set how often a user's  password should be changed, when password warnings should expire, and  when the account should be disabled.

**usermod:** This tool is a command that system  administrators can use to modify user accounts. For example, the command "usermod -L" is the command that locks a user's password, and the  "usermod -U" command is the command that unlocks it.

**PAM (Pluggable Authentication Modules):** PAM  provides authentication management in Linux. PAM modules allow to set  policies such as password complexity, trial times, and session controls.

**faillog:** This tool is used to monitor user failed login attempts.

**last:** This tool shows when and which users last logged into the system.

**sudoers:** This determines what privileges  certain users or groups have over the sudo command. This helps determine which commands users can run with what privileges.

Each of these tools is used to provide secure password and user management on Linux systems.

### Password Setting

In Linux, user passwords can be set with the "passwd" command. This  command allows you to change the password of the current user or a  specified user (when run as root user). In Linux distributions,  passwords are securely stored in the /etc/shadow file. This file is  allowed to be read by the root user. This prevents normal users from  being able to access the file and read the passwords. Passwords are not  stored in plain text form. Instead, passwords are first passed through a hash function. This function takes the password and converts it to a  unique string of a certain length. This string is then stored in the  "/etc/shadow" file.

An example line “/etc/shadow” file contents are as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/6/image5-1.png)

Details of the fields that are separated with “**:**” in each line of the file are as follows:

**Username**: In this example, the username is "root".

**Hash:** This section contains the password,  and it usually contains a password passed through a hash function such  as $6$80Ch3whg$2FPi6KtjhgTUwgY2iy, just like the one in the above image. The value $6$ indicates that the hash of the password was calculated  using the SHA-512 hash algorithm. Next comes the salt value and the  encrypted password.

**Date of Last Change**: This section displays the date of the last password change, expressed as Unix time.

**Minimum Password Age:** This section  determines how often the user can change the password. 0 indicates that  the user can change the password at any time.

**Maximum Password Age:** This section determines how often the user should change their password. 99999 usually means the password will not expire.

**Warning Period:** This section determines the  warning period alert that the user will receive before their password  expires. In this example, a warning will be given 7 days in advance.

**Inactivity Period:** Determines how long the  account will remain inactive after the password expires. In this example it is empty, meaning the account will not automatically get disabled.

**Account Expiry Time:** This section determines when the account will expire. In this example it is empty, meaning the  account will not expire automatically.

In addition, standard users in Linux have to know their current  password when they want to update their own password. However, there is  no obligation to know the current password in order to change the  password of the “root” user and any other user’s password to change it  using the root user.

In this part of the tutorial, we have covered the password  management, password management tools and the contents of the  “/etc/shadow” file in Linux. We will learn about the “**Password Policies on Linux/Unix”** topic in the next part of the training.

### Questions

1 - On which day of August was the last time the "pokemon" user logged into the system?

> **Answer:** 26

2 - What is the name of the user whose password hash starts with "$6$1twyE..." on the linux lab machine you connected to?

> **Answer:** pokemon

3 - Which hash algorithm is used to keep the password of the "letsdefend" user on the system you access?

> **Answer:** SHA512

## Password Policies on Linux/Unix

Password policies are used to enable users to choose passwords that  meet certain security standards. On Linux systems, password policies are usually managed with PAM (Pluggable Authentication Modules) and chage  commands. Also, the login.defs file is used to set some system-wide  default password policies.

### Setting Password Policies with PAM

PAM comes with a set of rulesets and modules. Using these modules and rule sets, we can tweak password policies that include complexity,  duration, and history. To edit these modules and rules, you must first  open the “/etc/pam.d/common-password” file with a text editor.

For example, if you want a password to be at least 10 characters long and contain both uppercase and lowercase letters and numbers, you can  add a rule like this:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/7/image5-2.png)

In this rule indicates that the password should contain;

**minlen:** minimum password length

**ucredit:** at least one uppercase letter

**lcredit:** at least one lowercase letter

**dcredit** : at least one digit number

### Setting Password Policies with the “chage” Command

The “chage” command allows you to edit policies that determine how long a user's password is valid and when it must be changed.

For example;

If you want to allow a user to use their password for a maximum of 60 days, you can use the following command:

**Command:** 

```sh
sudo chage -M 60 username             
```

You can use the -l (list) option to query a user's password duration. For example, to query the password duration of a user named username:

**Command:** 

```sh
sudo chage -l username        
```

The important parameters related to the chage command are given below:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/7/table-unix.png)

### Setting Password Policies with “login.defs” File

The “/etc/login.defs” file sets some system-wide default password  policies. This file contains information such as how long the user can  use his password, how long he can remain without a password, and when he should change his password. You must use a text editor to edit this  file.

Let's take the example of a policy. PASS_MAX_DAYS The default value  of 99999 specifies that the user password will be valid indefinitely. If you want to limit this value to 60 days, you can change it like this:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/7/image5-5.png)

Below is a summary of password policies that can be set in the file “/etc/login.defs”:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Linux-Unix-System-Security/7/table-unix-2.png)

### **Two-Factor Authentication**

Passwords are part of authentication, but it may not be enough if  used alone. So, we may need to set Two-Factor Authentication (2FA) to  ensure the access security. 2FA requires a password and another factor  to authenticate a user. On Linux, 2FA can be set up with tools like  Google Authenticator.

**Note**: In the "Authentication on Linux/Unix" lesson,  an example of how to do SSH access with Google Authenticator with 2FA  has been explained.

### Conclusion/Summary

In conclusion, password management in Linux offers a set of tools and policies to manage user passwords securely and effectively. Proper  implementation of these policies and tools can help keep systems secure. These methods adjust your password policies, forcing users to use  stronger passwords. However, it should be noted that password policies  are only a security measure and do not protect users against other  security threats.

In this part of the training, we have covered password policies on Linux and the applications of these policies.

### Questions

1 - What is the account expiration date of the “pokemon” user? (Answer Format: Jan 02, 2029)

> **Answer:** Jun 05, 2040

2 - What is the maximum validity period of the password of the "updater" user?

> **Answer:** 90



































