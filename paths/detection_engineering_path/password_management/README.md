# Password Management

Whether you're a seasoned professional or a novice in the realm of digital  security, this course provides practical insights and actionable  strategies to safeguard your online presence and confidential  information, ensuring a safer and more secure digital experience.

**Table of Contents:**

- [Password Creation Principles]()
- [Password Update and Change]()
- [Password Storage and Encryption]()
- [Password Sharing and Communication]()
- [Password Theft and Threats]()
- [Password Managers and Automatic Encryption Tools]()

**Evaluate Yourself with Quiz**

- [Password Management](https://app.letsdefend.io/training/quiz/password-management)

## Password Creation Principles

Password management is a  critical issue for digital security. A strong and effective password  management strategy is an essential step in ensuring the security of  information, accounts, and systems. Password management includes users  creating strong passwords, updating passwords regularly, and storing  passwords securely.

The first step is to  create strong passwords. Strong passwords should contain complex and  hard-to-guess combinations. Its length, complexity, and uniqueness  matter. Regularly changing passwords is a precaution that improves  password security and helps protect accounts from malicious use.

Safe storage of passwords is also very important. Writing down passwords, leaving them around  insecurely, and sharing them randomly poses a security risk. It is  important to store and access passwords securely using password managers or encryption tools. These tools encrypt and protect passwords securely and provide the user with access to a single master password.

Password management also  includes additional security measures such as two-factor authentication. Two-factor authentication requires users to log in using a second  authentication factor (for example, an SMS verification code, mobile  app, or a physical security key). This ensures accounts are secured with an additional layer of protection.

### Password Creation Policies

Password creation  policies should include the basic principles of creating strong and  secure passwords. Password generation principles basically consist of  important items such as length, complexity, uniqueness,  unpredictability, regular password updates, using automatic password  generation tools, etc.

**Length:** It is important that  passwords are too long to guess easily. It is generally recommended to  be at least 12 characters long. Longer passwords provide more robust  protection.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Password-Management/1/pass1.jpeg)

**Complexity:** Passwords being complex  will make them difficult to guess. It is ideal if it contains a  combination of uppercase letters, lowercase letters, numbers, and  special characters. For example, a complex password such as  "P4sSW0rD54S3cUr!tY10" can be considered secure.

**Uniqueness:** It is important to use  unique passwords for each account. Using the same password across  multiple accounts will put all those accounts at risk if one account is  compromised.

**Unpredictability:** Passwords should be unpredictable which will make it difficult for attackers to discover the password easily. Personal information such as birth dates, names, and  phone numbers should be avoided.

**Automatic Password Generation Tools:** Automatic password  generation tools can be used to generate secure passwords. These tools  generate strong passwords randomly and provide an easy option for users.

Password generation  policies guide the creation of strong and secure passwords. By following these principles, you can make passwords harder to guess, increase the  security of accounts and data, and be more protected from malicious  attacks.

The following section is used to set a password policy on Windows.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Password-Management/1/image4-1.png)

The following file is used to set a password policy on Linux:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Password-Management/1/image4-2.png)

In this part of the  training, we have covered the important points of setting a secure  password. In the next part of our training, “Password Update and Change” topic will be discussed.

### Questions

1 - What is the name of the file used to set the password policy on Linux?

> **Answer:** login.defs

2 - What is the minimum password length as a password policy on the Linux lab machine you are connected to?

> **Answer:** 12

3 - What is the maximum validity of the password as a password policy on the Linux lab machine you are connected to?

> **Answer:** 60

4 - According to the password  policy on the Linux lab machine you are connected to, what is the  minimum number of numbers in the password?

> **Answer:** 3

## Password Update and Change

Password updating and  changing is an important part of a secure password management strategy.  Regularly updating passwords helps increase the security of accounts and data. Some information on Password Update and Change is as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Password-Management/2/pwd1.jpg)

**Frequency of Updates**

How often passwords  should be updated often depends on policies set by the organization. The recommended period is usually 90 days. However, in some cases, this  period may be shorter or longer.

**Update Reminders**

Password update reminders are helpful for users to change their passwords regularly. These  reminders are delivered in different ways, such as email or mobile app  notifications. It is important to enable these reminders to ensure that  users regularly update their passwords.

**Password Change Guidelines**

Users should be provided  with detailed instructions for the password change process, password  policies, and requirements. Users should be made aware of creating  strong and complex passwords, not repeating previously used passwords,  and storing their passwords securely.

### Questions

1 - What is the recommended frequency of changing passwords to keep them secure?

> **Answer:** 90

## Password Storage and Encryption

Password storage and  encryption are important steps in keeping passwords secure and  protecting them from malicious use. More information on Password Storage and Encryption is below:

**Storing Password**

Storing passwords in  plain text poses a security risk. If passwords are compromised by  unauthorized persons, they can easily access accounts and data. A secure method of storing passwords is to store passwords encrypted. In this  method, the hash value of the password is calculated and this value is  stored in the database so the password cannot be viewed in a clear text.

**Password Encryption**

Password encryption is  another method for securely storing passwords. Encryption makes the  password unintelligible, protecting it from unauthorized access. It is  important to encrypt passwords using a strong encryption algorithm.  Commonly used algorithms include AES (Advanced Encryption Standard) and  bcrypt. It is important to securely store and manage the keys used for  encryption. Protecting keys from unauthorized access ensures the  security of the password encryption process.

**Secure Password Storage Tools**

Password managers or  password storage tools can be used to securely store passwords. These  tools encrypt and protect passwords and allow users to securely access  passwords. Password managers are applications where users can securely  store all their passwords with a single master password or key. In this  way, users are encouraged to use complex and unique passwords. Password  storage tools ensure that passwords are stored securely on the user's  device. These tools create a database where passwords are stored  encrypted and users can only access passwords with a master password or  key.

Password storage and  encryption are important steps that increase the security of passwords.  Accounts and data can be compromised when passwords stored in plain text or weak encryption methods are used. Therefore, it is important to  implement secure password storage and encryption methods.

For example, passwords on Linux are kept as in the image below.

![img](https://app-ld-img.s3.us-east-2.amazonaws.com/training/image4-3_new.png)

In this part of the training, we have covered password storage and encryption. We will be learning about the “Password Sharing and Communication” topic in the next part of the training.

### Questions

1 - What is the name of the file where the hashes of passwords are kept on Linux?

> **Answer:** shadow

2 - On the Linux lab machine  you are connected to, how many different users have password hashes in  the file where the hashes of the users' passwords are kept?

> **Answer:** 3

## Password Sharing and Communication

Password sharing and  communication is an important issue for the secure sharing and transfer  of passwords. If we fail to use the right methods, there is a high  possibility for the passwords to fall into the hands of unauthorized  persons. Here is some information on Password Sharing and Communication:

**Secure Sharing Methods**

When passwords need to be shared, secure methods should be used. Sending passwords via email,  instant messaging, or plain text are totally risky. Instead, it is  important to use secure encryption protocols. For example, tools such as PGP (Pretty Good Privacy) can be used to send passwords encrypted. It  is also a preferred method to securely share passwords face-to-face or  with people you trust. This reduces the risk of the password being  compromised by unauthorized persons.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Password-Management/4/pshare1.jpg)
(Image Source: https://www.freepik.com/free-vector/global-data-security-personal-data-security-cyber-data-security-online-concept-illustration-internet-security-information-privacy-protection_12953633.htm  )

**Secure Communication Tools**

Secure communication  tools should be preferred for the communication of passwords. It is  important to use secure communication tools such as encrypted messaging  apps or virtual private networks (VPN). In this way, the risk of  passwords being compromised by unauthorized persons is minimized.

**Password Storage and Sharing Tools**

Password storage and  sharing tools can be used to share passwords securely. These tools  provide security by encryption methods when storing and sharing  passwords. These tools facilitate the password-sharing process by  enabling the secure sharing of passwords among users.

**Password Sharing Policies**

Organizations should set  policies for password sharing. These policies should cover topics such  as how passwords could be shared, with whom they could be shared, and  which communication channels could be used to share them securely.  Password-sharing policies increase security awareness and provide  consistent security for password-sharing.

Password sharing and  communication are important steps for securing passwords. Using the  right methods and choosing secure communication tools makes the  password-sharing process secure and reduces the risk of unauthorized  access.

In this part of the  training, we have covered the important points to be considered about  password sharing. The next part of the training will be about the “Password Theft and Threats” topic.

## Password Theft and Threats

Password theft and  related threats are risks that arise when passwords are stolen or  misused by attackers or unauthorized people. Such threats can compromise the security of accounts and data. Let’s dive into more information on  Password Theft and Threats:

### Credential Harvesting Methods

**Phishing**

Attackers try to steal user passwords by deceiving users through fake emails, websites, or messages.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Password-Management/5/phish1.jpg)
(Image Source: https://www.freepik.com/free-vector/phishing-account-concept_7970704.htm)

**Keylogger**

A keylogger is a type of  software or hardware device that records every keystroke made on a  computer or mobile device. Keyloggers capture passwords by recording  keyboard entries through malware deployed on the victim system  previously.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Password-Management/5/phish2.gif)
(Image Source: https://www.nevis.net/en/blog/how-do-formbook-keylogger-and-snake-keylogger-work)

**Brute Force Attacks**

A brute force attack is a hacking technique that involves trying every possible combination of  characters until the correct one is found, usually used to crack  passwords or encryption keys. They generally do this through automated  applications.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Password-Management/5/phish3.jpg)
(Image Source: https://www.freepik.com/free-vector/hacker-password-composition-with-hacker-attack-headline-man-makes-password-guessing-illustration_6870816.htm)

**Dictionary Attack**

A Dictionary Attack is a  type of cyber attack where an attacker tries to gain unauthorized access to a computer system or network by using a pre-existing list of words,  phrases, or passwords.

**Social Engineering**

Social engineering is the tactic of manipulating, influencing, or deceiving a victim in order to  gain control over a computer system, or to steal personal and financial  information. It uses psychological manipulation to trick users into  making security mistakes or giving away sensitive information.

### Precautions Against Password Threats 

- It is important to use  strong and complex passwords. A complex password must be a combination  of upper and lower-case letters, numbers, and special characters.  
- It is important to change passwords regularly. Changing passwords after a certain period of time reduces the risk of theft.  
- Using multi-factor  authentication increases security. Additional verification steps should  be added, such as SMS verification, mobile app verification, or physical security keys.  
- Using secure internet  connections reduces the risk of passwords being stolen. Risky  connections such as public networks or unsafe Wi-Fi hotspots should be  avoided.  
- Using reliable and up-to-date anti-virus software prevents password theft attacks leveraged through malicious software.    

Keeping our credentials  and personal information is a vital part of our information security and we should be very careful protecting them by taking security measures  to ensure the security of our passwords. User awareness is important  also, it is important for users to be wary of suspicious communications  and fake websites.

In this part of the  training, we have covered the methods for protection against password  theft and related threats. The next part of the training will be about “Password Managers and Automatic Encryption Tools”.

### Questions

1 - What is the attack that tries to access the systems by guessing the users' passwords with the help of a list?

> **Answer:** Dictionary Attack

## Password Managers and Automatic Encryption Tools

Password managers and  automatic encryption tools are tools used to increase password security  and simplify password management. More information on Password Managers  and Automatic Encryption Tools is below:  

### Password Managers

- Password managers are applications that allow users to store and manage their passwords in a secure way.  

- Password managers help  users create unique and complex passwords as well as help them to use  different passwords for different accounts.  

- Password managers  encrypt and store passwords securely and allow users to access all their passwords with a single master password or key.  

- Password managers are  tools that allow users to log into their accounts quickly and securely  with the built-in password autofill.  

### Automatic Encryption Tools

- Automatic encryption tools are applications that allow users to encrypt their passwords automatically and store them securely.  

- These tools protect users' passwords by encrypting them using strong encryption algorithms.  

- Automatic encryption tools ensure that passwords are stored securely on the user's device or in the cloud.  

- Users can easily access, share, and update their passwords using these tools.    

Password managers and  automatic encryption tools simplify password security and management.  Today, users are encouraged to use strong passwords and choose different passwords for different accounts as well as using encryption techniques to securely store passwords. These tools reduce users' password  security issues and make password management more effective.

### Conclusion

In this tutorial, we've  detailed the importance and best practices of password management. We  have learned that the password is one of the most widely used means of  authentication and can pose significant security risks if not managed  properly.

We focused on the  importance of creating strong passwords, the need to change passwords  regularly and use different passwords for different services. We've also found that tools like multi-factor authentication and password  management systems make password management more secure and manageable.  We understand that password management is a critical element for  personal and corporate security.























