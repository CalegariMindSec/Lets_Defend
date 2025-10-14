# Secure Network Design

The  "Secure Network Design" course offers comprehensive insights into  designing and implementing networks that prioritize security, equipping  cyber people with the expertise to create resilient and protected  digital infrastructures against evolving cyber threats. Through a blend  of theoretical concepts and practical applications, participants will  gain a deep understanding of network architecture, access controls, and  risk management strategies, enabling them to develop and maintain secure communication channels within a dynamic and interconnected  technological environment.

**Table of Contents:**

- [Introduction to Secure Network Design]()
- [Overview of Security Principles]()
- [Security Principle: Access Control]()
- [Functional Separation and the Principles of the Least Privilege]()
- [Strong Authentication Methods]()
- [Session Management]()
- [Static and Dynamic Data]()

[Identification and Remediation of Weak Links](https://app.letsdefend.io/training/lesson_detail/identification-and-remediation-of-weak-links)

**Evaluate Yourself with Quiz**

- [Secure Network Design](https://app.letsdefend.io/training/quiz/secure-network-design)

## Introduction to Secure Network Design

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Secure-Network-Design/1.Introduction/sni1.png)

This training will cover the importance of secure network  infrastructure design and successful implementation. A secure network is crucial for safeguarding organizations' data, systems, and users. The  training will outline the key security principles needed for a robust  network infrastructure.
This is a brief introduction to the topic, and we will start our training with “**Overview of Security Principles**” in the next section.

## Overview of Security Principles

Security principles are the foundations of a secure network  infrastructure. In this section, we will cover the security principles  and their best practice approaches in detail. 

Followings are the foundational security principles that we will be covering in the training:

- Access Control
- Principles of Functional Segregation and Least Privilege
- Strong Authentication Methods
- Session Management
- Static and Dynamic Data
- Detection and Correction of Weak Links

Before we begin, a crucial point to remember is the utmost importance of adopting these approaches in every possible aspect, down to the  tiniest element of our network.

We should remember that “The chain is as strong as its weakest link.”

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Secure-Network-Design/2/image1.jpg)

(Image Source: https://stickybranding.com/the-weakest-link-in-your-strategy/)

We have briefly introduced the security principles in this part of  our training and we will be covering the "Security Policy: Access  Control" in the next section.

## Security Principle: Access Control

The best way to understand the importance of the access control in designing a secure network is to start with an example.

Imagine you are managing a workplace. There are various departments,  employees at various levels with different tasks in this workplace. Not  everyone should have access to every document and information, right?  Employees in the accounting department should not have access to human  resources documents, and vice versa; individuals in human resources  should not have access to accounting documents.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Secure-Network-Design/3/image2.png)

(Image Source: https://www.scutumlondon.co.uk/help-advice/a-guide-to-the-different-types-of-physical-access-control/)

The same principle applies to a computer network. A network can be  thought of as a workplace, where access control acts as a vigilant  security guard. Access control governs the permissions for different  individuals to access various information and resources within the  network, specifying when and how they can do so.

Inadequate access control design can cause to unintended access to  sensitive information by unauthorized individuals. This poses critical  risks to the security of data, applications, and other resources within  your network. This is just like leaving the doors wide open, allowing  the unrestricted entry into and exit from the workplace for anyone.

An accurate access control design not only determines who can access  which information, but also determines when and how users can access  this information. This will help implement processes and policies  better, comply with the regulations, and improve the overall security of your network.

And remember that access control is crucial in safeguarding against  both internal and external threats. While internal threats are often  overlooked, they constitute a significant portion of security breaches,  especially in larger organizations. Properly designing and implementing  access control is vital in securing your network against both internal  and external threats. The two common approaches to access control are  RBAC (Role-Based Access Control) and ABAC (Attribute-Based Access  Control). Now, let's dive into each of these methods.

### Role-Based Access Control (RBAC)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Secure-Network-Design/3/sni9.png)

Role-based access control is used to determine users' authorization  levels and the resources they can access. This ensures that the  principle of least privilege is followed and that data privacy is  protected.

Role-Based Access Control (RBAC) is an access control model that  efficiently manages user or group access permissions to a system by  assigning roles and associating them with specific permissions. RBAC is a highly effective and widely utilized method for controlling access to  data within network infrastructures and systems.

### Implementation of RBAC

#### **Defining the Role:**

- The first step is to define roles in the system. A role represents the permissions a user can have.
- For example, we can define the roles such as "Manager", "Employee" or "Customer".
- Each role represents a set of permissions that are determined based on the functions and responsibilities required by that role.

#### **Assigning Users to Roles:**

- Each user is assigned a role that limits access to the system and specifies the defined roles.
- Permissions are granted to users based on their assigned roles.
- Users are assigned appropriate roles based on their work requirements and responsibilities.

#### **Authorization and Definition of Permissions:**

- For each role, the permissions granted to users to perform the operations required by the role are determined.
- Permissions determine the actions users can perform, the data they can access, and  the level of access they have to applications.
- Permissions control access to specific resources, such as data sources, system components, or network segments.

#### **Implementation of Access Control:**

- The system implements access control using the user roles and permissions.
- As users attempt to access systems or data using their designated roles,  permissions are regulated following the system's established roles and  permissions.
- Access controls can be performed at different  levels, such as the login process, database queries, and access to  network resources.

#### **Advantages of RBAC:**

- Enhances the organization of business and authorization processes.
- Management of user roles and permissions becomes easier.
- Provides security by preventing unauthorized access.
- Improves collaboration and operational efficiency.
- Provides traceability and compliance in internal and external audits.

Role-based access control is an effective method in the design of  secure network infrastructures, providing an efficient way to limit  unauthorized access to data.

### Questions

1 - Brian noticed that among the granted accesses, he had authorization to  access an asset outside his department. He reported this access to be  reviewed. What is the asset to which Brian has access?

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Secure-Network-Design/questions/q1.png)

Note: Use the diagram image above to solve the problem.

> **Answer:** Network Topology Schemas

2 - Sarah realized that within the listed accesses, she had permission to  access an asset unrelated to her department. She reported this promptly  to the relevant personnel to examine her access authorization. What is  the specific asset that Sarah can access?

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Secure-Network-Design/questions/q1.png)

Note: Use the diagram image above to solve the problem.

> **Answer:** System Maintenance Reports

3 - What is the acronym for the access control principle that permits us to define it through attribute-based access control?

> **Answer:** ABAC

4 - What is a flexible and effective access control mechanism that can respond to current security needs? 

 Note: Write the short version of the answer.

> **Answer:** ABAC 

5 - In the diagram above, an incorrect authorization definition has been  applied to a role, leading to a security concern. This issue went  unnoticed within the organization for an extended period. During this  time, whose user activities should be investigated under the suspicion  of an "insider threat"?

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Secure-Network-Design/questions/q2.png)

> **Answer:** User4 

## Functional Separation and the Principles of the Least Privilege

Another crucial aspect of designing a secure network involves the  proper application of functional separation and the principle of the  least privilege.

Users should have limited access to the functions and data they need. The principles of functional separation and the least privilege  minimize the risk of unauthorized access.

Let's review the basics of these two principles:

**Functional Separation (Separation of Duties):**

- The principle of functional separation refers to the division of the permissions required to perform a task between people or roles.
- This principle aims to prevent a single person or role from being able to  perform all the tasks and to prevent potential malicious activities.
- Functional separation helps to prevent errors and malicious activities and increases the effectiveness of internal audits.
- For instance, when an individual initiates a task, another person might be required to authorize or finalize it.

**The Least Privilege:**

- The principle of the least privilege is simply providing users or roles only the minimum privileges necessary for their duties.
- It's crucial to ensure that a user or role is not granted permissions beyond what is necessary for their tasks.
- This principle prevents data breaches and improves network security by limiting the authorization level.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Secure-Network-Design/4/image3.png)

(Image Source: https://blog.grantmcgregor.co.uk/what-is-the-principle-of-least-privilege-and-should-you-be-following-it)

Now that we know about these principles, let's see how can practice these principles. We should simply follow the steps below:

**Role and Authority Analysis:**

- Roles, and permissions possessed by these roles are determined in order to ensure the functional separation.
- Roles represent the functions that users need to perform their tasks.
- The minimum privilege that’s required to perform the functions of each role is determined.

**Creating Authorization Policies:**

- According to the principle of the least privilege, authorization policies are designed for each user or role.
- Policies give users or roles only the minimum powers they need.
- Policies are determined based on functions and tasks and prevent users from accessing unnecessary permissions.

**Implementation of Access Control Mechanisms:**

- The principles of functional separation and the least privilege are applied through access control mechanisms.
- Access control mechanisms ensure that users or roles can only perform actions that are appropriate to their roles.
- These mechanisms can be implemented through authorization management,  role-based access control (RBAC), permission settings, network  firewalls, and so on.

The principles of functional separation and the least privilege play a vital role in enhancing data security, avoiding errors and malicious  activities, and ensuring the efficiency of internal audits. These  principles ensure that users or roles are granted with only the  necessary privileges to carry out their tasks.

In this part of the training, we have covered the security principle  of "functional separation and the least privilege". In the next part of  the training, we will learn **"Security Policy: Strong Authentication Methods"** topic.

### Questions

1 - What is the term for the principle that establishes limitation on users or roles to only perform their tasks?

> **Answer:** Least Privilege

2 - What is the name of the  principle that refers to the decoupling of the permissions required to  perform operations between multiple people or roles?

> **Answer:** **Separation of Duties**

## Strong Authentication Methods

Strong authentication methods provides additional layers of security  beyond the password to verify a user's identity. These include  two-factor authentication, biometrics, and security keys.

Strong authentication methods are access control methods that provide a higher level of security to verify the identity of users. These  methods typically involve more steps or components than single-factor  authentication methods. Let's take a look at those components:

### Multi-Factor Authentication (MFA):

- Multi-factor authentication stands as the most commonly used strong authentication method.
- It is a process in which more than one factor is used to verify the user's identity.
- Usually, three factors are used: the information factor (password), the  possession factor (phone or other physical devices), and the inherence  factor (biometric data or physical characteristics).

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Secure-Network-Design/5/image4.png)

(Image Source: https://www.monash.edu/esolutions/accounts-passwords/multi-factor-authentication)

### Technological Authentication Methods:

- Biometric Verification: Identity verification is provided by  using biometric data such as fingerprint, face recognition, and retina  scan.
- Physical Devices: Authentication is performed using  devices such as SMS verification codes, mobile verification  applications, or physical ID cards.
- Technological Authentication Methods provide stronger and more complex verification, reducing the  risk of identity theft and unauthorized access.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Secure-Network-Design/5/image5.png)

(Image Source: https://gkaccess.com/support/information-technology-wiki/biometric-authentication/)

### Password Policies and Long, Complex Passwords:

- Password policies are implemented as part of strong authentication.
- The use of long, complex, and unique passwords is encouraged.
- Passwords should be changed periodically, stored securely, and should not be reused.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Secure-Network-Design/5/image6.png)

### Secondary Confirmation Methods:

- Secondary confirmation methods such as email verification, phone verification, or verification through social media accounts can be  used.
- An additional verification step is required to verify the user's identity. 

**Strong authentication methods reduce the risk of  identity theft, unauthorized access, and data breaches by following the  steps mentioned below:**

- Enabling Multi-Factor Authentication for users.
- Determining password policies and encouraging the use of complex, long passwords.
- Application of technological authentication methods such as biometric verification or physical devices.
- The use of secondary confirmation methods and the activation of additional verification steps.
- Enhancing user education and awareness by emphasizing the significance and utilization of strong authentication methods.

Strong authentication methods provide a more secure environment for  access control and increase the security of data and systems by reducing unauthorized access.

In this part of the training, we have covered the security principle  of “Strong Authentication Methods”. In the next part, we will learn the “**Security Policy: Session Management**” topic.

### Questions

1 - What is the term for the  authentication method that incorporates an additional factor alongside  the username-password authentication?

> **Answer:** Multi-Factor Authentication

## Session Management

In addition to the access control we have previously discussed in the RBAC and ABAC domains, another critical risk area emerges after access  has been granted which should be properly managed and controlled. Users' access should be granted for the required time period and the session  should be terminated automatically. This measure safeguards against  unauthorized access and mitigates the risk of session hijacking. For  proper session management, you need to consider the following processes  individually and implement control mechanisms for each process.

**1. Starting a Session:** The session should start according to the conditions specified in the RBAC and/or ABAC articles.

**2. Maintaining a Session:** The session should persist under the same conditions in which it was initiated.

**3. Session Monitoring:** During the session period, there should be no activity other than the scheduled permissions and privileges.

**4. Session Termination:** The session must be terminated properly.

Authorization and session managements are key elements of access  control and are critical for a secure network infrastructure. These  processes manage the authorization process by assigning the correct  permissions to users and ensuring that sessions are managed securely.

We have discussed the “Session Management” security principle in this part of our training and we will be learning **"Security Principle: Static and Dynamic Data"** topic in the next part.

### Questions

1 - How many stages are there in the session management process?

> **Answer:** Multi-Factor Authentication

## Static and Dynamic Data

As you can anticipate, the realm of data encryption is quite  extensive. In this module, we will discuss the basic concepts and  methods related to the topic.

When constructing a secure network, categorizing data into two  distinct headings, static and dynamic, significantly simplifies our task when dealing with data encryption.

So what are the terms static and dynamic data?

**Static (stationary) data:** Static data, as  its name suggests, remains stationary; it is stored somewhere, awaiting  utilization. Examples include data on disks, etc. All forms of data  residing in these kinds of environments fall within this category.

**Dynamic data:** Dynamic data, as the name implies, is data that moves from one place to another. 

This can also be a file downloaded to your system from an internet  source (considered dynamic data as long as the download process  continue), as well as data acquired from your file server and saved onto your system.

We should know that we need to take distinct security measures  depending on the type and situation of the data. Let's explore this with an example: 

Let's assume you have two different locations, let's call them A and  B. Suppose you have a file server at location A, and we intend to  download the file "invoices.pdf" from here to a user's system at  location B.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Secure-Network-Design/7/sni2.png)

Let's consider that we have ensured all the required permissions in  our Firewall, the Role-Based Access Control on our File Server is  functioning correctly, the user's password adheres to strong password  policies, and two-factor authentication is implemented.

The endpoint at Location B has effectively cleared all these  criteria, including the invoice files. Let's visualize that you've  initiated the download of the PDF file. As the file download started, we observed a segment of its path across the internet. With this our user  has demonstrated to our system the capability to acquire this file,  which is now accessible and readable.

Although there are precautions we can take when connecting our two  locations, this is beyond our control. It is clear that we have no  control over the systems that our data passes through when leaving  Location A and going to Location B. 

At this point, the only action we can take is to transform the data  into something that only we can interpret before it leaves its source  and to restore it to its original state when it arrives at the  destination. 

In this illustration, the data residing on the file server was  considered static, but it transformed into dynamic mode as soon as the  user initiated the download. We are talking about different types of  data and in both scenarios which requires distinct measures for each set of dynamics.

Regarding our static data, we've already discussed segmentation,  RBAC, and so on. While these measures are effective, we must adopt  additional measures for dynamic data.

### Protection of Dynamic Data

Safeguarding this type of data revolves around ensuring data security during the processes of transfer and sharing. Within these processes,  safeguarding data for confidentiality, integrity, and accessibility are  the most important aspects and can be approached through five following categories:

**Data Encryption (Data Encryption):**

- Data encryption is one of the most widely used methods for protecting dynamic data.
- The data is encrypted and transferred securely during the transmission process.
- Encryption ensures that data is rendered unintelligible to protect it from unauthorized access.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Secure-Network-Design/7/image7.png)

(Image Source: https://www.egnyte.com/guides/governance/data-encryption)

**Secure Data Communication:**

- Secure communication channels should be used for the secure transmission of data on the move.
- Secure communication channels enable encrypted data transfer and verification.
- Encryption and authentication mechanisms such as SSL/TLS protocols can be used.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Secure-Network-Design/7/image8.png)

(Image Source: https://techaxiskenya.co.ke/product/moving-your-website-to-https-ssl/)

**Data Integration:**

- Dynamic data can be integrated between different systems and applications. 
- During the data integration process, we sure make sure that the data is transferred and verified securely.
- Integration points should be protected from unauthorized access and secure  authentication and authorization mechanisms should be utilized.

**Limitations of Data Storage:**

- Dynamic data protection also includes not storing data unnecessarily.
- Data should be stored as long as necessary and should be purged regularly to reduce the risk of unnecessary retention.
- In addition, the data must be stored securely for the duration of the  retention period and access to the data must be restricted.

**Data Control and Monitoring:**

- Data control and monitoring mechanisms should be utilized to protect dynamic data.
- Data flow and sharing should be monitored, and unauthorized access attempts or data breaches should be detected.
- Monitoring allows rapid detection and response to security incidents.

Protecting dynamic data ensures that the data is secure during  transmission and prevents unauthorized access, data breaches, or data  loss. Measures such as encryption, secure communication, data  integration, data storage restrictions, and data control play an  effective role in protecting data.

### Protection of Static Data

Safely storing static data is a crucial step to ensure the security  of an organization or system. Followings are some of the methods to  ensure the static data security:

**Data Encryption:**

Encrypting static data when stored guarantees to safeguard it against unauthorized access. Through cryptographic algorithms, the data  undergoes encryption, rendering it comprehensible solely to authorized  users. Encryption can be implemented within the data storage medium  (such as disks or databases) or during data transmission.

**Access Controls:**

Appropriate access mechanisms must be used to regulate data access.  Users should be granted only the access they need, and authorization  controls should be enforced. Defining user roles, permissions, and data  restrictions ensures that only legitimate users have access to data.

**Data Backup and Recovery:**

Secure backup and recovery processes should be established for static data. Regular backup of data and secure storage of backups ensure that  data is recovered in case of data loss so it is critical to pay  attention to the security of backup data as well.

**Data Storage Security:**

Storage areas for static data should be secured with a combination of physical and electronic security measures. Physical security includes  measurements like secure data centers or server rooms, access controls,  security cameras, and alarm systems. On the other hand, electronic  measurements include strong encryption, firewalls, security tools, and  intrusion detection systems.

**Security Monitoring and Incident Response:**

Monitoring the security status of static data and detecting anomalous activities has critical importance to detect and protect against  incident cases. Tools like daily logs and security information and  incident management systems (SIEM) are utilized to monitor security  incidents which make rapid and efficient intervention when abnormal or  unusual activities or security breaches are detected.

**Data Deletion and Destruction:**

We should be really careful when we need to delete and destroy the  static data securely.In this part of the training, we have covered the  security principle of “Static and Dynamic Data”. We will cover **“Security Principle: Detection and Correction of Weak Links**” in the next module.

### Questions

1 - What type of data is the data found on hard disks and similar data storage spaces?

> **Answer:** static data

2 - How does the utilization of SSL/TLS protocols enhance the security of dynamic data?

> **Answer:** Secure Data Communication

3 - Under which category does the implementation of cryptographic algorithms to secure static data fall? 

**Note:** Answer the question according to the “Protection of static data” topic.

> **Answer:** Data Encryption

## Identification and Remediation of Weak Links

The security measures we've covered so far aren't one-time tasks;  they require ongoing process and efforts as well as continuous  assessment and improvement is also required. Following are some of the  examples of these ongoing efforts that we should continue to implement  and improve:

### Detection of Weak Passwords and Policies

The risks posed by weak passwords on the network security are quite  significant. Weak passwords can seriously compromise the user's security it also endangers the whole network security. For example, using a  simple word or a basic combination of numbers increases the likelihood  that an attacker will be able to guess your password. Attackers can use  automated tools to quickly test thousands or even millions of password  combinations. These brute-force attacks significantly increase the  chances of success, especially in environments where the weak passwords  are vulnerable.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Secure-Network-Design/8/image9.png)

In addition, weak passwords may be the root cause of your account to  get compromised. They lay the groundwork for phishing attacks. Attackers may get passwords by misleading users through fake emails or websites.  If the password is weak, they can easily access your account and make  unauthorized operations without you even realizing it.

Weak passwords can also cause data leaks. If your account gets  accessed by an unauthorized person/user, your personal or company  sensitive information may fall into the hands of attackers. This, in  turn, can lead to privacy violations and potential data leaks.

For these reasons, it is important to use strong and complex  passwords for a secure network design. Updating your passwords regularly and using additional security measures such as multi factor  authentication also increases security.

### Weaknesses and Remedial Actions

Regular penetration testing (pentesting) exercises replicate actual  attack scenarios in order to evaluate the security posture of networks  and systems and pinpoint potential vulnerabilities. Pentesting serves as an assessment tool to uncover weaknesses, evaluate risks, and implement necessary countermeasures.

By simulating real attack scenarios, pentesting identifies security  vulnerabilities in networks and systems, in other words it highlights  potential weak points that require mitigation. Following pentests,  system administrators and security teams can address vulnerabilities,  update security policies, and implement necessary security measures  based on the findings of the pentest results.

Pentesting is a crucial process that evaluates the ability of  networks and systems to withstand real-world attacks by simulating  authentic attack scenarios. These tests effectively gauge the efficiency of security measures and work towards resolving any shortcomings.  Moreover, the outcomes of pentesting provide valuable insights for  assessing and prioritizing risks, guaranteeing proper resource  allocation and efficient risk management.

Furthermore, pentests serve to heighten security awareness within the organization. The results of these tests tangibly illustrate the actual impact of security vulnerabilities, encouraging employees and managers  to be more attentive to security matters. Consequently, this cultivates  an improved security culture, leading to an overall enhancement in the  organization's security posture.

In addition, conducting pentest on a regular basis proves the safety  standards of the organization and gives confidence to customers and  stakeholders. Pentest results increase the trust of customers and  stakeholders in the security of the organization and raise the  reputation. In many sectors, pentest is also required to meet compliance and regulatory requirements.

Finally, you should keep in mind that conducting penetration tests  alone is not sufficient; promptly implementing corrective actions based on the test results is equally critical.

### Update and Patch Management

Update and patch management are of vital importance for corporate  network security. Update and patch management processes ensure that  known vulnerabilities are remediated and systems are up to date with the latest security patches.

Update and patch management allows you to troubleshoot  vulnerabilities in operating systems, applications, and other  components. Software and hardware providers regularly release updates  and patches. Applying these updates regularly makes your systems secure  against current threats.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Secure-Network-Design/8/image10.png)

(Image Source: https://www.pcmag.com/how-to/computer-acting-up-how-to-uninstall-a-windows-10-update)

Update and patch management reduces the attack surface created by  outdated software or hardware components. Updates elimiinates security  vulnerabilities and make your systems more resistant to attacks. In this way, potential attack points are minimized and defense mechanisms  against vulnerabilities are strengthened.

Updating and patch management guarantees system compatibility and  adherence to current standards. In numerous industries, meeting  compliance and regulatory mandates holds the utmost significance.  Regularly applying updates is essential to fulfill these requisites and  ensure alignment with the relevant standards.

Update and patch management enables businesses to respond to evolving security demands. As new security threats emerge or vulnerabilities are identified, updates and patches should be deployed and pushed to the  endpoints quickly. This rapid and efficient response ensures effective  mitigation against security vulnerabilities.

In this part of the training, we have covered the security principle of “Detection and Correction of Weak Links”.

### Questions

1 - What is the attack that identifies weak passwords through trial-and-error called?

> **Answer:** brute-force attacks





















