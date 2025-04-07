# Detecting Web Attacks - 2

In  this comprehensive course on detecting web attacks, participants will  learn a range of crucial lessons, including identifying and mitigating  brute force attacks, detecting and preventing Directory-Traversal  vulnerabilities, understanding and defending against XML External Entity (XXE) attacks, as well as effectively recognizing and safeguarding  against Open Redirection vulnerabilities.

**Table of content:**

- Detecting Open Redirection Attacks

- Detecting Directory Traversal Attacks
- Detecting Brute Force Attacks
- Detecting XML External Entity Attacks

## Detecting Open Redirection Attacks

### What is Open Redirection?

Open redirection is a web security vulnerability that occurs when a  website or web application redirects users to a different URL without  proper validation or sanitization of the target URL. Attackers can  exploit Open Redirection to trick users into visiting malicious websites or performing actions unintended by the website owner.

In an open redirection attack, an attacker typically crafts a  legitimate URL hosted on the vulnerable website, but includes a  malicious URL as a parameter or query string. When a user clicks on the  crafted URL, the website's redirect mechanism automatically redirects  the user to the malicious URL, which can lead to various malicious  activities, such as phishing attacks, spreading malware, or stealing  sensitive information.

Open redirection vulnerabilities commonly occur when websites use  user-supplied input, such as URLs, as part of their redirect mechanism  without proper validation or sanitization. To prevent open redirection  attacks, web developers should validate and sanitize all user-supplied  input used in redirections, and ensure that only trusted and whitelisted URLs are allowed for redirection. Additionally, it's important to  implement proper authentication and authorization mechanisms to ensure  that only authenticated and authorized users can perform redirects.  Regular security testing, including vulnerability scanning and  penetration testing, can also help identify and fix open redirection  vulnerabilities in web applications.

### Open Redirection Types / Possible Vectors

There are several types of open redirection vulnerabilities that can occur in web applications. These include:

1. **URL-based open redirection:** This is the most  common type of open redirection vulnerability. It occurs when a website  takes a URL or a URL parameter as input and uses it in a redirect  without proper validation or sanitization. An attacker can craft a  malicious URL that includes a different domain or malicious URL as a  parameter which will be included in the redirect, leading to an  unintended redirection to a malicious website.
2. **JavaScript-based open redirection:** This type of open redirection vulnerability occurs when a website uses  JavaScript to perform a redirect, but the target URL is obtained from  untrusted or user-controlled sources without proper validation or  sanitization. An attacker can manipulate the JavaScript code or input  data to execute a malicious redirect to a different domain or URL.
3. **Meta refresh-based open redirection:** This type of open redirection vulnerability occurs when a website uses  the HTML "meta refresh" tag to redirect users to another URL  automatically, and the target URL is obtained from untrusted or  user-controlled sources without proper validation or sanitization. An  attacker can manipulate the meta refresh tag or input data to trigger a  malicious redirect to a different domain or URL.
4. **Header-based open redirection:** This type of open redirection vulnerability occurs when a website uses  HTTP headers, such as "Location" header, to perform a redirect, but the  target URL is obtained from untrusted or user-controlled sources without proper validation or sanitization. An attacker can manipulate the  header value or input data to trigger a malicious redirect to a  different domain or URL.
5. **Parameter-based open redirection:** This type of open redirection vulnerability occurs when a website uses a parameter in the URL or in a form submission as part of the redirect  process, but fails to properly validate or sanitize the parameter value. An attacker can manipulate the parameter value to trigger a redirect to a malicious URL.

It's important for web developers to be aware of these different  types of open redirection vulnerabilities and implement proper  validation and sanitization of user-supplied input to prevent such  vulnerabilities in their web applications.

### How Open Redirection Works?

Here's an example of a vulnerable code in a web application that demonstrates an open redirection vulnerability using PHP:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/open+redirection/carbon+(1).png)

In this example, the web application takes a target URL as a query  parameter (`url`) from the user and uses it in a redirect without  validating or sanitizing the input. This can lead to an open redirection vulnerability, as an attacker can craft a malicious URL and pass it as  the `url` parameter, leading to unintended redirection to a malicious  website.

For example, an attacker could create a URL like this:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/open+redirection/Bash+URL.png)

When a user clicks on this URL, the vulnerable application will  automatically redirect the user to `http://malicious.com`, which could  be a phishing website or a site hosting malware.

### Impact of Open Redirection

Open redirection vulnerabilities can have a significant impact on the security of a web application and its users. Some of the potential  impacts of open redirection vulnerabilities include:

1. Phishing attacks: Attackers can craft malicious URLs that appear legitimate and trick users into clicking on them, leading to unintended redirection to a phishing website. Phishing attacks aim to steal  sensitive information, such as usernames, passwords, and financial  details, from unsuspecting users.
2. Malware distribution:  Attackers can redirect users to websites hosting malware, which can  result in the automatic download and installation of malicious software  on the user's device. This can lead to malware infections, data  breaches, and other types of cyber attacks.
3. Social engineering  attacks: Attackers can use open redirection vulnerabilities to conduct  social engineering attacks, where they manipulate users into taking  unintended actions, such as downloading malware, making fraudulent  payments, or revealing sensitive information.
4. Reputation damage: If a website is found to have open redirection vulnerabilities, it can  result in reputational damage for the website owner or organization.  Users may lose trust in the website's security and reliability, leading  to loss of business, brand damage, and financial repercussions.
5. Legal and regulatory consequences: Open redirection vulnerabilities can  result in legal and regulatory consequences, especially if sensitive  user information is compromised. Organizations may face legal  liabilities, fines, or other penalties for failing to protect user data  and secure their web applications.

Overall, open redirection vulnerabilities can have serious  consequences, ranging from financial loss to reputational damage, and  can pose a significant risk to the security and privacy of web  application users. It is important for web developers to implement  proper input validation and sanitization, as well as follow other web  security best practices in order to prevent open redirection  vulnerabilities and protect their applications and users from potential  harm.

### Prevention Methods for Open Redirection

Actually, this issue was briefly mentioned above, but if we give a  more detailed explanation; to prevent open redirection vulnerabilities  in web applications, web developers should follow secure coding  practices and implement proper input validation and sanitization  techniques. Here are some preventive measures that can be taken:

**Validate and sanitize input:**  Always validate and sanitize any user-supplied input that is used in the redirection process. This includes URL parameters, form submissions,  and any other input that is used in generating redirect URLs. Validate  that the input conforms to expected formats, such as valid URLs or  whitelisted domains, and sanitize it to remove any malicious or  unexpected characters.

**Use a whitelist approach:**  Instead of trying to blacklist or filter out specific characters or  patterns from user input, it's generally safer to use a whitelist  approach where only known and trusted values are allowed. Define a  whitelist of trusted domains or URLs to which the application is allowed to redirect, and validate that the user-supplied input matches the  whitelist.

**Avoid using user-controlled data in redirects:** Avoid using user-controlled data, such as input from URL parameters or  form submissions, directly in the redirect process. If possible, use  other means of redirection, such as using HTTP headers or server-side  redirects that do not rely on user-controlled data.

**Implement proper authorization and authentication:** Ensure that only authorized users are allowed to trigger redirects.  Implement proper authentication and authorization mechanisms to verify  the legitimacy of the user and their actions.

**Implement secure coding practices:** Follow secure coding practices, such as using secure coding libraries  or frameworks, keeping software up-to-date with the latest security  patches, and conducting regular security reviews and vulnerability  assessments.

**Educate users about potential risks:** Educate users about the potential risks of clicking on suspicious or  unexpected URLs, and encourage them to be cautious when clicking on  links from unknown sources or providing personal information on  websites.

**Stay informed about web security best practices:** Stay updated with the latest web security best practices and  guidelines, such as the OWASP Top Ten Project, and incorporate them into your development processes.

By implementing these preventive measures and following secure coding practices, web developers can significantly reduce the risk of open  redirection vulnerabilities in their web applications and protect their  users from potential attacks. Regular security testing, including  penetration testing and vulnerability assessments, can also help  identify and mitigate any potential vulnerabilities in the application.

Here's an example of a vulnerable code in PHP that demonstrates an open redirection vulnerability, along with a fixed version:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/open+redirection/Example+Vulnerable.png)

Fixed Code:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/open+redirection/Example+Fixed.png)

In the fixed version, the `**filter_var`** function with `**FILTER_VALIDATE_URL`** filter is used to validate the user-supplied **`url`** parameter. This filter checks if the value is a valid URL according to the PHP filter extension, and if it returns **`true`**, the redirect is performed to the validated URL. If the **`url`** parameter does not pass the validation, a default URL or an error  message can be shown, and no redirection is performed. This helps to  prevent malicious URLs or invalid values from being used in the  redirection process, mitigating the open redirection vulnerability.

### Detecting Open Redirect Attacks

What was described in Part 1 was a list of things to do from the  perspective of a hacker/attacker. At the same time, the issues that a  developer should pay attention to while developing were also mentioned.

So in this part, let’s have a look at how to detect Open Redirection  attacks with an example. But, before moving, let’s quickly recap some of the important things to detect Open Redirection attacks;

1. If there is a  consecutive requests to query string parameters  such as ?next (http://website.com/param.php?next=), or ?url (  http://website.com/…?url=), with payloads like http://attacker.com or  attacker.com (URL structure)
2. For the WAF or other middleware products, sometimes payloads can have bypass techniques like;
   1. Localhost
      1. http://[::]:25/
      2. http://①②⑦.⓪.⓪.⓪
   2. CDIR
      1. http://127.0.0.0
   3. Decimal Bypass
      1. http://2130706433/ = http://127.0.0.1
   4. Hexadecimal Bypass
      1. http://0x7f000001/ = http://127.0.0.1
3. Encoded characters like %2f = /

Of course it’s not possible to detect or analyze web server logs  without using automated detection methods. For an easier way, any SOC  analyst can use the following regex to detect open redirection attacks. 

/^.*"GET.*\?.*=(https%3a%2f%2f[a-z0-9-]+%2e[a-z]{2,}).+?.*HTTP\/.*".*$/gm

This regex will match any log entry where the HTTP method is GET, the request contains a query parameter with https://x.com, and the request  is using HTTP version 1.0 or 1.1. This should match the most common open redirection attack patterns.

You can customize this regex to match specific query parameters or  HTTP methods that are relevant to your web application. Remember that  this regex is just one part of an overall security monitoring strategy  and should be used in conjunction with other security tools and best  practices.

### Detection Example

Example nginx access log file;

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/open+redirection/Access+Log.png)

As you can see it on the above screenshot, open redirection attacks  were made to the http://victim.com website on 18/Apr/2023:20:05:05. We  have mentioned that attention should be to encoded characters. Here is  where the importance of this issue is seen.

**Encoded:**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/open+redirection/encoded-open.png)

**Decoded:**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/open+redirection/decoded-open.png)

When we decode the request, we see that the attacker wants to  redirect to google.com with the ?pro parameter. When we realize that all requests occur within seconds, we understand that this is done with the help of a tool. At the same time, the source IPs are all the same.

In this lesson, we have covered the Open redirection attack. We have  talked about how the vulnerability appears, as well as its detection and prevention methods.

### Questions

Log location: /root/Desktop/QuestionFiles/Open-Redirection/access.log

1 - What date did the exploitation phase of Open Redirection start? Format: dd/MMM/yyyy HH:mm:ss

> **Answer:** 27/Apr/2023 15:45:22

2 - What is the IP address of the attacker who performed the Open Redirect attack?

> **Answer:** 86.236.188.85

3 - What was the parameter that attacked?

> **Answer:** postId

## Detecting Directory Traversal Attacks

### What is Directory Traversal?

Directory traversal is an attack type that the attackers leverage  often to access files and directories that are stored outside the web  server's root directory. It involves manipulating input to be able to  access files on a web server that are actually not intended to be  accessible by unauthorized users. This type of attack is also known as  the "dot-dot-slash" attack, and it can be used to gain unauthorized  access to sensitive data or execute arbitrary code on a web server.

For example, let's say a web application uses the following URL to display user profile pictures:

http://example.com/profiles/picture.php?name=user1.jpg

An attacker can leverage directory traversal attack to access files  outside of the intended directory by adding ../ to the URL. For  instance, they could use the following URL to access a file outside of  the profiles directory: http://example.com/profiles/picture.php?name=../../etc/passwd

This would give the attacker access to sensitive system files, such as the password file.

Actually, at first look, it’s pretty similar to a Local File  Inclusion vulnerability. The main difference between the directory  traversal and LFI is the source of the input. Directory traversal  involves in manipulating the input that is used to access files on a web server, whereas LFI involves in manipulating input that is used to  include local files within a web application.

In a local file inclusion vulnerability, an attacker can use user  input to include a file from the local file system into the web  application. This can allow the attacker to execute arbitrary code on  the server to access the sensitive data.

For example, consider a web application that includes a file based on user input, such as **include($_GET['page']).** An attacker could manipulate the **page** parameter to include a sensitive file on the server, such as **../../../../etc/passwd**. This would allow the attacker to read the password file and gain unauthorized access to the system.

In contrast, directory traversal vulnerabilities allow attackers to  access files outside of the web application's root directory. This can  also allow them to execute arbitrary code or access sensitive data, but  the attack vector is different.

### Directory Traversal Possible Vectors

Directory traversal attacks can occur through various attack vectors, including:

1. **User input:** Attackers can manipulate user input parameters, such as URLs, file paths, and form fields, to access files  outside of the intended directory. This can be done by adding "../" or  other special characters to the input.
2. **Cookies:** If a web application stores user data in cookies, attackers can try to  manipulate the cookie value to access files outside of the intended  directory.
3. **HTTP headers:** Attackers can  manipulate HTTP headers, such as the Referer or User-Agent header, to  access files outside of the intended directory.
4. **File upload:** If a web application allows file uploads, attackers can upload malicious files that contain directory traversal attacks.
5. **Direct requests:** Attackers can try to access files and directories directly by guessing or brute-forcing the file names or paths.
6. **URL manipulation:** Attackers can try to manipulate the URL of a web application to access  files outside of the intended directory. For example, they can add  "/../" to the URL to go up one directory level.
7. **Malicious links:** Attackers can send users malicious links that contain directory  traversal attacks. When the user clicks on the link, the attack is  executed on their computer.

### How Directory Traversal Works?

Here's an example of vulnerable code that is susceptible to directory traversal attacks in a PHP script:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/img1.png)

In this example, the script takes a file name as a parameter from the user input using the **$_GET** method. The script then concatenates the user input with the document root directory to form a full path to the file.

However, this code is vulnerable to directory traversal attacks since an attacker can manipulate the **file** parameter to include **../** characters, which will allow them to access files outside of the  intended directory. For example, an attacker could use the following URL to access the **/etc/passwd** file on the server:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/img2.png)

### Impact of Directory Traversal

The impact of a directory traversal attack can be severe, depending on the files and directories that the attacker can access.

Attackers who successfully exploits a directory traversal  vulnerability can view, modify, or delete files that they are not  authorized to access. This can lead to a variety of security risks and  attacks, including:

1. **Disclosure of sensitive data:** An attacker can  access sensitive files, such as password files, configuration files, and user data, which can be used for identity theft, fraud, or other  malicious activities.
2. **Execution of arbitrary code:** An attacker can upload and execute malicious files that contain  commands or code that can harm the system, such as malware or backdoors.
3. **Denial of service:** An attacker can delete critical files or cause a system to crash, resulting in a denial of service attack.
4. **System compromise:** An attacker who gains access to system files or directories can use  this access to escalate privileges, install rootkits, or take control of the entire system.

### Prevention Methods for Directory Traversal Attacks

Here are some best practices to prevent directory traversal attacks in web applications:

**Input validation and sanitization:** Validate and sanitize all user input, especially the file paths and the  directory names. This can involve using regular expressions or other  methods to check the input for valid characters, and to limit the input  to known values or directories.

**Access controls:** Limit the web server's access to only the files and directories required for the  application to function. Use file the system permissions and access  controls to restrict access to sensitive files and directories.

**Relative file paths:** Use  relative file paths instead of absolute paths whenever possible. This  can prevent attackers from using the "../" character to navigate up to  higher-level directories.

**Whitelisting:** Use a whitelist  approach where only specific characters are allowed in the file name  parameter. This can be done using a validation library or a custom  validation function.

**Secure coding practices:** Use  secure coding practices, such as avoiding the use of user input directly in file path concatenation, using secure file upload mechanisms, and  avoiding the use of insecure functions like eval() and system().

**Web application firewall:** Use a web application firewall (WAF) to detect and block directory traversal  attacks. WAFs can analyze incoming traffic for malicious requests and  prevent attacks from reaching the web application.

By following these best practices, web application developers and  administrators can reduce the risk of directory traversal attacks and  protect their web applications and systems from unauthorized access and  data breaches.

Here's an example of vulnerable PHP code that is susceptible to directory traversal attacks:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/img3.png)

In this code, the **$file** variable is set to the value of the **file** parameter from the user's input. The script then concatenates this  value with the document root directory to form a full file path in the **$full_path** variable. This code is vulnerable to directory traversal attacks  because an attacker can include directory traversal sequences like **../** in the **file** parameter to access files outside of the intended directory.

Here's an updated version of the code that uses input validation and sanitization to prevent directory traversal attacks:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/img4.png)

In this updated version of the code, we first validate the input  using a regular expression to ensure that the file name only contains  alphanumeric characters, underscores, and hyphens. We then use the **realpath()** function to get the absolute path of the file and check that the  resulting path is within the document root directory. This prevents the  use of directory traversal sequences like **../** to access files outside of the intended directory. If the file exists, we read  and output its contents; otherwise, we output an error message.

### Detecting Directory Traversal Attacks

In Part 1, we have overviewed what the directory traversal attack is  and how to prevent this attack type. In this part, we’ll have a look at  detection techniques and some tips to make it easier. Before the moving  on, let’s have a quick look for example payloads for the directory  traversal vulnerability;

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/img5.png)

These are really basic payloads for directory traversal attacks. So,  we should keep in mind ../ (dot dot slash), encoded and double encoded  ../ is the key values for this attack type. Here is the basic example  for detecting these payloads on nginx access.log file;

/^.*"GET.*\?.*=(%2e%2e%2f).+?.*HTTP\/.*".*$/gm

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/img6.png)

As a bypass technique, attackers may also use unicode encode characters to bypass WAF or any other product.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/img7.png)

In that case, Nginx access log will be like;

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/img8.png)

These are detection payloads for the Directory Traversal attack. For a successful exploit, attacker needs to access some files. most popular  ones are;

**Linux**

/etc/issue

/etc/passwd

/etc/shadow

/etc/group

/etc/hosts

**Windows**

c:/boot.ini

c:/inetpub/logs/logfiles

c:/inetpub/wwwroot/global.asa

c:/inetpub/wwwroot/index.asp

c:/inetpub/wwwroot/web.config

c:/sysprep.inf

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/directory+traversal/directory-log.png)

Basic regex that we have shared above will work with these logs but  to prevent False Positive alarms it can be updated more strictly like;

/^.*"GET.*\?.*=(.+?(?=%2e%2e%2fetc%2f)).+?.*HTTP\/.*".*$/gm

In this lesson, we have covered the Directory Traversal attack. We  have talked about how this attack appears, as well as its detection and  prevention methods.

### Questions

Log location: /root/Desktop/QuestionFiles/Directory-Traversal/access.log

1 - What date did the exploitation phase of Directory Traversal start? Format: dd/MMM/yyyy HH:mm:ss

> **Answer:** 23/Apr/2023 00:16:57

2 - What is the IP address of the attacker who performed the Directory Traversal attack?

> **Answer:** 123.114.236.235

3 - What was the parameter that attacked?

> **Answer:** uid

## Detecting Brute Force Attacks

### What is Brute Forcing?

Brute forcing is a type of attack that involves attempting to guess a password or authentication token by systematically trying every  possible combination of characters until the correct one is found. In  the context of web attacks, brute forcing typically refers to the  process of using automated tools to repeatedly submit login requests to a web application using different username and password combinations  until a valid one is discovered.

Brute force attacks can be used to gain unauthorized access to a  system, steal sensitive information, or launch further attacks against  the target or other systems. They can be particularly effective against  weak or poorly protected passwords, but can also be very time-consuming  and resource-intensive for the attacker, especially if the target system has implemented measures to detect and block brute force attacks.

Brute force attacks are one of the simplest and most straightforward  methods of attacking a web application, and it works by systematically  trying every possible combination of usernames and passwords until the  correct one is found. This process is typically automated using  specialized software or scripts, which can try thousands or even  millions of combinations per second.

The basic idea behind a brute force attack is to exploit the weak or  easily guessable passwords that a lot of people use especially the  non-techy users, such as common dictionary words, simple number  sequences, or their own names or birthdates. By systematically trying  every possible combination of characters, attackers can eventually find  the correct password and gain access to the target system.

### Brute Forcing Possible Vectors

Brute forcing on web applications is a common attack vector used by  hackers to gain unauthorized access to user accounts or web servers. In  this type of attack, the attacker will use automated tools to submit  multiple login requests to the targeted web application using different  usernames and passwords, in an attempt to find the correct credentials  and gain access to the system.

Web applications are particularly vulnerable to brute force attacks  because they are often accessible over the internet and rely on user  authentication to control access to sensitive data or functionality. If  an attacker is able to guess a valid username and password, they can  potentially gain access to sensitive user data, such as financial  information, personal data, or confidential business information. 

Actually, it’s not just guessing usernames and passwords also,  directory brute forcing on web applications is another type of brute  force attack that involves guessing file or directory names on a web  server in order to find hidden or sensitive files or directories. In  this type of attack, the attacker will use automated tools to submit  requests to the targeted web server using different file or directory  names, in an attempt to find files or directories that are not meant to  be publicly accessible.

This type of attack can be effective against web applications that do not implement proper access controls or that have poorly configured web servers. To prevent directory brute force attacks, web application  developers can implement access controls to restrict access to sensitive files and directories, and can configure their web servers to block  requests for known sensitive files and directories.

### How Brute Forcing Works?

Here's an example of vulnerable code that is susceptible to Brute Forcing attacks in a PHP script:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/brute+force/img1.png)

This form is vulnerable to brute force attacks because it allows  unlimited login attempts and does not implement any security measures to prevent automated login attempts.

Here's an example of how you can use Python requests library to send  multiple login requests with a list of usernames and passwords:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/brute+force/img2.png)

### Impact of Brute Forcing

Brute forcing can have significant impacts on a target system or  application. Here are some of the potential impacts of brute forcing:

1. **Denial of service:** Brute forcing can consume a  significant amount of computing resources, such as CPU cycles and  memory, which can lead to system slowdowns or crashes. This can cause a  denial of service (DoS) attack, which makes the target system  unavailable to legitimate users.

1. **Data leakage:** Successful brute force  attacks can allow unauthorized access to sensitive data, such as login  credentials, personal information, financial data, and intellectual  property. This can lead to data breaches, which can have severe  consequences for the target organization, including financial losses and damage to reputation.

1. **Account takeover:** Brute forcing can  allow attackers to gain access to user accounts without the owner's  consent. Once an attacker has access to an account, they can carry out  malicious activities, such as stealing data, sending spam, or carrying  out further attacks.

1. **Password reuse:** Brute forcing can  reveal weak or easily guessable passwords, which can encourage users to  reuse passwords across multiple accounts. This can increase the risk of  compromise, as a successful brute force attack on one account can  provide access to multiple accounts.

1. **Legal and reputational consequences:**  Brute forcing is illegal and unethical, and can result in significant  legal and reputational consequences for individuals and organizations  who engage in it. If caught, attackers can face criminal charges, fines, and other penalties. Additionally, organizations who are victims of  brute force attacks may suffer reputational damage, loss of trust from  customers and stakeholders, and legal liability for failing to protect  their systems and data.

### Prevention Methods for Brute Forcing

Implement account lockout policies: After a certain number of failed  login attempts, lock the user account for a specified period of time, to prevent further login attempts. This will make brute force attacks more difficult, as the attacker will need to wait for the account to become  unlocked before attempting more login attempts.

**Implement CAPTCHA:** Use CAPTCHA or other bot detection mechanisms to detect automated login attempts and prevent them from succeeding.

**Limit the rate of login attempts:** Implement a mechanism that limits the number of login attempts that can be made within a certain time period (e.g. 5 login attempts per  minute). This will slow down brute force attacks, as the attacker will  need to wait between attempts.

**Use multi-factor authentication:** Require users to provide additional authentication factors, such as a  one-time code sent via SMS or email, in addition to their username and  password.

**Monitoring login attempts:**  This involves monitoring login attempts for signs of suspicious  activity, such as multiple failed login attempts from the same IP  address, or unusual spikes in traffic or requests. This can help to  detect and prevent brute force attacks before they are successful.

**Using strong passwords and password policies:** This involves requiring users to choose strong passwords that are  difficult to guess, and enforcing password policies that require users  to change their passwords regularly and prohibiting the use of weak or  easily guessable passwords.

Web Application Firewalls (WAFs) are commonly used to protect web  applications from various types of attacks, including brute force  attacks. Here are some ways WAFs can prevent brute force attacks; 

IP blocking: WAFs can block access to the web application from IP  addresses that have made excessive login attempts or have triggered  other security rules. This can prevent brute force attacks by blocking  the attacker's access to the application altogether.

User behavior analysis: WAFs can analyze user behavior patterns to  detect abnormal activity, such as a high rate of login attempts or  unusual login times. This can help prevent brute force attacks by  detecting and blocking suspicious behavior before it becomes a problem.

It's important to note that WAFs are not foolproof and can be  bypassed by skilled attackers. Therefore, it's important to implement  multiple layers of security controls, such as strong passwords, account  lockout policies, and security awareness trainings for users, in  addition to using WAFs.

By implementing these measures, the login form can be more secure, robust, and resistant to brute-force attacks.

### Detecting Brute Forcing Attacks

In Part 1, we have described what the Brute Forcing is and how to  prevent this attack type. In this part, we’ll have a look at the  detection techniques and some tips to make it easier to detect and  prevent brute force attacks.

Analyzing brute force attacks can help you understand the methods  used by attackers and identify vulnerabilities in your security  controls. To do this, you should **collect and store** authentication logs from your web application, including the successful logins as well as the failed login attempts. Look for **patterns of suspicious activity** in the authentication logs, such as a high number of failed login attempts from a **particular IP address** or user account. **Analyze network traffic logs** to identify patterns of traffic that may be associated with brute force attacks, such as repeated login attempts from the same IP address or  requests to non-existent pages or directories. 

Deploy an **intrusion detection system (IDS) or intrusion prevention system (IPS)** to analyze network traffic and detect signs of brute force attacks. **Look for common attack vectors** used in brute force attacks, such as dictionary attacks or password  spraying. Identify user accounts that are vulnerable to brute force  attacks due to weak passwords or other vulnerabilities. Finally, monitor for incidents of brute force attacks and respond to them promptly **by blocking malicious IP addresses**, locking out user accounts, and implementing additional security  controls as necessary. By following these steps, you can strengthen your security controls and reduce the risk of successful brute force  attacks.

Example Nginx log file that contains Brute Force attack;

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/brute+force/img3.png)

The log file provided shows the unsuccessful login attempts only. In  order to detect the successful login attempts, you would need to analyze the logs further or modify your logging configuration to include the  successful login attempts as well.

Successful login attempts would typically result in a response code  of 200 or a redirect to a different page, which can be identified in the log file. However, keep in mind that some attackers may attempt to  obfuscate their successful login attempts by logging in with valid  credentials or using a compromised account, so it is important to  perform further analysis to determine if any suspicious activity is  occurring.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/brute+force/img4.png)

In this example, the log entry shows a POST request to the **/login.php** page with a response code of **302**, which indicates a successful login attempt. The **Cookie** header also includes a **PHPSESSID** value and a login value, which may be used to track the user session  and authentication status. Note that the exact format and contents of  the log files can vary depending on the web server and its  configuration.

To detect brute force attacks in nginx log files, you can use various tools and techniques such as:

**Log analysis tools:** There are  several log analysis tools such as Logstash, ElasticSearch, and Kibana  (ELK Stack) that can help you analyze nginx log files and detect brute  force attacks. These tools will allow you to search for specific  patterns in the log files, such as repeated failed login attempts from  the same IP address or user agent.

**Regular expressions:** Regular  expressions can be used to search for specific patterns in the log  files. For example, you can use a regular expression to match a sequence of repeated failed login attempts from the same IP address or user  agent.

***Things that you can do after the detection:\***

**Fail2ban:** Fail2ban is a  popular intrusion prevention tool that can be used to automatically  block the IP addresses that are detected as engaging in brute force  attacks. Fail2ban works by monitoring the nginx log files and applying  predefined filters to detect and block suspicious activity.

**IP blocking:** You can manually  block IP addresses that are detected as engaging in brute force attacks  by adding them to the nginx configuration file. For example, you can use the deny rule to block traffic from specific IP addresses:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/brute+force/img5.png)

It's important to note that detecting brute force attacks is not  always a straightforward process and may require additional analysis and investigation to identify the suspicious activity accurately.

Here's an example of a regular expression that can be used to detect  repeated failed login attempts from the same IP address in an nginx log  file:

/^(\S+) \S+ \S+ \[.*?\] "(POST|GET) \/login\.php.*?" (401|403) \d+ ".*?" ".*?"/gm

This regular expression will match any log file entry that includes a failed login attempt **(401 or 403 status code)** to the **/login.php** page. It will capture the IP address of the client making the request in the first capture group **((\S+))**. You can then use a log analysis tool or script to count the number of  times each IP address appears in the log file and flag any IP addresses  that have a high number of failed login attempts as potential brute  force attackers. Also, you can update the regex’s IP address as  suspicious IP source.

In this lesson, we have covered the Brute Forcing attack. We have  talked about how the vulnerability appears, as well as the detection and the prevention methods. 

### Questions

Log Location: /root/Desktop/QuestionFiles/Brute-Forcing/access.log

1 - What is the attacker's user agent?

> **Answer:** Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.5615.50 Safari/537.36

2 - What is the IP address of the attacker who performed the Brute Forcing attack?

> **Answer:** 146.241.73.240

3 - What date did the Brute Forcing successfully complete to login form? Format: dd/MMM/yyyy HH:mm:ss

> **Answer:** 26/Apr/2023 21:44:03

## Detecting XML External Entity Attacks

### What is XML External Entity?

For a better understanding let’s quickly look at what XML is.

XML (Extensible Markup Language) is a markup language that is used  for structuring and storing data in a structured format that is both  human-readable and machine-readable. XML was developed as a successor to HTML (Hypertext Markup Language) and is widely used for data exchange  between different systems and platforms, particularly on the web.

XML uses a set of tags to define the structure and content of the  data being represented. These tags are used to identify and describe  various elements and attributes of the data, such as tags for opening  and closing elements, attributes for specifying additional information  about the element, and entities for representing special characters and  symbols.

One of the key advantages of XML is its flexibility and  extensibility. It is possible to define custom tags and schemas for  representing data, making it a powerful tool for representing complex  data structures and exchanging data between different systems.

While XML was once widely used for a variety of purposes, its usage  has declined in recent years as newer data formats like JSON have gained popularity with its simplicity, ease of use, and better support for  modern web technologies.

XXE (XML External Entity) vulnerability is a type of security  vulnerability that affects applications that parse XML input. In an XXE  attack, an attacker injects malicious XML data into an application that  uses an XML parser without proper validation, which can result in the  application processing external entities that can be controlled by the  attacker.

An external entity is a piece of XML that is defined outside of the  XML document, but can be referenced and included within the document. An attacker can exploit an XXE vulnerability to include malicious external entities that can read local files, access internal systems, or perform other malicious actions on the server.

XXE vulnerabilities can be exploited in various ways, such as through web forms that accept XML input, SOAP and REST APIs that use XML-based  payloads, or other applications that accept and process XML input. These attacks can lead to sensitive data leaks, server-side request forgery  (SSRF), denial of service (DoS) attacks, and other serious security  issues.

It is important for developers to be aware of XXE vulnerabilities and take steps to prevent them, such as disabling external entities,  validating and sanitizing XML input, and using secure XML parsers that  are specifically designed to prevent XXE attacks.

### XML External Entity Possible Vectors

To find XML External Entity (XXE) vulnerabilities in a web  application, you can start by examining the application's XML processing code to identify any input points that accept XML input. These input  points could include:

1. Form fields that accept XML input
2. XML files uploaded by users
3. APIs that accept XML requests
4. XML files used for configuration or other purposes

Once you have identified the input points that accept XML input, you  can test them for XXE vulnerabilities by providing input that includes  external entity references and observing the application's response.

You can also use automated vulnerability scanners and penetration  testing tools that can detect and exploit XXE vulnerabilities. These  tools can send various payloads that include external entity references  and observe the response to determine if the application is vulnerable.

### How XML External Entity Works?

XXE attacks can depend on the programming language used by the  server-side application. The XXE attack vector exploits a vulnerability  in the XML parser of the server-side application, and the specific  vulnerabilities and defenses can vary depending on the programming  language used.

For example, PHP has a built-in XML parser called DOMDocument that is often used in web applications. The parser can be vulnerable to XXE  attacks if the XML input is not properly validated and sanitized, and  external entities are not disabled. As a defense, developers can use the libxml_disable_entity_loader() function to disable the loading of  external entities in PHP.

Here's an example of vulnerable PHP code that demonstrates an XXE vulnerability:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img1.png)

In this example, the PHP script accepts an XML input parameter named  "xml" and uses the loadXML() method of the DOMDocument class to parse it into a DOMDocument object. However, the code does not properly validate or sanitize the XML input, which can allow an attacker to inject an  external entity and perform a variety of malicious actions.

An attacker could send the following XML input to exploit the XXE vulnerability:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img2.png)

In this XML input, the attacker defines a new external entity called  "xxe" that references the "/etc/passwd" file on the server. When the PHP script processes this input, it will load the "/etc/passwd" file and  include its contents in the output, which can allow the attacker to read sensitive information from the server.

To prevent XXE attacks in PHP, it is important to validate and  sanitize any XML input properly and disable the processing of external  entities whenever possible. You can use the  libxml_disable_entity_loader() function to disable the loading of  external entities in PHP. Additionally, you can use input validation and sanitization functions such as filter_var() to ensure that the XML  input is properly formatted and does not contain any malicious payloads.

Let’s take a look at how XXE vulnerability appears in Java servlet applications;

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img3.png)

In this example, the servlet accepts an XML input parameter named  "xml" and uses a DocumentBuilder object to parse it into a Document  object. However, the code does not properly validate or sanitize the XML input, which can allow an attacker to inject an external entity and  perform a variety of malicious actions.

An attacker could send the following XML input to exploit the XXE vulnerability:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img4.png)

In this payload, we define an external entity xxe that points to a remote XML file **http://attacker.com/xxe.xml**. Then, we include the entity within the **<data>** element using the &xxe; syntax.

When the XML parser processes this payload, it will attempt to fetch  the remote xxe.xml file specified in the xxe entity. If the server  hosting the vulnerable application is vulnerable to SSRF, this can  result in the attacker being able to access internal systems or perform  other malicious actions on the server.

### Impact of XML External Entity

The impact of an XXE vulnerability can vary depending on the specific vulnerability and the context of the application. In general, however,  an XXE vulnerability can be quite serious and can result in a range of  harmful outcomes, including:

1. **Information disclosure:** An attacker can use an  XXE vulnerability to access sensitive data from the server with  read/write capability that will allow the attacker to modify/transfer  the data, such as configuration files, user credentials, and other  sensitive information.
2. **Server-side request forgery (SSRF):** An attacker can use an XXE vulnerability to make requests on behalf of  the server, allowing them to scan internal networks, exploit other  vulnerabilities, and carry out further attacks.
3. **Denial of service (DoS):** An attacker can use an XXE vulnerability to launch a DoS attack by  sending an XML input that causes the server to consume excessive  resources, such as memory or CPU time.
4. **Remote code execution (RCE):** In some cases, an attacker can use an XXE vulnerability to execute  arbitrary code on the server, allowing them to take full control of the  server and carry out further attacks.

Therefore, it is important to identify and remediate XXE  vulnerabilities in web applications to prevent these and other harmful  outcomes. Best practices for preventing XXE attacks include properly  validating and sanitizing all XML input, disabling the processing of  external entities, and using the latest secure versions of XML parsers  and frameworks.

### Prevention Methods for XML External Entity

There are several best practices that can help prevent XXE attacks:

**Disable external entities:** One of the most effective ways to prevent XXE attacks is to disable the  processing of external entities in the XML parser configuration. This  can be done by setting the appropriate parser configuration or using a  secure XML parser that has external entity processing disabled by  default.

**Input validation and sanitization:** Always validate and sanitize all XML input before parsing it. This includes  checking for malicious input such as nested XML entities, XML  injections, and other forms of malicious input.

**Use secure parsers:** Use the  latest version of a secure XML parser that has been specifically  designed to prevent XXE attacks. These parsers have features that can  help detect and prevent XXE attacks.

**Use whitelist filtering:** Implementing a whitelist of allowed entities and DTDs can help reduce the risk of  XXE attacks by blocking any input that is not on the whitelist.

**Implement access controls:**  Implement proper access controls to restrict access to sensitive data  and resources. This can help limit the damage in case an XXE  vulnerability is exploited.

**Use secure coding practices:**  Use secure coding practices, such as input validation, data  sanitization, and error handling, to minimize the risk of XXE attacks.

By implementing these best practices, you can significantly reduce  the risk of XXE attacks in your web application. It is important to keep up-to-date with the latest security best practices and patches for your web application, and to periodically perform security assessments to  identify and remediate any vulnerabilities.

Here's an example of vulnerable PHP code that is susceptible to XML External Entity attacks:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img5.png)

The code above loads an XML input from the **php://input** stream and passes it directly to the **loadXML()** method of the **DOMDocument** class without any validation or sanitization. This makes it vulnerable to XXE attacks.

To fix this vulnerability, we need to validate and sanitize the XML  input and disable external entities. Here is an example of a fixed  version of the code:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img6.png)

In the code above, we have disabled external entities using the function **libxml_disable_entity_loader()**, which prevents XXE attacks. We have then validated and sanitized the  XML input using a regular expression that only allows alphanumeric and  underscore characters. If the input passes validation, we load it into  the **DOMDocument** object and output the sanitized XML. If the input fails validation, we output an error message.

This fixed code ensures that the XML input is properly validated,  sanitized, and processed securely, and is much less vulnerable to XXE  attacks.

### Detecting XML External Entity Attacks

In Part 1, we have overviewed what the XML External Entity is and how to prevent this vulnerability. In this part, we’ll have a look at the  detection techniques and some tips to make it easier. Before moving on  let’s take a quick look for example payloads for the XML External Entity vulnerability;

**Basic XXE Payload**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img7.png)

**Blind XXE Payload**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img8.png)

**XXE Payload with PHP Filter**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img9.png)

Here's an example of what an Nginx log might look like when an XXE  attack occurs via a vulnerable parameter on a GET request (This  methodology is the same as analyzing POST requests):

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img10.png)

In this log, the IP address of the client making the request is  123.45.67.89. The request was a GET request to the processXML endpoint,  with an xml parameter that contains an XXE payload. The XXE payload  attempts to read the contents of the /etc/passwd file. The response code is 200, indicating that the request was successful, and the response  size is 143 bytes. The user agent string indicates that the request was  made from a Chrome browser on a Windows 10 machine.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img11.png)

The most important things to detect XXE attacks on the logs, you should check specific keyword like;

- DOCTYPE
- ELEMENT
- ENTITY

So for the detecting !DOCTYPE keyword in nginx logs, we can use regex like;

^(\S+) - (\S+) \[(.*?)\] "(\S+) (.*?)\?(?=.*?\b21DOCTYPE\b).*? HTTP\/\d\.\d" (\d+) (\d+) "(.*?)" "(.*?)"

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img12.png)

21 is for the encoded version of the ! character. Because !DOCTYPE is equal to %21DOCTYPE. This regex will match the following line on the  example that we have shared above;

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img13.png)

And decoded versions are;

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Detecting-Web-Attacks-2/xxe/img14.png)

So, it can be clearly seen that the user sends to XXE payload from  source IP 123.45.67.89 on dates 30/Apr/2023:12:34:57 and  30/Apr/2023:12:34:59. 

In this lesson, we have covered the XML External Entity attack. We  have talked about how the vulnerability appears, as well as its  detection and prevention methods.

### Questions

Log location: /root/Desktop/QuestionFiles/XML-External-Entitiy/access.log

1 - What parameter affected XXE?

> **Answer:** data

2 - What file did that attacker try to read using XXE?

> **Answer:** /etc/shadow

3 - What was the attacker's IP address?

> **Answer:** 94.23.33.25