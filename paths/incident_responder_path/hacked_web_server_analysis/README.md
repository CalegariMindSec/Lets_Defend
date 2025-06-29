# Hacked Web Server Analysis

Learn how to analyze compromised web servers.

**Table of Contents:**

- Introduction to Hacked Web Server Analysis
- Log Analysis on Web Servers
- Attacks on Web Servers
- Attacks Against Web Applications
- Vulnerabilities on Servers
- Vulnerabilities in Programming Language
- Discovering the Web Shell
- Hacked Web Server Analysis Example

**Practice with SOC Alert**

- [117 - SOC167 - LS Command Detected in Requested URL](https://app.letsdefend.io/monitoring?channel=closed&event_id=117)
- [120 - SOC170 - Passwd Found in Requested URL - Possible LFI Attack](https://app.letsdefend.io/monitoring?channel=closed&event_id=120)
- [125 - SOC175 - PowerShell Found in Requested URL - Possible CVE-2022-41082 Exploitation](https://app.letsdefend.io/monitoring?channel=investigation&event_id=125)
- [119 - SOC169 - Possible IDOR Attack Detected](https://app.letsdefend.io/monitoring?channel=closed&event_id=119)
- [115 - SOC165 - Possible SQL Injection Payload Detected](https://app.letsdefend.io/monitoring?channel=closed&event_id=115)
- [116 - SOC166 - Javascript Code Detected in Requested URL](https://app.letsdefend.io/monitoring?channel=closed&event_id=116)
- [118 - SOC168 - Whoami Command Detected in Request Body](https://app.letsdefend.io/monitoring?channel=closed&event_id=118)

**Evaluate Yourself with Quiz**

- [Hacked Web Server Analysis](https://app.letsdefend.io/training/quiz/hacked-web-server-analysis-quiz)

**Challenge**

- [Http Basic Auth.](https://app.letsdefend.io/challenge/http-basic-auth)
- [Investigate Web Attack](https://app.letsdefend.io/challenge/investigate-web-attack)

## Introduction to Hacked Web Server Analysis

### Introduction to Hacked Web Server Analysis

When the internet is widely available in almost every home, web services  have become a part of life and this has led to attackers targeting these services.

Attackers can steal information from web services for the purpose of  making them nonfunctional, gaining fame, etc. They organize attacks on  web servers to perform illegal activities. During the training, various  attacks on web servers and analysis methods will be examined.

### **Introduction to Log Analysis**

Log recording is the recording of events that occur on the server.  Thanks to the log records, undesired situations such as system errors  and security risks can be analyzed.

In log analysis, it is of great importance that the analyst knows  what he/she is looking for. Considering that there are all kinds of  activity records in the log files, it will be very troublesome to reach  the result without filtering.

Thus, it is crucial to pay attention to 3 steps during log analysis:

1. Accessing the logs
2. Determining the purpose for which log analysis will be carried out
3. Extracting data by filtering log records for your intention

In the following sections, UNIX tools will be used while performing  log analysis. If you are not familiar with these tools, we recommend  that you should complete the ["Linux for Blue Team"](https://app.letsdefend.io/training/lessons/linux-for-blue-team) training first to get a better understanding.

### Log Analysis on Web Servers

While logging on web servers, requests made with the POST method may not be  logged by default. In this case, the situation can be compensated by  using modules such as mod_forensic or mod_security.

The data sent with the POST method is not included in the logs. Network traffic needs to be examined to access data.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image.png)

A screenshot of the log record of a request sent with the POST method is given above. As can be seen, it is seen in the relevant request to  which address the request was sent. Looking at the sent package itself,  there is also information such as the data sent by the client to the  server and the referring page. A sample POST request has been added  below for clarity.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-1.png)

### **Apache Web Server**

In this section, we will see how a web application hosted on an  Apache server was exposed to an SQL Injection attack by examining the  log records.

### **Log Records**

In the Apache web server, log records are kept in access.log and  error.log files under /var/log/apache2 folder. In the "access.log", a  record of requests made to the server is kept.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-2.png)

In the screenshot above, from the IP address “192.168.2.232” to the  “/index.php” page, in the “GET” method in the “[18/Aug/2017:15:02:05  +0000]” time zone, “Mozilla/5.0 (X11; Linux x86_64) ) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/60.0.3112.78 Safari/537.36” User-Agent  request was sent.

The "error.log" file contains errors that the server encounters while processing requests.

The following screenshot shows that the client trying to navigate to the "/test" directory failed.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-3.png)

### **How did the SQL Injection attack happen?**

To examine the logs of the server exposed to the SQL Injection attack, go to the /var/log/apache2 folder.

**cat access.log**

When you look at the log file with the above command, it is clear  that many SQL injection attempts are made by the same IP address. If the injection attempts were not made noticeably, the most used parameters  in sql attacks would be searched in the logs. These are union, select,  from, or, They are parameters such as version. These parameters can be  searched in log files with the grep command.

**cat access.log | grep -E “%27|--|union|select|from|or|@|version|char|varchar|exec**

Below is a screenshot of the SQL injection records in the "access.log" file.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-4-1024x415.png)

In order to view the successful attempts, the responses that return 200 codes from the server must be filtered.

**cat access.log | grep 200**

Filtering is performed with the grep command. After the filtering,  output shows the logs that has HTTP Response 200 status code were  returned to the SQL query where the username and password were drawn.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-5.png)

Let's apply the "URL Decode" operation to the URL address above.

**Decoded URL:** /cat.php?id=1 UNION SELECT 1,concat(login,':',password),3,4 FROM users;

When the encoded URL is decoded, you can see that there is clearly a SQL Injection attack.

To check if the attacker is logged into the "admin" panel, we can look at the access logs via command below:

**cat access.log | grep 192.168.2.232 | grep admin/index.php**

The screenshot of the records of the attacker who made a request to the admin panel is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-6.png)

In the screenshot, it is seen that the attacker sends a request to  the admin panel with the POST method. When the sent POST request is  examined with Wireshark, it is certain that the attacker has logged into the panel.

The details of the POST request sent to the admin panel are given in the screenshot below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-7.png)

### **Nginx Server**

In this section, log records of "directory traversal vulnerability"  attempts, which are an attack on the application running on the Nginx  server, will be examined. In this attack, different files are accessed  by changing the directory with dot-dot-slash ( ../ ).

### **Log Records**

On Nginx servers, log files are kept in the /var/log/nginx directory, as in Apache servers, in access.log and error.log files.

### **How Did the Attack Occur?**

It would be more convenient for us to filter the characters “../” or “..\” for the detection of the attack.

Command: **cat access.log | grep ../**

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-8.png)

As can be seen in the output above, the attacker tried to read the  passwd file. After the third attempt, he transferred the page to himself with the wget command.

When the transferred page is examined, it is seen that the  information in the "passwd" file has been disclosed. The screenshot of  the page copied by the attacker is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-9.png)

### **IIS Web Server**

Log records are kept in the C:\inetpub\logs\LogFiles\W3SVC1 folder on the IIS web server.

A sample screenshot of the log records on IIS web servers is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-10.png)

### Questions

1 - In what year was the request made to the "/letsdefend.html" path of the Nginx web server? 

Answer Format: xxxx 
Sample Answer: 2016 

> **Answer:** 2022

2 - What is the IP address trying to read the /etc/passwd file on the Nginx web server? 

Answer Format: X.X.X.X 

> **Answer:** 91.93.236.194

3 - What is the IP address that attempted SQL injection attack on Apache2 web server? 

Answer Format: X.X.X.X 

> **Answer:** 91.93.236.194

## Attacks on Web Servers

Attacks on web servers are usually caused by the vulnerability of the web  server itself, the vulnerabilities of the application server, or the web application that has not taken adequate security measures.

### **Application Servers**

In this section, we will examine the security vulnerabilities arising from application servers such as tomcat, jboss, glassfish.

### **Tomcat Application Server**

The vulnerability is caused by the server using mod_jk and the  application server allowing the URL addresses sent by the client to be  decoded.

The purpose here is to use the directory traversal vulnerability by encoding the ".." parameter twice.

**“..” → “%2e” →“%252e”**

The page cannot be accessed when the "/manager/html" path of the target address is accessed.

However, when trying to go to the “/examples/jps/%252e%252e/%252e%252e/manager/html” path , the login panel is encountered.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-11.png)

After trying the default user name and password, access to the admin  panel is provided. Before the prepared webshell is loaded,  “/examples/jsp/%252e%252e/%252e%252e/” is added to the beginning of the  action part of the deploy button. After the process, the webshell is  loaded.

The screenshot of the action part of the Deploy button is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-12.png)

Then, the desired commands can be run by going to the "/examples/jsp/%252e%252e/%252e%252e/test" path.

The screenshot of the path with Webshell is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image.jpeg)

#### **Log Records**

Requests made to the login panel are listed with the command below.  When the requests were examined, it was seen that the address was  reached with the [URL encode.](https://www.w3schools.com/tags/ref_urlencode.ASP)

**Command:** cat access.log | grep manager/html | grep 200

The relevant screenshot is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-13.png)

When filtering the logs with the IP address of the attacker reaching  the panel; The requests sent by the attacker were examined. The POST  request sent is noteworthy.

With the following command, all 200 http response code requests of the target are listed.

**Command:** cat access.log | grep 192.168.68.1 | grep 200

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-14.png)

Using the Wireshark filter below, the relevant request is found and examined.

**Wireshark filter:** ip.src == 192.168.68.1 && http.request.method == POST

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-1.jpeg)

As seen in the screenshot above, the attacker installed the test.war file on the system.

#### **Protection Methods**

The vulnerability can be avoided by updating “mod_jk”.

### **GlassFish**

This section will discuss [CVE-2011-0807](https://nvd.nist.gov/vuln/detail/CVE-2011-0807) and the remote code execution vulnerability. You can access the vulnerability details by clicking [here.](https://nvd.nist.gov/vuln/detail/CVE-2011-0807)

The panel is accessed using various methods such as authentication  bypass, default user name, and password, and remote access is provided  by uploading a malicious file to the system. The target system has Sun  GlassFish Enterprise Server 2.1 and Java System Application Server 9.1.  In this case, the target system is exploited using the  "exploit/multi/http/glassfish_deployer" exploit in the Metasploit  Framework.

First of all, the target is scanned with nmap and it is tried to  determine the open ports on the system and what the ports are used for.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-15.png)

As seen in the image above, GlassFish 2.1 is running on the target  system. Exploits created for GlassFish are searched with the help of  msfconsole.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-16.png)

The exploit is selected with the “use” command and necessary  adjustments are made. The settings for the exploit are given in the  screenshot below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-17.png)

The exploit is run by issuing the "run" command.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-18.png)

After the exploit is run, our meterpreter session is prepared and we can run commands on the target.

Below is a screenshot showing that the Meterpreter session is active and the command is executable on the target.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-19.png)

#### **Log Records**

With the "netstat -an" command, the addresses that the system  communicates with are displayed and it is seen that it is communicating  with an unrecognized address on port 4444.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-20.png)

When the network traffic is examined, it is seen that the attacker  sent three different GET requests. Relevant requests are given in the  screenshot below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-21-1024x52.png)

After GET requests, lots of TCP traffic occurs over 4444 ports.  However, since Metasploit encrypts the data with AES, we cannot learn  which commands the attacker executed over the network traffic.

#### **Protection Methods**

- Not leaving the username and password as default.
- Installing updates.

### **Jboss**

In this section, the remote code execution vulnerability running in  Jboss AS versions 3,4,5, and 6 will be examined. The target system is  running Jboss 6 on Ubuntu 14.04. Exploit ID number 36575 in exploit-db;

- https://www.exploit-db.com/exploits/36575/

The vulnerability will be exploited.

After the exploit is downloaded, the target address and port number are specified and the attack is started with command below.

**python 36575.py http://192.168.2.105:8080**

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-22.png)

Then the exploit is performed and the shell appears on the screen. "Whoami" and "uname -a" commands are run on this screen.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-23.png)

#### **Log Records**

When the HTTP requests to the server are examined, parameters such as id, whoami, uname -a draw attention.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-24.png)

When the details of the relevant packets are examined, the response  returned by the server and the address of the request is seen.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-25-1024x290.png)

As seen in the records, requests are made to "/jbossass/jbossass.jps" path.

The file where the request is made is searched on the server with the command below:

**find /opt/jboss-6.0.0.Final/ -type f -name "jbossass.jsp"**

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-26.png)

Below is a screenshot of the source code of the "jbossass.jsp" file.  When the related file is examined, as seen that it is a webshell.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-27.png)

#### **Protection Methods**

- Upgrade to JBoss EAP 7.
- Running software with an unauthorized user.

### Questions

1 - The attacker with the IP address “91.93.236.194” made various XSS  attempts on the Apache2 server. On what September day happened this  attack? (??/Sept/2022) 

 **Answer Format:** Number(1-31)  

 **Sample Answer:** 15

> **Answer:** 27

2 - What is the name of the attack that the IP address “156.146.59.9” tried on the Apache2 web server? 

 Answer Format: XXX 

> **Answer:** XSS

3 - What is the User Agent information of the POST request sent to the Apache2 web server on “27/Sep/2022 10:56:39“? 

 Answer Format: X/X.X.X  

> **Answer:** PostmanRuntime/7.29.2

## Attacks Against Web Applications

### **Injection**

Injection is manipulation by adding various parameters to the query sent to the server.

SQL Injection is sending the desired query to the database by  manipulating SQL queries. This article is described as assuming a basic  knowledge of SQL injection attacks. For detailed information about SQL  injection, you can look at our lesson.

- [Detecting SQL Injection Attacks](https://app.letsdefend.io/training/lesson_detail/detecting-sql-injection-attacks-web-attacks-101)

Here, we will briefly touch on which steps a person should try to  detect a SQL injection attack. Our main purpose in the detection stages  is to receive error messages. Database information used in the error  messages we receive, etc. We will get the details.

For this;

- The most basic payload used is the ' (single quote) character.
- The number of columns can be determined. For this, the payload given below can be used.

**?id=6 ORDER BY 6--**

- All data in a column must have the same data type. For this, the column type can be determined using the payload below.

**?id=6 UNION SELECT 1,null,null--**<.p>

- The following payloads can be used to detect logic-based SQL injection vulnerability.

**test.php?id=6**
 **test.php?id=7-1**
 **test.php?id=6 OR 1=1**
 **test.php?id=6 OR 11-5=6**

- The following payloads can be used to detect time-based SQL injection vulnerability.

**SLEEP(25)--**
 **SELECT BENCHMARK(1000000,MD5('A'));
userID=1 OR SLEEP(25)=0 LIMIT  1-- userID=1) OR SLEEP(25)=0 LIMIT 1-- userID=1' OR SLEEP(25)=0 LIMIT  1-- userID=1') OR SLEEP(25)=0 LIMIT 1-- userID=1)) OR SLEEP(25)=0 LIMIT  1-- userID=SELECT SLEEP(25)--**

### **Example of SQL Injection Attack**

In this example, we will consider a web application that simply asks the user for the user id number.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-29.png)

When the ID number is entered, the name and surname information of the user of the entered number is returned.

Details of the information of the user whose ID is 2 are given in the screenshot below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-30.png)

However, if a manipulated query is sent that the application does not expect, the unsecured web application will be exposed to an injection  attack.

For example, the database version is drawn with the query **' or 0=0 union select null, version() #** below. While the previous query is completed with quotation marks in  this query, the result is always correct with the expression “or 0=0”.”  union select null , version()”, version information is also retrieved.  Lastly, the "#" sign ensures that the rest of the query remains as a  comment line.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-31.png)

As above, it was manipulated by a sql injection attack with a sql  query, which was waiting for id information, and caused data leakage.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-32.png)

The following image shows the response returned by the query run.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-33.png)

### **Log Records**

It has been determined that the most used characters and words in SQL Injection attacks are ' , -- , union , select , from , or , @ , version , char , varchar , exec .

When the relevant characters are encoded in the URL, a Linux command as follows is generated for attack detection.

**cat access.log | grep -E “%27|--|union|select|from|or|@|version|char|varchar|exec**

As a result of the search made in the "access.log" file with the relevant command, the following result is obtained.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-34.png)

It appears that the query **' or 0=0 union select null, version() #** is sent when the record URL in the acces.log file is decoded.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-35.png)

### **Protection Methods**

- Using prepared query statements
- Checking the sent data
- Filtering the sent data
- Restricting user privileges

measures that can be taken.

### **Broken Authentication and Session Management**

It is a security weakness caused by not providing full session security.

### **Attack Sample**

The purpose of this attack will be to change the cookie information  and switch to the desired user account without any authentication  mechanism.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-36.png)

Login to the system as "user1".

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-37.png)

Then the cookie value is checked. The screenshot of the cookie value of the user "user1" is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-38.png)

As you can see, the cookie value is the same as the username. When  the cookie value is changed to admin, if there is an admin user in the  system, it will be switched to the admin user.

The screenshot of changing the cookie data is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-39.png)

The screenshot showing the switch to the admin user is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-40.png)

As a result, without using any password, only the cookie value was changed and the admin user was switched.

### **Log Records**

When the log records are examined, it is seen that there is no remarkable situation.

The screenshot showing that the user "user1" is logged in the analyzed log records is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-41.png)

However, when the details of the requests sent with the network  traffic were examined, it was seen that there was an abnormality in the  cookie values.

A screenshot of the cookie value of the user entering the system from the 192.168.68.1 IP address is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-42.png)

The screenshot of the cookie value in the second request sent to the system from the same IP address is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-43.png)

As seen in the screenshots, the person connecting to the system from  the same IP address has changed the cookie values and switched to the  "admin" user.

### **Protection Methods**

- Providing strong authentication and session management
- Preventing XSS attacks so that cookie information is not stolen

### **Cross-Site Scripting (XSS)**

XSS is a type of attack that allows the client to run code on a site  with the help of HTML and JavaScript. In addition, attacks such as  cookie stealing and page redirection can also be organized.

XSS is usually found in sections where GET and POST methods are used. It is found in fields that take input such as search boxes, galleries,  messages, and memberships. The payload used for detection is usually in  the form of given below. Of course, this payload is a very classic  example. Different event handlers (onclick, onload, onmouseover, etc.)  can be used depending on the filtering situation. For detailed  information about XSS and for examples, you can visit the website.

**Example Payload:** "><script>alert(1)</script>

- [Detecting Cross Site Scripting (XSS) Attacks](https://app.letsdefend.io/training/lesson_detail/detecting-cross-site-scripting-xss-attacks-web-att)

### **Attack Sample**

In this sample attack, the vulnerability will be exploited by adding  JavaScript code to the section where a message should be written for the guestbook.

For this, the appropriate JavaScript code is written and sent to the  message section first. If the vulnerability is exploited with the code  written as an example, "1" will be written on the screen as a pop-up  message.

The application is tried to be exploited by writing JS code outside of the expected message in the guestbook.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-44.png)

Users who visit the page after the message is sent are affected by the code written.

Below is a screenshot showing that the user visiting the page is affected by the JavaScript code.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-45.png)

Looking at the source code of the page, it is seen that the javascript code has been added.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-46.png)

### **Log Records**

When the log records are examined, it is seen that data is sent to the page related to the POST method.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-47.png)

Network traffic is inspected to see the details.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-48.png)

As can be seen in the records of the examined traffic, JavaScript code was injected into the attacker message section.

In order to detect XSS attacks performed with the GET method, it is  necessary to filter some keywords in the log files. The most used  characters and words in XSS attacks are <, >, alert, script, src,  cookie, onerror, document. While filtering the search with the grep  command, it is necessary to search for the URL encoded version of the  '<' and '>' characters.

As a result;

**cat access.log | grep -E "%3C|%3E|alert|script|src|cookie|onerror|document"**

A command appears.

A screenshot of an example XSS attack detection is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-49.png)

### **Protection Methods**

- Verifying the input (checking that the data entered is indeed the requested type).
- Using whitelist instead of blacklist.

### **Security Misconfiguration**

This vulnerability is due to security configurations being left incorrect, weak, or default.

### **Attack Sample**

In this sample attack, as a result of not changing the password of  the "admin" user automatically created by the system, the attacker can  log into the system with the default user name and password.

### **Protection Methods**

- Editing the default configurations.
- Keeping software up to date.
- Disable unused services and ports.

### **Cross-Site Request Forgery (CSRF)**

CSRF stands for cross-site request forgery. It is a type of attack  that is carried out by making the user take action against his will by  the attackers.

### **Attack Sample**

In this sample attack, our goal will be to change the victim's  password by sending a request to the target application with a fake web  page.

There is only a "click" button on the fake web page. The screenshot of the relevant button is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-50.png)

A screenshot of the source code of the fake page is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/img2new-1.png)

The following action will be taken on our fake page; If the victim  clicks the "click" button, they will send a request to the target  application that they want to change their password to 123456.

And the password of the user who clicked the button will be changed. The relevant screenshot is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-52.png)

### **Log Records**

When the log records are examined after the attack, it is seen that  the victim requested a password to the application and the user's  password was changed.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/img1new-1.png)

### **Protection Methods**

- Using the CSRF protection mechanisms offered by the frameworks.
- Using token and session.

## Vulnerabilities on Servers

In this section, the vulnerabilities on the server itself will be  reviewed. For further information on the vulnerabilities, you can visit  the below site:

- http://www.cvedetails.com 

### **Apache Web Server**

The vulnerability with the code CVE-2014-6271, which is called  "Shellshock" for the Apache web server and is used to run commands  remotely, will be discussed. Systems using mod_cgi and mod_cgid modules  on Apache servers are affected by the vulnerability and bash versions  1.14 to 4.3 are affected.

The vulnerability can be exploited by modifying the HTTP_USER_AGENT  environment variable to be malicious and targeting it to CGI scripts.

### **Attack Sample**

For the sample attack to be carried out, the script runs on the  target that pulls the "uptime" and "kernel" information from the server.

With the following command, it is desired to read the "passwd" file of the destination address.

**echo -e "HEAD /cgi-bin/status HTTP/1.1\r\nUser-Agent: () { :;};  echo \$(</etc/passwd)\r\nHost: TARGET_ADDRESS\r\nConnection:  close\r\n\r\n" | nc TARGET_ADDRESS 80**

When the HTTP header of the response is examined, the content of the "passwd" file is displayed.

The screenshot below shows that the user-agent header information has been changed and the request has been sent to the target.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-54.png)

### **Log Records**

When the log records are examined, it is noteworthy that a HEAD request is sent to /cgi-bin/status.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-55.png)

At the same time, the /etc/passwd section, which is sent with various parameters, stands out. Network traffic is inspected to display the  returned response.

The request sent to the “cgi-bin/status” file is given in the screenshot below.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-56.png)

Below is a screenshot of the response returned by the server to the requested request.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-57.png)

When the response is examined, it is seen that the server information has been disclosed.

### **Protection Methods**

- Upgrade Bash to the current version.

The command to be used for this is;

**sudo apt-get update && sudo apt-get install --only-upgrade bash**

### **Nginx Web Server**

Looking at the security vulnerabilities found for the Nginx server, there is no critical vulnerability in 2010-2017.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-58.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-59.png)

### **IIS Web Server**

In this section, two vulnerabilities will be mentioned. These are CVE-2017-7269 and MS15-034.

### **MS15-034 Vulnerability**

This vulnerability allows remote code execution when a specially crafted HTTP request is sent to the windows system.

Vulnerable versions: Machines with any version of IIS using HTTP.sys  on Windows 7, Windows Server 2008 R2, Windows 8, Windows Server 2012,  Windows 8.1, and Windows Server 2012 R2 operating systems.

When the target is scanned with [nmap](https://nmap.org/), it is seen that it is using Windows Vista, 2000 or 7 and also IIS 7.5 is active.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-60.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-61.png)

In order to understand whether the related vulnerability is valid for the target, HTTP request with the "Range" header is sent to the target. The added range will be processed by the server.

**wget --header="Range: bytes=0-18446744073709551615" http://192.168.10.169/welcome.png**

The above command is entered and it is understood that the  vulnerability exists due to the "416 Requested Range Not Satisfiable"  output.

Then it is sent again by changing the Range and is under overload.

**wget --header="Range: bytes=18-18446744073709551615" http://192.168.10.169/welcome.png**

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-62.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-63.png)

It is possible to get rid of the vulnerability associated with installing Windows updates.

### **CVE-2017-7269 Vulnerability**

CVE-2017-7269 vulnerability found on a machine running IIS 6.0 on  Windows Server 2003 R2 will be discussed. The vulnerability is due to  the buffer overflow attack of the ScStoragePathFromUrl function in the  WebDAV service in IIS 6.0.

The vulnerability can be exploited by using the “iis_webdav_scstoragepathfromurl” exploit in Metasploit.

The screenshot of the settings made for the exploit is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-64.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-65.png)

The screenshot of the meterpreter session obtained as a result of exploiting the vulnerability is given above.

## Vulnerabilities in Programming Language

### **PHP**

The mail() function of PHP and the "Phpmailer" library that uses it  is used by millions of people. Remote code execution vulnerability  occurs due to the use of the "mail()" function without fully checking  the extra parameter sending feature. The code for the relevant  vulnerability is “CVE-2016-10033”.

### **CVE-2016-10033 Vulnerability Attack Sample**

As an example, an application with a security vulnerability is installed.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-66.png)

Then the exploit prepared for this vulnerability is run. The relevant exploit can be downloaded from the link given below:

- https://github.com/opsxcq/exploit-CVE-2016-10033

The screenshot of the exploit process performed at the target address is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-67.png)

After the exploit is performed, the system is waiting for the remote command to be executed.

Below is a screenshot of the vulnerability being exploited and running a remote command.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-68.png)

### **Log Records**

When the network traffic of the vulnerability is examined, it is noticed that GET requests are sent to the “backdoor.php” path.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-69.png)

When the sent commands are decoded with base64, the commands executed by the attacker are exposed. To access detailed information about [base64](https://app.letsdefend.io/training/lesson_detail/base64-encodingdecoding), you can click [here.](https://app.letsdefend.io/training/lesson_detail/base64-encodingdecoding)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-70.png)

### **Protection Methods**

\- The vulnerability affects versions 5.2.18 and below. The vulnerability can be avoided by updating. 

### **Java**

Under this title, the "Session Injection" vulnerability that occurs  in the Java Play Framework will be discussed. The vulnerability is due  to session encode.

### **Attack Sample**

The target application tells the screen whether the user has admin  rights. Here, the attacker's goal will be to gain admin rights.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-77.png)

First, registration is made under the user name in a normal way and the submitted requests are examined using [Burp Suite](https://portswigger.net/burp) software.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-71.png)

Here, assuming the admin user exists, null bytes are used to switch to the admin user.

A new record is created and the **"%00%00admin%3a1%00"** parameter is added after the user name and the injection is completed. The new  session to be created here is misinterpreted by the server with the **"admin:1"** parameter and access to admin rights. By using empty characters, the **"admin:1"** parameter is set to the previous parameter. separated from the username.

The user interface of the registration screen is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-72.png)

The parameter 00%00admin%3a1%00 is added to the end of the username on the sent request.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-73.png)

The screenshot showing access to admin rights on the application after the request is made is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-74.png)

### **Log Records**

When the log records are examined, it is seen that the "test" user  seems to have registered normally, but when the cookie value is  examined, an injection attack occurs.

The screenshot of the POST request sent to the Register page is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-75.png)

The screenshot of the post-registration request and the server's response are given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-76-1024x434.png)

### **Protection Methods**

\- This vulnerability has been fixed with the update. The vulnerability can be mitigated by updating.

## Discovering the Web Shell

### **Finding the Shell Installed on the Server**

Shell is a script that transfers the rights to the installer on the server it is installed on. **c99**,**r57** is one of the most popular shells known. In this section, we will talk about PHP shells.

If we take a look at the shell example, which allows running a simple command, it is seen that it runs the system() function outside of  ordinary commands.

Below is a screenshot of a simple PHP shell.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-78.png)

In this case, if the files that call the system() function in the  server are extracted, the malicious file can be found more easily among  hundreds of files.

With the command below, all files that call the system function under the /var/www directory are scanned.

**Command:** grep -Rn "system *(" /var/www

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-79.png)

When a different PHP shell is examined, it is seen that the shell_exec() function is preferred instead of the system function.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-80.png)

As mentioned before, **shell_exec()** and **eval()** functions also stand out when paying attention to the different functions used.

In other words, the shell_exec and eval functions should also be scanned while searching for the shell.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-81.png)

When PHP shells are examined, it is observed that they generally contain parameters such as **passthru**, **shell_exec**, **system**, **phpinfo**, **base64_decode**, **edoced_46esab**, **chmod**, **mkdir**, **fopen**, **fclose**, **readfile**, **php_uname**, and **eval**. For this, it is possible to find the shells in the server in a scan performed with the command given below.

**grep -RPn "(passthru|shell_exec|system|phpinfo|base64_decode|chmod|mkdir|fopen|fclose|readfile|php_uname|eval) \*\(" /var/www**

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-82.png)

### **Shell Hide Methods**

In order not to be caught in the firewall by the system administrator or while uploading files, attackers apply some shell hiding methods. In this section, we will discuss these methods.

### **Remote Summoning**

In this method, the shell is not actually hosted on the target  server. The codes belonging to the shell from another address are pulled and run on the target server.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-83.png)

### **Encrypted Code**

By encrypting the code of the shell, the firewall, if any, is tried to be bypassed it.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-84.png)

### **Hiding in Picture**

Here, the malicious code is placed in the exif information of any  image, and the code is run by reading the exif information of the image  with PHP.

First, the desired codes are placed in the exif information of the  image with the help of exiftool. The screenshot of the image whose  "exif" information has been changed is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-85.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-86.png)

Then PHP code is written to read the exif information from the image.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-php.png)

Firewalls can be bypassed with such hiding methods. When it comes to  finding the shell, it is not very difficult by searching the files on  the server one by one with the help of grep. But apart from the  functions mentioned earlier, it will be necessary to scan the **exif_read_data()** and **preg_replace()** functions.

As can be seen above, the encrypted shell, the hidden shell in the  picture, and the remotely called shells have all been located.

### Questions

1 - There is a PHP shell on the server. What is the filename of this shell? 

 Answer format: xxx.xxx

> **Answer:** run.php

2 - Is there a webshell hidden in the image on the server? 

 Answer Format: Y/N 

> **Answer:** N

## Hacked Web Server Analysis Example

In this section, we will be examining a fully compromised web server running Wordpress by post-attack analysis.

First, understanding whether the attacker has access to the admin panel can be discovered by entering this command below:

**cat access.log | grep POST | grep wp-login**

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-89.png)

As can be seen in the output in the screenshot above, many POST  requests have been sent to the admin panel login page over the same IP  address. Network traffic is examined to check the data sent with the  request. For this, in Wireshark;

[Wireshark](https://www.wireshark.org/) is the world's foremost and widely-used network protocol analyzer.

**Query:** ip.src == 192.168.2.232 && ip.dst == 192.168.2.31 && http.request.method == POST

POST requests to the web server through the attacker are listed using the filter.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-90.png)

When the requests were examined, it was determined that a brute force attack was carried out on the "wp-login" page.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-91.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-92.png)

As a result of the attack, the correct username and password were found as admin: admin.

When the “error.log” file is examined, it is seen that the  fscockopen() function is intended to be activated. Thus, it can be  predicted what the attacker did in the admin panel. The **cat error.log** command reads the error.log page.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-93.png)

Looking at the file details, it was determined that it sent a request to the /words/test123123 path. The relevant screenshot is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-94.png)

The attacker wanted to go to an inaccessible page and get a 404 Not  Found. Thus, instead of the classic 404 Not Found error page, it is  thought that the code he has placed will work. We can look at the change by examining the network traffic or logging into the admin panel.

Looking at the changes, it was determined that the content of the 404 Not Found error page was changed by the attacker.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-95.png)

The piece of code used by the attacker for the error page is shown in the screenshot below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-96.png)

When the code used by the attacker for the 404 error code page is  examined, it is seen that he opened access to his own address on port  1234.

The attacker will have access to the server with www-data user rights with this door opened for himself. In this case, the commands run by  the "www-data" user on the server are examined.

Below is a screenshot of the commands the attacker ran on the server.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-97.png)

The attacker, who read the "wp-config.php" file, switched to the root user. When looking at the wp-config.php file, the database password is  the same as the root user's password.

A screenshot of the contents of the wp-config.php file is given below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Hacked+Web+Server+Analysis/images/image-98.png)

With the above password, the attacker gained root authority and took over the entire server.

### **Conclusion**

As discussed in the tutorial, attackers can attack the web server in various ways to take over. In order to detect attacks, [log analysis](https://app.letsdefend.io/training/lessons/network-log-analysis) and good control of network traffic are required. For this, it is  necessary to know and understand the attack vectors for effective  analysis.

Sometimes a security vulnerability can be caused by the server or  programming language you are using. Therefore, it is necessary to keep  the components on the server constantly updated.