# Detecting Web Attacks

Investigating web attacks as a SOC Analyst.

**Table of content:**

- [Introduction](#introduction)
- [Why Detecting Web Attacks Important](#why-detecting-web-attacks-important)

- [OWASP](#owasp)
- [How Web Applications Work](#how-web-applications-work)
- [Detecting SQL Injection Attacks](#detecting-sql-injection-attacks)
- [Detecting Cross Site Scripting (XSS) Attacks](#detecting-cross-site-scripting-xss-attacks)
- [Detecting Command Injection Attacks](#detecting-command-injection-attacks)
- [Detecting Insecure Direct Object Reference (IDOR) Attacks](#detecting-insecure-direct-object-reference-idor-attacks)
- [Detecting RFI & LFI Attacks](#detecting-rfi--lfi-attacks)

**Practice with SOC Alert**

- [120 - SOC170 - Passwd Found in Requested URL - Possible LFI Attack](https://app.letsdefend.io/monitoring?channel=investigation&event_id=120)

- [119 - SOC169 - Possible IDOR Attack Detected](https://app.letsdefend.io/monitoring?channel=investigation&event_id=119)
- [116 - SOC166 - Javascript Code Detected in Requested URL](https://app.letsdefend.io/monitoring?channel=investigation&event_id=116)
- [115 - SOC165 - Possible SQL Injection Payload Detected](https://app.letsdefend.io/monitoring?channel=investigation&event_id=115)
- [118 - SOC168 - Whoami Command Detected in Request Body](https://app.letsdefend.io/monitoring?channel=investigation&event_id=118)
- [117 - SOC167 - LS Command Detected in Requested URL](https://app.letsdefend.io/monitoring?channel=investigation&event_id=117)

**Challenge**

- [Http Basic Auth.](https://app.letsdefend.io/challenge/http-basic-auth)

- [Investigate Web Attack](https://app.letsdefend.io/challenge/investigate-web-attack)

## Introduction

We have created the Web Attacks 101 course to help you better understand  cyber attacks (75% of which are against web-based applications) and how  to respond to them.

### **What are web attacks?**

Web applications are applications that provide services to users  through a browser interface. Today, web applications make up a large  part of internet usage. Sites such as Google, Facebook, and YouTube  (excluding their mobile applications) are actually web applications.

Because web applications serve as the interface to the internet for  many organizations, they can be exploited by attackers to gain access to devices, steal personal data, or cause service disruptions, resulting  in significant financial damage.

A study by Acunetix found that 75% of all cyber-attacks were at the web application level.

Below are some of the attack methods used to infiltrate web  applications. We will cover these methods in our Web Attacks 101 course, explaining what they are, how and why attackers use them, and how we  can detect such activity.

- SQL Injection
- Cross Site Scripting
- Command Injection
- IDOR
- RFI & LFI
- File Upload (Web Shell)

### **What skills will you have by the end of the course?**

You will gain knowledge of web vulnerabilities such as SQL Injection, Command Injection, IDOR; knowledge of why hackers use these methods,  and the skills to identify these attack methods.

**References**

[1] https://www.acunetix.com/websitesecurity/web-application-attack/

## Why Detecting Web Attacks Important

If you look at the average person's daily routine, you'll see that they  use a variety of web applications, such as Spotify to listen to music,  YouTube to watch videos, and Twitter to read tweets.

It is no surprise that attackers choose web applications as a gateway for their attacks, because all organizations have web applications,  most of which contain critical data, and because today's applications  are highly complex and have numerous attack vectors.

> “””According to Acunetix research, 75% of cyber attacks are done at the web application level, supporting this idea.“”” [1]

If we examine the anatomy of an attack, we can clearly see that the  best scenario is to prevent the attack in its first phase. This is why  there are various security measures aimed at preventing and detecting  threats against web applications (WAF, IPS, SIEM rules...).

It is essential that a SOC analyst detects and takes precautions  against these web application-based attacks that are favored by  attackers.

**Reference** 

 [1]    https://www.acunetix.com/websitesecurity/web-application-attack/

## OWASP

The Open Web Application Security Project (OWASP) is a non-profit foundation dedicated to improving software security.[1]

Without a doubt, OWASP is one of the best resources for information on web application security.

### **OWASP Top Ten**

Every few years, OWASP publishes a list of the 10 web application  vulnerabilities that pose the most critical security risks. The latest  release was in 2021 at the time of writing.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/Owasp-Top-10.png)

The 2021 OWASP list contains these critical vulnerabilities:

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery (SSRF)

You can read the OWASP publication containing the most critical security risks [here](https://owasp.org/).

**References**

[1] https://owasp.org/

### **Questions**

1 - What is the name of the tool that OWASP has prepared to help scan web applications for vulnerabilities?

> **Answer:** zap

2 - Which area does OWASP focus on? 

 A) Web Applications 
 B) Server Management 
 C) Wireless Security

> **Answer:** A

3 - What is the name of the vulnerable web application project that OWASP wrote  using Node.js for security researchers to improve themselves? 

 **Answer Format:** xxx_xxx

> **Answer:** juice_shop

4 - What does the OWASP Top 10 list, published every few years, reveal? 

A) Most critical security risks to mobile applications
B) Most critical security risks to web applications
C) Most encountered web application vulnerabilities
D) Most encountered mobile application vulnerabilities

> **Answer:** b

## How Web Applications Work

To identify an anomaly, we should first understand how the technology  works. Applications use specific protocols to communicate with each  other. In this case, web applications communicate using the Hyper-Text  Transfer Protocol (HTTP). Let's take a look at how the HTTP protocol  works.

First of all, it's important to know that the HTTP protocol is on  layer 7 of the OSI model. This means that protocols such as Ethernet,  IP, TCP, and SSL are used before the HTTP protocol.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/HTTP-Protocol-TCP-IP-Model-OSI-Model.png)

HTTP communication is between the server and the client. First, the  client requests a specific resource from the server. The server receives the HTTP request and sends an (HTTP response) back to the client after  passing the request through certain controls and processes. The client's device receives the response and displays the requested resource in an  appropriate format.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/HTTP-Request-and-HTTP-Response.png)

Let's take a closer look at HTTP requests and HTTP responses.

### **HTTP Requests**

An HTTP request is used to retrieve a specific resource from a web  server. This resource can be an HTML file, a video, JSON data, etc. The  web server's job is to process the response received and present it to  the user.

All requests must conform to a standard HTTP format so that web  servers can understand the request. If the request is sent in a  different format, the web server will not recognize it and will return  an error to the user, or the web server may not be able to provide  service (which is another type of attack).

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/HTTP-Request.png)

An HTTP request consists of a request line, request headers, and a  request message body. The request line consists of the HTTP method and  the resource requested from the web server. The request headers contain  certain headers that the server will process. The request message body  contains the data to be sent to the server.

The image above shows an example of an HTTP request. Let's examine this HTTP request line by line.

1. The GET method indicates that the resource "/" is being  requested from the server. Because there is no name, a symbol like "/"  means that the main page of the web server is being requested.
2. Nowadays there are web applications that belong to more than one domain found on a single web server, so browsers use the "Host" header to identify  which domain the requested resource belongs to.
3. When a web  application wants to store information on the client's device, it stores it in a "cookie" header. Cookies are typically used to store session  information. This saves you from having to re-enter your username and  password when you visit a web application that requires you to log in.
4. The “Upgrade-Insecure-Requests” header indicates that the client wants to communicate using encryption (SSL).
5. The “User-Agent” header contains information about the client's browser and operating system. Web servers use this information to send specific  HTTP responses to the client. You can find some automated vulnerability  scanners by looking under this header.
6. The type of data requested is in the “Accept” header.
7. The type of encoding accepted by the client is found in the  “Accept-Encoding” header. You can usually find the names of compression  algorithms under this header.
8. The “Accept-Language” header  contains the client's language information. The web server uses this  information to display the prepared content in the client's language.
9. The “Connection” header shows how the HTTP connection is made. If there is  data such as "close", it means that the TCP connection will be closed  after receiving the HTTP response. If you see "keep-alive", this means  that the connection will be maintained.
10. An empty line is inserted between the HTTP request header and the HTTP request message body to create a partition.
11. Any other data to be sent to the web application is in the Request Message  Body. If the HTTP POST method is used, then the POST parameters can be  found here.

### **HTTP Responses**

When the web server receives an HTTP request, it performs the  necessary checks and processes and then sends the requested resource to  the client. There is no standard process, as there are many technologies and designs involved. The server may pull data from the database  depending on what the requested resource is, or it may process the  incoming data. However, the HTTP Response Message must reach the client  after all the processing.

An HTTP response message contains a Status Line, Response Headers,  and a Response Body. The Status line contains the status code (e.g. 200: OK) and HTTP protocol information. Within the Response Header, some  headers are used for a variety of purposes. The Response Body contains  information about the requested resource.

If a web page has been requested, there will usually be HTML code in  the Response Body. When the client receives the HTML code, the web  browser will process the HTML code and display the web page.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/HTTP-Response.png)

You can see an HTTP response request in the image above. Let's examine an HTTP response request using this image.

**Status Line**

The Status Line contains information about the HTTP version and the  HTTP Response Status Code. The HTTP Response Status Code is used to  describe the status of the request. There are many HTTP response status  codes, but they can be summarized as follows:

●   **100-199**: Informational responses

●   **200-299**: Successful responses

●   **300-399**: Redirection messages

●   **400-499**: Client error responses

●   **500-599**: Server error responses

**Response Headers**

Here are some HTTP Response Headers that you may encounter frequently:

●   **Date**: The exact time the server sent the HTTP Response to the client.

●   **Connection**: This indicates how the connection is handled, just like the HTTP Request header.

●   **Server**: It informs about the operating system of the server and the version of the web server.

●   **Last-Modified**: It provides information about when the requested resource was modified. This header is used by the caching mechanism.

●   **Content-Type**: The type of data being sent.

●   **Content-Length**: The size of the data sent. 

**Response Body**

The HTTP response body contains the resource sent by the server and requested by the client.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/HTML-example.png)

### **Questions**

1 - What layer is HTTP on in the OSI model?

> **Answer:** application

2 - Which HTTP Request header contains browser and operating system information?

> **Answer:** user-agent

3 - What is the HTTP Response status code that indicates the request was successful?

> **Answer:** 200

4 - Which HTTP Request Method ensures that the submitted parameters do not appear in the Request URL?

> **Answer:** POST

5 - Which HTTP Request header contains session tokens?

> **Answer:** cookie

## Detecting SQL Injection Attacks

### **What is SQL Injection (SQLi)?**

SQL Injections are critical attack vectors in which a web application directly includes unsanitized user-provided data in SQL queries.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/sql-injection.png)

The frameworks we use today to develop web applications have  preventative mechanisms in place to protect against SQL Injection  attacks. However, we still come across SQL injection vulnerabilities  because sometimes raw SQL queries are used, sometimes the framework has  an inherent SQL injection vulnerability, or the framework is not used  properly.

### **Types of SQL Injections**

There are 3 types of SQL Injection. These are: 

1. **In-band SQLi (Classic SQLi)**: When an SQL query is  sent and responded to on the same channel, we call this in-band SQLi.  This is easier for attackers to exploit than other categories of SQLi.
2. **Inferential SQLi (Blind SQLi):** SQL queries that  receive a response that cannot be seen are called Inferential SQLi. They are also called "Blind SQLi" because the response cannot be seen.
3. **Out-of-band SQLi**: If the response to an SQL query  is communicated through another channel, this type of SQLi is called  "out-of-band SQLi". For example, if the attacker receives replies to the SQL queries via DNS, this is called out-of-band SQLi.

### **How Does SQL Injection Work?**

Today, most standard web applications receive data from a user and  use that data to display specific content. The login page is where most  SQL injection attacks occur. Let's look at how SQL injections work  through an example.

A user is usually expected to enter their username and password on  the login page. Then, on the other side, the web application will use  this username and password information to create an SQL query like the  one below:

> SELECT * FROM users WHERE username = '**USERNAME**’ AND password = '**USER_PASSWORD**'

The meaning of this SQL query is "Bring me all the information about the user from the user's table whose name is **USERNAME** and whose password is **USER_PASSWORD**". If the web application finds a matching user, it will authenticate the  user, if it cannot find a user after executing the query, the login will fail.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/Login-page.png)

Let's say your username is "**john**" and your password is "**supersecretpassword**". When you enter this information and click the 'Login' button, the SQL  query shown below will be queried and you will be able to log in because a match was found after the SQL query.

> SELECT * FROM users WHERE username = ‘**john**’ AND password = '**supersecretpassword**'

So what if we do not use this system as it was designed and we put an apostrophe (') in the username field? The SQL query will look like this and the error will be excluded from the database because the query was  incorrect.

> SELECT * FROM users WHERE username = ‘**john**’’ AND password = '**supersecretpassword**'

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/SQL-Injection-login-page.png)

Of course, an attacker would be pleased to get an error message, as  they can manipulate the information in the error message to their  advantage. It also shows that the attacker is on the right track. So  what if the attacker enters a payload like the following in the username section?

> ‘ OR 1=1 -- -

When the attacker submits the payload, the web application executes the following SQL query:

> SELECT * FROM users WHERE username = ‘’ OR 1=1 -- - AND password = '**supersecretpassword**'

In SQL, any characters after "-- -" are considered to be a comment  line. So if we look at the query above, the characters after "-- -" mean nothing. So, for the sake of simplicity, let's remove that part before  we examine the SQL query further.

> SELECT * FROM users WHERE username = ‘’ OR 1=1

The query above now looks like this "**if the username is empty or 1=1**". It does not matter whether the username field is empty or not, because 1 is always equal to 1. So this query will always be true and will most  likely call the first entry in the database. The attacker will be able  to successfully enter the web application because there is a match.

This is a typical SQL injection attack. Of course, SQL injection  attacks are not limited to this example, the attacker could use SQL to  execute commands in the system using SQL commands such as **xp_cmdshell**.

### **What Attackers Gain from SQL Injection Attacks**

To understand why SQL injection attacks are so important, let's take a look at what an SQL injection attack can do.

- Authentication bypass
- Command execution
- Exfiltration of sensitive data
- Creating/Deleting/Updating database entries

### **How to Prevent SQL Injections**

- **Use a framework:** Of course, just using a framework  is not enough to prevent a SQL injection attack. However, it is still  very important to use the framework according to the documentation.
- **Keep your framework up to date:** Keep your web application secure by following security updates according to the framework you use.
- **Always sanitize data received from a user:** Never trust data received from a user. In addition, sanitize all data (such as headers, URLs, etc.), not just form data.
- **Avoid the use of raw SQL queries:** You may be in the habit of writing raw SQL queries, but you should take advantage of the security provided by the framework.

### **Detecting SQL Injection Attacks**

In the previous section, we discussed what an attacker can do with a  SQL injection attack. Each of the results of a SQL Injection mentioned  above can cause great damage to an organization, so as SOC analysts we  should be able to detect these attacks and take precautions against  them.

So how do we detect SQL injection attacks?

There is more than one answer to this question:

- **When examining a web request, check all areas that come from the user:** As SQL injection attacks are not limited to the form areas, you should  also check the HTTP request headers such as the "User-Agent".
- **Look for SQL keywords:** Look for words such as "INSERT", "SELECT", and "WHERE" in the data received from users.
- **Check any special characters:** Look for apostrophes  ('), dashes (-), or parentheses used in SQL or special characters  commonly used in SQL attacks in the data received from the user.
- **Familiarise yourself with commonly used SQL injection payloads:** Although SQL payloads change depending on the web application,  attackers still use some common payloads to test for SQL injection  vulnerabilities. If you are familiar with these payloads, you can easily detect SQL injection payloads. You can find some commonly used SQL  injection payloads [here](https://github.com/payloadbox/sql-injection-payload-list).

### **Detecting Automated SQL Injection Tools**

Attackers use many automated tools to detect SQL injection  vulnerabilities. One of the well-known tools is Sqlmap. However, let's  look at the bigger picture rather than focusing on one particular tool.

You can use the following methods to detect SQL injection tools:

1. **Look at the User-Agent:** Automated tools usually have their names and versions recorded. You can look at the User-Agent to detect these automated tools.
2. **Check the frequency of requests:** Automated tools  are designed to send an estimated number of requests per second to test  payloads as quickly as possible. A normal user might send 1 request per  second, so looking at the number of requests per second will tell you if the requests are from an automated tool or not.
3. **Look at the content of the payload:** Automated tools usually include their own names in their payloads. For example, an SQL  injection payload sent by an automated tool might look like this: **sqlmap’ OR 1=1**
4. **If the payload is complicated:** This detection method may not always work, but based on my experience I  could say that automated tools send more complicated payloads.

### **A Detection Example**

We have access logs of a web application that was the victim of a SQL injection attack.

You may not know what an access log is. In a nutshell, they are the  access logs from the web server. These logs usually contain the source  IP address, date, requested URL, HTTP method, user agent, and HTTP  response code, and they are very useful for investigations.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/sql-injection-access-log.png)

**(SQL Injection Access Logs)**

We have an access log in hand. What do we do now?

First of all, if we look at the pages that were requested, we see  that besides pages like "info.php", which is quite readable, there are  also requests for pages that are complex and contain symbols like %. We  cannot say that requests for pages like this are malicious, but the fact that they are repeated many times is suspicious.

Next, let's talk about what the % symbols mean. When we request a  page that contains special characters, these requests are not sent  directly to the web server. Instead, our browsers perform a URL encoding ("Percent Encoding") of the special characters and replace each special character with a string that starts with % and contains 2 hexadecimal  characters. So the pages that contain the % symbol above are pages that  contain special characters.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/URL-Encoding.png)

Now that we understand what the % symbols mean, let's revisit the  access logs. If we look at the requests, we can easily see that there  are readable words such as "UNION", "SELECT", "AND", and "CHR" next to  the % symbols.  As these are specific words belonging to SQL, we can see that we are facing an SQL injection attack.

To protect our eyes, let's make the investigation a bit easier :) You can search with the keywords " Online URL Decoder " to find web  applications that automatically decode URLs for you. To make it easier  to read these access logs, we'll get help from these web applications,  so we don't have to strain our eyes.

**Please note this:** It is not wise to upload something like access logs, which contain critical information, to a 3rd party  web application. The access logs uploaded in this course have been  prepared specifically for educational purposes; don't make such a  mistake in your professional life.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/Access-logs-with-URL-decoding.png)

When we decode the URL, we can see more clearly that this is a SQL injection attack. So what do we do now?

We are going to find any other information we can from these access logs.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/sql-injection-access-logs-date.png)

First, let's look at the request times. All the SQL injection  payloads were sent on "19/Feb/2022 11:09:24". We can see that more than  50 requests were made in 1 second. The fact that so many requests were  made in such a short period indicates that this is an automated attack.  In addition, as we mentioned earlier when attackers do manual testing,  they choose to test simple payloads first. But when we look at the  access logs, we see that the payloads are very complicated. This shows  that the attack could be automated.

We have confirmed that an SQL injection attack was performed and that it was performed with an automated tool. So we can finish our analysis, right?

There is one more step to take. We need to determine whether or not  the attack was successful. You can determine whether a SQL injection  attack has been successful by looking at the response, but in real life, you will almost never have access to the response. We can assume that  all responses will be about the same size because the attack is on the  same page and via the "id" variable, and estimate the success of the  attack by looking at the size of the response.

Unfortunately, the simple web server developed as an example cannot  provide a reliable response size. Therefore, we cannot estimate whether  the attack was successful by looking at this example. However, for  correctly configured web servers, we can find the response size in the  access logs. You can examine this area to see if there is a noticeable  difference in response sizes. If there is a noticeable difference, then  you can assume that the attack was successful. However, in this  situation, it would be best to escalate this alert to a senior analyst.

**So far we have covered that:**

1. There has been an SQL injection attack on the 'id' parameter on the main page of the web application.
2. The requests came from IP address 192.168.31.174.
3. As there were more than 50 requests per second, this attack was carried out by an automated vulnerability scanning tool.
4. The complex nature of the payloads supports the assertion in #3.
5. We cannot determine if the response was successful or not as we have no informat

### **Questions**

**Note:** Use the "/root/Desktop/QuestionFiles/SQL_Injection_Web_Attacks.rar" file for solving the questions below.

 **File Password:** access 

1 - What date did the exploitation phase of SQL Injection Attack start? 

 **Answer Format:** 01/Jan/2022:12:00:00

> **Answer:** 01/Mar/2022:08:35:14

2 - What is the IP address of the attacker who performed the SQL Injection attack?

> **Answer:** 192.168.31.167

3 - Was the SQL Injection attack successful? (Answer Format: Y/N)

> **Answer:** Y

4 - What is the type of SQL Injection attack? (Classic, Blind, Out-of-band)

> **Answer:** Classic

## Detecting Cross Site Scripting (XSS) Attacks

### **What is Cross-Site Scripting (XSS)?**

Cross-site scripting (XSS) is a type of injection-based web security  vulnerability that can be incorporated into legitimate web applications, allowing malicious code to be executed.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/xss.png)

Today, most frameworks used to develop web applications have taken  preventative measures against cross-site scripting attacks. However, we  still see XSS vulnerabilities today because frameworks are sometimes not used, or the framework itself has an XSS vulnerability and the data  coming from the user is not sanitized.

### **Types of XSS**

There are 3 types of XSS. These are:

1. **Reflected XSS (Non-Persistent)**: This is a non-persistent type of XSS where the XSS payload must be present in the request. It is the most common type of XSS.
2. 
3. **Stored XSS (Persistent)**: This type of XSS is where  the attacker can permanently upload the XSS payload to the web  application. Compared to other types, Stored XSS is the most dangerous  type of XSS.
4. 
5. **DOM Based XSS**: DOM Based XSS is an XSS attack where the attack payload is executed as a result of modifying the DOM  "environment" in the victim's browser used by the original client-side  script so that the client-side code runs in an "unexpected" manner.  (OWASP)

### **How does XSS work?**

Like other web attack methods, XSS is a vulnerability that is caused  by a lack of data sanitization. It occurs when the data received from  the user is sent in the response without being sanitized.

Let's look at an example to understand XSS attacks better.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/XSS-vulnerable-code.png)

First, we'll examine the piece of code above. What it does is  actually quite simple. It simply displays whatever is entered in the  'user' parameter. If we enter "LetsDefend" as the 'user' parameter, we  will see the words "Hello LetsDefend".

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/XSS-image-1.png)

So far there is no problem. If we enter the appropriate data in the  user parameter, we are greeted with a warm welcome. But, as we have  already seen, there is no control mechanism for the user parameter. This means that whatever we put in the "user" parameter will be included in  the HTTP response we receive back.

So what would happen if we didn't enter a normal value, but instead a payload that would trigger a popup?

Payload: **<script>alert(1)</script>**

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/XSS-popup.png)

Because whatever is put in the 'user' parameter is included directly  in the HTTP response, the javascript code we wrote worked and a pop-up  window appeared on the screen.

This is exactly how XSS works. Because the value entered by the user  is not validated, the attacker can enter any javascript code and get the result they want. Another question is, what if the attacker wants to  redirect the user to a malicious site?

Payload: **<script>window.location=’https://google.com’</script>**

https://letsdefend.io/xss_example.php?user=%3Cscript%3Ewindow.location=%27https://google.com%27%3C/script%3E

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/XSS-google-redirect-1.png)

Of course we are not going to direct you to a web application.  Directing you to Google will be sufficient as an example. When the user  clicks on the URL he will be directed to Google instead of the perfect  LetsDefend web application. 

![img](https://app-ld-img.s3.us-east-2.amazonaws.com/training/img60-google.png)

### **How Attackers Take Advantage of XSS Attacks**

Because XSS is a client-based attack method, it may seem less  important than other attack methods, but XSS attacks and their impact  should not be taken for granted.

Attackers can do the following with an XSS attack:

- Steal a user’s session information
- Capture credentials
- Etc.

### **How to Prevent a XSS Vulnerability**

- **Sanitize data coming from a user:** Never trust data  that you receive from a user. If user data needs to be processed and  stored, it should first be encoded with "HTML Encoding" using special  characters, only then can it be stored.
- **Use a framework:** Most frameworks come with preventative measures against XSS attacks.
- **Use the framework correctly:** Almost all frameworks  used to develop web applications come with a sanitation feature, but if  this is not used properly, there is still a chance for XSS  vulnerabilities to occur.
- **Keep your framework up-to-date:** Frameworks are  developed by humans, so they too can contain XSS vulnerabilities.  However, these types of vulnerabilities are usually patched with  security updates. You should therefore make sure that you have completed the security updates for your framework on a regular basis.

### **Detecting XSS Attacks**

As we mentioned in the previous lesson, according to a study by  Acunetix, 75% of cyber-attacks are conducted through web applications.  As XSS is one of the most commonly tested vulnerabilities, you will  encounter it throughout your career as a SOC analyst.

- **Look for keywords:** The easiest way to detect XSS  attacks is to look for keywords such as "alert" and "script" that are  commonly used in XSS payloads.
- **Learn about commonly used XSS payloads:** Attackers  tend to use the same payloads to look for vulnerabilities before  exploiting an XSS vulnerability. Therefore, familiarizing yourself with  commonly used XSS payloads would make it easier for you to detect XSS  vulnerabilities. You can examine some commonly used payloads [here](https://github.com/payloadbox/xss-payload-list).
- **Check for the use of special characters:** Check data coming from a user to see if any special characters commonly used in  XSS payloads, such as greater than (>) or less than (<), are  present.

### **An Example of Detection**

In this example, we have access logs from an Apache server running  WordPress. Don't forget to revisit our lesson "Detecting SQL injection  attacks" for more information about access logs.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/XSS-apache-access-log.png)

Let's examine the access logs provided.

First, let's take a general look at the requests that were made and  try to understand them. We can see that all the requests were made for  the "/blog/" page and that only the "s" parameter values were changed.  If you pay attention to the URLs of the websites you visit, you probably have noticed before that when you perform a search in WordPress, the  words you enter are sent with the "?s=" parameter. The example we are  looking at shows us that these are searches carried out in WordPress.

It is difficult to find examples that are easy to read, such as the  example in the lesson " Detecting SQL Injection Attacks ". Instead, we  usually come across characters that have been converted to %XX as a  result of URL encoding. We'll do URL decoding next, but first, let's  look at the URLs and see if we can spot any words.

Looking at the logs, there are javascript-related words such as  "script", "prompt" and "console.log". The word javascript immediately  brings XSS to mind. If we decode the URL, we can easily understand the  requests being made.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/xss-apache-access-log-with-url-decoding.png)

Let's take another look at the access logs after decoding the URLs.  We can clearly see the XSS payloads and definitely conclude that the  WordPress application from which we received these access logs has been  the victim of an XSS attack.

When we examine the requested IP addresses, we find that there is  more than one. Is there more than one attacker trying to perform an XSS  attack at the same time? Or is the attacker constantly changing their IP address to avoid being blocked by security products such as firewalls  and IPS? If you check the IP address, you will see that it belongs to  Cloudflare. Since WordPress has a partnership with Cloudflare, it is  quite normal that Cloudflare would be the source of the request.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/xss-apache-access-log-date.png)

Now, if we look at the dates of the requests, we see that a request  was made every 3-4 seconds. It is not really possible for a human to try to enter that many XSS payloads in such a short time, but it still  doesn't mean you can be sure that the number of requests made per second is excessive. Because we have the user-agent information in this  example, our job is easier. Once we check the information, we see that  it belongs to a urllib library. This indicates that these requests were  made by an automated vulnerability scanner tool.

So was the attack successful? 

Without access to the responses, we cannot be sure.

**As a result of our investigations:**

1. It is clear that the attack was aimed at the web application where the access logs came from.
2. Looking at the number of requests and the user agent information, we determined that the attack was carried out by an automated  vulnerability scanner.
3. As the application is hosted behind Cloudflare, the source IP addresses were not found.
4. We do not know if the attack was successful or not.

### **Questions**

**Note:** Use the "/root/Desktop/QuestionFiles/XSS_Web_Attacks.rar" file for solving the questions below.

 **File Password:** access 

1 - What is the start date of the XSS attack?

 **Answer Format:** 01/Jan/2022:12:00:00

> **Answer:** 01/Mar/2022:08:53:20

2 - What is the IP address of the attacker who performed the XSS attack?

> **Answer:** 192.168.31.183

3 - Was the XSS attack successful?

> **Answer:** Y

4 - What is the type of XSS attack? (Reflected, Stored, Dom based)

> **Answer:** Reflected

## Detecting Command Injection Attacks

### **What are Command Injection Attacks?**

Command injection attacks are attacks that occur when data received  from a user is not sanitized and is passed directly to the operating  system shell.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/command-injection.png)

Attackers exploit command injection vulnerabilities to execute  commands directly on the operating system. Since the attacker's priority is to take control of the system, these vulnerabilities are more  critical than other vulnerabilities.

A misconfigured web application would grant the attacker access with  admin rights because the command the attacker sends uses the rights of  the web application user.

### **How does Command Injection work?**

Command injection vulnerabilities occur when the data received from  the user is not sanitized. Let's examine command injection  vulnerabilities with an example.

Suppose we have a basic web application that copies the user's file  to the "/tmp" folder. The web application code is shown below:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/web-application-code-example.png)

Under normal circumstances, if used correctly, the application will  work normally. For example, if we upload a file called "letsdefend.txt", it will successfully copy the file to the "/tmp" folder.

So what if we upload a file called "letsdefend;ls;.txt"? The command would be:

Command: **cp letsdefend;ls;.txt**

The ";" indicates that the command has ended. So if we look at the  payload above, there are three different commands that the operating  system executes. These are:

1. cp letsdefend
2. ls
3. .txt

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/command-injection-example.png)

The first command is for the copying process, but if the parameters are not entered correctly it will not work correctly.

Command #2 is the directory listing command that the attacker wants  to execute. The user does not receive the command output, so the  attacker cannot see the files in the directory, but the operating system successfully executes the command.

If the operating system tries to run command number 3, it will get an error message because there is no ".txt" command.

As you can see, the code has been executed in the web server's  operating system. So what if the attacker were to upload a file called  "letsdefend;shutdown;.txt"? The operating system would shut down and the web application would not be able to function.

With the correct payload, the attacker can create a reverse shell in the operating system.

### **How attackers can exploit Command Injection Attacks**

Attackers can execute commands on an operating system by exploiting  command injection vulnerabilities. This means that the web application  and all other components on the server are at risk.

### **How to Prevent Command Injection**

- **Always sanitize data you receive from a user:** Never trust anything you receive from a user. Not even a file name!
- **Limit user privileges:** Whenever possible, set web  application user rights at a lower level. Few web applications require  users to have administrator rights. 
- **Use virtualization technologies such as dockers.**

### **Detecting Command Injection Attacks**

I think we all understand the criticality of the command injection  vulnerability. If such a critical vulnerability is exploited and goes  undetected, the targeted company can lose a great deal of money and  reputation.

So how do we detect command injection attacks?

Actually, there is more than one way. These are: 

- **When examining a web request, look at all areas:** The command injection vulnerability may be in different areas depending on  how the web application works. Therefore, you should check all areas of  the web request.
- **Look for keywords related to the terminal language:** Check the data received from the user for keywords related to terminal commands such as dir, ls, cp, cat, type, etc.
- **Learn about commonly used command injection payloads:** When attackers discover a command injection vulnerability, they usually  create a reverse shell to make their work easier. Therefore, knowing  commonly used command injection payloads will make it easier to detect a command injection attack.

### **A Detection Example**

In this example, we will not be looking at access logs, but instead at an HTTP request.

> GET / HTTP/1.1
>
> Host: yourcompany.com
>
> User-Agent: () { :;}; echo "NS:" $(</etc/passwd)
>
> Accept:  text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
>
> Accept-Encoding: gzip, deflate
>
> Accept-Language: en-US,en;q=0.9
>
> Connection: close

Looking at the HTTP request above, we can see that the main page of the web application yourcompany[.]com was requested.

But if we look at the HTTP request headers, we see a suspicious  situation in the User-Agent header. There is a bash command in the  User-Agent header where there should be browser/operating system  information.

In fact, this request was captured while a security vulnerability  called Shellshock was being exploited. Shellshock is a security  vulnerability that was disclosed in 2014 and had a major impact.

Shellshock comes from bash somehow executing environment variables  unintentionally. It is a great example of a command injection attack.

The contents of the file "/etc/passwd" are returned to the attacker  as "NS" in the HTTP response header when the bash command, which is in  the user agent, is executed.

### **Questions**

**Note:** Use the "/root/Desktop/QuestionFiles/Command_Injection_Web_Attacks.rar" file for solving the questions below.

 **File Password:** access 

1 - What is the date the command injection attack was initiated?

 **Answer Format:** 01/Jan/2022:12:00:00

> **Answer:** 01/Mar/2022:09:03:33

2 - What is the IP address of the attacker who performed the Command Injection attack?

> **Answer:** 192.168.31.156

3 - Was the Command Injection attack successful? 

> **Answer:** N

## Detecting Insecure Direct Object Reference (IDOR) Attacks

### **What is IDOR?**

**I**nsecure **D**irect **O**bject **R**eference (IDOR) is a vulnerability caused by the absence or improper use of an  authorization mechanism. It allows one person to access an object that  belongs to another.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/idor.png)

IDOR, or "Broken Access Control", is the number one web application vulnerability listed in the 2021 OWASP.

### **How IDOR Works**

IDOR is not a vulnerability caused by poor sanitation like other web  application-based vulnerabilities. The attacker manipulates the  parameters sent to the web application, gains access to an object that  doesn't belong to him, and is then able to read, modify, or delete the  contents.

Here’s an example to better understand how the IDOR vulnerability is exploited.

Imagine a simple web application. It retrieves the “**id”** variable from the user and then displays data that belongs to the user who made the request.

URL: **https://letsdefend.io/get_user_information?id=1**

When a request like the one above is made in our web application, it displays the information of the user with an id value of 1.

If I am the user who made the request and my ID value is 1,  everything will work normally. When I make the request, I see my  personal information.

But what happens if we make a request with 2 as the “id” parameter? Or 3?

If the web application does not check that the "id" value in the  request belongs to the person making the request, then anyone can make  that request and see the user's information. This web vulnerability is  called IDOR.

Attackers can access items that do not belong to them by changing  parameters such as the "id". The type of information they can access may vary depending on the web application, but either way, you wouldn't  want anyone to access your personal information, so this is very  critical.

### **How Attackers Take Advantage of IDOR Attacks**

What an attacker can do is limited by the scope of an IDOR  vulnerability. However, the most common areas are usually pages where a  user's information is received. If an attacker were to exploit an IDOR  vulnerability, they could:

- Steal personal information
- Access unauthorized documents 
- Take unauthorized actions (such as deleting, modifying)

### How to Prevent IDOR

Always check that the person making the request is authorized to provide a secure environment without an IDOR vulnerability.

In addition, unnecessary parameters should be removed and only the  minimum number of parameters should be taken from the user. If we think  about the previous example, we don't need to get the "id" parameter.  Instead of getting the "id" parameter from the user, we can use the  session information to identify the person who made the request.

### **Detecting IDOR Attacks**

IDOR attacks are harder to detect than other attacks. This is because it does not have certain payloads such as SQL injection and XSS.

HTTP responses would help identify IDOR attacks. However, HTTP  responses are not logged for several reasons. This makes it more  difficult to identify IDOR attacks.

A number of methods can be used to identify IDOR attacks. These are:

- **Check all parameters:** An IDOR vulnerability can occur in any parameter. Therefore, do not forget to check all parameters.
- **Look at the number of requests made to the same page:** When attackers discover an IDOR vulnerability, they usually want to access  the information of all the other users, so they typically perform a  brute-force attack. This is why you may see many requests for the same  page from one source.
- **Try to find a pattern:** Attackers will plan a  brute-force attack to reach all objects. Since they will be performing  the attack on successive and predictable values, such as whole numbers,  you can try to find a pattern in the requests you see. For example, if  you see requests like id=1, id=2, id=3, you might be suspicious.

### **A Detection Example**

Below is a screenshot of logs found on a web server running WordPress.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/idor-apache-access-log.png)

As with our other examples, let's start with a general, broad search. As there are no special characters in the requests made, we can easily  read the logs.

If you have used Wordpress before, you may know that the  "wp-admin/user-edit.php?user_id=" page contains information about  registered Wordpress users. It might seem normal to be able to access  this page, in fact, if you have more than one registered user you might  be able to access it with more than one "user_id:" parameter. But it is  abnormal to have so many different "user_id" parameters.

It looks like we have an IDOR attack on our hands.

When we look at the source IP, we see that it belongs to Cloudflare.  This means that the web application for which we have got the access log was using a service provided by Cloudflare. So the requests were being  sent to the web application through Cloudflare.

The fact that the access logs record 15-16 requests within the short  time frame shows us that the attack is being carried out with an  automated device. If we look at the User-Agent header, we can see that  it says "wfuzz/3.1.0". Wfuzz is a tool that is often used by attackers.  So not only have we established that this attack was carried out by an  automated scanning tool, but we have also established that it was  carried out by a tool called Wfuzz.

But we still haven't answered the most important question. Was the attack successful?

Did the attacker gain access to the users' information?

Our job would be easier if we had the HTTP responses. But since we  don't have the HTTP responses, let's look at the response size in the  access logs and make an inference.

As we mentioned earlier, the requested page displayed user  information. Information such as user names, surnames, and the total  size of the user names will not be the same. Therefore, we can ignore  requests with a response size of 479 bytes.

Looking at the requests with response sizes 5691 and 5692, we can see that the response code is 302 (redirect). Successful web requests are  usually returned with a response code of 200. So we can assume that the  attack was unsuccessful. However, this information alone may not be  enough to determine that the attack was definitely unsuccessful.

There are 10 requests with the response size of 5692 and 4 with the response size of 5691.

As we mentioned before, there is a very small chance that the sum of  all information such as user name, surname, and username will be the  exact same. This increases the likelihood that the attack was not  successful.

### **Questions**

**Note:** Use the "/root/Desktop/QuestionFiles/IDOR_Web_Attacks.rar" file for solving the questions below.

 **File Password:** access 

1 - What is the date when the attack started?

 **Answer Format:** 01/Jan/2022:12:00:00

> **Answer:** 01/Mar/2022:11:42:32

2 - What is the IP address of the attacker who carried out the IDOR attack?

> **Answer:** 192.168.31.174

3 - Was the attack successful?

> **Answer:** Y

4 - Was the attack carried out by an automated tool?

> **Answer:** N

## Detecting RFI & LFI Attacks

### **What is Local File Inclusion (LFI)?**

Local File Inclusion (LFI), is the security vulnerability that occurs when a file is included without sanitizing the data obtained from a  user. It differs from RFI because the file that is intended to be  included is on the same web server that the web application is hosted  on.

Attackers can read sensitive files on the web server, they can see  the files containing passwords that would allow them to access the  server remotely.

### **What is Remote File Inclusion (RFI)?**

Remote File Inclusion (RFI) is a vulnerability that occurs when a  file is included without sanitizing the data received from a user. It  differs from LFI because the included file is hosted on another server.

Attackers lure victims through websites on remote servers and trick  them into running malicious code on the servers they have prepared.

### **How does LFI & RFI work?**

Like most web application-based vulnerabilities, LFI and RFI have  vulnerabilities caused by the failure to sanitize data received from a  user.

So far we have learned that SQL injection vulnerabilities occur when  data received from a user is entered into SQL queries; Command Injection vulnerabilities occur when data received from a user is executed  directly in the system shell; IDOR vulnerabilities occur when data  received from a user is used to directly access objects. RFI and LFI  vulnerabilities arise when data received from a user is used directly in the system or to include a file on a remote server.

How could data received from a user be exploited to include a file?  Web applications have become very complex over time and unfortunately,  any feature that is developed can be used for malicious purposes. For  example, the language setting in web applications is used to include  files based on data received from a user.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Detecting+Web+Attacks/images/local-file-inclusion-code-example.png)

If we examine the piece of code in the image above, we can see that  the desired website language is selected using the 'language' parameter  received from the user.

In a normal situation, the web application will work as intended. For example, if "en" is entered as the "language" parameter, we will  receive the file shown below.

“website/**en**/home.php”

However, if an attacker enters the payload below in the "language"  parameter, the web application will unfortunately display the  "/etc/passwd" file to the user.

Payload: **/../../../../../../../../../etc/passwd%00**

“website/**/../../../../../../../../../etc/passwd%00**/home.php

"../" is used to go to the parent directory. Since the attacker does  not know what directory the web application is in, he tries to use "../" to access the "root" directory. Later he names the file "/etc/passwd"  and allows it to be included in the web application. The end of the  string will be "%0". This way, the rest of the "/home.php" string will  not be read by the web application.

### **How Attackers Use RFI & LFI?**

- Executing code
- Disclosure of sensitive information
- Denial of Service

### **How to Prevent LFI & RFI?**

The most effective way to prevent RFI and LFI attacks is to make sure that all data received from a user is sanitized before it is used.  Remember that client-based controls are easily bypassed. Therefore, you  should always implement your controls on both the client and server  sides.

### **Detecting LFI & RFI Attacks**

We have already mentioned what attackers can achieve with RFI and LFI attacks. Since an organization can lose a lot of money if these  vulnerabilities are exploited, we should be able to detect these attacks and take the necessary precautions.

How can we detect and prevent LFI and RFI attacks?

- **When examining a web request from a user, examine all fields.**
- **Look for any special characters:** Within the data received from users, look for notations such as '/', `.`, `\`.
- **Become familiar with files commonly used in LFI attacks:** In an LFI attack, the attacker reads the files on the server. Knowing the  critical file names on the server will help you detect LFI attacks.
- **Look for acronyms such as HTTP and HTTPS:** In RFI attacks, the attacker injects the file into their own device and allows the file to run.
- To host a file, attackers usually set up a small web server on their own  device and display the file using an HTTP protocol. You should therefore look for notations such as 'http' and 'https' to help you detect RFI  attacks.

### **Questions**

**Note:** Use the "/root/Desktop/QuestionFiles/File_Inclusion_Web_Attacks.rar" file for solving the questions below.

 **File Password:** access 

1 - What is the start date of the attack?

 **Answer Format:** 01/Jan/2022:12:00:00

> **Answer:** 01/Mar/2022:11:58:35

2 - What is the attacker's IP address?

> **Answer:** 192.168.31.174

3 - Was the attack successful?

> **Answer:** N