# Python for Blue Team

The  "Python for Blue Team" course focuses on equipping cybersecurity  professionals within the Blue Team with practical Python skills tailored for effective threat detection and strategic defense methodologies.

**Table of Contents:**

- [Web Scraping with Python]()
- [Web Scraping Lab]()
- [Python and Socket Programming]()
- [Port Scanner Application]()
- [IDS Application with Python]()
- [FIM Application with Python]()
- [Forensic and Incident Response with Python]()

Evaluate Yourself with Quiz

- [Python for Blue Team](https://app.letsdefend.io/training/quiz/python-for-blue-team)

## Web Scraping with Python

### What is Web Scraping and Why Should We Know?

Web scraping is the  process of parsing the HTML content of a website and extracting data  from that content. Web scraping is usually done using automated software or scripts. These scripts typically do the same thing a web browser  might do: open a website, find certain information, and collect or store that information in the most effective way.

Web scraping is very  useful and widely used in many scenarios. Its use in the security  perspective is already our topic, but it would be eye-opening to give  examples of other issues where it can be useful:

**Data Science and Machine Learning**

Most machine learning  models need data, and web scraping can be used to collect this data. For example, a person may need to analyze the sentiment of social media  comments and use web scraping to collect these comments.

**Market Research**

Companies and individual  researchers can use web scraping to gather information about online  product prices, product features, consumer reviews, and more. This can  be used to track trends, look at competitor prices, or perform market  analysis.

**Web Content Scraping**

A person or company may  use web scraping to gather information about a particular topic. For  example, a person can collect all recipes and put them together in a  single database.

**Data Integration**

Web scraping can also be  used to collect data from different sites and combine it in one place.  This can be used to create a news portal or a price comparison site that provides information from different sources.

**Warning:**   Before continuing with  the topic, it is important to remember that Web Scraping applications  may cause legal responsibilities. For example, a website's terms of use  may prohibit scraping on that site. Additionally, the use of collected  data may also be subject to various data protection and privacy laws.  Therefore, when starting a web scraping project, it is important to  consider these aspects.

Python is an ideal tool  for web scraping with its extensive library support and ease of use. In  this part of the training, we will cover the basic concepts of web  scraping with Python and look at some examples that security  professionals can use in their daily work.

### Tools for Python Web Scraping

There are many libraries for web scraping in Python such as “Beautiful Soup”, “Scrapy” and “Requests”.

**Beautiful Soup**

It is a Python library used for web scraping. It is used to parse HTML and XML files.

In fact, “Beautiful Soup” is not a scraper on its own, but a  parsing library. Its main power is HTML, XML, etc. It can parse many  formats automatically and does not compromise on performance. It needs a library like “requests”, etc. to work. 

Although it is a very powerful tool, it is not preferred in very large projects.

**Scrapy**

It is a more powerful and feature-packed web scraping library  than Beautiful Soup. It has various features such as parsing, processing requests, and storing data.

This tool does everything Beautiful Soup does, plus includes its own request libraries. Although it is a bit complicated to learn, it  offers highly advanced support in large and complex projects, from  optimization of requests to user-agent manipulations, from data storage  automation to middleware integrations.

**Requests**

It is used to send HTTP requests in Python. This library is used to retrieve the content of a web page. There is no parser mechanism in  itself. Although it is quite sufficient in cases where the raw response  meets your needs, it can be quite tiring as you will be left with string functions to perform complex operations on the returned response.

Python is a wide world to which many developers contribute, and  therefore, apart from the ones we have mentioned, there are dozens of  different libraries/frameworks, etc. available that are specialized for  various purposes. Although we cannot explain all of them here, we  recommend that you investigate these options when you have a web  scraping project.

### Beautiful Soup

Let's start by making a sample of Beautiful Soup together. Let our code be like this:

```python
import requests from bs4 
import BeautifulSoup 
URL = "https://letsdefend.io" 
page = requests.get(URL) 
soup = BeautifulSoup(page.content, "html.parser") 
results = soup.find("meta", {"name":"description"}) 

print(results)

                  
```

When we run it, it is very likely that you will get an output like this:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/1/py17.png)

The message here says that the “bs4” library is not yet  installed on our system, so we cannot use BeatifulSoup. What we need to  do is simple:

```sh
pip3 install bs4

                  
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/1/py18.png)

When we wanted to install the bs4 library with pip3 in our  Ubuntu 20.4 environment, we received a notification saying that pip3 was not installed yet. Fortunately, there is a notification right below  telling us what to do. We immediately ran the "  **sudo apt install python3-pip**  "    command, and then we installed the   **bs4**   library on our system with the "  **pip3 install bs4**  " command:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/1/py19.png)

In the later parts of the course, the missing libraries in your  system will appear again, in this case, you will need to proceed by  installing the missing libraries with pip3, just like we have done here. Now we can get back to work. We think our script will now work:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/1/py20.png)

Now let's examine what we did line by line:

```python
import requests from bs4 
import BeautifulSoup 

                  
```

In these two lines, the modules required for the operation of  the code are included. The "requests" module allows communicating with  web servers using the HTTP protocol. "BeautifulSoup" is used to parse  HTML and XML documents.

In the next line, we assign the URL of the target website to a variable.

```python
URL = "https://letsdefend.io" 

                  
```

In the next line, an HTTP GET request is sent to the specified  URL using the "requests.get()" method. The response to this request is  thrown into a variable called "page".

```python
page = requests.get(URL)

                  
```

In the next line, we create an instance of the BeautifulSoup  class. We use BeautifulSoup to parse the content of the retrieved web  page. We obtain the content with "page.content" and parse it in HTML  format with "html.parser".

```python
soup = BeautifulSoup(page.content, "html.parser") 

                  
```

In the next line, using the "find" method of the BeautifulSoup  library, we look for the "meta" tag and the element whose "name"  property is "description" in the HTML document. We assign the first  match found to the "results" variable.

```python
results = soup.find("meta", {"name":"description"}) 

                  
```

And finally, we print the result to the screen:

```python
print(results)

                  
```

### Scrapy

Now let's take a look at how things work with Scrapy:

We first need to create a project with Scrapy. We created our project by naming it “letsdefend_scraper”:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/1/py21.png)

When we ran this command, scrapy created a project directory for us and automatically placed the  directories it needed to run in the project directory:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/1/py22.png)

Now all we need to do is to write the code for our purpose and save it in the   **spiders**   directory in the project directory.

Let's continue by saving the following code in the   **spiders**   directory under the name "  **description_spider.py**  ":

```python
import scrapy

class DescriptionSpider(scrapy.Spider):
    name = 'description'
    start_urls = ['https://letsdefend.io']

    def start_requests(self):
        for url in self.start_urls:
            yield scrapy.Request(url, callback=self.parse_description)

    def parse_description(self, response):
        description = response.xpath('//meta[@name="description"]/@content').get()
        print("Description:", description)

                  
```

When we run the command, “  **scrapy crawl description**  ”    at the   **“letsdefend_scraper”**   directory we will get an output like the following (we have  highlighted the part we are looking for with a gray background for you):

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/1/py23.png)

The output looks very complicated, right? Our suggestion to you  is to examine and understand the working logic of Scrapy on each line in this output. Then, all you have to do is to add the    “  **–nolog**  ” parameter    to the end of your command to see the cleaner output you requested:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/1/py24.png)

### Requests

We already used requests above, with   **page = requests.get(URL)**   in Line 4 of our  BeatifulSoup example. Then we processed the response by giving it to  BeatifulSoup's HTML parser. We don't actually need this for simple tasks that don't require Performance and Optimization. We can parse the data  we are looking for by using Python's built-in string functions within  the content we receive with Python requests.

Let's look at an example:

```python
import scrapy 
class DescriptionSpider(scrapy.Spider): 
    name = 'description' 
    start_urls = ['https://letsdefend.io'] 

def start_requests(self): 
    for url in self.start_urls: 
    yield scrapy.Request(url, callback=self.parse_description) 

def parse_description(self, response): 
    description = response.xpath('//meta[@name="description"]/@content').get()
    print("Description: ", description)

                  
```

When we save and run the above code as “request.py”, we get the following output:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/1/py25.png)

In this part of the  training, we have covered what web scraping is, important items to know  about web scraping and some tools and usage examples that can be used  for web scraping in Python. In the next part of the training, we will be learning about the “  **Web Scraping Lab with Python**  ” topic.

### Question

1 - In the Python script  "/root/Desktop/QuestionFiles/python7.py" on the Linux lab machine you  accessed, which method is used for HTTP requests?

> **Answer:** GET

## Web Scraping Lab

Let's try to put what we learned in the previous lesson into use.

You can see the bad IP list screenshot from   https://www.projecthoneypot.org/list_of_ips.php  . We parsed the IP  addresses in this table from this site and saved them in a text file to  be able to make searches on them in our web access logs in the upcoming  lessons.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/2/py26.png)

First, we need to determine which data we will parse with  BeatifulSoup. For this, the shortest way is to use the inspection  feature of our web browser:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/2/py27.png)

When we examine the  source code, we see that the data we need is in the first column of an  HTML table. Let's write the code to read this data:

```python
import requests
from bs4 import BeautifulSoup

URL = "https://www.projecthoneypot.org/list_of_ips.php" 
html_content = requests.get(URL)
soup = BeautifulSoup(html_content, 'html.parser')

ip_addresses = [] 
for row in soup.select('table.manmx tr')[1:]:
    ip_cell = row.select_one('td a.bnone') 
    if ip_cell:
        ip_addresses.append(ip_cell.text.strip())

for ip in ip_addresses: 
    print(ip)

                  
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/2/py28.png)

Let's examine our code line by line. First, as always, we start by importing the libraries we will need:

```python
import requests
from bs4 import BeautifulSoup

                  
```

In the next step, we assign the address from which we will retrieve data to a variable and then give this variable as a   **parameter**   to the   **get**   method of the   **requests**   library:

```python
URL = "https://www.projecthoneypot.org/list_of_ips.php" 
html_content = requests.get(URL)

                    
```

We could have also  combined these two lines into one as follows, but we didn't because we  might have to retype the URL over and over again if we needed to reuse  it for any reason later in the code:

```python
html_content = requests.get("https://www.projecthoneypot.org/list_of_ips.php")

                  
```

We assign the output that we imported in the   **“html_content”**   as a   **parameter**   to the “  **BeautifulSoup”**   object that we initialized with the “  **soup**  ” variable, and in the second parameter, we specify that we want   **html_parser t**  o be used    as the   **parser**  .

```python
soup = BeautifulSoup(html_content, 'html.parser')

                  
```

Now, we are ready to read the data, but first, we need a space  to store the data we read. At this stage, we create an empty Python list object named   **ip_addresses**   to add the IP addresses we found:

```python
ip_addresses = []

                  
```

Now, it's time to start reading the data. First, we want  BeatifulSoup to find the rows of the tables assigned the “manmx” class.  Since the first line contains the header information, we tell it to skip the first line with   **[1:]**   which will take everything after line 1.

```python
for row in soup.select('table.manmx tr')[1:]:

                  
```

When we examined the source code, we saw that the IP Information we needed was in the "  **a**  " tag    assigned to the “  **bnone**  ” class. Now we are looking for:

```python
ip_cell = row.select_one('td a.bnone')

                  
```

Then, before we continue, we do a simple check to make sure we found what we're looking for:

```python
if ip_cell:

                  
```

If our code has come this far without any problems, it means that the IP information we need is  right in front of us. It is a great idea to take this IP address and add it to the "ip_addresses" list we created before:

```python
ip_addresses.append(ip_cell.text.strip())

                  
```

While doing this, you can use the   **.strip()**   method, formatting at the beginning or end of the IP address, etc. We also do not forget to  remove whitespace characters placed for certain purposes, so that they  do not cause us issues when using this list in the future.

Now we have a list of IP  addresses. We can print this list to the screen, save it to a text file, or print it to a database. In our example code, we printed the list on  the screen and used the following code to do this:

```python
for ip in ip_addresses: 
    print(ip)

                  
```

If we wanted to print the output to the “iplist.txt” file instead of printing it to the screen,  we would simply change the above part of our code as follows:

```python
with open('iplist.txt', 'w') as file: 
    for ip in ip_addresses: 
        file.write(ip + '\n')

                  
```

We could even do this to print both to the screen and to the file:

```python
with open('iplist.txt', 'w') as file: 
    for ip in ip_addresses: 
        print(ip)
        file.write(ip + '\n')

                  
```

As you can see in this  lab, Python offers very powerful tools for web scraping, but this alone  is not enough. We also have HTML, XML, LXML, etc. Being familiar with  the formats and knowing them even at a basic level is a must for  effective web scraping. Fortunately, LetsDefend has great courses where  you can find answers to all of these.

In this part of the  training, we have covered a lab study that will be an example of web  scraping with Python. In the next part of the training, we will be  learning about the “  **Python and Socket Programming**  ” topic.

### Question

1 - In the  "/root/Desktop/QuestionFiles/python8.py" Python script on the Linux lab  machine you accessed, there is no library that is required for the code  to run. What is this library?

> **Answer:** requests

2 - The Python script  "/root/Desktop/QuestionFiles/python9.py" on the Linux lab machine you  accessed is not running due to an error. Which is this error according  to the numbered comment lines?

> **Answer:** 3

3 - What is the name of the  Python library that calculates the sha256 hash according to the Python  script "python9.py"? (/root/Desktop/QuestionFiles/python9.py)

> **Answer:** hashlib

## Python and Socket Programming

In this lesson and other  upcoming lessons, we will go over how a security professional can make  things easier with Python. But first, learning the capabilities of  Python will help us understand how we can leverage it effectively from a security perspective.

Since Python is a modern  language, it has very advanced capabilities that can provide answers to  almost all the needs of today’s security world. Let's start by looking  at its networking skills.

Since you are taking this course, we assume you know the Basics of Networking. Let's make an  introduction to the socket/port concepts, which we think you have heard  about frequently, using Python.

Python offers very  simplified and powerful libraries and features in this regard, as in  almost every subject. In this way, it allows you to easily perform  socket operations from the simplest to the most complex.

Creating a network socket with Python is as easy as this:

```python
import socket
socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                  
```

But in order for this  socket to become functional, we need to add a few more features to it,  such as which interface and port it will work on:

```python
import socket
HOST, PORT = '127.0.0.1', 65432
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: 
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()

                  
```

First, we created a  socket object. Then, we connected this socket to the 65432/TCP port of  the loopback interface and started listening. In the output below, you  can see that after running our code (in a different terminal window  while our code continues to run), we start listening on   **TCP**   Port   **65432**   in   **the netstat output**  :

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/3/py29.png)

We mentioned that we created an IPv4 socket with   **socket.AF_INET**  , which we used when  creating our socket. You can see the general types we can use other than IPv4 in the list below. Please keep in mind that not all of these types may be supported due to reasons such as the Python version you are  using or the version of the socket library you are using in Python.

  

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/3/stable1.png)

WE mentioned that we created a   **TCP socket**   with   **socket.SOCK_STREAM**  . Here, there are different methods we can use depending on our purpose:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/3/stable2.png)

We now have a code that  listens to the TCP port of 65432 port on which we run our code but does  nothing. Let's continue by adding some capabilities to it:

```python
import socket
HOST, PORT = '127.0.0.1', 65432
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s: 
    s.bind((HOST, PORT))
    s.listen()
    conn, addr = s.accept()

with conn: 
    print('Connected:', addr) 
    conn.sendall(b'Hello, socket!')

                  
```

Our code now displays  "Connected: <ip_address>" to the screen where it runs when there  is a connection to the socket it opens and says "Hello socket!" to the  connecting party. It sends the message and ends:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/3/py30.png)

If we wanted to listen to the same socket with UDP instead of TCP, we would have to do some things differently:

```python
import socket
HOST, PORT = '127.0.0.1', 65432
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s: 
    s.bind((HOST, PORT))
    data, addr = s.recvfrom(1024)
    s.sendto(b'Hello from  UDP socket!', addr)
    print("Received from client:", data.decode())

                  
```

As you can see below, we  first start listening to UDP port 65432 with this code. Then we connect  to this port with nc (netcat). We should remember that Telnet is only  used for TCP connections. After connecting, we send our message, and we  receive a reply back stating “Hello from UDP socket!” in response to the message we sent.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/3/py31.png)

As you can see, it is  possible to add much more advanced features, and capabilities such as  handling multiple connections, exchanging commands, etc., but  unfortunately we are going to be ableto detail all those in here as our  topic in this course is the use of Python in security applications and  we must continue after showing how Python uses the socket.  

In this part of the  training, we have covered what socket programming is in Python and its  use with practical examples. In the next part of the training, we will  be learning about the "  **Basic Port Scanner Application with Python**  " topic.

### Question

1 - In the  "/root/Desktop/QuestionFiles/python10.py" Python script on the Linux lab machine you accessed, a TCP socket is desired to be used. What should  be written in the "?" field for this?

> **Answer:** SOCK_STREAM

## Port Scanner Application

So, can we create a tool  with Python that monitors the continuity of our systems and reports to  us if there is any problem? The answer is of course, yes.

First, let's look at how to make a simple port scanner:

```python
import socket 
target = "letsdefend.io" 
for port in range(1, 1025): 
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
s.settimeout(1) 
result = s.connect_ex((target, port)) 
if result == 0: 
    print(f"Port {port} open!") 
s.close()

                  
```

Here we use the  “connect_ex” method instead of the “connect” method. The connect method  throws an exception if it cannot open the connection, and the  “connect_ex” method returns 0 if the connection is successful, and if it is not successful it returns an error indicating why it failed. For  example, it will return “Error 11 - Resource temporarily unavailable” if it cannot connect to the relevant port on POSIX-compatible systems.

We wrote our port scanner using the knowledge that this method returns 0 on successful  connections. When you run the code you will see output similar to the  following:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/4/py32.png)

Now that we understand how it works, let's take our scenario a little further:

Our code should check  letsdefend.io 80/TCP, letsdefend.io 443/TCP, 8.8.8.8 80/TCP ports every  60 minutes, and if it doesn't get a response, report it to a Slack  channel using a webhook.

```python
import socket
import time
import requests 

targets = [ 
    ("letsdefend.io", 80, "TCP"), 
    ("letsdefend.io", 443, "TCP"), 
    ("8.8.8.8", 80, "TCP") ] 

SLACK_WEBHOOK_URL = "YOUR_SLACK_WEBHOOK_URL_HERE" 

def check_port(target, port, protocol): 
    try: 
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)

        if protocol == "TCP": 
            result = s.connect_ex((target, port)) 
            s.close() 
            return result == 0 

def send_slack_notification(target, port, protocol): 
    payload = {"text": f"{target}:{port}/{protocol} port not responding!"}
    print(payload) 
    requests.post(SLACK_WEBHOOK_URL, json=payload) 

while True: 
    for target, port, protocol in targets: 
        if not check_port(target, port, protocol):
           send_slack_notification(target, port, protocol)     
    time.sleep(3600)

                  
```

When we run our code, we  will see an output like the following and if we entered our  SLACK_WEBHOOK_URL value correctly, the message "8.8.8.8:80/TCP not  responding!" appears on the channel to which the webhook is connected. 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/4/py33.png)

In this part of the  training, we have covered how to make a basic port scanner application  with Python and we will be learning about the "  **Basic IDS Application with Python**  " topic.

## IDS Application with Python

As you may remember, in  our Web Scraping lesson, we downloaded a list of malicious IP addresses  detected by honeypots and wrote it into a text file. Now, let's look for the IP addresses in this list in the real-time network traffic on the  system where we run our code, and if there is traffic related to any of  these IP addresses, we will generate an alarm. There are multiple ways  to do this with Python. In this example, we will use the scrapy library, which is specialized for packet capture and analysis.

First, let's remember our code that writes IP addresses to a file:

```python
import requests
from bs4 import BeautifulSoup

URL = "https://www.projecthoneypot.org/list_of_ips.php" 
html_content = requests.get(URL)
soup = BeautifulSoup(html_content, 'html.parser')

ip_addresses = [] 
for row in soup.select('table.manmx tr')[1:]:
    ip_cell = row.select_one('td a.bnone') 
    if ip_cell:
        ip_addresses.append(ip_cell.text.strip())

with open('iplist.txt', 'w') as file: 
    for ip in ip_addresses: 
        print(ip)
        file.write(ip + '\n')

                  
```

Our code was extracting 25 IP addresses detected by honeypots from projecthoneypot.org and writing them into a text file   **(iplist.txt)**  .

Now we know what to look for: we want to receive an alert when any communication is made to any of the IP addresses in the   **iplist.txt file.**

```python
import socket
import struct
import os

if not os.path.exists('iplist.txt'):
    print("Error: 'iplist.txt' file not found.")
    exit()

with open('iplist.txt', 'r') as file:
    monitored_ips = [line.strip() for line in file.readlines()]

host = socket.gethostbyname(socket.gethostname())
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.bind((host, 0))
s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

while True:
    packet, addr = s.recvfrom(65565)
    ip_header = packet[0:20]
    iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
    
    version_ihl = iph[0]
    ihl = version_ihl & 0xF
    iph_length = ihl * 4

    src_addr = socket.inet_ntoa(iph[8])
    dst_addr = socket.inet_ntoa(iph[9])

    if src_addr in monitored_ips:
        print(f"Alert: Incoming connection for blacklisted IP {src_addr}!")

    if dst_addr in monitored_ips:
        print(f"Alert: Outgoing connection for blacklisted IP {dst_addr}!")

                  
```

Previously, we have  learned about creating a socket, binding the socket to an interface, and setting socket options. The part that is new to you in this code is the part that starts with “  **while True:**  ”. So before we continue, let's examine what's happening here:

In the line below, we assign the first 20 bytes of the packets we started listening through while True to   **the ip_header**   variable. As you may  remember from the TCP/IP course, the first 20 Bytes in IPv4 packets are  header information and information such as source IP address and  destination IP address are kept in this section.

```python
ip_header = packet[0:20]

                  
```

In the next line, we divide the “ip_header” information into smaller pieces. Here, we indicate that the series is big endian    with the   **!**   sign. “  **B**  ”    character indicates 8Bit (1 Byte) data, “  **H**  ” indicates two bytes (16bit) data, and “4s” indicates   **4**   byte string:

```python
iph = struct.unpack('!BBHHHBBH4s4s', ip_header)

                  
```

Element 0 of the header information that we unpacked in the previous line carries the version information.

```python
version_ihl = iph[0] 

                  
```

We perform bitwise AND  operation to get the title length. We get the last 4 bits of the first  byte by ANDing with 0xF (i.e. 15 decimal or 1111 binary). These last 4  bits specify the header length.

```python
ihl = version_ihl & 0xF

                  
```

Then we calculate the IP  header length (IHL) in bytes. The IHL value specifies the length of the  header as a 32-bit word, so we multiply by 4.

```python
iph_length = ihl * 4

                  
```

After the header  information, let's come to the information we really need: the source IP address and the target IP address. The inet_ntoa() function converts  the IP address in byte format into a human-readable dotted decimal  format, and we take the byte format information in the 8th element of  the IPH and convert it into a decimal format that we can read more  easily (and compare it with the IP addresses in the text file) with the  inet_ntoa function:

```python
src_addr = socket.inet_ntoa(iph[8])

                  
```

Then we take the 9th element of IPH in the same way and obtain the dst address:

```python
dst_addr = socket.inet_ntoa(iph[9])

                  
```

Finally, we compare the  IP addresses we obtained with the list in our text file, and if we  detect any of these IP addresses in any traffic through the network, we  write this information to the screen:

```python
if src_addr in monitored_ips: 
    print(f"Alert: Incoming connection for blacklisted IP {src_addr}!") 

if dst_addr in monitored_ips: 
    print(f"Alert: Outgoing connection for blacklisted IP {dst_addr}!")

                  
```

Now let's try our code.  For testing, let's add the IP address 8.8.8.8, which is Google's DNS  server, somewhere in our "iplist.txt" file and then run our code. As you can see in the screenshot below, we ran our code with sudo this time.  This is because the user does not have permission to read network  packets at the kernel level.  

After we ran our code, we opened up a second terminal window and ran   **the wget 8.8.8.8**   command. Since we did not specify any other details, wget started sending “tcp_syn” packets to  TCP Port 80 of this IP address by default. However, since the system at  IP address 8.8.8.8 is a DNS server and a service is not running on port  80, wget could not get the response it expected. Then, as you can see in the screenshot below, this time with the dig command, we asked the  Google DNS server for the DNS record of the address “letsdefend.io”, and the Google DNS server sent us a response.

In the screenshot, the first alert belongs to the request sent by   **wget**  , the second alert belongs to the request sent by   **dig**  ,    and the third alert belongs to the response given by the Google DNS server.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/5/py34.png)

Our simple IDS is ready,  and now you can enrich the “iplist.txt” file with the IP addresses you  collect from different sources, and add the Slack integration we used in the previous example to this code to be instantly informed about what  is happening.

What you should not  forget is the gateway, server, etc. systems may have a very large amount of network traffic, and analyzing this traffic in this way may consume  much more system resources than you expect.  

In this part of the  training, we have covered how to make a basic IDS application with  Python through codes. In the next part of the training, we will be  learning about the "  **Basic FIM Application with Python**  ".

## FIM Application with Python

Well, this time, let's  make a simple File Integrity Monitoring (FIM) application with Python.  Let our application monitor the integrity of the paths/files we provide  as a list and notify us if there is any change in the files:

The simplest version of our code will be as follows:

```python
import hashlib 
import time 
import os 

files_to_monitor = ["/etc/passwd", "/etc/shadow"] 
hash_dict = {} 

def get_file_hash(file_path): 
    with open(file_path, 'rb') as f: 
        return hashlib.sha256(f.read()).hexdigest() 

def initialize_hashes(): 
    for file in files_to_monitor: 
        hash_dict[file] = get_file_hash(file) 

def check_integrity(): 
    for file, initial_hash in hash_dict.items(): 
        if not os.path.exists(file): 
            print(f"{file} not found!") 
            continue 
        current_hash = get_file_hash(file) 
        if current_hash != initial_hash: 
            print(f"A change has been detected in {file}!")
            

initialize_hashes()

while True: 
    check_integrity() 
    time.sleep(3600)

                  
```

When our program first runs, it calls   **the initialize_hashes()**   function and gets the current hash values of the files we provide in   **the files_to_monitor**   list.

Then, it enters a loop that will continue unless we terminate it in any way with   **while True:.**

In this loop, it first calls the   **check_integrity()**   function.

The   **check_integrity()**   function compares the current hashes of the files in the   **files_to_monitor**   list with the hashes it just created during the first run and wrote into   **hash_dict**  .    If there is a difference, it displays it on the screen.

If there is no difference, our function ends and our code moves to the   **time.sleep(3600)**   line, which is the 2nd line in the   **while True:**   loop.

After waiting 3600 seconds, it goes to   **the check_integrity()**   function which is in the first line of the loop. And this cycle continues until we end it.

As you can see from the  examples, Python offers highly advanced support in almost every aspect  you may need. All that remains for us is to determine our needs  correctly, install the right algorithms, then identify the best  libraries for this purpose and get to work.  

In this part of the  training, we have covered how to implement File Integrity Monitoring  (FIM) with Python and we will be learning about the “  **Forensic and Incident Response with Python**  ” topic.

## Forensic and Incident Response with Python

Forensic and incident  response processes often require analyzing large amounts of data and  identifying certain patterns, evidence, or situations. For example,  following a security incident, system logs, network traffic, file  changes, and many other data points should be analyzed carefully. Python offers great tools to make these operations much easier.

A Python script can  automate all these analyses and speed things up. For example, we can use Python scripts for tasks such as searching for network traffic from  specific IP addresses, monitoring changes made to a specific file, or  looking for a specific error message in system logs. In addition, we can use Python scripts for much more complex analyses. For example,  recording an attacker's activities or combining and analyzing data  collected from multiple systems.

Of course, python  scripting is just a tool and success depends on how you use it. The  power of Python scripting lies in its flexibility and customizability.  You can create a customized script according to your needs and get the  most effective and efficient solution for a particular situation.

In short, python  scripting, when used as part of forensic processes, provides the ability to analyze large amounts of data quickly and effectively. This can help resolve a case faster, find more evidence, and achieve a more  successful outcome overall. Above all, python scripting can help  information security professionals do their jobs more effectively and  efficiently, especially in large and complex systems.

Now, let's take a look at how we can utilize Python scripts in these processes by making a few examples of these:  

### IOC Search

In our first example,  let's write a Python script that searches for an IP address in the log  files under the "/var/log" directory on the Linux system and lists the  findings:

```python
import os 

def search_logs_for_ip(ip): 

    log_directory = "/var/log" 
    files = [os.path.join(dp, f) for dp, dn, filenames in os.walk(log_directory) for f in filenames if not f.endswith('.gz')]

    for file in files: 
        try: 
            with open(file, 'r', errors='ignore') as f:
                lines = f.readlines() 
                for line in lines: 
                    if ip in line: print(f"[{file}] {line.strip()}") 
        except Exception as e:
            print(f"Error in {file} file: {e}") 

if __name__ == "__main__": 

    target_ip = input("Input IP Address: ")     
    search_logs_for_ip(target_ip)

                  
```

When we run this script, it will first ask for the IP address and will send this IP address as a parameter to   **the search_logs_for_ip()**   function. The   **search_logs_for_ip()**   function will search all files under the   **/var/log**   directory (skipping those with .gz extension) and list its findings on the screen:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Python+for+Blue+Team/7/py35.png)

As you will notice, we  gave /var/log as the search location and asked it to search the IP  address we entered in the files there. For example, if we had access  logs of an application we developed in our system under the  "/opt/custom_web_app/logs" directory, we could search that specific  directory by giving /opt/custom_web_app/logs as the path.

In previous lessons, we  mentioned that even though Python offers a portable environment, you may need to customize your codes according to the operating system you will run them on. In this example, if we were to search for the same IP  address in the Windows operating system, we would not look in the  C:\var\log directory but would have to search in the event logs. The  code we would write for this would be completely different:

```python
import win32evtlog
import win32evtlogutil 

def search_event_logs_for_ip(target_ip):
logs = ['Application', 'Security', 'System']

for log in logs: 
    try: 
        hand = win32evtlog.OpenEventLog(None, log) 
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ 
        total = win32evtlog.GetNumberOfEventLogRecords(hand) 

while True: 

    events = win32evtlog.ReadEventLog(hand, flags, 0) 

    if not events: 
        break 

    for event in events: 
        data = win32evtlogutil.SafeFormatMessage(event, log) 
        if target_ip in data: 
            print(f"[{log}] {data}") 
    except Exception as e: 
        print(f"Error in {log} log: {e}") 

if __name__ == "__main__": 
    target_ip = input("Input IP Address: ")    
    search_event_logs_for_ip(target_ip)

                  
```

Now, let's do another example and look for the sha256 hash value in the files under /usr/bin on a Linux system:

```python
import os 
import hashlib 
def calculate_sha256(file_path):

    sha256_hash = hashlib.sha256() 
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):     
            sha256_hash.update(byte_block) 
    return sha256_hash.hexdigest() 

def search_files_for_hash(target_hash): 
    directory = "/usr/bin"

    files = [os.path.join(directory, f) for f in os.listdir(directory) if os.path.isfile(os.path.join(directory, f))] 

    for file in files: 
        current_hash = calculate_sha256(file) 
        if current_hash == target_hash: 
            print(f"Matched: {file} - {current_hash}") 

if __name__ == "__main__": 
    target_hash = input("Input SHA-256 hash value: ")     
    search_files_for_hash(target_hash)

                  
```

To run the same script on Windows, it will be sufficient to change the value of the directory variable to   **directory = "C:\\Windows\\System32"**  . Because we did not use any operating system-specific features and did our work with Python's internal functions.  

### Analyze Memory

There are many ways to  analyze memory with Python, and even volatility, one of the most used  tools for this purpose, is also written in Python. But first, we need a  memory dump to examine and we will do this with the “  **Lime**  ” tool. You can install  the current version of the Lime tool by executing the following commands sequentially on the Linux console.

```sh
letsdefend@letsDefend:~$ git clone https://github.com/504ensicsLabs/LiME 
letsdefend@letsDefend:~$ cd LiME/src 
letsdefend@letsDefend:~$ Make
letsdefend@letsDefend:~$ sudo insmod lime-$(uname -r).ko "path=/tmp/memdump.lime format=lime"

                  
```

We now have a dump file  saved under the /tmp directory with the name “memdump.lime” and we can  search for a keyword of our choice in this dump using the Python and  volatility duo:

```python
import subprocess 
import os 

def dump_memory(): 
lime_path = './LiME/src/lime-$(uname -r).ko' 
    output_path = '/tmp/memdump.lime' 

     subprocess.run(['sudo', 'insmod', lime_path, f'path={output_path}', 'format=lime']) 
    return output_path 

def search_memory_with_volatility(memdump, keyword):
    command = [ 
                'volatility', 
                '-f', memdump, 
                '--profile=LinuxUbuntu_x64', 
                'linux_find_file', 
                '-F', keyword, 
                '-O', 'output_dir' 
              ] 

               process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

              stdout, stderr = process.communicate() 
              if process.returncode == 0: 
                  print(stdout.decode()) 
              else: 
                  print(f"Error: {stderr.decode()}") 

if __name__ == '__main__': 
    memdump_path = dump_memory() 
    search_keyword = input("Search keyword: ")
    search_memory_with_volatility(memdump_path, search_keyword)     
    os.remove(memdump_path)

                  
```

As you may noticed, we  have divided the process into two parts, taking a memory dump and  analyzing the dump. In this case, you must notice that we can bring  together the dumps taken from remote machines and perform various  analyses on all of them.  

### Disc Images

You can work on disk  images with the “pytsk” library that you can use with Python, and  “pytsk” supports many file systems by default. Now let's analyze the  code that will get the list of deleted files in an NTFS disk image:

```python
import pytsk3 

def list_deleted_files(image_path): 

    img_info = pytsk3.Img_Info(image_path) 
    fs_info = pytsk3.FS_Info(img_info)
    file_list = fs_info.open_dir(path="/") 
    print("Deleted Files:") 

    for file in file_list: 
    if '$' not in file.info.name.name.decode('utf-8'): 
        Try:
            file.read_random(0, 1) 
        except IOError: 
            print(file.info.name.name.decode('utf-8')) 

image_path = "/mnt/images/ntfs.img" 
list_deleted_files(image_path)

                  
```

In this example, after  placing the disk image we will examine under “/mnt/images” with the name “ntfs.img”, we run our code. Our code produces a list of files with the names are present in the file system and with a size of 0 bytes. No  doubt, this is a simple example, but it is enough to understand what we  can do with Python.  

In this part of the  training, we have learned through examples and codes how Python can be  utilized in forensics and incident response processes.

### Question

1 - What is the name of the library in Python to work with disk images?

> **Answer:** pytsk















































































































