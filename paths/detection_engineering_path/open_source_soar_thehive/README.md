# Open Source SOAR: TheHive

The "Open Source SOAR: TheHive" course offers comprehensive training focused on utilizing TheHive, an open-source Security Orchestration, Automation, and Response (SOAR) platform. Participants will gain  practical insights into leveraging this tool for effective incident  response and security operations.

**Table of Contents:**

- [What is TheHive?](#what-is-thehive)
- [TheHive4py](#thehive4py)
- [TheHive Installation](#thehive-installation)
- [Linux Installation for TheHive](#linux-installation-for-thehive)

Evaluate Yourself with Quiz

- [Open Source SOAR: TheHive](https://app.letsdefend.io/training/quiz/open-source-soar-thehive)

## What is TheHive?

In this lesson, we will  see practical scenarios regarding the installation, configuration and  use of the SOAR product. At this stage, we will use TheHive, which,  although open source, does not lag behind its commercial competitors in  terms of functionality, stability and speed. The most important reason  for this is that you may experience problems when downloading and  installing commercial products for testing.  

### What is TheHive?

TheHive is an open-source security incident response and information management (SOAR/SIEM)  platform that serves as a security operations center (SOC) for  organizations. It is designed to help security teams automate and manage incident response, threat intelligence and security operations.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/1/soar5.png)

### TheHive Basis Features

**Incident Response**

TheHive can automatically detect, classify and respond to incidents. This can help security teams reduce incident response time and resolve incidents more efficiently.  TheHive can automatically detect incidents using data from firewalls,  intrusion detection systems, and endpoint security solutions. It can use artificial intelligence and machine learning to determine the  importance and priority of events. It can automatically task incident  response teams with tasks that help resolve incidents quickly and  effectively.

**Threat Intelligence**

TheHive4 can be used to  collect, analyze and distribute threat intelligence. This can help  security teams better understand threats and respond more effectively.  It can automatically collect threat intelligence from various sources.  It can use artificial intelligence and machine learning to analyze the  threat intelligence it collects and turn it into meaningful information. Can distribute threat intelligence to security teams and stakeholders.

**Security Operations**

Offers a variety of tools and features to help security teams manage security operations. It can  help security teams work more efficiently and prevent threats more  proactively.

**Integration Capabilities**

TheHive4 can be  integrated with a variety of security tools and systems. It can be  integrated with firewalls, IPS systems, SIEM products and TI resources  within the organization to both receive data and take action.

Hive has a great API where you can do everything you do in the interface programmatically, so your integration and automation options are nearly endless. But the  conveniences don't end there. Thanks to the python library called  TheHive4py distributed by its developers, you can send direct queries to thehive4 API and receive responses using just an API key.

While TheHive does all this, there is a second application it works with: Cortex.

(The Cortex we're talking about here should not be confused with PaloAlto's Cortex.)  

### Cortex

Cortex is literally the brains of TheHive. While TheHive focuses on processes, cortex handles  tasks that require automation in the background, such as observable  analysis and active response.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/1/soar6.png)

In this part of the  training, what TheHive is, its basic features and cortex are mentioned. The next part of the tutorial covers “TheHive4py”.

### Questions

1 - Which application does TheHive delegate the background automation and integration work to?

> **Answer:** Cortex

## TheHive4py

TheHive4py is TheHive's official python library and is an excellent tool for talking to TheHive API.

The Hive4Py provides  greatly streamlined functions for talking to the TheHive Rest API, using the Python Requests library. Thanks to these, you can do everything you can do in the interface in TheHive programmatically with Python codes.

- Administrator Functions  
- Alert Functions  
- Case Functions  
- Observables Functions  
- Task Functions  

These are functions you can access from within Python.

For example, with the  following simple code snippet, you can list alarms in TheHive with TLP  Value AMBER, Severity High and Title containing “MALSPAM” in JSON  format:

```python
import json
from thehive4py.api import TheHiveApi
from thehive4py.models import *
from thehive4py.query import *

THEHIVE_URL = 'http://127.0.0.1:9000'
THEHIVE_API_KEY = '**YOUR_API_KEY**'

api = TheHiveApi(THEHIVE_URL, THEHIVE_API_KEY)

query = And(
    Eq('tlp', Tlp.AMBER.value),
    Eq('severity', Severity.HIGH.value),
    Like('title', '*MALSPAM*')
)
response = api.find_alerts(query=query)

# Print the JSON response 
print(json.dumps(response.json(), indent=4, sort_keys=True))       
```

You can access the documents of this library at the following address:  

https://thehive-project.github.io/TheHive4py/  

In this part of the training, TheHive4py library and its use are mentioned. The next part of the tutorial explains “About TheHive Installation”.

### Questions

1 - What is the name of the Python library designed to work with TheHive API?

> **Answer:** TheHive4py

## TheHive Installation

TheHive, like almost all open source products, can be installed and run in a variety of ways.

  [https://docs.thehive-project.org/thehive/installation-and-configuration/installation/step-by-step-guide/ ](https://docs.thehive-project.org/thehive/installation-and-configuration/installation/step-by-step-guide/)  and click on the “TheHive 4” link at the top of the menu, you can follow the step by step  installation steps for both RedHat and You can find the instructions  needed to install it on Debian-based Linux systems.

However, there are some  decisions you need to make before starting such an installation, because TheHive is designed very modularly to meet different needs and to be  easily integrated into your environment.

### System Resource

The first detail we need  to decide on will be the CPU and RAM. A user-by-user table for this is  given in TheHive's documentation:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/3/soar8.png)

We have to say that these values are minimum values. Therefore, we will work with 4 CPUs and 8 RAM.  

### Database

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/3/soar7.png)

In the next step, Database selection awaits us. Here we have two options:   **BerkeleyDB**   and   **Apache Cassandra .**   There will not be too  much load, testing etc. While BerkeleyDB is a very sufficient and  lightweight system for environments, Apache Cassandra will be the right  choice for production environments where a significant amount of data  will be processed.  

### File System

In the next step we will need to select our file system. Here, our options are **Local File System, NFS Folder, Apache Hadoop, S3 Compatible**.  

Local File System, as its name suggests, is the file system of the operating system on which we  will install TheHive and can be used as ext4, xfs, etc. Any scheme can  be used. This option is again suitable for small operations, test  environments, etc. However, it is prone to problems in issues such as  High Availability and Flexibility.

**NFS Folder** is a method that you can use without any hassle, especially when you want to use remote disks on the network.

**Apache Hadoop** is an open source  framework designed for places where BigData exists. Hadoop allows  processing large data sets in a distributed manner using a programming  model called MapReduce. MapReduce works by splitting a dataset into  small pieces, processing those pieces across multiple nodes, and  combining the results. As you will have understood, it is an important  option for processing, storing and using huge amounts of data.

**S3 Compatible**, Amazon S3 Bucket etc. It is the option where you can use S3 compatible cloud services as a file system.   

### Index System

And now we have only one  decision left to make. Which system will we use to index the data? Here  we also have Apache Lucene and ElasticSearch options. Apache Lucene is a very sufficient option for Standalone installations where we will not  create a distributed structure. If we need larger and more complex  structures, it would be appropriate to consider the ElasticSearch  option.  

Our recommendations for the test system will be   **Local File System**   ,   **Apache Cassandra**   ,   **ElasticSearch**   search trio, and we will  proceed using these options in the rest of the lesson. Let us add the  information that whichever options we choose will not change anything in terms of the functionality of TheHive.  

Finally, in order to  eliminate compatibility problems in different operating systems and  different Linux distributions and to turn our main focus to the features of the product, we will install with docker and share our  docker-compose.yml file with you.  

Also, let us remind you  that the installation we will do here is a test environment and we do  not recommend it for a production environment.  

In this part of the  training, some points to know about TheHive installation are mentioned.  The next part of the tutorial covers “Installing Linux for TheHive”.

### Questions

1 - How many GB of RAM does TheHive require as a minimum in scenarios with up to 10 users?

> **Answer:** 8

## Linux Installation for TheHive

We will install Rocky Linux 8.8 together. You can download the installation media from   [https://download.rockylinux.org/pub/rocky/8/isos/x86_64/Rocky-8.8-x86_64-minimal.iso ](https://download.rockylinux.org/pub/rocky/8/isos/x86_64/Rocky-8.8-x86_64-minimal.iso)  . If we are going to do a baremetal installation, you will need to write the ISO image to a USB  disk and boot your machine with it. If you are going to use a  virtualization environment, it will be enough to present this iso file  as the Boot media. 

As we talked about above under the “System Resource” heading, we provided 4 CPUs and 8GB RAM.

Regarding the hard disk, 20GB will be enough for the test environment, that's what we did.  

If your virtualization environment cannot decide which operating system the image is, you can proceed by choosing   **Linux**   , or if it cannot decide which Linux distribution it is,   **Redhat 8**   .

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar9.png)

When we start the  machine, the boot menu will greet us and we will see a countdown timer.  If we wait for this timer, the “Test this media & install Rocky  Linux 8.8” option will run and it will check the integrity of your iso  file before starting the installation. Since we were sure of our iso  file, we proceeded with the “Install Rocky Linux 8.8” option. (If you  downloaded the iso file for the first time, did not check the hash  values after downloading, or moved it from one place to another on your  computer/network, we do not recommend skipping the test mode.)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar10.png)

After a while, we will be greeted by the screen on the left below. We leave the installation  language in English and proceed by pressing button   **1 and come to the screen on the right.**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar11.png)

On this screen, we click on button   **2**   and see the disk  configuration screen on the left below. By pressing button 3 twice on  this screen, we accept the default disk configuration.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar12.png)

This time we select   **“Network & Host Name” from the options.**   On the screen that appears, we write the host name of our system in field   **4 (we did thehive-test**   , you can do the same too) and make this change valid by clicking on button   **5 .**   Finally, by clicking button number   **6**   , we open the network  card of our system and enable it to connect to the network by obtaining  the IP address. If this is not the case, we return to the main menu by  clicking the “   **Done ” button**   in the upper left corner .

Now it's almost over, this time in the main menu, we scroll down a little and click on the "   **Create User**   " option and we are greeted by the screen on the left below.  

**Make this user Administrator**” option at the bottom of the username and click on the “Done” Button in the upper   **left**   corner . If there is a policy conflict with the password we chose, if the password is not complex enough, etc. in cases   **!**   We receive a warning in the area we indicate with , but if we do not want to make any changes, we can return to   **the Main Menu by clicking the " Done**   " button again . Now all we have to do is click on the "   **Begin Installation**   " button (in the lower right corner) and get ourselves some coffee.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar13.png)

When the installation is completed, we complete the installation by clicking the “   **Reboot System**   ” button in the lower right corner. Our system automatically restarts and we are presented with the following screen:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar14.png)

We now have a working operating system, but first we need to bring it up to date.

To do this, after logging in with the username and password we created during the installation.

We get updates with the   **sudo dnf update command.**   After this command, when you are asked for confirmation for the updates to be installed, simply press   **Y**   and then press Enter.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar15.png)

After completing the updates, we can move on to installing the docker environment.

For installation, we first need to add the docker repo to our operating system:

```sh
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo             
```

Afterwards, we can start installing the docker engine and other packages we will need:

```sh
sudo dnf install docker-ce docker-ce-cli containerd.io docker-compose-plugin             
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar16.png)

After the installation is completed, we set the docker service to run automatically at system startup:

```sh
sudo systemctl enable docker             
```

Then we run the docker service:

```sh
sudo systemctl start docker             
```

Then we check if everything is OK:

```sh
sudo systemctl status docker               
```

If everything is OK, we should see   **Active (Running) , as we see in the screenshot below**   :

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar17.png)

Now, the next step is to add ourselves to the docker group:

```sh
sudo usermod -aG docker $(whoami)        
```

Finally, we end our session with   **the logout**   command and log in again.  

### TheHive Docker

Now you can copy our “docker-compose.yml” file that we configured for TheHive:

```yml
version: "3.8"
services:

  nginx:
    container_name: nginx
    hostname: nginx
    image: nginx:1.19.5
    ports:
      - 80:80
      - 443:443
    networks:
      - proxy
    volumes:
      - ./vol/nginx:/etc/nginx/conf.d
      - ./vol/ssl:/etc/ssl
      - ./vol/nginx-logs:/var/log/nginx
    restart: on-failure

  cassandra:
    container_name: cassandra
    image: cassandra:3.11
    restart: unless-stopped
    hostname: cassandra
    environment:
      - MAX_HEAP_SIZE=1G
      - HEAP_NEWSIZE=1G
      - CASSANDRA_CLUSTER_NAME=thp
    volumes:
      - ./vol/cassandra/data:/var/lib/cassandra/data
    networks:
      - backend

  elasticsearch:
    container_name: elasticsearch
    image: elasticsearch:7.11.1
    environment:
      - http.host=0.0.0.0
      - discovery.type=single-node
      - cluster.name=hive
      - script.allowed_types= inline
      - thread_pool.search.queue_size=100000
      - thread_pool.write.queue_size=10000
      - gateway.recover_after_nodes=1
      - xpack.security.enabled=false
      - bootstrap.memory_lock=true
      - ES_JAVA_OPTS=-Xms256m -Xmx256m
    ulimits:
      nofile:
        soft: 65536
        hard: 65536
    volumes:
      - ./vol/elasticsearch/data:/usr/share/elasticsearch/data
      - ./vol/elasticsearch/logs:/usr/share/elasticsearch/logs
    networks:
      - backend

  thehive:
    container_name: thehive
    image: 'thehiveproject/thehive4:latest'
    restart: unless-stopped
    depends_on:
      - cassandra
    ports:
      - '0.0.0.0:9000:9000'
    volumes:
      - ./vol/thehive/application.conf:/etc/thehive/application.conf
      - ./vol/thehive/data:/opt/thp/thehive/data
      - ./vol/thehive/index:/opt/thp/thehive/index
    command:
      --cortex-port 9001
      --cortex-keys ${CORTEX_KEY}
    networks:
      - proxy
      - backend

  cortex:
    container_name: cortex
    image: thehiveproject/cortex:latest
    depends_on:
      - elasticsearch
    networks:
      - proxy
      - backend
    command:
      --job-directory ${JOB_DIRECTORY}
    environment:
      - 'JOB_DIRECTORY=${JOB_DIRECTORY}'
    volumes:
      - '/var/run/docker.sock:/var/run/docker.sock'
      - '${JOB_DIRECTORY}:${JOB_DIRECTORY}'


networks:
  backend:
  proxy:
    external: true        
```

You will need to go back  to the system we installed and save the above content to a file named  “docker-compose.yml”. You can use editors such as   **vi and nano**   for this . We won't go  into detail about these in this lesson, but if you don't know how to do  it or don't remember it, this is a great time to remember the relevant  lessons.  

In the next step, we need to create a file named   **.env in which we will  define the API key for cortex to communicate with thehive and define  cortex's job directory: (the . at the beginning of the file name**   is important)

```txt
CORTEX_KEY=123456
JOB_DIRECTORY=/opt/cortex/jobs    
```

**.env**   file and exit.

In our config file, you  see 5 service definitions: Nginx, Cassandra, Elasticsearch Thehive and  Cortex. Again, if you examine our config file carefully, you will see  some storage mapping definitions. In order for these to work, we need to create a directory named   **vol in the directory where we saved the “docker-compose.yml” file:**

```sh
mkdir vol             
```

Those of you who looked  more carefully may have noticed that we also added an nginx service,  although we never mentioned it before. In fact, it is possible to run  TheHive without Nginx, but TheHive and Cortex's web interfaces do not  support SSL/TLS. To provide this support, we will use Nginx as a reverse proxy.

```sh
[thehive-user@thehive-test ~]$ mkdir vol/ssl
[thehive-user@thehive-test ~]$ touch vol/nginx/ssl.conf
[thehive-user@thehive-test ~]$ touch vol/nginx/thehive.conf
[thehive-user@thehive-test ~]$ touch vol/nginx/cortex.conf              
```

After creating the files, it's time to fill in their contents. You need to save the following  contents by writing them into the relevant files:  

**ssl.conf:**

```txt
ssl_certificate /etc/ssl/nginx-crt.crt;
ssl_certificate_key /etc/ssl/nginx-key.key;   
```

**thehive.conf:**

```txt
server {
  listen 443 ssl;
  server_name thehive-01.localhost;
  proxy_connect_timeout   600;
  proxy_send_timeout      600;
  proxy_read_timeout      600;
  send_timeout            600;
  client_max_body_size    2G;
  proxy_buffering off;
  client_header_buffer_size 8k;

  location / {
    add_header              Strict-Transport-Security "max-age=31536000; includeSubDomains";
    proxy_pass            http://thehive:9000;
    proxy_http_version      1.1;
  }
}            
```

**cortex.conf:**

```txt
server {
  listen 4443 ssl;
  server_name cortex-01.localhost;

  proxy_connect_timeout   600;
  proxy_send_timeout      600;
  proxy_read_timeout      600;
  send_timeout            600;
  client_max_body_size    2G;
  proxy_buffering off;
  client_header_buffer_size 8k;

  location / {
    add_header              Strict-Transport-Security "max-age=31536000; includeSubDomains";
    proxy_pass            http://cortex:9001;
    proxy_http_version      1.1;
  }
}          
```

Now, we need to create SelfSigned certificates in the ssl directory we defined for nginx by running the following commands:

```sh
[thehive-user@thehive-test ~]$ mkdir vol/nginx/
[thehive-user@thehive-test ~]$ openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout vol/ssl/nginx-key.key -out vol/ssl/nginx-crt.crt           
```

While creating the  certificates, it will ask you for some information, we have filled it in our own way, you can fill it in as you wish. The information you enter  will not affect the result at this stage.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar19.png)

If everything is OK, you should have an image like this in your current directory:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar20.png)

Now we are ready to start our services, just run the following commands:

```sh
[thehive-user@thehive-test ~]$ docker network create proxy
[thehive-user@thehive-test ~]$ docker compose up -d      
```

On the first run, docker images will be downloaded, so this stage will take some time, we recommend you to wait patiently.  

After the installation is finished, when you run   **the docker compose ps**   command, you should see an output similar to the following:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar21.png)

There is a hurdle we need to overcome to access the web interfaces of Thehive and Cortex. In the  Rocky Linux 8.8 we installed, the firewall is running by default and  will reject our requests to 443 (TheHive) and 4443 (Cortex) services. To allow requests to these ports, we will need to run the following  commands:

```sh
[thehive-user@thehive-test ~]$ sudo firewall-cmd --zone=public --add-port=443/tcp --permanent
[thehive-user@thehive-test ~]$ sudo firewall-cmd --zone=public --add-port=8443/tcp --permanent      
```

Now that everything is  ready, we can open a browser and see TheHive on the 443 (https) port of  our virtual machine and Cortex on the 4443 (https) port. (Since we are  using a SelfSigned certificate, we will see a certificate warning, we  will have to accept it and proceed)  

you can log in using the default username   **admin@thehive.local**   and default password:   **secret .**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar25.png)

On the Cortex side, the  process is a little different. It will bring up a screen for us to set  an administrator password, where you need to set a username and password that you will not forget.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar31.png)

Afterwards, it will take us to a screen where we can log in with the username and password we specified:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar34.png)

Our next job, TheHive Creating the API-Key required for Cortex to work together.

Since Cortex works  multi-tenancy just like TheHive, let's first define an organization for  our tests and then create an api-key for this organization. 

First, we click on   **the Organizations link**   in field   **(1)**   . Then, in area (2), we click on the   **+Add Organization**   link. After giving a name and a Display Name to our Organization in the   **Create Organization window**   that opens , we finish the process by clicking the   **Save**   button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar24.png)

Now we will click on our organization and create not one but two users with the   **+Add User button.**

One of these users will  be the API User, which will allow our organization in TheHive to  communicate with our organization in Cortex, and the other will be the  user with whom we will do our work at the organizational level in  Cortex.  

**read and analyze**   roles for API User . For our own user, we give   **the read, analyze, orgAdmin**   roles:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar23.png)

After adding both users, we create a password for the API User by clicking on   **the Create API Key**   button and clicking on the API Key,   **New Password**   button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar32.png)

You will need to make a  note of the Api-Key we created because we will need to enter this key in the CORTEX_KEY= section in the .env file we created before. After doing this, we need to restart TheHive Service in the console so that it can  use this key.

```sh
docker compose  up --build  thehive           
```

, you should see (3) (   **OK**   ) in the CORTEX section in the popup that opens.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar36.png)

Next up is to create an  organization on TheHive. As we said at the beginning, TheHive Multi  Tenancy works and allows you to manage many different organizations from a single interface. We will click on the "Add Organization" button to  create an organization that we will use in the rest of our work, give a  name to the organization and click "OK".

Afterwards, the newly created organization will be displayed in the "Organizations" list:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar37.png)

As you can see in the  screenshot, we created the “LetsDefend” organization. Now it's time to  add users to our organization. When we click on the "LetsDefend"  organization in the list, we will go to a screen where we can manage the relevant organization and here we will see the "   **+Create New User**   " option in the upper  left corner. We click immediately and create our user as follows. (We  will create our user in the orgAdmin profile.)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Open+Source+SOAR%3A+TheHive/4/soar38.png)

After adding the user,  when we return to the Users list, we will see the "Create Password"  button next to the user we created. What we need to do is to click on  this button and create a password that we will not forget.  

Finally, let's log out from the admin account and log in with this new account.  

In this part of the training, the installation of TheHive is mentioned.

### Questions

1 - Which parameter is used to make a rule permanent in Firewalld?

> **Answer:** --permanent



















































