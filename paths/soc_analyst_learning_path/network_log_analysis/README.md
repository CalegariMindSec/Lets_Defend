# Network Log Analysis

SOC Analysts should be able to examine different network log sources during the investigation. Find out how you can do this.

**Table of content:**

- [Introduction to Network Log Analysis](#introduction-to-network-log-analysis)

- [Generic Log Analysis (Netflow)](#generic-log-analysis-netflow)
- [Firewall Log Analysis](#firewall-log-analysis)
- [VPN Log Analysis](#vpn-log-analysis)
- [Proxy Log Analysis](#proxy-log-analysis)
- [IDS/IPS Log Analysis](#idsips-log-analysis)
- [WAF Log Analysis](#waf-log-analysis)
- [Web Log Analysis](#web-log-analysis)
- [DNS Log Analysis](#dns-log-analysis)

**Challenge**

- [Disclose The Agent](https://app.letsdefend.io/challenge/disclose-the-agent)

- [Investigate Web Attack](https://app.letsdefend.io/challenge/investigate-web-attack)
- [Port Scan Activity](https://app.letsdefend.io/challenge/port-scan-activity)
- [Remote Working](https://app.letsdefend.io/challenge/remote-working)
- [Shellshock Attack](https://app.letsdefend.io/challenge/shellshock-attack)

## Introduction to Network Log Analysis

The components that make up the concept of the Internet and its  infrastructure are network devices. It would not be possible to talk  about the internet without the network devices which we keep using with  different roles and categories day by day. In the past, a network  communication reached its destination by passing through devices such as hubs, switches, and routers, but today, many devices with different  tasks (such as Firewall, IPS/IDS, Proxy, and WAF) come into play with  different tasks and capabilities.

Within the scope of this training, we will cover the analysis of the  logs of important network devices and services that carry the traces  within the network communications.

At the end of the training, you will learn how to analyze logs of  important network equipment that a SOC Analyst needs to know. The logs  shared during the training are shared as an example. Each device,  product, application logs are unique and may differ according to the  examples within the scope of training. The important thing here is to  understand the essence of the subject.

## Generic Log Analysis (Netflow)

Netflow is a network protocol that collects IP traffic information. Although it was developed by Cisco, it supports Netflow from different  manufacturers. Some manufacturers support Sflow or different similar  protocols. It is important for it to provide visibility on the network  with this protocol regardless of its brand or the developer of the  protocol.

Thanks to this visibility;

\- ISPs can bill for services

\- It is used in network design or analysis

\- It is used for network monitoring. (The sources that generate the most traffic, the most used port information, etc.)

\- Service quality can be measured

\- It provides information for SOC analysts for the detection of anomalies.

Netflow works in a stateful structure and monitors and reports all IP traffic passing over the monitored interface. Every IP communication  here is defined as a flow. Flow is the set of packets that make up the  communication between the source and destination. The information  collected for the formation of Flow are as follows;

\- Source IP Address

\- Destination IP Address

\- Source Port (Only for UDP ve TCP protocols)

\- Destination Port  (Only for UDP ve TCP protocols)

\- IP Protocol

\- Interface Information

\- IP Version Information

An example NetFlow output;

**NOTE:** Devices producing NetFlow data usually do not produce  this data in legible format as text. The output below is taken from  applications that convert this data into a format that we can read.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Network+Log+Analysis/images/generic-1.png)

In order to create NetFlow data, NetFlow settings are configured on  the supported routers or switches on the network. These configurations  can be made over the host’s command line or web interface. Hosts  transmit this data to network devices such as “Netflow Collector” or  “Netflow Analyzer”. These will process the incoming NetFlow data and  generate them into a report by visualizing the data on their interfaces  according to their capabilities.

Via the NetFlow outputs, we can detect:

\- Abnormal traffic volume increases

\- Data leaks

\- Access to private systems

\- New IPs in the network

\- Systems accessed for the first time as well as analyze related issues

### Questions

1 - Can “Layer 7 - Application Layer” information be obtained with Netflow analysis? 

 Answer Format: Y/N

> **Answer:** N

2 - Which of the followings are not produced through Netflow logs?

\- IP Information
 \- XFF IP Information
 \- Port Information
 \- Interface Information

> **Answer:** XFF IP Information

3 - What types of attacks can be detected with Netflow data? 

\- Network Anomaly Detection
 \- Detection of an Infected System
 \- Detection of malicious applications running on the Endpoint
 \- Suspicious Domain Requests

> **Answer:** Network Anomaly Detection

4 - According to the NetFlow data above, what could it be to see 10k  requests from different source IPs to the same destination within 2  minutes?  

 ![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Network+Log+Analysis/images/pr3-beautified-JSON-data.png)

\- SYN Flood
 \- UDP Flood
 \- ICMP Flood
 \- DNS Flood

> **Answer:** UDP Flood

5 - Which of the following is not true according to the NetFlow data above?

 ![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Network+Log+Analysis/images/pr3-beautified-JSON-data.png)

A) Total number of package is 1.
B) The amount of data transmitted is 71 bytes.
C) NTP service is definitely running on the target port 123.

> **Answer:** C

## Firewall Log Analysis

Firewalls are physical or virtual devices that control incoming and outgoing  packets on the network according to rules created depending on the  network’s cyber policies. Each system/server may have its own firewall  application, or a public facing firewall device may be placed for  central management of the network in large organizations. In this way,  network communication primarily passes through the firewall and reaches  its destination according to the rules determined on the firewall setup.

In this sense, firewalls are one of the most important security  components as it controls network access in organizations. Therefore, it is extremely important for the SOC Analyst to be able to analyze the  logs produced by the firewall devices.

Compared to the past, today's firewall devices not only decide where  the packets will go (OSI Layer-3) according to the determined rules, but also undertake different tasks thanks to its additional modules. For  example, it can recognize applications and their content (OSI Layer-7).  In other words, firewalls that recognize which application (http, https, ssh, dns, etc.) make the communication in the application layer are  defined as NGFW (Next-Generation Firewall). Application names that are  mentioned in the firewall logs, app, and services etc. describe this  firewall as NGFW. The fact that it recognizes an application allows to  write application-based rules while writing rules on the firewall. That  actually means that just blocking packets with destination port 22 to  forbid outbound ssh access does not mean that ssh traffic is completely  blocked. When the target application is defined as SSH instead of target port 22, the firewall will recognize it at the application layer, and  block the ssh access regardless of the port that the ssh communication  carried out.

The most essential firewall logs are the logs of the traffic passing  over the device. Basically, this log provides us traffic time, source  IP/Port information, destination IP/Port information, interface  information, location information, etc.

### A sample firewall traffic log

date=2022-05-21 time=14:06:38 devname="FG500" devid="FG5HSTF109K"  eventtime=1653131198230012501 tz="+0300" logid="0000000013"  type="traffic" subtype="forward" level="notice" vd="root"  srcip=172.14.14.26 srcname="CNL" srcport=50495 srcintf="ACC-LAN"  srcintfrole="lan" dstip=142.250.186.142 dstport=443 dstintf="Wan"  dstintfrole="wan" srccountry="Reserved" dstcountry="United States"  sessionid=445180938 proto=6 action="accept" policyid=284  policytype="policy" poluuid="8ec32778-a70a-51ec-9265-8fdf896d07f1"  service="HTTPS" trandisp="snat" transip=89.145.185.195 transport=50495  duration=72 sentbyte=2518 rcvdbyte=49503 sentpkt=13 rcvdpkt=42

#### Looking at the details of the above log

date= Date

time= Time

devname= Hostname 

devid= Device ID 

eventtime= 1653131198230012501 

tz= time zone 

logid= Log ID 

type= Log Type (traffic, utm, event, etc.)

subtype=Sub Log Type (Forward, vpn, webfilter, virus, ips, system, etc.)

level= log level

srcip= Source IP Address

srcname= Source Hostname

srcport= Source Port

srcintf= Name of the Source Interface

srcintfrole= Role of the Source Interface

dstip= Destination IP Address

dstport= Destination Port

dstintf= Name of the Destination Interface

dstintfrole= Role of the Destination Interface

srccountry= Source IP information (Country)

dstcountry= Destination IP information (Country)

action= info on the action taken (drop, deny, accept, etc.)

service= service information

transip= NAT IP info (internal output of the private source address) 

transport= NAT port info

duration= time elapsed

sentbyte= size of the packets sent (byte)

rcvdbyte= size of the packets received (byte)  

sentpkt= number of the packets sent

rcvdpkt= number of the packets received

When performing log analysis, the very first thing we need to check  is the IP and port information. After we have the IP and port  information we should check whether this traffic reaches the target or  not under the "action" section. In other words, the firewall log will  provide us the information on source and destination of the traffic as  well as on what port it is carried out.

As action;

\- **accept:** indicates that the packet passed successfully.

\- **deny:** packet transmission is blocked, information is returned back to the IP address that it is blocked.

\- **drop:** packet transmission is blocked. No information is returned back to the IP address that it is blocked.

\- **close:** indicates that the communication is mutually terminated.

\- **client-rst:** indicates that the communication was terminated by the client.

\- **server-rst:** indicates that the communication was terminated by the server.

For example, checking the firewall logs, you will be able to find  information on whether the network communication has been established  with an IP address that has been forwarded to you for your review. It  will make you search easier if you filter down your findings by the  source and destination IP addresses. Firewall logs are one of the most  important resources for the SOC Analyst to refer to when investigating  incidents, cases, suspicious activities. For example, it will be very  important to find the details like below:

\- Is there a accept request at different times from the IP address  that was detected as attacking and denied by the IPS on firewall logs?

\- Checking the firewall logs, you will be able to find whether there  is access to/from the suspicious IPs/Domains obtained as a result of the analysis of the malicious content in the antivirus logs.

\- Firewall traffic logs are also good resources to detect which  different systems an infected system is communicating within the  network.

#### Through the firewall logs, suspicious activities like:

\- Port-Scan activities

\- Communication detection with IoCs

\- Lateral (lan-lan) or vertical (lan-wan, wan-lan) unauthorized access can be detected

### Questions

1 - How many different ports did the attacker attempt to access?

**Note:** Use the "/root/Desktop/QuestionFiles/firewall.log" file for solving the questions below.

> **Answer:** 12

2 - What kind of attack/activity could have been made according to the logs above?

A) Brute-Force Attack
B) Port-scan activity
C) TCP-SYN-Flood Attack
D) No suspicious activities detected

> **Answer:** B

3 - How does Firewall determine whether to forward an incoming packet to the destination or not?

A) By analyzing behaviorally
B) According to the rule policy
C) According to the size of the traffic
D) According to the location information

> **Answer:** B

4 - How many open ports did the attacker detect? 

> **Answer:** 3

5 - Will the attacker get a response from the Firewall stating that its access request was blocked? 

 Answer Format: Y/N

> **Answer:** Y

## VPN Log Analysis

VPN is the technology that allows you to connect to a local network that  you are not physically connected to. Generally, organizations prefer  this technology to access their internal systems remotely. Today, it is  known as a technology to access sites that are not accessible. The logic here works like this; you are able to access sites you normally cannot  access from your current location by switching your location to a  different location (connecting to the internet as if you were there).

VPN technology for enterprise networks is an indispensable type of  access. Therefore, VPN logs are crucial for the daily routine of SOC  Analysts. Since VPN is one of the services that are open public, it  becomes as an entry point for attackers. Data such as time information,  source IP information, user information in the VPN logs are among the  most useful information for the analysts when investigating  events/alarms.

VPNs are generally used over the organization's existing Firewall  (firewall that supports VPN). In addition, it is possible to see  products that provide dedicated services only for VPNs in some networks. In summary, VPN logs may be obtained from Firewall devices as well as  other devices that only provide VPN service.

### An example VPN log

date=2022-05-21 time=14:06:38 devname="FG500" devid="FG5HSTF109K"  eventtime=1653134913959078891 tz="+0300" logid="0101039424" type="event" subtype="vpn" level="information" vd="root" logdesc="SSL VPN tunnel up" action="tunnel-up" tunneltype="ssl-web" tunnelid=462105151  remip=13.29.5.4 user="letsdefend-user" reason="login successfully"  msg="SSL tunnel established"

#### When we review the details of the above log

date= Date

time= Time

devname= Hostname 

devid= Device ID 

eventtime= 1653131198230012501 

tz= time zone 

logid= Log ID 

type= Log Type (traffic, utm, event, etc.)

subtype=Sub Log Type (Forward, vpn, webfilter, virus, ips, system, etc.)

level= log level

logdesc= log description

action= action taken

tunneltype= VPN tunnel type

remip= IP address that established the VPN connection

user= User information

reason= VPN Connection Request Result

msg= Message (Detailed message after the access)

The most important information to review in the VPN log is the IP  address that makes the connection, which user it connects to, and the  result of this access request (successful-failure status). The given  sample log is a log of the VPN service running as an additional module  on a firewall. Therefore, the type is listed as “event” and the subtype  is “vpn”. After a successful VPN connection, an IP is assigned to you  for your access through the VPN system. The log of the assigned IP  information may be sent either in the same log record or in a different  log. In addition to the information in the sample log above, you can  also see the IP information assigned to you with the “tunnelip” value in the other log after successful VPN connection.

When we review the sample vpn log above, we can detect that a  successful VPN access has been established as the IP address that makes  the VPN request is 13.29.5.4, the user name is "letsdefend-user" and the message produced by the device belonging to the VPN activity is "login  successfully".

Your firewall traffic logs will be created with the IP address  specified in the "tunnelip" assigned to you as the source IP address in  the network activities carried out over the VPN going forward.

For example, SOC Analysts are expected to analyze VPN logs when faced with a scenario like the one below.

**Scenario:** After a phishing e-mail  targeting the organization, it has been determined that some users in  the organization opened this e-mail and entered their username and  password information. For these users, it is necessary to check all the  activities of these users in all services especially the ones publicly  available accounts (i.e. VPN). The VPN logs of the relevant users should be analyzed. The successful access source IP and country information  and whether these successful accesses are indeed made by the user should be further investigated.

Following suspicious activities can be detected through the VPN logs:

\- Successful/Unsuccessful VPN accesses

\- Detection of brute-force attacks against VPN accounts

\- Detection of VPN accesses outside the specified countries

\- Detection of VPN accesses outside the specified time periods

The traffic log on the same device for the successful VPN connection  that we have reviewed its log above is as follows. (There is more than  one record, only 1 has been added as an example.) As seen in the log,  the firewall creates the log of this traffic first before the VPN access is made as the traffic/connection occurs on the firewall side. You can  see that the **srcip** in this log and the **remip** values in the VPN log are the same. The fact that the application  (service) information in the traffic log is HTTPS is due to the fact  that the VPN type used is SSL-VPN.

### Questions

1 - Which of the following is not a type of VPN?

**Note:** Use the "/root/Desktop/QuestionFiles/vpn.log" file for solving the questions below.

A) SSL-VPN
B) Site-to-Site VPN
C) IPSec VPN
D) DNS over VPN

> **Answer:** D

2 - Which of the followings are true for the user3 VPN User?

**Note:** Check the VPN logs in the previous question above.

A) Brute-Force Attack
B) user3 made a successful VPN connection
C) There were failed login attempts from different locations within short period of time
D) user3 made a successful VPN connection from the US location

> **Answer:** C

3 - VPN only works on firewall devices. (True/False)

> **Answer:** False

4 - Which one is true for the "letsdefend" user logs?

A) Brute-Force Attack
B) 4 Successful VPN connections were established with Letsdefend user
C) Letsdefend user has successfully logged in from DE location

> **Answer:** A

## Proxy Log Analysis

The Proxy basically acts as a bridge between the endpoint and the internet. Organizations generally use proxy technology for purposes such as  internet speed, centralized control and increasing the level of  security. A simple schematic drawing of the Proxy structure is shared  below. Requests made by the client reach the Proxy Server first and then the Internet. Proxies can basically work in 2 different types:

**Transparent Proxy:** Target server that we access can see the real source IP address.

**Anonymous Proxy:** Target server that we  access cannot see the real source IP address. It sees the IP address of  the proxy as the source IP address. Thus, it cannot obtain any  information about the system that actually made the request in the  background.

Cisco Umbrella, Forcepoint Web Security Gateway, Check Point URL  Filtering, and Fortinet Secure Web Gateway products are examples of  well-known proxy solutions in the market.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Network+Log+Analysis/images/proxy.png)

The proxy working structure controls the access of systems (server,  client, etc.) to services such as HTTP, HTTPS, FTP according to the  determined policies and operates the actions taken according to the  policies as block or pass actions. Although these policies vary  depending on the proxy capabilities, it basically queries the URL/domain to be accessed from the category database, and if the category is a  risky category, a block action is applied, otherwise a pass action is  applied. Since some systems do not need to reach any networks other than some certain ones, an implicit deny may be applied to all networks  other than the ones that are needed to be accessed.

### A sample proxy log:

date=2022-05-21 time=16:15:44 type="utm" subtype="webfilter"  eventtype="urlfilter" level="warning" srcip=192.168.209.142  srcport=34280 srcintfrole="lan" dstip=54.20.21.189 dstport=443  dstintfrole="wan" service="HTTPS"  hostname="android.prod.cloud.netflix.com" profile="Wifi-Guest"  action="blocked" url="https://android.prod.cloud.netflix.com/"  sentbyte=517 rcvdbyte=0 direction="outgoing" urlsource="Local URLfilter  Block" msg="URL was blocked because it is in the URL filter list"

#### When we review the above log;

date= date information

time= time information

type= log type

subtype= log sub type (values like forward, vpn, webfilter, virus, ips, system etc.) 

eventtype= event type that belongs to the sub type

level= incident severity level

srcip= source IP address

srcport= source port information

srcinfrole= source interface information

dstip= destination IP address

dstport= destination port information

dstinfrole= destination interface information

service= service information

hostname= requested domain

profile= source profile

action= action information

url= URL address requested

sentbyte = size of data sent by bytes

rcvdbyte= size of data received by bytes

direction= direction of the traffic

urlsource= URL sources

msg= message information

When we review the log we see that the request has been blocked to  access the “https[:]//android[.]prod[.]cloud[.]netflix.com/” address of  the system with the IP address 192.168.209.142 in the “Wifi_Guest” group due to the policy applied to the relevant profile. The reason why this  request was blocked is because the url to be accessed is in the "Local  URLfilter Block" list and access to the URLs in this list is blocked.

Proxy logs are one of the most important log types when a SOC analyst needs to check which domain/URL a system (server, client, etc.) is  making a request to our internal systems and whether it was able to  establish a successful connection. It is also important to be able to  determine if the domain/URL is a risky category and if there were able  establish any successful connections before.

\- We can detect following suspicious activities through reviewing the proxy logs:

\- Connections to/from suspicious URLs

\- Infected system detection

\- Detection of tunneling activities

For example, when the Forcepoint Web Security Gateway log below is examined;

Jun 17 10:47:00 10.10.18.11  CEF:0|Forcepoint|Security|8.5.4|194|Transaction blocked|7| act=blocked  app=https dvc=10.10.18.11 dst=104.26.11.18 dhost=sentry-proxy.cargox.cc  dpt=443 src=10.80.18.50 spt=61603 suser=Test_User requestMethod=POST  requestClientApplication=Mozilla/5.0 (Windows NT 10.0; Win64; x64)  cs1Label=Policy cs1=Block_Risk_Category_Policy(Servers)  request=https://sentry-proxy.cargox.cc/api/3/envelope/?sentry_key\=e2506000e29247eba06eee9df3f011e0&sentry_version\=7 

The Test_User user sent a POST request to the address  “https[:]//sentry-proxy[.]cargox[.]cc/” with the Mozilla browser over  its server with an IP address of 10.80.18.50 (it was determined by the  name of the policy), and the target address was determined as  “Block_Risk_Category_Policy( Servers)” policy and blocked according to  the “act=blocked” action.

The domain category to be accessed in this log is expressed by the  category number. The category number is 194. The equivalent of these  numbers can be obtained from the following document. (Pages 31-36)

https://www.websense.com/content/support/library/web/v84/siem/siem.pdf

When we review category 194, we find out that there is a category  belonging to suspicious domains in the form of "194:Extended Protection  Suspicious Content".

After we review the log analysis above, we found out that the action  is blocked, but it is clear that this request was made by a server, and  the server may be infected and that it may be trying to access a  different Proxy address in order to hide which destination it is  actually going to. In this case, the analysis should continue more in  depth and the process that made this request should be determined and  examined. EDR/XDR log sources should be investigated for the  continuation of this review.

### Questions

1 - Proxy is only used for accessing the internet via the web. (True/False)

> **Answer:** False

2 - According to the Proxy log above, which of the following is not true?

Mar 30 19:07:16 10.60.28.21  CEF:0|Forcepoint|Security|8.5.4|1900|Transaction permitted|164|  act=permitted app=https dst=18.11.96.7 dhost=letsdefend.io dpt=443  src=172.20.40.42 spt=59228 suser=user1 requestMethod=CONNECT  cs1Label=Policy cs1=default-user-policy request=https://letsdefend.io/ 

A) SSL/TLS used.
B) User1 made the query.
C) The proxy device has blocked this request.
D) The domain accessed works on the server with the address "18.11.96.7".

> **Answer:** C

3 - Through which logs do we verify the response from the requested target  in the proxy log above? (assuming that there are Firewall, AV, DLP,  IPS/IDS, EDR, WAF devices in the environment.)

A) From the antivirus logs
B) From Email Gateway logs
C) From Firewall logs
D) From DLP logs

> **Answer:** C

4 - When the above proxy log record turns into an alert, which action below is not required?

Mar 30 19:07:16 10.60.28.21  CEF:0|Forcepoint|Security|8.5.4|1900|Transaction permitted|164|  act=permitted app=https dst=18.11.96.7 dhost=letsdefend.io dpt=443  src=172.20.40.42 spt=59228 suser=user1 requestMethod=CONNECT  cs1Label=Policy cs1=default-user-policy request=https://letsdefend.io/

A) Checking domain reputation
B) Dynamic analysis of the accessed address
C) Controlling which different systems accessed the requested domain
D) Obtaining information by contacting the user who made the request
E) Blocking access to the domain
F) Check of Windows Application Events of the requesting system

> **Answer:** F

## IDS/IPS Log Analysis

The IDS/IPS concept and solutions are technologies developed at the point  where only rule-based access controls of firewall devices are not  sufficient in the security world. Roughly, while the firewall works on a rule basis so that red apples shall pass and yellows not, IDS/IPS  solutions can check whether there are worms in the apple or not. In  other words, it has a decision-making mechanism by inspecting the packet content. In this way, it can prevent suspicious/malicious  packets/requests from reaching the target and prevents systems from  being affected by this attack.

Today, although IDS/IPS technology is provided by many Firewall  manufacturers as an additional module/license on firewall devices, it is only available in devices with IDS/IPS as core functions.

### IDS vs IPS

\- IPS: Intrusion Prevention System - Detects and prevents the suspicious activities

\- IDS: Intrusion Detection System - Only detects the suspicious activities

IDS and IPS have signature database. A signature is a set of rules  designed to detect known attacks. The structure that presents this set  of rules centrally is called the signature database. An open source  signature database link is shared below. These databases are constantly  updated against newly formed attack vectors. Network activities that  trigger these signatures can be blocked or only detected according to  the determined action of the signature. In other words, IDS and IPS are  the same device/product, but 2 different concepts/terms emerge according to the action in the signatures. Many firewall manufacturers can  provide the IDS / IPS module with an additional license in their  products. Snort or Suricata are two well known open source IDS/IPS  solutions in the market.

You can access the source of open source code signatures from the link below:

https://rules.emergingthreats.net/open/suricata-5.0/rules/

IDS/IPS systems are one of the sources that will generate the most  frequent alarms amongst all in place security tools for the detection of network-based or host-based attacks. Because many attacks are on the  network or endpoint, IDS/IPS systems can detect and block many  suspicious activities. Many different attack categories such as log4j  attack, post-scan activities, vulnerability exploits, botnet activities  can be detected and prevented with the help of IDS/IPS technologies that are vital security solutions for organizations.

SOC analysts can usually access these outputs produced by IDS/IPS via SIEM or SOAR. SIEM presents the collected IDS/IPS alarms to the SOC  Analyst by turning them into alarms with various rules/correlations  according to their level, category, and occurrence in a certain number  of times. These alerts can be investigated as an independent case or as a group by associating them with different alerts (Some SIEMs can also  establish this relationship). For example, after the port-scan activity, the generation of events/alarms in the exploit category towards the  targets that port-scan from the same source IP address will be  associated with each other and considered as a red flag from the  security perspective.

### A sample IPS log

date=2022-05-21 time=14:06:38 devname="FG500" devid="FG5HSTF109K"  eventtime=1650585615163261716 tz="+0300" logid="0419016384" type="utm"  subtype="ips" eventtype="signature" level="alert" vd="root"  severity="high" srcip=12.11.2.4 srccountry="Reserved" dstip=19.66.201.16 dstcountry="United States" srcintf="AOS_LAN" srcintfrole="lan"  dstintf="Wan_RL" dstintfrole="lan" sessionid=254830141 action="detected" proto=17 service="DNS" policyid=2  poluuid="6b5c8674-a36a-51ec-bbfd-2250544a9125" policytype="policy"  attack="DNS.Server.Label.Buffer.Overflow" srcport=57673 dstport=53  direction="incoming" attackid=37088 profile="default"  ref="http://www.fortinet.com/ids/VID37088" incidentserialno=254762092  msg="misc: DNS.Server.Label.Buffer.Overflow" crscore=30 craction=8192  crlevel="high"

#### Looking at the details of the above log

date= date information

time= time information

devname= system name

devid= system ID information

tz= timezone

logid= log ID information

type= log type (values like traffic, utm, event, etc.)

subtype= log sub type (values like forward, vpn, webfilter, virus, ips, system etc.)

level= log level

severity= incident severity level

srcip= source IP address

dstip= destination IP address

srccountry= source country

dstcountry= destination country

action= action information

service= service information

attack= attack details

srcport= source port information

dstport= destination port information

direction= direction of packet

attackid= attack ID information

msg= additional message information

IDS/IPS logs usually contain information about source-target IP and  port information, action information, information about attack type,  attack category, and attack level.

Following information should be investigated in details when analyzing IDS/IPS logs;

\- The direction of attack (inbound or outbound) should be checked.

\- The event severity level should be checked. Levels are usually set  as low, medium, high, critical. High and critical levels indicate that  activity is more important, quick action is required, and a false  positive is less likely.

\- A different signature trigger state should be checked between the  same source and target. Triggering different signatures means that the  severity level of the event should be raised higher and a faster action  should be taken. The event is resolved within the service level  agreement (SLA) depending on its severity level in case of following  situations like:

\- If a single signature is triggered,

\- there are no different requests from the relevant source,

\- there is no different accept in the firewall logs.

\- Is the port/service specified in the attack detail running on the  target port? If it is running, the event level should be raised to the  critical level, and the target system should be checked for infection.  It should also be checked whether a response has been returned to the  relevant system from the source. If the answer is no, blocking the  attacking IP address as a precaution would be an appropriate action.

\- Is the action taken just detection or has it been blocked as well?  If the attack is blocked and there are no other requests from the same  IP address on the firewall, we can wait a little longer for taking the  action. However, if the action taken for the attack is only a detection, then other similar requests should be reviewed and block action should  be applied if the content of the requests coming from the IP address is  not false positive.

For example, in the example log given above,  “DNS.Server.Label.Buffer.Overflow” attack was detected in the request  made from IP address 12.11.2.4 to port 53 of IP address 19.66.201.16.  When we look at the details of this attack which can be accessed via the ref. url in the log, we see that Tftpd32 DNS Server was affected by  this attack. If the service running on port 53 of 19.66.201.16 IP  address is not Tftpd32 DNS Server, we can say that it has not been  affected by this attack. However, the fact that it says "detected" in  the action section means that this traffic occurs between the source and the destination and is not blocked. In other words, this request made  by the source IP address reached the service running on port 53 of the  destination IP address.

Following suspicious activities can be detected monitoring the IDS/IPS logs;

\- Port scanning activities

\- Vulnerability scans

\- Code Injection attacks

\- Brute-Force attacks

\- Dos/Ddos attacks

\- Trojan activities

\- Botnet activities

### Questions

1 - IDS is a system that …………. the attacks. IPS is a system that …………. the attacks.

A) prevent - detect
B) detect - prevent
C) detect - detect
D) prevent - prevent

> **Answer:** B

2 - Which of the following is not correct?

"timestamp":"2022-06-13T08:25:36", "in_iface":"ens1f1",  "event_type":"alert","vlan":1,"src_ip":"192.168.1.11",  "src_port":53,"dest_ip":"172.16.2.25", "dest_port":1029,"proto":"UDP",  "alert":{"action":"allowed", "gid":1, "signature_id":2811577, "rev":3,  "signature":"ETPRO TROJAN Possible Virut DGA NXDOMAIN Responses",  "category":"A Network Trojan was detected", "severity":1,  "metadata":{"updated_at":["2021_09_22"],"created_at":["2015_06_18"]}},  "app_proto":"failed"}, "payload":"dnV5ZWltLmNvbQo=",  "payload_printable":"vuyeim.com", "stream":0} 

 Answer the following questions according to the above referenced IDS log:

A) The system making malicious domain request may be infected.
B) The relevant domain has not been accessed.
C) The DNS server has responded to the domain request.
D) The domain categorized as DGA is vuyeim.com.

> **Answer:** B

3 - What is the IP address related to the malicious domain?

{"timestamp":"2022-06-13T08:25:36", "in_iface":"ens1f1",  "event_type":"alert","vlan":1,"src_ip":"192.168.1.11",  "src_port":53,"dest_ip":"172.16.2.25", "dest_port":1029,"proto":"UDP",  "alert":{"action":"allowed", "gid":1, "signature_id":2811577, "rev":3,  "signature":"ETPRO TROJAN Possible Virut DGA NXDOMAIN Responses",  "category":"A Network Trojan was detected", "severity":1,  "metadata":{"updated_at":["2021_09_22"],"created_at":["2015_06_18"]}},  "app_proto":"failed"}, "payload":"dnV5ZWltLmNvbQo=",  "payload_printable":"vuyeim.com", "stream":0}

> **Answer:** 172.16.2.25

4 - Which of the following is a true statement?

{"timestamp":"2022-06-13T08:25:36", "in_iface":"ens1f1",  "event_type":"alert","vlan":1,"src_ip":"192.168.1.11",  "src_port":53,"dest_ip":"172.16.2.25", "dest_port":1029,"proto":"UDP",  "alert":{"action":"allowed", "gid":1, "signature_id":2811577, "rev":3,  "signature":"ETPRO TROJAN Possible Virut DGA NXDOMAIN Responses",  "category":"A Network Trojan was detected", "severity":1,  "metadata":{"updated_at":["2021_09_22"],"created_at":["2015_06_18"]}},  "app_proto":"failed"}, "payload":"dnV5ZWltLmNvbQo=",  "payload_printable":"vuyeim.com", "stream":0}

> **Answer:** B

5 - Which of the following information is normally not included in the IDS/IPS alarm outputs?

A) Payload information
B) IP and Port information
C) Parent process information
D) Action information
E) Signature information

> **Answer:** C

## WAF Log Analysis

WAF (Web Application Firewall) is the technology used to secure web-based  applications. The analysis of firewall or IDS/IPS logs alone are often  not sufficient for the detection of web-based attacks. The main reasons  for this are the SSL offload issue and the control of the data in the  payload (data) part of the web request.

SSL Offload is the decryption of SSL-encrypted traffic. The main  purpose of the system is to reduce the load and increase performance, as well as to decrypt the encrypted traffic/request to make the content  visible and controllable from a security point of view. In this way,  invisible attack vectors in encrypted traffic become detectable or  preventable.

In networks equipped with WAF, requests from end users reach WAF  first over the internet. Then the WAF inspects the request, and makes  the decision whether it will be transferred to the Web Server or not.  One of the biggest advantages of WAFs here is that it can perform SSL  Off-load, which helps examine the content of HTTPS traffic. WAF without  SSL Offloading capability cannot provide a full effective protection as  it won’t be able to inspect the payload (data) part of the HTTPS  communication.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Network+Log+Analysis/images/WAF.png)

F5 Big-IP, Citrix, Imperva, Forti WAF products are examples of WAF  solutions that are well-known in the market. In addition, Cloudflare,  Akamai, AWS WAF solutions are also used as cloud WAF solutions.

WAF systems are generally the systems that handle the web access  requests on the public faced systems. Therefore, we can say that WAFs  are the first systems to detect web attacks and WAF logs are the ones  that help SOC Analysts to detect suspicious activities. The analysts  need to know their location on the network clearly when analyzing WAF  logs. WAF logs are the source of the logs to view all web requests made, and to analyze detected web attacks or blocked web attacks. While  examining the alerts generated for detected or blocked attacks, the  reputation of the source IP address that created the log/alert should be analyzed also other similar activities that the source IP created in  other log sources (such as IDS/IPS, Firewall) should be investigated.

### A sample WAF log:

date=2022-01-26 time=19:47:26 log_id=20000008 msg_id=000018341360  device_id=FVVM08 vd="root" timezone="(GMT+3:00)Istanbul"  timezone_dayst="GMTg-3" type=attack main_type="Signature Detection"  sub_type="SQL Injection" severity_level=High proto=tcp  service=https/tls1.2 action=Alert policy="Alert_Policy" src=19.6.150.138 src_port=56334 dst=172.16.10.10 dst_port=443 http_method=get  http_url="?v=(SELECT  (CHR(113)||CHR(120)||CHR(120)||CHR(118)||CHR(113))||(SELECT (CASE WHEN  (1876=1876) THEN 1 ELSE 0 END))::text" http_host="app.letsdefend.io"  http_agent="Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9b1)  Gecko/2007110703 Firefox/3.0b1" msg="Parameter(Password) triggered  signature ID 030000136" signature_subclass="SQL Injection"  signature_id="030000136" srccountry="Germany" attack_type="SQL  Injection"

All determined web traffic passes through WAF. In other words, you can find all web request records on the WAF logs.

#### Following is the information you can find looking at the details of the above log

date= date information

time= time information

type: log type

main_type: detection type

sub_type: detected activity detail

severity_level: incident severity level

proto: protocol

service: service information

action: action taken

policy: rule name

src: source IP address

src_port: source port address

dst: destination IP address

dst_port: destination port address

http_method: http request method

http_url: URL requested

http_host: host requested

http_agent: user-agent info

msg: message related to the incident

signature_subclass: signature class

srccountry: source IP country

attack_type: attack type

When the sample WAF log is analyzed, the source and target IP  information should be checked since it references a high severity level  SQL Injection attack type through signature detection. WAF’s response to this request should be checked if the reported attack is a generic (SQL injection, XSS, etc.) web attack as above. If the WAF did not block  this request the response returned by the application should be checked. The response code of the response of the application (IIS, Apache,  Nginx, etc.) is also important and should be investigated. If the  application responded 200 for an attack that WAF could not prevent, it  means that the attack reached the web server and returned a successful  response. In some cases, the application returns code 200 while it  should actually return code 404 due to some technical deficiencies in  the application. These can be considered as false-positives for the  relevant requests.

Examples of some of the application responses;

\- 200 (OK): The request was received successfully and the response was returned.

\- 301 (Permanent Redirect): The request was redirected to a different location.

\- 403 (Forbidden): Data requested to be accessed is not allowed.

\- 404 (Not Found): The requested content could not be found.

\- 503 (Service Unavailable): The server cannot respond.

Response code categories:

\- Informational responses (100–199)

\- Successful responses (200–299)

\- Redirection messages (300–399)

\- Client error responses (400–499)

\- Server error responses (500–599)

The connection request in the sample WAF log shared above was blocked due to the signatures that WAF recognize as malicious and generated an  alert about it because of the expressions in the URL within the request  coming from the IP address 19.6.150.138 to the port 443 of the  172.16.10.10 host behind the WAF. The policy name applied for requests  matching this signature on the WAF is "Alert_Policy" and the action is  set to "alert" which is monitoring mode. Therefore, we can say that the  request reached the destination host.

If the attack reported by WAF for the requests is for the purpose of  detecting vulnerabilities, it is necessary to look at the details of the vulnerability to be detected here. For example, if your web application is running on ASP and the vulnerability detection is a PHP application  specific scan, then such a vulnerability cannot be expected to be  reported. However, it would still be a good practice to take any actions for the IP address that performs scanning activity. The best action to  take here is to block the inbound requests at the very first security  device at the gateway where the inbound requests first interacts with  our network. 

We can help use WAF logs when analyzing the following detections:

\- Detection of known web vulnerabilities

\- Detection of variety of web attacks like SQL Injection, XSS Attack, Code Injection, Directory Traversal

\- Detection of suspicious method usage such as PUT, DELETE

\- Top requesting IP address information

\- Most requested URL information

**Request Method:** Indicates which method the request is made within the web language. The main request methods are as follows.

\- GET: It is used to retrieve data from the server

\- POST: It is used to send data to the server (such as picture, video)

\- DELETE: It is used to delete the data on the server

\- PUT: It is used to send data to the server (sent data creates or updates files)

\- OPTIONS: Tells which methods the server accepts

### Questions

1 - Which of the following is not true according to the WAF log above?

date=2022-01-26 time=19:47:26 type=attack main_type="Signature  Detection" sub_type="SQL Injection" severity_level=High proto=tcp  service=https/tls1.2 action=Alert policy="Alert_Policy"  src=199.26.150.138 src_port=56334 dst=172.16.10.10 dst_port=443  http_method=get http_url="?v=" OR 1 = 1 -- -"  http_host="app.letsdefend.io" http_agent="Mozilla/5.0 (Nikto/2.1.6)"  srccountry="Italy" attack_type="SQL Injection"

A) The request has reached the server
B) The server responded to the request successfully
C) According to the log record, the request came through the automated web browsing tool
D) The request method is GET

> **Answer:** B

2 - Which of the following actions should be taken when the above WAF log is examined?

A) Whether the attack was successful or not should be simulated.
B) Requests with high source port numbers should be blocked on the firewall.
C) SSL certificate should be reviewed.

>  **Answer:** A

## Web Log Analysis

Today, most services are web-based and the web services of organizations are  the most common services that are open to the outside world. This comes  with a lot interest to the web attacks from the attackers point of view. Therefore, it is very important for SOC Analysts to be able to analyze  web logs correctly. The most commonly used web servers are Microsoft  IIS, Apache, Nginx. Although the applications are different, the web  server logs have similar contents.

### A sample web server log

71.16.45.142 - - [12/Dec/2021:09:24:42 +0200] "GET /?id=SELECT+*+FROM+users HTTP/1.1" 200 486 "-" "curl/7.72.0"

#### When we analyze the above log

Source IP: 71.16.45.142

Date: 12/Dec/2021:09:24:42 +0200

Request Method: GET

Requested URL: /?id=SELECT+*+FROM+users

Version Info: HTTP/1.1 

Server Response: 200

Data Size: 486

User-Agent Info: curl/7.72.0

### Request Method:

Indicates the method of the request within the web language. The main request methods are:

\- GET: It is used to retrieve data from the server.

\- POST: It is used to send data to the server. (such as picture, video)

\- DELETE: It is used to delete the data on the server.

\- PUT: It is used to send data to the server (sent data creates or updates files)

\- OPTIONS: Tells which methods the server accepts.

Note: Usually (by default) web servers do not write the content of  the data sent to the server by POST or PUT to the web log. Therefore, it is important to know this when analyzing web logs. 

**Requested URL:** Indicates the  directory/file on the server the request was made. At the same time, if  there is an attack, it can be detected. As in the example above,  “SELECT+*+FROM+users” statements represent us a “SQL Injection” attack  pattern. Examining URLs is very important in web log analysis.

### Web attack types and sample request URLs

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Network+Log+Analysis/images/WEB.png)

**Server Response:** Server responds back to the requests with some number expressions. These response codes  indicates whether the request is successful or unsuccessful.

Let’s say you find the URL contains information about the sql  injection attack vector while analyzing the web logs, then you should  pay attention to the response of the web server;

\- If 200 is returned: The request has successfully reached the server and the server has responded successfully, and the attack has been  successful. Sometimes, application glitches cause servers to respond  back with 200 while they actually should return 404. In such cases, to  clarify this it is necessary to query the URL and analyze the response  given to the request.

\- If 404 is returned: The server returned "Not Found" because the  requested url was not found on the server. In other words, we consider  it as the attack failed.

\- If 500 is returned: The server could not interpret this request and a "Server Error" response was returned. In other words, we can  interpret it as the attack failed. However, since these requests on the  server side prevent the web service from working properly, it is  considered as a DOS attack by causing a service interruption while the  attacker wanted to make a web attack.

The meanings of these status codes are as follows.

\- 200 (OK): The request was received successfully and the response was returned.

\- 301 (Permanent Redirect): The request was redirected to a different location.

\- 403 (Forbidden): Access to the data requested was not allowed.

\- 404 (Not Found): The requested content could not be found.

\- 503 (Service Unavailable): Occurs when the server service cannot respond.

Categorical response codes

\- Informational responses (100–199)

\- Successful responses (200–299)

\- Redirection messages (300–399)

\- Client error responses (400–499)

\- Server error responses (500–599)

**User-Agent Information:** Indicates the  application that was used for the request. User-Agent information will  help understand whether the requests made are by a real user or an  automated scanning tool during the web log analysis. Some of the  automated web scanning tools are “nikto”, “nessus”, “nmap”. If we see  "Mozilla, Chrome", or a similar web browser information on the  User-Agent information section that means the request was made by a real user. However, the User-Agent information may be changed and so we  should be aware of that and make sure to verify the information we see  within the logs.

If the web server you detect that it was attacked (through SQL  injection, XSS attack, code injection, etc. methods) is behind the  security devices (firewall, IPS/IDS, WAF, etc.) it means that this  request (actually the attack) passes through these security devices. In  summary, almost every detail is important to the analysts in the web log analysis.

Through the web logs, we can generate findings like below and use them in our analyses:

\- Web requests with attack vector (SQL Injection, XSS Attack, Code Injection, Directory Traversal)

\- Top requesting IP information

\- Most requested URL information

\- Most received HTTP response code

\- Detection of suspicious method usage (such as PUT, DELETE)

### Analysis of sample web request, web log and output

#### Web Request

192.168.8.11/bwapp/sqli_1.php?title=%25iron%27+union+select+1%2Cuser%28%29%2C3%2C4%2C5%2C6%2C7--+-+%25%27&action=search

#### Decoded Web Request: 

You may decode them at (http://meyerweb.com/eric/tools/dencoder)

192.168.8.11/bwapp/sqli_1.php?title=%iron' union select 1,user(),3,4,5,6,7-- - %'&action=search

#### Browser output of the Web request

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Network+Log+Analysis/images/bwapp.png)

### Web Log

192.168.8.54 - - [29/Jun/2022:07:42:48 +0300] "GET  /bwapp/sqli_1.php?title=%25iron%27+union+select+1%2Cuser%28%29%2C3%2C4%2C5%2C6%2C7--+-+%25%27&action=search HTTP/1.1" 200 13539  "http://192.168.8.11/bwapp/sqli_1.php?title=&action=search"  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36  (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36"

The log analysis of the above web attack shows that the attack was a  SQL injection, made from 192.168.8.54, and was successful. We can see it was a SQL injection as the URL of the request contains expressions like "union”, and “select”, the response of the web server was 200, and the  analyst was able to confirm that he was able to access the information  from the database about the user “root@localhost”. 

If you are interested in this subject, you can take a look at the  "Detecting Web Attacks" training at the link below, which we have  prepared specifically on how to detect Web attacks as a SOC analyst.

### Questions

1 - Which of the following is not an HTTP request method?

A) GET
B) OPTIONS
C) TRACE
D) HEAD
E) BLOCK

> **Answer:** E

2 - Are there any SQL injection attacks with a status code of 200? (True or False)

**Note:** Use the "/root/Desktop/QuestionFiles/http.log" file for solving the questions below.

> **Answer:** true

3 - Identify the highest requesting IP address.

> **Answer:** 192.168.203.63

4 - How many web requests are made with "DELETE" method in total?

> **Answer:** 223

5 - Are there web logs with “Nmap Scripting Engine” in the user-agent information among the web requests made? (True or False)

> **Answer:** true

## DNS Log Analysis

DNS is one of the most basic building blocks of the internet. DNS is  basically a technology that is used for domain - IP resolution. Network  traffic is basically conducted over IPs and DNS is the system that tells us what the IP address for the server of google.com when we need to  access "google.com" .

SOC analysts generally use DNS logs to check which domains and when  they were  requested during an incident investigation of a system. We  should keep the followings when checking these logs:

\- Has the system made domain requests in categories that actually should not access?

\- Has the system made domain requests that are actually risky categories?

\- Were any known services (google drive, one drive, etc.) attempted to access during situations like data leak, and etc.?

\- Is there any systems that make requests to domains obtained from Threat Intelligence resources?

\- Investigations on DNS logs should be conducted to detect if there  is access to DNS Over TLS (DOT) or DNS over HTTPS (DOH) services.

DNS logs can be divided into 2 different categories from the SOC  Analyst's point of view as the DNS server events, and the DNS queries.

DNS Server Records are simply the DNS audit events on the server that hosts the DNS records. These events are kept on "Application and  Services Logs -> Microsoft -> Windows -> DNS-Server\Audit"  section on the Eventlog on Windows servers. Operations like adding,  deleting, editing, records, etc. on the DNS server could be monitored on these logs.

For example, the screenshot below shows you the event about the  deletion of the Event_ID: 516 deneme.dc.local with the details of who  deleted it and on what server it was deleted inside the Default zone.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Network+Log+Analysis/images/dns1.png)

DNS queries are a difficult source of logs to collect and analyze.  DNS servers do not keep these logs by default and they must be enabled  in order for them to keep these logs. The DNS queries generated directly by the DNS service are also difficult to analyze. However, these are  records where you can find which systems query the domains in the  obtained IoCs. In summary, applications that provide DNS server services such as Microsoft DNS, Bind DNS, Dnsmasq record the DNS queries they  receive upon request.

IOCs (Indicator of compromise) are the evidences that take part  before, during and after a cybersecurity incident and are revealed  during the analysis and investigation of that cyber security incident.  The IOCs are crucial in determining the details like the type of the  attack, tools leveraged during the attack, and who the possible attacker is.

Bind logs, that are DNS server services generally used in Linux  systems, can be accessed via the "/var/log/querylog" log file in the  default configuration.

### A sample DNS log

{  "timestampt": 1591367999.306059,  "source_ip": "192.168.4.76",  "source_port": 36844,  "destination_ip": "192.168.4.1",  "destination_port": 53,  "protocol": "udp",  "query": "testmyids.com",  "qtype_name": "A", }

#### DNS query logs generally contain the following data

\- Date-Time

\- Querying IP, Port

\- Query type

\- The requested domain

Since the above example log is taken from a product (Bro/Zeek) that  captures DNS records on the external network outside of DNS server,  there is also the server information where the query was made along with the IP that made the query. For this reason, DNS logs can be obtained  directly from the server, as well as in the systems that collect these  queries over the network.

In DNS log analysis, the requested domain and its reputation/category are important. The domains utilized in the 2020 "SolarWinds SUNBURST"  attack could have been detected by analyzing the DNS logs. The domains  that a network device, a database or 3rd party application servers will  communicate are clear. Domains that the manufacturer shared with you and are supposed to make communications should be investigated through the  DNS logs for:

\- First time visited domains

\- Domains or subdomains over a certain character size

\- Detection of NX returning domains

\- Domain IOC controls

\- Detection of DNS over TLS, DNS over HTTPS accesses

When the DNS logs below are analyzed, we see that there are DNS  requests made towards subdomains that were randomly created from the IP  address 192.168.10.12 in 1 minute time period. This activity of DNS  requests may be a sign for a potential DNS tunneling activity. The  investigation should be conducted at the endpoint by determining the  source process that creates this activity.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Network+Log+Analysis/images/dns.png)

Our investigations on the DNS log below show that the requested  domains appear to be legitimate. Considering that the Oracle Database  server with an IP address of 192.168.10.3 is querying these domains, the Oracle server asking the domains of Microsoft services used for data  transfer makes this activity suspicious.

Feb  5 09:12:11 ns1 named[80090]: client 192.168.10.3#3261: query: login.microsoftonline.com IN A

Feb  5 09:13:11 ns1 named[80090]: client 192.168.10.3#4536: query: onedrive.live.com IN A

### Questions

1 - Which of the following is not a DNS record type?

A) MX
B) NS
C) A
D) IP

> **Answer:** D

2 - What could the suspicious activity be at the DNS and firewall logs above?

DNS log;
Feb  5 09:12:11 ns1 named[80090]: client 192.168.10.3#3261: query: dns.google IN A

Firewall log;
date=2022-05-21 time=09:12:13 type="traffic" subtype="forward"  srcip=192.168.10.3 srcport=50495 srcintfrole="lan" dstip=8.8.4.4  dstport=853 dstintfrole="wan" proto=6 action="accept"

A) DNS Flood
B) DNS Tunnel
C) DNS over HTTPS
D) DNS Hijacking

> **Answer:** C

3 - What could the suspicious activity be at the DNS log above?

Mar  5 19:12:11 ns1 named[80090]: client 172.16.11.34#3261: query: am4wuz3zifexz5u.onion IN A 

A) DNS Proxy 
B) DNS Tunnel
C) DNS over HTTPS
D) Access to the TOR network

> **Answer:** D