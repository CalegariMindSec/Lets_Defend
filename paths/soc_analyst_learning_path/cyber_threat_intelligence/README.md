# Cyber Threat Intelligence

Start learning CTI types, attack surfaces, gathering TI data, and how to use them as a blue team member

**Table of content:**

- [Introduction to CTI](#introduction-to-cti)

- [CTI Lifecycle](#cti-lifecycle)
- [Types of Cyber Threat Intelligence](#types-of-cyber-threat-intelligence)
- [Determining the Attack Surface](#determining-the-attack-surface)
- [Gathering Threat Intelligence](#gathering-threat-intelligence)
- [Threat Intelligence Data Interpretation](#threat-intelligence-data-interpretation)
- [Using Threat Intelligence](#using-threat-intelligence)
- [Threat Intelligence and SOC Integration](#threat-intelligence-and-soc-integration)

**Practice with SOC Alert**

- [75 - SOC105 - Requested T.I. URL address](https://app.letsdefend.io/monitoring?channel=investigation&event_id=75)

- [20 - SOC105 - Requested T.I. URL address](https://app.letsdefend.io/monitoring?channel=investigation&event_id=20)
- [28 - SOC105 - Requested T.I. URL address](https://app.letsdefend.io/monitoring?channel=investigation&event_id=28)
- [16 - SOC105 - Requested T.I. URL address](https://app.letsdefend.io/monitoring?channel=investigation&event_id=16)

## Introduction to CTI

Cyber threat intelligence (CTI) is a cyber security discipline that aims to produce actionable output after processing and interpreting the data  collected from multiple sources, and to inform organizations against  cyber attacks through these outputs to minimize damages. 

CTI basically aims to understand the Techniques, Tactics and Procedures  (TTPs) of attackers. CTI means to collect data from multiple sources  (IOCs etc.) and processes this data to create information.  Organization-specific intelligence can be produced by matching the  information related to specific organizations. CTI is a field that keeps constantly changing and evolving by its nature. This change is an  inevitable reflection of the cyber security industry. It is possible to  explain this field, which keeps up with the change, with certain  processes.

## CTI Lifecycle

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/cti-lifecycle.png)

**Planning and Direction**

The planning and directing phase should be the foundation of a structure that must function flawlessly. Planning is the part that allows us to  find answers to questions such as what exactly is expected from  intelligence, who will consume the intelligence obtained, and which  teams or individuals will take action as a result of the intelligence  obtained. Intelligence will be used by executives or a team of analysts. You can directly feed your SOC team with the intelligence obtained  and/or present summary reports to your managers. At this point, what you want is important. Your requests will also clarify the scope of the  intelligence. For example, an organization can determine the scope of  intelligence it wants to obtain by asking the following questions: 

**Does your organization have a SOC team?**

This question shows us whether there is a technical team that will  actively use the intelligence obtained, and if there is, it is an  indication that shows us we can go down to the technical details of the  intelligence. If there is not a SOC team it indicates that the  intelligence will be consumed by managers. In this case, an intelligence model that offers clearer and more understandable summaries can be  taken as a basis, without being bogged down in technical details. 

**Has your organization been attacked before? If so, what was the success rate of the attack?**

The fact that the organization was exposed to a high rate of successful  attacks can be used to reduce the success rate of future attacks by  putting the intelligence on the basis of the established structure, and  the intelligence obtained with the data collected from the current  attacks. This tells us how often we will use intelligence in the  organization. It controls how often we pull data from internal and  external sources. It is important that the intelligence obtained is  constantly updated and consumed quickly for frequently attacked  organizations. 

**Do the attacks target organization or individuals?**

It is important to focus on the External Attack Surface Management area, which the intelligence contains, to make the threat surface as clear as possible and to follow it up regularly for attacks targeting the  organization. External Attack Surface Management is to determine and  manage the attack surface of organizations. It will be covered in detail in the following sections. For attacks targeting individuals, the Digital Risk Protection part is  crucial. Digital Risk Protection defines the digital risks that  organizations may face through the attack surface. It will be covered in detail in the following sections. It reveals that we need to clarify  certain issues such as users' login credentials, their risks to be  exposed to phishing attacks, and defining the strength of your password  policy. 

**Are other companies in your industry exposed to the same attacks you received?**

This question explains the need for us to turn to industry-based  intelligence that provides us with intelligence about other companies in our industry. When other companies are getting attacked, industry-based intelligence provides us with the IOC (Indicators used to identify  attacks digitally, and threat actors) related to that specific attack,  and also it will allow us to avoid that attack with minimum damage if we are exposed to the same attack. 

**Information Gathering**

The information collection stage is the part where we determine what  sources we will collect data from. These resources can be both internal  and external. Some of the sources we will collect data from are as  follows: 

- Hacker Forums
- Ransomware Blogs
- Deep/Dark Web Forums and Bot Markets
- Public Sandboxes
- Telegram/ICQ/IRC/Discord/Twitter/Instagram/Facebook/LinkedIn
- Surface Web(Cybersecurity Blogs etc.)
- Public Research Reports
- File Download Sites
- Github/Gitlab/Bitbucket etc.
- Public Buckets (Amazon S3/Azure Blob etc.)
- Shodan/Binary Edge/Zoomeye vb.
- Sources that provide IOC (Alienvault, Abuse.ch, MalwareBazaar vb.)
- Honeypots
- SIEM, IDS/IPS, Firewalls
- Public Leak Databases

**Processing**

The data obtained is processed at this stage which may be considered a  filter. We clean the data from false positives as much as possible, pass it through certain rule sets, and subject it to some correlations. At  the end of this process, we get the information we need. 

**Analysis and Production**

The information obtained is interpreted and analyzed at this stage and  the consumable intelligence is obtained as a result of the output of the analysis. After this point, appropriate reports are to be prepared  according to who will consume the intelligence. 

**Dissemination and Feedback**

Dissemination of the intelligence appropriately is the next step for  whom the intelligence is intended. For example, intelligence from  external sources to the technical team should be distributed to other  users in the organization through appropriate channels, and the  necessary feedback should be given to make the intelligence better and  more efficient at the end of the whole process. Let's say that content  with the name of our organization is created through a site builder at  the subdomain of letsdefend.blogspot.com. If the blogspot.com domain is  marked as suspicious or harmful in the intelligence and not this  subdomain, this will result in many false positives. In such cases, we  need to improve the intelligence with feedback.

### Questions

1 - At what stage is big data created in cyber threat intelligence?

> **Answer:** Information Gathering

2 - Which of the following is not among the questions that the organization  should ask itself during the Planning and Direction phase?

- A- Does the organization have a SOC team?
- B- Has the organization been attacked before?
- C- Do the attacks target the organization or the individuals?
- D- Which EDR product is used in the organization?

> **Answer:** D

3 - Tom, the cyber security  analyst in the SOC team, wants to collect data from the major  intelligence sources for his organization. Tom wants to use decoy  systems to detect potential attackers. Which intelligence source is Tom  trying to bring in?

> **Answer:** Honeypot

## Types of Cyber Threat Intelligence

Cyber threat intelligence varies by position within the organization. The  intelligence is divided into types since the threat intelligence the  technical staff and the manager receive is not the same. The  intelligence that the L1 SOC analyst and the SOC manager will receive  will differ. This way the intelligence becomes more appealing to its  final consumer. 


 ![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/type_of_cti_edited2.png) 

**Technical Cyber ​​Threat Intelligence** 

Technical CTI can be considered as the output of more technical analysis studies based on IOCs. It is an output of the technical CTI to create  certain rulesets and to protect the organization against attacks by  using a report containing hashes of malicious IP addresses, phishing  domains, and malicious files, and by investigating the information  obtained from this report. This type of intelligence is generally used  by the technical personnel (SOC Analyst, Incident Responder) in the  organization. 

**Tactical Cyber ​​Threat Intelligence** 

Tactical CTI is used to understand the TTP (Technical, Tactical,  Procedure) of the attackers by trying to find answers to certain  questions. For instance, we have an intelligence report containing the  TTP of an attacker named “mordecai”. When we go over this report we  should be able to find answers to questions like “what vulnerabilities  does the attacker use the most?”, “in which countries does the attacker  operate?”, “what is the attacker's motivation?”, and “what methods does  the attacker use?” to be able to protect our organization by taking  precautionary measures against a possible attack. This intelligence is  mostly provided for the management personnel (i.e. SOC Manager, etc.)  who are leading the technical teams. 

**Operational Cyber Threat Intelligence** 

Operational CTI is often confused with Tactical CTI because they have so much in common. Operational CTI also focuses on the attackers' TTPs  just like Tactical CTI but it is mostly used for Threat Hunting, unlike  tactical CTI. While tactical CTI is a more automated process,  operational CTI can focus on a specific type of attack, or a single  attacker in particular, and carry out the investigation to a narrower  scope. This type of intelligence can be used by Security Managers or  Threat hunting personnel in the organization. 

**Strategic Cyber ​​Threat Intelligence** 

Strategic CTI is for the top executives of the organization. It is  generally used for long-term tasks such as product purchasing,  budgeting, and planning for the organization in the long run by weighing the tactical CTI outputs.

### Questions

1 - What type of intelligence is appropriate for a threat hunter in the organization?

> **Answer:** Operational Cyber Threat Intelligence

2 - What type of threat intelligence is appropriate for an employee working as an L1 analyst in the organization?

> **Answer:** Technical Cyber Threat Intelligence

## Determining the Attack Surface

#### The Importance of Attack Surface in Threat Intelligence

Today, classical threat intelligence models are falling short. The  concept of External Attack Surface, which has recently entered the  literature, has shown us this inadequacy and has closed the  deficiencies. This concept has brought a new perspective to threat  intelligence. The concept of Extended Threat Intelligence (XTI) has  gained more popularity apart from classical intelligence. To define,  XTI, unlike CTI, creates an attack surface belonging to the organization in order to produce intelligence specific to the organization. Thanks  to this attack surface, organizations gain visibility. This visibility  can be a forgotten endpoint or a forgotten subdomain. The main interest  at this point is that organizations now know their inventories and  clearly know which assets to defend against. 

#### Determining the Attack Surface

When creating the attack surface, domains, subdomains, websites, login  pages, CMS applications, technologies used on websites, IP addresses, IP blocks, DNS records, C-level employee mails, network applications,  operating systems, bin numbers, and swift codes, and SSL certificates  will be included. We will determine all these by proceeding through the  main domain, which was provided to us by the organization as per the  scenario. 

**Domains**

The only information that will be given to us in the first place will be the primary domain of the organization. We will try to create the  entire entity structure over this domain. In the sample scenario below,  an asset inventory of Abanca, a bank located in Spain, will be created. 

**Main Domain:** abanca.com 

**Related Domains:**

In order to find other domains of the company, we can find domains that  provide redirects to the main domain. We can use the host.io service for this. Host.io will provide us with all the domains hosted on the same  IP, the domains hosting the relevant domain within the website, and  other domains hosted by the relevant domain within the website, apart  from other domains that provide redirection to the relevant domain. Not  all domains obtained may belong to the organization. We can decide which domains belong to the organization and which ones don’t by checking the whois outputs of the domains or by looking at their content. 

![cti co hosted](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/hostio_cohosted.png)

When we search the abanca.com domain on host.io, we can also see other  domains hosted on the same IP address in the “Co-Hosted” section. 

![backlinks](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/hostio_backlinks.png)

In a subsection, we can view other domains that contain our relevant  domain, and after making the necessary verifications, we can include  these domains in our asset list. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/hostio_linksto.png)

In the "Links to" section, we can view other domains that our domain hosts within the website. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/hostio_redirects.png)

In the Redirects section, we can view other domains directed to our domain. 

Since the number of domains displayed on the screen is limited, we can obtain all domains via the API by becoming a member. 

As a secondary method, we can find similar information in whois records  of the primary domain we are working on by performing a Reverse whois  lookup (Reverse by Org Name, reverse by Registrant Mail, etc.) for  certain information. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/abanca_whois.png)

For example, when we look at the whois information of the abanca.com  domain, we see that the organization section contains the name of the  company. We will be able to see all other domains registered under this  organization name when we reverse the organization name. We will use the reverse whois tool at  [viewdns.info](https://viewdns.info) for this. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/viewdnsinfo_reversewhois.png)

266 domains containing this name are displayed when we searched "ABANCA" in the search section. These domains are potentially our domains. After we verify each one, we can add it to our inventory. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/abanca_dns_recors.png)

Alternatively, we can use the whoxy.com tool to do the same check. With  this tool, we can reverse whois in 4 categories with the help of this  tool. 

As a third method, we can examine the DNS records of the relevant domain and reach other domains using the same DNS records, check these domains and add them to our inventory after verification. 

We can check the DNS records with the “dig” command on the command line  or we can use the tools that work online on the internet. In this  example, we are viewing DNS records using the dnslytics.com tool. In  order to discover potential domains, we need to reverse records that are managed by the organization. For example, a shared nameserver belonging to any hosting company hosts too many domains, and these domains mostly do not belong to us. Therefore, it is useful to examine the records of  the mail server or nameserver that belongs to the organization. In this  example, the ns2.abanca.com record stands out. When the related  nameserver is reversed on the same tool, it shows that 98 other domains  are hosted on this nameserver. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/dnslytics_reversedns.png)

All the domains that are listed here are potentially our own, as they  are hosted on our own nameserver. After performing the verification, we  can add them to our inventory. 

**Subdomains**

There are many tools that are available online or on the command line to find subdomains. We will now use 4 of them. These tools are  SecurityTrails, Aquatone, Sublist3r, and Assetfinder. 

SecurityTrails can be used on the command line via the hacktrails tool  or API or queries can be made from the visual interface. It produces  high-quality output. 

 https://securitytrails.com/list/apex_domain/abanca.com 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/securitytrails.png)

Secondly, the Sublist3r tool runs on the command line and finds and  outputs findings from multiple sources. It is run with the command in  the screenshot. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/sublist3r.png)

Thirdly, "Aquatone" collects data and produces output by querying from  multiple sources, just like the Sublist3r tool. If you enter the  necessary API keys in the configuration files for the resources that  require API keys, the number of subdomains it finds will increase.  Aquatone can check the activity status of the subdomains it finds with  the help of the scan module it contains, and it can check whether there  is a takeover vulnerability on the subdomains it finds with the help of  the takeover module it has. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/aquatone.png)

Finally, with the “assetfinder” tool, you can query subdomains and obtain data from many sources. 



![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/assetfinder.png)

One of the most important points when searching for a subdomain is to  get as much data from as many sources as possible. After collecting and  bringing all the data together, we will have a fairly large list of  subdomains. 

**Websites**

In order to find the websites, we need to send requests to the domains  and subdomains we find. We obtain our active websites by examining the  domains or subdomains that respond to our HTTP/HTTPS requests. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/httpx.png)

As you can see in the above screenshot, when we list all of our domains  and scan them on the “httpx “ tool, it will list all the domains that  respond to our http/https requests. As an alternative to “httpx” tool  you can also use “httprobe” tool which is a tool that will meet your  needs with similar functions. 

**Login Pages**

Detecting websites with login screens is a bit more challenging than  usual. If you wish, you can go through the websites you find manually  and separate those with a login screen and list them together. Since  this process requires complete manpower, it will be an unnecessary and  time-consuming process. Instead, this can be done with some simple  scripts. The “python” language is a perfect fit for this process. Thanks to the many libraries it contains, we can do this with very few lines  of code with very little effort. We can detect the login pages by  sending requests to the websites we have and searching for clues for the login pages in the content of the returned response by using the  requests and BeautifulSoup libraries in python. For this process, we  first need to check the background code of the login page and look for  some indicators that will give us a clue about whether there is a login  page or not. We can simply look for answers to the following sample  questions and try to figure out whether the page is a login page or not  with the indicators and answers we have obtained: 

- Is the word "Login" or its corresponding phrase in any language possible on the page?
- Are form tags used on the page?
- Are there expressions such as “Username” or “Password” in the placeholder section of the input fields on the page?
- Are there “Login” or similar expressions in the title or header of the page?

In short, if the script we wrote parses the content in the response to  answer these questions, we can detect most of the login pages in a short time. 

**Technologies Used on Websites**

The technologies used on the websites we detect will make an important  contribution to us, especially in terms of vulnerability intelligence.  For example, after we determine the CMS and the version used on a  website, we can take quick action on the remediation if there is any  matching vulnerability found in the product and the version used on the  website in the CVEs we pull from our intelligence sources. There are multiple tools and manual methods to detect the technologies  used on the websites. We will use https://soy.abanca.com/, one of the websites we have  identified for testing purposes. First of all, we install the  “Wappalyzer” tool  (https://chrome.google.com/webstore/detail/wappalyzer-technology-pro/gppongmhjkpfnbhagpmjfkannfbllamg) in our browser in the Chrome Web Store. After opening soy.abanca.com on our browser, we click on the “Wappalyzer” tool icon in the upper right  corner, the application gives us as much as it detects in terms of the  technologies used on the page. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/wappalyzer.png)

As you can see in the screenshot above, the content management system  has listed all the information about the database and the libraries used as much as it can detect. “Whatruns”, “BuiltWith” and “Whatcms” applications can be used as an  alternative to the Wappalyzer tool. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/whatruns.png)



![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/builtwith.png)

The above screenshots show that “Whatruns” and “BuiltWith” tools are  installed as browser add-ons and work just like “Wappalyzer” tool. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/whatcms.png)

Unlike other tools, “Whatcms” is an online tool and it is available at  whatcms.org. All you need to do is to enter the URL address you want to  scan, and it will display the detections. 

If you want to detect it manually rather than using a tool, you can  examine the source code of the page and make a technology detection by  viewing the file paths of the theme belonging to the content management  system and the libraries given in the code, especially in the script  tags. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/sourcecode.png)

Another tool-independent method would be to examine the header of the  response returned from the page from the developer console. We can  display information about the technologies used on the page within the  header of the returned responses. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/devconsole.png)

**IP Addresses**

IP addresses are one of the most important assets of our organization.  There are serious risks involved when open ports on IP addresses are not checked regularly or if the ports are still used after the services  running on these ports are outdated. Therefore, the monitoring of these  ports and services and detecting the risks involved in a timely manner  is vital for a network. We can make a list by analyzing the IP addresses of the domains and  subdomains we found. In order to detect these IPs, we can collect the A  records of the domains or detect the IP addresses by sending a request  and resolving it. In addition, in order to detect all the active IP  addresses contained in the IP blocks used within the organization, we  can send requests to all the IPs in the block and select the active  ones. 

**IP Blocks**

Since IP blocks contain mostly the IPs owned by the organization, the  IPs with the highest risk are within these blocks. Therefore, follow-up  of these is very important. We can detect IP blocks by looking for  patterns in the IP addresses we obtained from the domains and checking  the whois information of consecutive IP addresses to understand whether  they belong to the organization or not. 

As a secondary method, we can search for the keywords of our  organization by using the org parameter on Shodan. The org parameter is a search parameter used for the organization part of the IP addresses.  For instance when we search for org:“Abanca” it will list the IP  addresses with the word Abanca in the organization section. By examining these IP addresses, we can look at their whois information and find out whether they belong to the organization and which block they belong to. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/shodan_ipblock.png)

In addition to Shodan, alternatives such as Binaryedge and Zoomeye can be used. 

Lastly, you can also detect blocks by using online tools that make IP  block associations over bgp.he.net and similar domain or IP addresses. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/bgp.he_.net_.png)

**DNS Records**

Monitoring DNS records is important for detecting unknown DNS record  changes. You can use Google's online dig tool or use websites like  dnslytics.com to detect DNS records. In addition, DNS records can also  be accessed with the dig command on the command line. 

**C-Level Employee Mails**

For senior executives, email compromises may result in disaster. The  data that’s transmitted within the mail traffic on a daily basis is  crucial for the organization. Therefore, it is very important to monitor corporate email traffic as well as personal emails.  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/salesql.jpg)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/rocketreach.jpg)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/apollo.jpg)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/contactout.jpg)

There are several tools that are frequently used to detect these  e-mails. We recommend using a fake Linkedin account and a fake email  address when using the tools. These tools work as chrome extensions. You can download the extensions from the Chrome Web Store or download them  from their website and import them into chrome. These applications  include “SalesQL”, “RocketReach”, “Apollo”, and “ContactOut”. All  extensions work in the same logic. Basically, we just go to the person's Linkedin profile and click on the extension. Extensions will list us  the e-mail addresses they can detect. 

**Network Applications and Operating Systems**

One of the most important steps for us to be able to track  vulnerabilities actively or passively is to find all the applications  and operating systems. All the methods mentioned in item 5 are also  valid in this section. In addition, in this section, we can collect  discovered services by querying our IP addresses via shodan with passive scanning or we can detect them via active scanning. Network  applications and operating system detections can be made according to  the responses to the requests we sent to the open ports of our  previously removed IP addresses in our asset list 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/shodan_networkapp.png)

**Bin Numbers and Swift Codes**

Bin numbers and swift codes are one of the most important assets to be  monitored for matters such as the detection of stolen credit cards on  the intelligence side, which are of particular interest to fraud teams  in banks. We will use public databases designed for the detection of bin numbers and Swift codes. There is more than one database to find the  bin numbers of an organization. Some of those are sites like  “bincheck.io”, “freebinchecker.com”, “bintable.com”. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/bincheckio.png)

For example, we can list the bin numbers of Abanca on the bincheck.io  site by filtering the country and the bank names, as seen above. Other  databases work in a similar way. There are sites such as “wise.com”, “bank.codes”, “theswiftcodes.com” to detect Swift codes. We can also obtain swift codes by making bank-based inquiries on these sites. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/wise.com_.png)

**SSL Certificates**

SSL certificates are one of the most important factors for secure  communication. Therefore, we need to determine carefully if there is an  SSL certificate on the domains we have detected and add it to our asset  list. It is possible to collect SSL certificates manually on the site,  but we prefer to use some tools to make it easier since this is a  time-consuming process. The most common tools are “Censys” and “crt.sh”. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/censys.png)

For example, the above screenshot shows that we are able to list all the certificates that contain the abanca.com domain on Censys. We can also  search for the abanca.com domain on crt.sh, and it lists all the  certificates with abanca.com in it. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/crt.sh_.png)

We can collect the SSL certificates quickly and easily using these tools.

### Questions

1 - How many subdomains does "blueteam.training" have?

> **Answer:** 0

2 - What is the service of the page builder on letsdefend.io/blog/ ?

> **Answer:** webflow

3 - Which of the following is not one of the subdomain discovery tools?

\- Aquatone
 \- Httpx
 \- Sublist3r
 \- SecurityTrails

> **Answer:** httpx

4 - Shodan can be used to detect IP blocks. (True or False)

> **Answer:** true

## Gathering Threat Intelligence

One of the most important things when collecting threat intelligence is to  keep the range of sources from which data is collected as wide as  possible. For example, when collecting malicious hashes, it is useful to collect them from as many sources as possible. In addition, in order  not to increase the false positive rate while expanding the sources, we  can set a false positive limit value and apply false positive filters to the collected sources. This way we can remove the sources that bring  high false positive values from our intelligence sources. We will  briefly talk about the most popular sources where we can collect threat  intelligence data and their possible equivalents: 

 **Shodan** 

Shodan is a web-based server search engine. It is one of the most  popular search engines of its kind, where users can search for systems  open to the internet with certain filters. Searches related to an  organization or a country may be conducted through Shodan worldwide.  Shodan has a flexible structure that can be shaped in any direction we  want to use it. For example, we can detect all the systems of a specific country or an organization with port# 21 that are open to the internet  via shodan. Usage examples will be explained in detail in the following  sections. 

![shodan spain filter](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/shodan_veritoplama_faceit.png) 

Many data can be accessed instantly by searching the interface on  Shodan. Also, we may need to pull the data through the API as collecting intelligence manually is not possible. 

![shodan API reference](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/shodan_api.png) 

You can access the api documentation at https://developer.shodan.io/api and see how data can be retrieved via the API. 

Other search engines alternative to Shodan are “BinaryEdge”, “Zoomeye”, and “Censys”. 

**Resources Providing IOCs** 

Collecting IPs, domains, hashes, and C2s is one of the most important  methods to protect from potential attacks. Collecting these artifacts  that belong to newly emerged threat actors allows us to detect these  malicious actors and protect our systems before they are infected and  also to take early actions when an activity related to these IOCs is  observed in our systems. 

Resources such as Alienvault, Malwarebazaar, Abuse.ch, Malshare, Anyrun, Virustotal, Hybrid-Analysis, Totalhash, Phishunt, Spamhaus, Tor Exit  Nodes, Urlscan, Zone-h, Rats, Sorbs, Barracuda and many more can provide us with IOCs. One of the most basic rules here is to have a list of  sources as wide as possible and to pull data from these sources as often as possible. Almost all of the sources that provide IOC provide data  via API. Just like Shodan, we can pull data from these sources via API  and then reach the lowest possible false positive rate through some data elimination methods like whitelisting, etc. 

**Hacker Forums** 

Hacker forums are one of the most important places to gather  intelligence. Threat actors usually share in hacker forums first when  they are in preparation for an attack or before they launch a campaign  against an organization or a country. By analyzing the posts they made  in these forums, we can find answers to critical questions such as the  direction of the attack, the targets, the methods to be used in the  attack, and who is behind the attack.  

Sometimes, sales of access to hacked systems are common on these forums. In such cases, even if we are compromised, the remediation issues such  as closing the access to our systems outside of our network, to avoid  the access of more dangerous people and determining the root cause of  the incident should be addressed. Below are screenshots of content  shared on hacker forums: 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/exploit2.png) 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/exploit1.png) 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/altenen2.png) 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/altenen1.png) 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/xss2.png) 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/xss1.png) 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/breached3.png) 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/breached2.png) 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/breached1.png) 

**Ransomware Blogs** 

Ransomware blogs are one of the sources that have gained popularity with the start of the Covid-19 pandemic. Ransomware groups have ramped up  their activities as of 2020 and started posting the data of their  victims who refused to pay on their blogs. In addition, they have been  making their announcements through these blogs. These blogs should  definitely be resources that we should monitor closely to find answers  to questions such as which organization is targeted by which group,  which groups are targeting which countries, what their motivations are,  and to gather more intelligence on ransomware groups. Some of the most  popular ransomware groups today are; Lockbit, Conti, Revil, Hive, Babuk. You can view the active ransomware groups from the link below and view  the links to their blogs: 

http://ransomwr3tsydeii4q43vazm7wofla5ujdajquitomtd47cxjtfgwyyd.onion/ 

We need to install the Tor Browser to be able to visit the sites with  the .onion extensions as .onion extensions are not accessible via  regular browsers. Tor Browser can be downloaded from torproject.org. 

Below are some screenshots from ransomware blogs: 

 ![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/conti.png) 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/lockbit.png) 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/hive.png) 

**Black Markets** 

Black Markets are like more systematized versions of the posts in the  "Selling" categories in the hacker forums. In black markets, credit  cards, stealer logs, RDP accesses, and prepaid accounts are generally  sold. 

Since the data to be collected from here contains limited information,  it will not have an actionable output on its own. However, as explained  before, if an attack surface has been created and if the collected data  matches any data on the attack surface, then it will produce an  actionable output. As black markets don’t provide data via API, we can  extract data from the black markets only by sending requests with  scripts we write and by parsing the returned requests. Below are  screenshots from some black markets. 

![russian cyber market](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/russianmarket.png) 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/russianmarket2.png) 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/russianmarket3.png) 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/genesis.png) 

**Chatters** 

Platforms, where bilateral or multiple written, and audio-visual  communications are possible, are important in terms of threat  intelligence. Threat actors may share sensitive data throughout their  communications with each other on these chatters or important  information or documents regarding the preparation of an attack may be  disclosed. This is why we should follow the chatters as possible as we  can and record everything on those chatters into our database as much as possible. Today, popular chatters frequently used by threat actors are  applications such as Telegram, ICQ, IRC, and Discord. It is possible to  see posts selling credit cards, accounts, and sales for direct access to companies on some groups on these platforms. Below are screenshots of  some chatters. 

 ![telegram cybersecurity](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/telegram1.png) 

 ![russian cyber market](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/icq.png) 

**Code Repositories** 

Code Repositories are full of sensitive data that has been forgotten in  them. Organizations or individual users may forget database access  information, login information, sensitive configuration files for their  applications, secret API keys, etc. in the code repositories. This  information may sometimes be detected by malicious actors and leveraged  in their attacks. Therefore, monitoring public code repositories is  important from the threat intelligence perspective. In addition, when a  new vulnerability is announced, its exploit is often uploaded to these  code repositories and it is important to identify them. Github, Gitlab,  and Bitbucket are some of the popular code repository applications. It  is possible to find sensitive data when searching with certain  parameters in these applications. For example, let's search for "password" "abanca.com" in github. 

![github dork usage](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/github1.png) 

As the screenshots show, we have 40 results for our search for  "password" and  "abanca.com" keywords. When we review these results we  clearly see that the secret API key of Abanca is left open in the second file. 

 ![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/github2.png) 

This information may belong to the organization or a third party that  provides services, but either way, it is obvious that it is highly risky that this data is open in this way. 

**File Share Websites** 

File share sites are applications that many threat actors use actively.  They can share files anonymously through these sites. Files uploaded on  these platforms do belong to a specific organization, sometimes to a  country. Confidential documents of these organizations may be  distributed through these file share sites in case of a breach of these  organizations. Monitoring of these sites is important from the threat  intelligence aspect as we will be aware of the shares about an  organization that we follow. Thus, if there is a breach, it can be  detected as early as possible. Popular sites that allow file uploading  anonymously are sites such as Anonfiles, Mediafire, Uploadfiles,  WeTransfer, File.io. We cannot download files from these sites directly, therefore, we need to use different methods other than API to extract  data from them. There are 2 different methods to download data from  these sites. First, before guessing the file name on such sites, we  detect the unique keys produced for that file through the guessing  algorithm, and then by sending a request to the application server with  that key we can retrieve the file in the returned response. This method  is costly because it requires large processing power. The second method  is a simpler method with a very low cost. When you upload any file to  these sites as public, it is observed that browsers index these files  after a while. These indexed files can be captured and pulled to our own servers by using Dork through a script. Dork is queries that allow us  to search more effectively and quickly. 

**Public Buckets** 

Bucket applications are cloud-based environments that organizations or  individuals use to store their data. These environments should be closed to the outside of the network and only the authorized users of the  organization should access them. But this is not the case all the time  and these environments may be left wide open which causes the disclosure of sensitive and confidential data. For this reason, buckets left as  the public have been an important source of threat intelligence. In  order to detect these public buckets and to find the endpoints, brute  force attempts can be made. Let’s say there is a structure named  “bucketname.amazonaws.com”, we can detect existing buckets by brute  force in the bucket name field in this structure, and then search for  files under that endpoint. It is sufficient to have a wordlist  containing the names of the organization for this. Popular applications  include Amazon S3 Buckets, Azure Blobs, and Google Cloud Storage. 

**Honeypots** 

Honeypots are one of the most effective ways to catch the attackers.  Systems that are easy to breach are very attractive to attackers.  Honeypots are basically systems with security vulnerabilities that are  not connected to any critical server or system that works with the logic of trapping. It is intended for attackers to attack honeypots so we can actively collect IOCs such as attacker IPs and use them in our own  systems. If we wish, we can build our own honeypot or we can use popular honeypots that are already active. Kippo, Cowrite, Glastopf, Nodepot,  Google Hack Honeypot, ElasticHoney, Honeymail are some of the popular  honeypots. 

**SIEM/IDS/IPS/Firewalls** 

An institution may receive hundreds of attacks per day and these attacks may be prevented by the written rules on the security products used.  One of the most effective sources of intelligence is the logs of these  security products. The logs collected in SIEM or the logs containing the blocked IP addresses of the firewall will give us good information  about the attackers. We can obtain the list that contains the attacker's IPs by filtering these logs. Also, the hash of a malicious file  captured on the SIEM is intelligence for us. It will always keep us one  step ahead if we see the products we use within the organization as  critical resources and use them effectively by creating rules and  scripts to collect data from these sources.

### Questions

1 - What is the name of the data that identifies a threat, threat actor, malicious files, and plays an important role in threat intelligence?

> **Answer:** IOC

2 - What is the filter that allows us to search the name of an organization on Shodan?

> **Answer:** org

3 - Which of the following is not among the messaging applications that threat actors frequently use?

- \- Telegram
- \- ICQ
- \- IRC
- \- Instagram DM

> **Answer:** Instagram DM

4 - Practice question – Tom is a SOC analyst at “LetsDefend” organization.  Tom received a notification stating that malware containing the name of  his organization was uploaded to AnyRun. Find the IP address the malware is connecting to?

File MD5 Hash: f6517b0a49bb245e1983d77d2f5b2f98

> **Answer:** 192.168.50.104

5 - How many processes does the malware with the MD5 Hash value "f6517b0a49bb245e1983d77d2f5b2f98" create?

> **Answer:** 2

## Threat Intelligence Data Interpretation

As explained in the previous section, the data collected for threat  intelligence will be complex and very large, as we captured the data  from multiple sources. If it is not processed properly, it will lead to  many false positives and prevent us from producing quality threat  intelligence. Therefore, we need to understand the data and interpret it properly. In this section, we will cover the cause and effect  relationship that will be useful for us when we interpret the data  rather than diving into the “Big Data Analysis” etc. as it is out of  scope. Those who are curious about “Big Data Analysis” can easily find  information about it online. 

 ![threat intelligence data information](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/data-information-intelligence.jpg) 

When analyzing data collected for threat intelligence, it is very  important to weed out false data to avoid false positive situations. For example, if the hash belonging to one of Microsoft's legit applications is accidentally included in the intelligence data, this application  will be marked as malicious within the organization. This will cause  disruption of the processes that need to be done with that application  within the organization. For this reason, we need to convert all the  legitimate data such as IP addresses, hashes, domains, and URLs into a  whitelist, apply it to filter, and clean and legitimate data of the  intelligence. Regardless of the field, the data collected should be  cleaned from false information. Before this process, we have to classify and label the complex structure to be able to navigate through the data faster and interpret it more easily. We can constantly be aware of  threats through the bridge between the attack surface and the data by  associating each classified data group with the relevant parts of our  attack surface.

### Questions

1 - What is the first data collected in threat intelligence called?

> **Answer:** big data

## Using Threat Intelligence

After the data is interpreted in relation to the attack surface, it will  become consumable threat intelligence. The intelligence obtained can be  used in the following 3 different areas.  

- External Attack Surface Management (EASM)
- Digital Risk Protection (DRP)
- Cyber Threat Intelligence (CTI)

When these 3 areas are combined, they form the XTI structure we  mentioned at the beginning of our training. Each structure consumes  intelligence by using it on different topics. 

### External Attack Surface Management (EASM)

EASM is part of XTI, which manages organizations' outward assets. We  explained how to create the attack surface, which is the basis of  External Attack Surface Management, in the previous sections. In this  section, we will cover how we manage the attack surface we have created  and how it is fed from the collected intelligence. 

Attack surface is essential for organizations to detect their unknown or forgotten assets and provide visibility and the EASM will come into  play right at this point since any security vulnerability on these  assets will pose a risk for the organization. Detected assets must be  monitored constantly. For example, adding a newly purchased domain to  the asset list immediately or deleting a discontinued domain from the  asset list is a part of this monitoring effort. We can keep track of  these assets through External Attack Surface Management. EASM will  notify the user if a domain expires, the title of the website changes or a subdomain is created. One of the main factors that will provide  intelligence in this section is the use of information obtained from the assets themselves. A second factor is using the intelligence produced  as a result of the vulnerability data obtained from outside sources like Shodan, etc. In this part, we receive notifications about security  vulnerabilities on our assets as a result of the intelligence we used. 

In the section below, the alarms that may occur as a result of the  active use of threat intelligence by EASM and the actions we can take  are mentioned: 

**New Digital Asset(s) Detected**

This is the warning we will encounter when a new asset is detected and  added to our continuously monitored asset list. We need to check whether the asset really belongs to our organization and was created by the  authorized users of our organization. 

**Domain Information Change Detected**

It is the warning that alerts us when there is any change in the whois  information of the domain in our asset list. We should check this  activity to see if it is a harmful activity or not by comparing the old  and the new data, and verifying if the change is made by the authorized  users of our organization. 

**DNS Information Change Detected**

This is the warning that alerts us when there is any change in the DNS  records of the domain in our asset list. We should check this activity  to see if it is a harmful activity or not by comparing the old and the  new data, and verifying if the change is made by the authorized users of our organization. 

**DNS Zone Transfer Detected**

This is the warning that alerts us when there is a change DNS Zone  Transfer status of the domain in our asset list. We should check the DNS records for the relevant assets and verify if there is a zone transfer. 

**Internal IP Adress Detected**

Since the IP addresses we specify in the A records of our domains are  open to the public and can be seen outside of our network, they must not be internal IP addresses. If an internal IP is disclosed in the A  record of a domain or subdomain, we will receive an alert that warns us  of the “Internal IP Address Detected” on our EASM side. This may happen  due to the lack of communication between different teams in our  organization. In such cases, the process should be verified by  contacting the POC of the DNS record maintenance and the root cause  should be investigated. The IP should be changed if its use is not  necessary. 

**Critical Open Port Detected**

This is the warning that alerts us when there is an indication for open  critical ports on the IPs that we are monitoring within the intelligence we received from sources such as “Shodan”. We should check the ports  claimed to be open on the relevant IP addresses that we receive the  alert, and we should close or filter them if they are not the ports used by our network actively. If the open ports are used actively, then we  should update the services running on them and keep them up to date, and make sure that necessary configurations are complete. 

**SMTP Open Relay Detected**

This is the warning that alerts us when there is an open relay status  for our mail server which we monitor within our asset list. We should  investigate the mail server in question and verify the status of the  mail server by contacting the POC of the server. 

**SPF/DMARC Record Not Found**

SPF and DMARC records are constantly checked for domains that we track  in our asset list, and we receive this alert when these records are not  found. These records must be configured correctly for the security of  our mail servers. We need to contact the POC of our mail server and  verify its status. 

**SSL Certificate Revoked/Expired**

SSL certificates are one of the most important elements for secure  communication. Our SSL certificates hosted on our domains should be  monitored regularly within our asset list. We will receive this alert if one of our SSL certificates is expired or revoked. Any communication  carried out without SSL poses high risks as the data is transmitted in  clear text and can be seen by third parties. Therefore, we need to renew our SSL certificate as soon as possible when we receive this alert. 

**Suspicious Website Redirection**

Sometimes we redirect some of our domains to some of our websites. If we do this frequently, we are likely to miss suspicious redirects.  Therefore, we need to receive feeds that provide us with the status  codes of our websites and where they are directed. If we receive this  alert, it means that one of our domains in our asset list is redirecting to a website that is not in our asset list. This indicates a potential  breach. We must urgently check the redirection and report the case to  the relevant team that manages these issues. 

**Subdomain Takeover Detected**

We receive this alert if a takeover is detected on a subdomain. This  case should be investigated to find the DNS record that this takeover  took place and the details should be shared with the team that will  handle the case. 

**Website Status Code Changed**

We receive this alert when the status code that our website returns back to us is changed. This warning comes to us from the data containing the status codes of the websites. In order to prevent service  interruptions, the status code and the problem should be determined with its root cause, and the solutions to remediate the issue should be  applied immediately. 

**Vulnerability Detected**

This alert comes to us as a result of intelligence obtained from  vulnerability data. If we encounter this warning, it means that there is a match between the vulnerabilities in the data and our network  applications, SSL certificates, domains, websites, IPs, or 3rd party  technologies. If the warning is generated from the CVE data and there is product and version information in which the vulnerability is triggered in the details of the CVE, the accuracy of the alert is very high,  immediate action must be taken and the suggested fixes should be applied immediately. The accuracy rate may be slightly lower if the warning is  coming from other sources like shodan, etc. 

### Digital Risk Protection

DRP is the part of XTI that constitutes most of the intelligence for the organization after all the data collected from all the sources are  mapped with the attack surface following the interpretation of the data. In this section, we will cover topics such as the protection of brand  reputation, threats on the Deep&Dark Web, fraud protection specific  to banks, the impact of risks that may occur in any organization in the  supply chain, threats to the organization on the web surface and  protection for senior executives, and the threats and risks we may face  related to these as well as how we should take action against them will  be detailed. Below are the alarms that we may encounter within the scope of DRP and  the actions we can take: 

**Potential Phishing Domain Detected**

Newly registered domains or previously registered domains with newly  created SSL certificates are an intelligence source for us. After  interpreting the data obtained from these sources, we encounter this  warning for domains with a structure similar to our domains in the  intelligence obtained. When we receive this alert, we should investigate the relevant domain in safe environments and determine whether they are mimicking our original content. If these domains mimic our brand and/or content, we should contact the domain registrar and the ISP that hosts  the content of the fraudulent site to take it down immediately. If there is nothing suspicious in the content, the domain should still be  monitored there is a high potential for that domain to turn into a  phishing site. 

**Rogue Mobile Application Detected**

If our organization has mobile applications, we will receive this alert  if there is a match with our official mobile application and the data  that contains the pirated APK files found on pirated APK sites with  similar names and similar content. The APK files transmitted in this  alert should be analyzed in a safe environment, and quick remediation  action should be taken if they are found malicious. These copycat mobile applications should be taken down immediately to avoid any malicious  activities and to protect our brand reputation. 

**IP Address Reputation**

There are multiple reasons that cause the loss of reputation of IP  addresses. If we receive this alert it means that there is an incident  that occurred affecting our IP reputation. Possible reasons for the loss of the IP reputation are as follows: 

- If the IP address is blacklisted on any source for any reason,
- If the IP address is found in a feed containing harmful IOCs, 
- If the IP address has been involved in an activity in the torrent network,
- then the reputation of the IP address will be lost.  

We will receive this alert if any of our IP addresses are among the  resources that will cause this reputation loss. If it is a blacklist  case, we should investigate the root cause and determine on what sources it has been blacklisted. The root cause of the blacklist should be  investigated and eliminated. It will be more risky and harmful if our IP addresses have been found in a feed containing harmful IOCs or involved in the torrent network because our IP addresses could potentially be  used in a malicious campaign. This raises the possibility that the  organization has been breached. In this case, we must quickly  investigate the relevant systems retrospectively and identify the root  cause. If the breach has happened, we need to enforce the internal  policies. 

**Impersonating Social Media Account Detected**

Social media is a platform that many organizations use to represent  themselves. Thousands of new accounts are created every day on these  platforms. Not all accounts are created with good intentions. Many  accounts may be created with user names that can imitate the original  accounts of the organization or with the intention to conduct smear  campaigns against the organization. We will receive this alert if we  encounter such a situation. In this case, the relevant account should be reviewed and determined whether it is just a name similarity or an  attempt to mimic. If the account is being used for fraud or a smear  campaign against our organization, we should contact the support team of the relevant social media application and request that this account be  closed. 

**Botnet Detected at Black Market**

We receive this alert if any of our organization’s domain or IP  addresses is included in the botnet data in the black markets. The user  system that became a bot reported in the alert may belong to one of our  employees or customers. If the system belongs to a customer, the user’s  password should be reset to remediate the incident. If the system  belongs to one of our employees forensics investigation should be  conducted, the system should be isolated from the network immediately,  employee’s network credentials must be reset. Further investigations  must be conducted on the system to determine if the system is infected  or not. 

**Suspicious Content Detected at Deep&Dark Web**

Deep&Dark web environments are monitored and all data is collected  regularly. We receive this alert if there is anything that mentions our  organization in the data after the collected data is interpreted. For  example, if there is a post on a hacker forum mentioning an attack  against our organization, then we can implement security tightening even before the attack occurs. We can avoid the attack totally or get it  over with the least damage thanks to these posts. When we encounter this alert, the post that threatens our organization and its content should  be analyzed thoroughly, and necessary actions should be taken  accordingly. 

**Suspicious Content Detected at IM Platforms**

Instant messaging platforms such as Telegram, ICQ, and IRC are the  environments that threat actors use for communication. We receive this  alert if there is anything that mentions our organization in the data  after the conversations of the threat actors in the public or private  groups of these platforms are monitored and the collected data is  interpreted. In this case, the conversation or the statement about our  organization should be analyzed thoroughly and the context of the  mention regarding our organization should be determined. If there is a  threat to the organization, necessary actions should be taken quickly. 

**Stolen Credit Card Detected**

It is a common situation for fraud teams of banks. Threat actors steal  credit card information by phishing or other ways and share or sell them in the dark web environment. In these types of cases, banks should  follow these stolen credit cards well in order to protect their  customers. We receive this alert if a stolen credit card number matches  with one of the bank’s with the help of the intelligence gathered. In  this case, we must inform the fraud teams immediately and take action to cancel the card. 

**Data Leak Detected on Code Repository**

We mentioned that code repositories such as Github, Bitbucket, Azure  Blob, and Amazon S3 where we can store data or store codes are one of  the sources of intelligence. Sometimes sensitive data for the  organization may be forgotten in such environments. We will receive this alert if sensitive and critical data such as an IP address of the  organization, domain, database access information, login information  that belongs to employees, or if a sensitive report related to the  organization is detected in a bucket through the intelligence gathered.  In this case, we must take quick action to delete the sensitive data if  we manage the relevant repository or bucket. If someone outside of our  organization manages it, then, we should go after the takedown option. 

**Company Related Information Detected on Malware Analysis Services**

Public sandboxes are one of the important intelligence sources for the  organization to detect malicious files against our organization.  Thousands of samples are uploaded and analyzed in these sandboxes every  day. A malicious file referring to our organization is crucial for our  organization. It may target our organization directly or may have been  uploaded by an attacker with the intention of smearing our organization. In these cases, we receive these alerts as a warning for these  malicious files that refer to our organization within the collected data and we should investigate and analyze the malicious file and take the  necessary actions.  

**Employee and VIP Credential Detected**

These are the warnings that will occur if there is a data leak related  to our employees, especially the VIPs that we keep monitoring actively.  When we see these alerts we need to apply the password reset process for the relevant users quickly. 

### Cyber Threat Intelligence 

CTI is considered a part of XTI, which is the next-generation threat  intelligence. It is a sub-branch of XTI and it is where we can be aware  of what is happening in the cyber world in general, where we can learn  about current malicious campaigns, the orientation of ransomware groups, or offensive IP addresses around the world. Since it may be difficult  to protect our organization with CTI alone, we should support the CTI  with our corporate feeds to obtain the most efficient intelligence. We  are able to use our SIEM, SOAR, and EDR tools more effectively by  integrating them into the CTI feeds and protect our organization better.

### Questions

1 - What part of extended threat intelligence contains vulnerability management?

> **Answer:** EASM

2 - If we receive an alarm from the threat intelligence product we use  indicating that an IP address of our organization has been blacklisted.  Which of the following actions would be incorrect to apply in this  situation?

- A- The reason why the IP address is blacklisted should be determined.
- B- The reputation should be corrected by contacting the vendor whose IP address is blacklisted.
- C- The IP address should be disabled.
- D- A search should be made for the server to which the IP address points.

> **Answer:** C

3 - Mike is a SOC analyst at LetsDefend. The organization received  intelligence indicating that the "fac941eefc8571e51aef69289b5903c4" MD5  value of one of its systems was found in malicious data. Mike needs to  isolate the device from the network. Can you help us, what is the  hostname of this endpoint?

The user should go to the Endpoint Security page through the “Go There”  option under the question, create a search, and find the hostname of the endpoint.

> **Answer:** TempHost

## Threat Intelligence and SOC Integration

Due to its nature, threat intelligence can be integrated into other SOC  products easily. As a result of integration, it is possible to use  threat intelligence much more effectively. Organizations generally use  products like SIEM, SOAR, EDR, and Firewalls under the umbrella of SOC.  Each one of these products has different capabilities in its own use.  Combining the outputs of these products in order to gain more effective  and functional use will produce the best results for us. In this  context, integrating the threat intelligence flow with the security  products under the SOC framework will provide us with the highest  visibility inside and outside of the organization.  

![threat intelligence integration to SOC](https://ld-images-2.s3.us-east-2.amazonaws.com/Cyber+Threat+Intelligence/images/Integration.png) 

For example, the false information/output on the SIEM side can be  minimized if the logs collected in SIEM are integrated with the threat  intelligence feed and the necessary elimination of data is set up in  accordance with this structure. This will help the SOAR products to  produce better quality outputs as we minimized the false information on  the SIEM. Integrating threat intelligence with EDR will provide great  convenience to detect the risks that will occur on end users' devices.  The EDR will make much clear and more detailed detection on the systems  if the users’ web traffic feeds the threat intelligence.   Firewalls are another good example of the SOC and Threat Intelligence  integration. if we are able to feed our firewall products, which are  used to monitor and manage traffic coming from outside the organization, with threat intelligence, then the Firewalls will be able to take  action much faster. If the necessary rules are created for a malicious  IP address on it, the firewall will block any traffic that may come from that IP address and the risks will be detected and eliminated right on  the spot even before an alert occurs within the SOC security tools.

### Questions

1 - Which network security tool should be integrated to the threat  intelligence products in order to prevent malicious inbound traffic  coming into our organization in the fastest way?

> **Answer:** firewall

2 - Which of the following cannot be integrated with threat intelligence?

- \- EDR
- \- SIEM
- \- SOAR
- \- Nmap

> **Answer:** Nmap