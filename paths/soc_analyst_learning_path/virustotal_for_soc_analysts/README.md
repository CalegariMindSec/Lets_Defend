# VirusTotal for SOC Analysts

Learn how to use VirusTotal to become a better SOC Analyst.

**Table of content:**

- [Introduction to VirusTotal for SOC Analysts](#introduction-to-virustotal-for-soc-analysts)

- [File Analysis with VirusTotal](#file-analysis-with-virustotal)
- [Scanning URLs with VirusTotal](#scanning-urls-with-virustotal)
- [Searching for IOC](#searching-for-ioc)
- [Key Points to Pay Attention](#key-points-to-pay-attention)

## Introduction to VirusTotal for SOC Analysts

SOC analysts are constantly encountering suspicious malware, IP addresses,  domain names, and must decide whether they are malicious or not in order to move the investigation forward. While performing the analysis of  this malware, many hashes, IP, and domain data are obtained. Various  online services can be used to obtain more detailed results about the  collected data.

“VirusTotal” is a service that gathers many antivirus solutions in a  single point and you can query and analyze them all. It was acquired by  Google in 2012. It can be used in two different ways, paid and free. The parts that we will explain during the training include completely free  parts.

This tutorial will show you how you can increase the information you  have during file, hash, IP, domain, and URL analysis with VirusTotal.  You will learn how to use VirusTotal as a SOC Analyst in the most  effective way by seeing how the collected data should be interpreted and common mistakes.

## File Analysis with VirusTotal

While reviewing the alert of a SIEM or other security solution, you may have  noticed a suspicious file and want to analyze it. To view the file  analysis results of different AV companies, you can upload the file on  VirusTotal and find out if AV products detect this file as malicious.

*** Please note that** uploaded files can be downloaded by premium VirusTotal users. Because of this if you suspect that file may have  contains sensitive informations, you shouldn't upload to VirusTotal.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-1-1024x539.png)

https://www.virustotal.com/gui/file/415ba65e21e8de9196462b10dd17ab81d75b3e315759ecced5ea8f5812000c1b

In order to interpret the results in more detail, it is necessary to  look at various areas. In the image below, it is stated that 42 of 58  security companies have detected this file as malicious.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-2.png)

In the section with tags, there is information about how the file is  classified. For example, it was stated that the file we uploaded  contains "macro" and was "obfuscated".

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-3.png)

### **Detection**

In the Detection section, you can view the label with which the vendors marked the file as malicious.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-4-1024x378.png)

### **Details**

Here you can find some basic information about the file and details  about its VirusTotal history. For example, the “Basic Properties” area  contains file hash information and more.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-5-1024x273.png)

In the "**History**" field, there are the dates of the first and last analysis of the file in VirusTotal.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-6.png)

As a SOC Analyst, you can draw very important conclusions from this  field. For example, there is a phishing attack on your institution and  you analyze the attachment in the email. After you upload the file to  VirusTotal, if you see that this file has been analyzed before you, you  can draw the conclusion that this malware was not written specifically  for your institution. (Not exactly, but more likely.)

Similarly, if you come across a file that has been analyzed before,  you can understand that this attack was done on different institutions.

### **Relations**

This is the tab that shows detailed information about the domain, IP, URL, and other files that the suspicious file in your hand communicates with. The data shown here is scanned by security vendors within  VirusTotal and you can see the results.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-7.png)

You can usually use this tab to check for a suspicious address that  the file is communicating with. At the same time, you can detect  suspicious communication activities faster by viewing its reputation  with the “Detections” score. There is an important point to note: new  generation malware does not always exhibit the same behavior. They try  to bypass security solutions by taking different actions in different  systems. For this reason, the addresses you display in the relations tab may not give the entire list that the malware wants to communicate  with, you should be aware that this list may be incomplete.

### **Behavior**

What determines whether a file is malicious is its activities. In the "Behavior" tab, you can see that different manufacturers list the  activities that the scanned file has done. Among these activities, you  may encounter many behaviors such as network connections, DNS queries,  file reading/deletion, registry actions, and process activities.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-8.png)

In section 1, you can specify which manufacturer you want to see the  results of. Section 2 contains the activities performed by the scanned  file. For example, if you look at the image above, you can see that the  file makes four HTTP requests and a few DNS queries.

**IMPORTANT NOTE:** As we mentioned earlier, today's  malware may not always exhibit the same behavior. For example, malware  that cannot communicate with the command and control center (CC) may not activate itself. If the command and control center of the malware you  want to analyze is not active, dynamic and static analyzes may not yield a clear result. In such cases, you should find old analysis reports  made in environments such as VirusTotal and examine the behavior as in  the "Behavior" tab.

### **Community**

You can see the comments added by the community in this area.  Sometimes, there are those who share important details about how the  suspicious file was obtained, what needs to be considered during the  analysis, or undetected. For this reason, checking the "Community" tab  can be of great benefit.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-9.png)

In general, we talked about why you should look at which areas after  uploading and scanning a file. This way you can better interpret  VirusTotal outputs.

### Questions

1 - According to the analysis report in the link, what is the creation date of the file? 

https://www.virustotal.com/gui/file/415ba65e21e8de9196462b10dd17ab81d75b3e315759ecced5ea8f5812000c1b/details 

 Answer Format: YYYY-MM-DD

> **Answer:** 2020-08-20

2 - According to the VirusTotal result, how many URL addresses does the malicious file communicate with? You must enter number.

https://www.virustotal.com/gui/file/415ba65e21e8de9196462b10dd17ab81d75b3e315759ecced5ea8f5812000c1b/relations

> **Answer:** 14

3 - Examine the analysis report, what is the '**Compilation Timestamp**' of the file? (You should copy paste the timestamp from VT.)

https://www.virustotal.com/gui/file/6c745b8c701574b32cce2cdec63de7e669127cc0aa6afa654165ebd46c4252b4/detection

> **Answer:** 2022-07-17 22:57:46 UTC

## Scanning URLs with VirusTotal

You can analyze URL addresses as well as file analysis in VirusTotal. All  you have to do is query the relevant address from the URL section.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-10.png)

In the rest of the article, the malicious address “**thuening[.]de[/]cgi-bin/uo9wm/**” will be examined. (Do not directly access this address as it is a  malicious address. You can follow the lesson by clicking the VirusTotal  link below that we provided.)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-11-1024x594.png)

https://www.virustotal.com/gui/url/2bcbc32b84d5d2f6ca77e99232134947377302e7eeee77555672e57f81cd9428

We encounter a similar interface as in file analysis. You can review the previous article for **Detection** and **Details**, it will be continued with the Links tab without explaining the same fields again.

### **Links**

It is the part where the links that the URL address leads to outside  are listed. If you look at the image below, you can see that the address we scanned is linked to the address in **strato[.]de**.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-12.png)

When we scan the "**letsdefend.io**" address, it is seen that there are links to social media accounts.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-13.png)

You can make various inferences with the data you will obtain in this area. For example, even if the URL address does not directly contain  harmful content, it may link to harmful addresses, in which case the  investigation should continue.

### Questions

1 - In which category is google.com classified according to Sophos?

https://www.virustotal.com/gui/url/cf4b367e49bf0b22041c6f065f4aa19f3cfe39c8d5abc0617343d1a66c6a26f5/detection 

> **Answer:** search engines

2 - What is the name of the hash file "**349d13ca99ab03869548d75b99e5a1d0**" scanned in VirusTotal?

> **Answer:** 1word.doc

3 - In which category is letsdefend.io classified according to Forcepoint ThreatSeeker?

https://www.virustotal.com/gui/domain/letsdefend.io/details

> **Answer:** Information Technology

## Searching for IOC

During the investigation, you may receive various IOCs (Indicator of  Compromise). To find out more about these IOCs, you can search in the "**Search**" section of VirusTotal. For example, by searching the hash value of a  suspicious file here, you can find historical analysis results or other  different data, if any.

As an example, let's search for the SHA256 value “**415ba65e21e8de9196462b10dd17ab81d75b3e315759ecced5ea8f5812000c1b**”.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-14.png)

As can be seen, we are faced with the result of an analysis made in the past.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-15-1024x406.png)

https://www.virustotal.com/gui/file/415ba65e21e8de9196462b10dd17ab81d75b3e315759ecced5ea8f5812000c1b

Or if we want to search for an IP address, we can similarly search and view its reputation. Example IP address **70[.]121[.]172[.]89**

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-16-1024x531.png)

When we uploaded a file, we could see the IP addresses that the malware was connecting to in the "**Relations**" tab. This is also true for the opposite. By searching the IP address,  you can find the files related to the IP address in the "**Relations**" tab. We can get more ideas by looking at the scores of the files. If we look at the image below, we can understand that the IP address we are  looking for is related to files such as “**SplitPath**”, and “**TestMfc**”.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-17.png)

In short, you can view past VirusTotal results and different files, IPs, and URL associations by searching in the “**Search**” section.

### Questions

1 - Search VirusTotal for the MD5 value “**b92021ca10aed3046fc3be5ac1c2a094**”. What is the First Submission date? (YYYY-MM-DD)

> **Answer:** 2019-09-16

## Key Points to Pay Attention

VirusTotal is frequently used by SOC Analysts during the day, the data provided by the platform quickly makes the analysts' job much easier. If care is  not taken in some matters, the data obtained may cause incorrect  analysis. It is very important that you read the following section  carefully and avoid this common mistake.

### **Old Analysis Results**

When you start a scan/search on VirusTotal, old results, if any, are  shown for faster results. For example, if you scan the URL  "letsdefend.io", you may see a result like the one below.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-18-1024x164.png)

If you pay attention to the area in the image above, you are viewing  the scan result 1 month ago. Since attackers know that you use the  VirusTotal platform a lot, they can follow this method: Generate a  harmless URL address and scan it in VirusTotal (For example  letsdefend.io/file). It then replaces the content of the URL with  something that is harmful. An amateur SOC analyst thinks the address is  harmless when he sees a green screen (where all security vendors give  the result Clean) when he searches VirusTotal.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-19.png)

But in this case, the analyst falls into the trap of the attacker.  All it needs to do is start a new query and view the analysis results of the current content in the URL address. By clicking the “**Reanalyse**” button, the analysis is performed again.

### **Detection Tags**

One of the points to consider when deciding whether a file is malicious or not via VirusTotal is how AV companies label it.

A file may have a detection rate of 10/52 on VirusTotal, but when you examine the tags, you can see that it's not actually harmful. The most  common example of this situation is setup files. In the setup files,  there may be advertisements that appear on the setup screen from time to time. Since AV engines generally work on a rule-based basis, they can  mark files with these ads as "Adware". For this reason, you may see  these types of files as “red” on VirusTotal.

For example, you can see the legitimate WinRAR setup file is marked as malicious in image below.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/VirusTotal+for+SOC+Analysts/images/image-20-1024x334.png)