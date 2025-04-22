# Malicious Document Analysis

Attackers have taken advantage of documents by using macros. And macros have been used by malicious actors to deliver malware. With this course, we'll teach you how you can analyze these things with static and dynamic analysis.

**Table of content:**

- [Introduction to Malicious Document File Analysis](#introduction-to-malicious-document-file-analysis)

- [Static Malicious Document Analysis](#static-malicious-document-analysis)
- [More Details About Document File Analysis 1](#more-details-about-document-file-analysis-1)
- [More Details About Document File Analysis 2](#more-details-about-document-file-analysis-2)
- [Analysis with Sandboxes](#analysis-with-sandboxes)

**Challenge**

- [Excel 4.0 Macros](https://app.letsdefend.io/challenge/Excel-40-Macros)

- [Malicious Doc](https://app.letsdefend.io/challenge/malicious-doic)
- [Malicious VBA](https://app.letsdefend.io/challenge/Malicious-VBA)

## Introduction to Malicious Document File Analysis

**Video link:** https://youtu.be/Q9MhydfhzzY

## Static Malicious Document Analysis

**Video Link:** https://youtu.be/p3AQjmEvApI

### Questions

1 - What is the MD5 value of the "/root/Desktop/QuestionFiles/PO-465514-180820.doc" file?

> **Answer:** d7e6921bfd008f707ba52dee374ff3db

2 - What is the file type of the "/root/Desktop/QuestionFiles/PO-465514-180820.doc" file?

> **Answer:** doc

## More Details About Document File Analysis 1

**Video Link:** https://youtu.be/RRbrLuYXdTw

## More Details About Document File Analysis 2

**Video Link:** https://youtu.be/ym6Crrn-D2c

### Questions

**Note:** Before starting, install the oletools: "sudo -H pip install -U oletools"

1 - Does the file "/root/Desktop/QuestionFiles/PO-465514-180820.doc" contain a VBA macro?

**Answer Format:** Y/N

> **Answer:** Y

2 - Some malicious activity occurs when the document file  "/root/Desktop/QuestionFiles/PO-465514-180820.doc" is opened. What is  the macro keyword that enables this?

> **Answer:** Document_open

3 - Who is the author of the file "/root/Desktop/QuestionFiles/PO-465514-180820.doc"?

> **Answer:** Alexandre Riviere

4 - What is the last saved time of the "/root/Desktop/QuestionFiles/PO-465514-180820.doc" file?

> **Answer:** 2020-08-18 08:19:00

5 - The malicious file "/root/Desktop/QuestionFiles/Siparis_17.xls" is  trying to download files from an address. From which domain is it trying to download the file?

> **Answer:** hocoso.mobi

6 - How many IOCs are in the "/root/Desktop/QuestionFiles/Siparis_17.xls" file according to the Olevba tool?

> **Answer:** 2

## Analysis with Sandboxes

**Video Link:** https://youtu.be/angOCPFG4P8

### Questions

**Note:** You can install Firefox on the Linux machine to upload the malicious file to Hybrid-Analysis or just use the hash search feature  on Hybrid-Analysis.

1 - The file "/root/Desktop/QuestionFiles/PO-465514-180820.doc" is trying to make a request to a domain ending with ".kz". What is this domain?

> **Answer:** www.msbc.kz

2 - With which Windows tool are the connection requests made? (File: /root/Desktop/QuestionFiles/PO-465514-180820.doc)

> **Answer:** powershell.exe

3 - How many addresses does the file send DNS requests to? (File: /root/Desktop/QuestionFiles/PO-465514-180820.doc)

> **Answer:** 5

4 - The "/root/Desktop/QuestionFiles/Siparis_17.xls" malware document is  trying to download a file. With what name does he want to save the file  it is trying to download to the device?

> **Answer:** 6LeGwKmrm.jar