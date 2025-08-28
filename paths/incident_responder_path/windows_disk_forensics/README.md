# Windows Disk Forensics

Windows Disk Forensics is a comprehensive course designed to equip participants with the knowledge and skills necessary to conduct digital  investigations and forensic analysis on Windows-based computer systems.  This course delves into the intricacies of collecting, preserving, and  analyzing digital evidence from Windows disks, ensuring that students  are well-prepared to navigate the complex world of digital forensics.

**Table of Contents:** 

- [SRUM Database](#srum-database)
- [Jumplists](#jumplists)
- [Recycle Bin Artifacts](#recycle-bin-artifacts)
- [Search Index](#search-index)
- [RDP Cache](#rdp-cache)
- [Thumbnail Cache](#thumbnail-cache)

**Evaluate Yourself with Quiz**

- [Windows Disk Forensics](https://app.letsdefend.io/training/quiz/windows-disk-forensics)

## SRUM Database

Windows System Resource Usage Monitor (SRUM) was first introduced in  Windows 8. SRUM tracks 30 to 60 days of system resource usage,  particularly application's resource usage, energy usage, Windows push  notifications and network connectivity, and data usage.

SRUM is considered a gold mine of forensic information, as it  contains all the activities that occur on a particular Windows system.  SRUM tracks and records program executions, power consumption, network  activities, and much more information that can be retrieved even if the  source has been deleted. This type of information enables the examiner  to gain insights into the previous activities and events on a system.

SRUM artifacts are stored in a file named SRUDB.dat located at

- **C:\Windows\System32\SRU\SRUDB.dat**

SRUM artifacts are stored in an Extensible Storage Engine (ESE)  database format. This database file contains multiple tables recoding  all the activities that occurred on a particular system.

There are multiple categories of data in SRUM db.

1. SRUM Application Resource Usage
2. SRUM Network Usage
3. SRUM Network Connections
4. SRUM Energy Usage
5. SRUM Push Notification Data
6. SRUM Energy Usage (Long Term)

We will discuss only 1 and 2 as these provides the most value. But  first, we will discuss how to analyze the data stored in this db. We  will be using a tool called srumEcmd by Eric Zimmerman to parse the  database and get the results in a CSV.

We first acquire the srum db file. We acquired using kape and placed  the acquired data in a folder called srum on desktop. Then we ran  SRUMEcmd . we provided the path of the srudb dat file as well as of the  software registry hive which kape also acquires alongside srum db. This  is because the current entries are not pushed in srum db as srum db gets updated at reboot or every hour.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/1-+SRUM+Database/images/Image+1.png)

Command used : 

```cmd
SrumECmd.exe -f "C:\Users\LetsDefend\Desktop\srum\C\Windows\System32\SRU\SRUDB.dat" -r "C:\Users\LetsDefend\Desktop\srum\C\Windows\System32\config\SOFTWARE" --csv "c:\users\letsdefend\desktop\results"            
```

Here switch “f” denotes path of srum db file, “r” switch denotes path to Software hive and –csv tells the tool where to save the results

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/1-+SRUM+Database/images/Image+2.png)

Here we have multiple results according to categories. Lets quickly discuss these.

**Application resource usage:**

This one is most important to us as it can serve as evidence of  execution. We can determine if any program or malware ran and at what  time. This can be chained to prove execution of an application with  other artifacts like prefetch.
SRUM Application Resource Usage is one of the most useful, and usually the noisiest, of the categories. That’s because it’s tracking every exe that’s executed on the system whether  it still exists on disk or not. If it is executed, it *should* be logged. SRUM Application Resource Usage stores the full path that the  application executed from. This can help us filter down to un-expected  application paths

We will use timeline explorer to open these csv files. Lets open the appresourceuse info csv.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/1-+SRUM+Database/images/Image+3.png)

We can find many entries in this category, but important for us would be the exe info which is full path of the executed executable, the  timestamp of when it was executed, and the username who executed it.  This would be very useful in cases where malware was executed on a  system. We can find exe executed from odd paths, or files with odd  names, the time when they ran.

We also get detailed resource usage info like bytes read, written or  cpu cycles used, Read-write operations, etc. These could be useful in  cases of miners causing more cpu usage or infostealers which could be  detected on basis of the bytes read and written.

For example, we got an alert that an attacker utilized anydesk.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/1-+SRUM+Database/images/Image+4.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/1-+SRUM+Database/images/Image+5.png)

We can see lots of bytes were Received read from memory and also written down (probably for caching)

**SRUM Network Usage:** 

This is the second most useful category after Application usage. The  SRUM Network Usage tracks wired and wireless connections and the network SSID (when wireless) the asset was connected to. It also captures  bandwidth usage in bytes sent and received by the application. As with  other SRUM categories, these results include the full path of the  application and the SID that executed it. If you suspect a data  exfiltration event, you can utilize these artifacts to see what  applications are responsible for the most data on the wire—either sent  or received—and correlate to the user behind them.

Lets analyze the artifacts of this category.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/1-+SRUM+Database/images/Image+6.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/1-+SRUM+Database/images/Image+7.png)

We can see the application ID (which can be used across the SRUM data categories to track a certain application), timestamps, the exe full  path, the username which executed the application, and most importantly  total number of bytes received and sent over the network. These are not  to be confused with bytes written and read from the previous category as those were for the Input/Output operations. Here these are the actual  network bytes sent and received. 

These are really helpful in case of data exfiltration as we can  easily spot an application transferring lots of bytes when it shouldn't. For example, if we spot an exe name notepad.exe transferring lots of  bytes that is surely suspicious and it could be a case of process  injection where malicious shellcode was injected into a legit notepad  process.

Note: You can use Timeline Explorer to analyze the artifact results  CSV in this and all upcoming lessons. It will be placed on the lab for  convenience.

### Questions

1 - At what time PowerShell was used to download malicious tools from the internet? Format (YYYY-MM-DD HH:MM:SS)

> **Answer:** 2023-09-28 18:25:00

2 - How many foreground context switches were made for the executable with the SRUM ID of 12629?

> **Answer:** 235

## Jumplists

The Jump Lists feature was first introduced with Windows 7 and  continued in later versions of Windows systems including Windows 11. The feature is designed to provide the user with quick access to recently  accessed application files and common tasks. 

The records maintained by Jump Lists are considered an important  source of evidentiary information during investigations. The analysis of Jump List files can provide valuable information about users’ historic  activity on the system such as file creation, access, and modification.  Examiners can utilize data extracted from Jump List files to construct a timeline of user activities. What makes this artifact more valuable is  the fact that the information is maintained on the system long after the source file and application have ceased to exist on the system. 

There are 2 types of jumplists in Windows:

1. Automatic destinations
2. Custom destinations

Each file consists of 16-digit hexadecimal number which is the AppID  (Application Identifier) followed by automaticDestinations-ms or  customDestinations-ms extension. Note that these files are hidden and  navigating through Windows Explorer will not reveal them even if you  turned on hidden items in Windows Explorer. They can be viewed by  entering the full path in the Windows Explorer address bar.

**AutomaticDestinations**

The AutomaticDestinations Jump List files are located in the following directory:

- **C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations**

These Jump List files are created automatically when the users open a file or an application. The files are Microsoft Compound File Binary  (CFB) file format, also referred to as OLE (Object Linking and  Embedding) files. These files contain streams of individual hexadecimal  numbered SHLLINK streams and a DestList stream.

**CustomDestinations**

The CustomDestinations Jump List files are located in the following directory:

- **C:\%UserProfile%\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations**

These are custom made Jump Lists, c reated when a user pins a file or an application to the Taskbar or Start Menu. The structure of these  files is different from AutomaticDestinations Jump List files; it  follows a structure of sequential MS-SHLLINK binary format.

To summarise this artifact gives recently accessed files and  applications information, recently accessed URLs from browsers, recently access documents, pdfs zips, settings all kinds of information.  Detailed analysis of this artifact can give us a very good overview of  all kinds of activities on the endpoint.

We will be using the Jumplist explorer tool by Eric Zimmerman to  analyze jumplists. But first lets do acquisition of jumplists using  kape. If you want to learn more about acquisition and triage checkout  the acquisition course on letsdefend.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/2-+Jumplists/images/Image+1.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/2-+Jumplists/images/Image+2.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/2-+Jumplists/images/Image+3.png)

We can see the jumplists files because these are acquired and triaged. These are hidden on live systems.

Anyway, select all these files under automatic destinations. Then do the same with a custom destination.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/2-+Jumplists/images/Image+4.png)

Note: You might encounter an error message. Simply ignore that.

Let's say we want to find out which files were interacted using  Notepad. We go to the notepad jumplist and we see the files accessed  using notepad.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/2-+Jumplists/images/Image+5.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/2-+Jumplists/images/Image+6.png)

We get the full file path, how many times it was accessed and the  timestamp of access. What's great about this artifact is that we also  get a timestamp when this file was created.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/2-+Jumplists/images/Image+7.png)

If we get lucky we can sometimes get pinned urls from browsers or  most often visited urls from the browsers. Just like our notepad  example, we can get many more use cases from this artifact like how a  certain application was used. For example we can find names of the word  documents, their timestamps and how many times they were interacted with from the jumplist file of microsoft word program.

On top of that we can also use jumplists as an artifact for finding  folder access like shellbags. This can be done from the jumplist file of windows explorer program. We get all the folders accessed via file  explorer, when they were created, when they were accessed, how many  times they were visited/interacted.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/2-+Jumplists/images/Image+8.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/2-+Jumplists/images/Image+9.png)

### Questions

1 - What is the name of the secret file which was accessed via Wordpad?

> **Answer:** Secret769121.txt.txt

2 - When was this secret file accessed? Please answer in UTC time format (YYYY-MM-DD HH:MM:SS)

> **Answer:** 2023-09-04 10:15:44

## Recycle Bin Artifacts

Windows Recycle Bin was first introduced with Windows 95 and  continued until Windows 11. A recycle bin is a temporary storage for the items that have been deleted by the user. The user then has the option  to remove the items permanently or recover them in case they were  deleted by mistake.

Windows recycle bin is considered an essential source of evidence  when conducting a forensic investigation, as any item that is deleted  via File Explorer and from any recycle bin aware program will be  initially placed into the recycle bin. Recycle bin artifacts retain  valuable information related to the deleted item such as the name of the deleted item, the original location of the item before deletion, the  size of the deleted item and the date and time when the item was  deleted.

This makes it a very valuable artifact during investigations as we  can potentially find malware or what steps were taken by an adversary at a given time such as deleting a file or folder.

Recycle bin artifacts are stored in files starting with "$I" which  is located within the user's SID sub-folder under recycle bin directory. The full path is as follows

-  C:\$Recycle.Bin\{SID}\$I######

These $I files contains metadata like file path, size, and timestamp  of deletion. For each $I file there exists a $R file if the item is not  permanently deleted. These $R files are the actual contents of the  deleted file itself.

We will use the RBcmd tool by Eric Zimmerman to parse the recycle bin data. First, we will acquire the recycle bin artifacts.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/3-+Recycle+Bin+Artifacts/images/Image+1.png)

Here we can see the acquired artifacts. Lets use RBcmd to parse these and get some data to analyze.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/3-+Recycle+Bin+Artifacts/images/Image+2.png)

Command used:

```cmd
RBCmd.exe -d c:\Users\LetsDefend\Desktop\RecycleBinArtifacts\ --csv c:\Users\LetsDefend\Desktop\results       
```

Here “d” switch indicates the directory to recursively search for the artifacts. In our case its the folder where we stored the acquired  data. “Csv” switch denotes the directory where to store the results.

Lets analyze the csv in timeline explorer.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/3-+Recycle+Bin+Artifacts/images/Image+3.png)

In our example, only 1 file was deleted for the demo so theres only 1 result.

We can see the UTC time when the file was deleted, the original filename and full path, and the size of the file in bytes.

From the above example, we see the file has double extension, this is a common technique used by attackers to trick users into executing  malware. It seems that the attacker deleted the file used for initial  access after getting persistent remote access.

### Questions

1 - What was the original full path of the file deleted?

> **Answer:** C:\Users\LetsDefend\Desktop\Collectors\Yrtxakdn.exe

2 - What was the size (byte) of the deleted file?

> **Answer:** 1113600

3 - At what time the file was deleted from the victim's computer? Please input in UTC format (YYYY-MM-DD HH:MM:SS)

> **Answer:** 2023-09-04 10:18:35

## Search Index

Windows Search is a desktop search platform that was first introduced by Microsoft in Windows Vista and continued with later versions of  Windows (Windows 7, 8 and 10). The service *"provides content indexing, property caching, and search results for files, e-mail, and other content".* In other words, Windows Search service acts as an internal dictionary  running in the background, collecting and indexing the content of the  system.

Whenever a user searches for a document, image or any other file  type, she is actually searching the Windows Search Index database rather than conducting the search in real time making the search process  easier and faster. The service is enabled by default; however, the user  can modify which files and folders are indexed via “Indexing Options” or even disable the feature altogether. 

Windows Search can be a valuable source of evidence during  investigations. The database contains a large amount of data related to  the files, images, videos, directories and other file types found on  Windows systems. In addition, Windows Search database may also collect  and index data from other sources such as Microsoft Outlook. What makes  Windows Search even more valuable is that users may not be aware of it.  The service is enabled by default, running in the background, collecting and indexing potential evidence without the user's knowledge.

The search index database is located at

\-  **C:\%USERPROFILE%\ProgramData\Microsoft\Search\Data\Applications\Windows\Windows.edb**

We can get partial contents of different files types like docx, pdf,  txt etc, browser history even if the history was deleted from the  browser. This artifacts makes a perfect evidence especially for insider  threats cases.

We will use a tool called SIDR which will parse the search index  database nicely and give results in csv format. The tool is available on github here [https://github.com/strozfriedberg/sidr](https://github.com/strozfriedberg/sidr)

Lets first acquire the search index database and then use the SIDR tool to parse it.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/4-+Search+index/images/Image+1.png)

Command:

```cmd
sidr.exe "c:\Users\LetsDefend\Desktop\Search index" -f csv -o c:\Users\LetsDefend\Desktop\results            
```

The first path is the directory where we have the acquired artifacts. The path after “o” switch is the path where the results will be stored. The “f” switch specifies the output format. Default is json but we will go with csv as it's easier to analyze in our opinion.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/4-+Search+index/images/Image+2.png)

We are most interested in FileReport Csv and the internet history one. Lets start by File Report.

In this csv we get the file name, the time it was modified,created,  accessed, its size, which users its owned by , the time it was indexed  by windows and added to the database , and most important of all the  partial content of the file. This tab is named “System search auto  summary”.

Lets look at results of a single file for this demo. Lets say we are  interested in a file Employee payroll.txt which was permanently deleted  from the system. The file and its contents would have been indexed and  we can recover the contents of it. Its important to note that search  index would keep the records for deleted files for a few days and after  that they would be removed from the database too.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/4-+Search+index/images/Image+3.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/4-+Search+index/images/Image+4.png)

Lets focus on the contents of the file.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/4-+Search+index/images/Image+5.png)

If we click we can see more of the contents.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/4-+Search+index/images/Image+6.png)

We can see that its name of employees and the amount looks like their salary each month.

This is how we can read the contents of any type of file. Now let's analyze the internet history report.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/4-+Search+index/images/Image+7.png)

We can see the urls and the website titles. 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/4-+Search+index/images/Image+8.png)

For example in above image we can see that when we downloaded the  SIDR tool which we used to parse search index artifact, it also got  indexed into search index.

And how can we forget this awesome training platform.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/4-+Search+index/images/Image+9.png)

We also get the time of url visit under the system link date visited column.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/4-+Search+index/images/Image+10.png)

From this we can conclude that this artifact is very informative and  covers large variety of evidences in forensics investigations

### Questions

1 - In  Question 1 from Jumplists lesson, there was a secret file which was  accessed on the victim machine. You have been tasked to find the  contents of the file because the file was deleted by the insider threat. What is the killcode?

> **Answer:** 652195142

2 - At 10:19:59 on 4 September 2023, which URL was accessed?

> **Answer:** https://f001.backblazeb2.com/file/EricZimmermanTools/MFTExplorer.zip

## RDP Cache

When a user connects to another system using RDP, small size (bitmap) images are stored in their RDP profile files, so that once the same  image is to be used in the session it can be fetched/pulled quicker. And the overall RDP session experience is enhanced in case of a slow  connection. This artifact can help us sometimes in identifying what the  user was seeing in their RDP sessions.

In the case of an  investigation which consists of lateral movement using RDP, one of the  most important pieces of evidence we would like to investigate is RDP  bitmap Cache files.

The cache is different for every user and is user specific

Its located at

- **C:\Users\<username>\AppData\Local\Microsoft\Terminal Server Client\Cache**

We can use this artifact in cases of lateral movement in internal  networks and it would help us uncover attackers activities on the  laterally moved victim.

We will use a tool called https://github.com/ANSSI-FR/bmc-tools .

We will get the output of lots small images which we can either view manually or use another tool called rdp cache stitcher https://github.com/BSI-Bund/RdpCacheStitcher .

We acquired the artifact and placed it in a folder named bitmap. Then we ran the bmc tools on the artifacts

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/5-+RDP+Cache/images/Image+1.png)

Command:

```cmd
python3 bmc-tools.py -s "C:\Users\LetsDefend\Desktop\bitmap\C\Users\LetsDefend\AppData\Local\Microsoft\Terminal Server Client\Cache" -d c:\Users\LetsDefend\Desktop\results -b        
```

Here the switch “s” specifies the source directory a.k.a directory  containing our cache files. The “d” switch specifies the directory where we want the resultant images to be stored.The “b” switch creates a  collage image, which helps us get the summary and a combined collage of  all other bitmap images.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/5-+RDP+Cache/images/Image+2.png)

We can see there are a lot of images, around 2024.

So how does this artifact provide value??. We can go through all  these images as they are just like screenshots of a RDP session, just  smaller in size. For example, the image below proves that there was a  folder called Regshot on the victim machine where attacker logged in via RDP.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/5-+RDP+Cache/images/Image+3.png)

Similarly, we will find many more small pictures of the whole screen. For example, if attacker ran commands on command prompt, or used the  browser or performed any action. We can uncover attacker activities with this. The only downside is this that this is very time consuming  especially in real cases, as there would be many images.

One helpful technique is to open the folder where all files are  placed and maximize the window. This way all images preview will be  displayed and we can make out what each image is.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/5-+RDP+Cache/images/Image+4.png)

Its still not very easy, but more efficient.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/5-+RDP+Cache/images/Image+5.png)

Here we can easily understand that whoami command was being ran.

I opened a random image from here, and as we can see below this  indicates that during this RDP session a GitHub repository was visited

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/5-+RDP+Cache/images/Image+6.png)

Remember that when using bmc tools we added a -b switch which creates a collage. If we search for keyword collage in the folder where all  bitmaps are stored, we will get a single file

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/5-+RDP+Cache/images/Image+7.png)

Lets view it

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/5-+RDP+Cache/images/Image+8.png)

this would give us all images combined and we can make the sense of  whole RDP session just alone from this if possible. So analyzing this is important.

Now we will explore RdpCacheStitcher tool, which can be more useful  than manual image analysis. IT will help us reconstruct a more  meaningful screenshot from all the small bitmap images.

Open the tool and go to file and new case. Then browse to the  directory storing all the bitmap images. Double click the directory and  then click select folder

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/5-+RDP+Cache/images/Image+9.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/5-+RDP+Cache/images/Image+10.png)

All the bitmap images will be loaded. Now you can play with the tool  however you want. We won't discuss this tool in detail as it is out of  scope for the lesson.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/5-+RDP+Cache/images/Image+11.png)

The images are still messed up but making sense of each image is more easier than before.

## Thumbnail Cache

ThumbCache is a feature in Windows operating systems available  starting from Windows Vista, which is used to cache thumbnail images of  files for Windows Explorer view. When you open Windows Explorer in  thumbnail view, the files within the folder are displayed as small  images that represent the contents of the files. These images are stored in a centralized Thumbnail Cache file. The purpose of this feature is  to avoid strenuous disk I/O, CPU processing, and load times. Microsoft  Windows stores thumbnails of many file types, some of which include:  JPEG, BMP, GIF, PNG, TIFF, AVI, PDF, PPTX, DOCX, HTML, MP4 etc.

Thumbnail cache files have been used by law enforcement agencies to  prove that a file of interest was stored on a Windows systems hard drive even if deleted. When a user deletes a file, its thumbnail remains in  the cached file. Analysis of the ThumbCache file yields information such as the metadata of the original file, its cache ID, header checksum,  data offset, data type, and data size. The metadata can give  investigators critical information like when the file was created, its  location on the file system, when it was last accessed, when it was last modified and much more.

ThumbCache Artifacts are stored in the following location:

- **C:\Users\[Username]\AppData\Local\Microsoft\Windows\Explorer**

These files are named as Thumcache_xxx.db and iconcache_xxxx.db where xxx is bits/pixel/res value. Lets take a look at these files.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/6-+Thumbnail+cache/images/Image+1.png)

We will get the thumbnail image of files, screenshots or images, size of the file, location of source cache file.

We will use a tool called ThumbCache Viewer to analyze these db files. You can download the free tool from here https://thumbcacheviewer.github.io/ . But first let's acquire the artifact using kape.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/6-+Thumbnail+cache/images/Image+2.png)

Now lets run thumbcache viewer.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/6-+Thumbnail+cache/images/Image+3.png)

Open file and click open. Then browse to the folder where acquired artifacts are stored and select all the thumbcache db files.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/6-+Thumbnail+cache/images/Image+4.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/6-+Thumbnail+cache/images/Image+5.png)

We have lots of lots of data. If we click on any filename interesting to us, it will open up the image. We have lots of bmp files in this  cache. This is because in the previous lesson we parsed the RDP cache  which resulted in 2000+ bitmap images.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/6-+Thumbnail+cache/images/Image+6.png)

We also see some PNG files. This db will show PEG, BMP, GIF, PNG,  TIFF, AVI, PDF, PPTX, DOCX, HTML, MP4 etc. Lets say we have a pdf  document which has an interesting title page. That title page would get  cached in this db and we can recover that even if the original pdf was  deleted.

Lets analyze the latest entry in the db

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/6-+Thumbnail+cache/images/Image+7.png)

If we double click on the b38570a01c180ac4.jpg  we see the image.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/6-+Thumbnail+cache/images/Image+8.png)

To add to context, the reason this image was cached in thumbcache data was because it was displayed as thumbnail of the image.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Disk-Forensics/6-+Thumbnail+cache/images/Image+9.png)

In File Explorer we made the view option “Extra large icons”, hence  the thumbnail saved in the db is in higher res. If we leave the file  explorer view option to something else like medium or small, then the  image in thumbcache db would be smaller and less clear.

Overall this artifact is indeed valuable as we can find evidence of  documents, and images which are long deleted from the system.

### Questions

1 - The threat intel team mentioned that the company's systems were hacked  and a JPG image was found in all of them. No data was stolen or  ransomed. Your task is to find what this jpg image is and belongs to  which group. 

Please answer the name of the hacker group. Format (XXXXXX group)

> **Answer:** Anonymous group

2 - What was the size (kb) of the image?

> **Answer:** 18































