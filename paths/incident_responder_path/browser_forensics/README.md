# Browser Forensics

This course will explain how you can acquire the browser data for the  incident response process. And you'll learn how you can use browser data as evidence to investigate security incidents.

**Table of Contents:**

- [Introduction to Browser Forensics](#introduction-to-browser-forensics)
- [Acquisition](#acquisition)
- [Browser Artifacts](#browser-artifacts)
- [Tool: BrowsingHistoryView](#tool-browsinghistoryview)
- [Manual Browser Analysis](#manual-browser-analysis)
- [Hindsight Framework](#hindsight-framework)
- [Practical Case: Corporate Policy Violation](#practical-case-corporate-policy-violation)
- [Practical Case 2: Insider Threat](#practical-case-2-insider-threat)

**Evaluate Yourself with Quiz**

- [Browser Forensics Quiz](https://app.letsdefend.io/training/quiz/browser-forensics-quiz)

## Introduction to Browser Forensics

Browser forensics is a type of digital forensics analysis that  involves examining web browsers and their associated artifacts in order  to extract evidence that can be used in a legal proceeding. This type of analysis can be useful for investigating threats such as insider  threats, a cause of compromise, data exfiltration.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/1-+Intro+to+browser+forensics/1.png)



The process of browser forensics typically involves the extraction and examination of web browser history, cache, and cookies.  

- **"Web browser history"** is a record of the websites that a user has visited and can provide important information about the user's online activities.  
- **"Cache"** is a temporary storage area for web content, such as images and text, that is used to speed up the loading of websites.  
- **"Cookies"** are small pieces of data that are stored on a user's computer and can be used to track the user's online activities.

In addition to analyzing these artifacts, forensics analysts should  also examine web browser extensions, which are small programs that can  be added to a web browser to add new features or functionality.  Extensions can be used for a variety of purposes, including improving  the user experience, enhancing security, or tracking online activities.  We will discuss these and some more artifacts in detail in the coming  lessons.

### Scope and Objectives

The goal of browser forensics is to provide investigators with a  clear picture of the events that occurred on a computer or device and to help establish a timeline of those events. This can be particularly  helpful in case of an incident where analysts can analyze a user's  browser activity to determine root cause of an incident like a malicious website visited or a phishing link clicked. By carefully examining the  artifacts left behind by web browsers, forensics analysts can gain  valuable insights into a user's online activities and can provide  important evidence in a legal proceeding.

Browser forensics can also be valuable for investigators looking to  understand the details of an attack on a computer or a device. By  examining the artifacts left behind by the web browsers, forensics  analysts can gain insights into how an attack was conducted and can help identify the source of malware, adware, spyware, malicious emails, and  phishing websites.  

 There are many different web browsers available, including Chrome,  Firefox, Safari, Internet Explorer, and Opera, and the specific browser  being used can impact the forensics analysis, however we will be  conducting this exercise with Chrome browser.

In addition to its role in the criminal investigations, browser  forensics can also be used in civil cases and in other legal proceedings where the examination of web browser artifacts may be relevant. For  example, browser forensics can be used to investigate potential  instances of workplace harassment or to uncover evidence of intellectual property theft. Overall, the role of browser forensics is to provide  investigators with a thorough understanding of a user's online  activities and to help uncover evidence that can be used in legal  proceedings.

### A Typical Scenario

A company has reported that sensitive customer information has been  leaked to a competitor. The company's IT department has conducted an  initial investigation and identified a potential suspect who is a  current employee of the company. The IT department has asked a forensics analyst to examine the employee's computer to determine if there is any evidence of the employee leaking the sensitive information.

The forensics analyst started a forensics image of the employee's  computer. He first extracted the web browser history, cache, and cookies from the user’s computer by using forensics acquisition tools like FTK  imager, Encase, Autopsy, etc. The analyst also examines the user's web  browser extensions to determine if any of them could be leveraged for  the stealing of sensitive information.

The analyst found that the employee had visited the competitor's  website multiple times and had also been using a web browser extension  that allows users to easily share files. Based on this information, the  forensics analyst is able to establish that the employee had been using  the company's computer to leak sensitive customer information to the  competitor. The analyst provides this information to the company's IT  department, which will support the company’s legal proceeding’s as an  evidence related to the employee's actions.

At the end of the course, you will be given 2 different cases related to browser forensics to test your skills learned in the course.

### Questions

1 - What is the goal of browser forensics?

A) Invading individuals privacy
B) Track user’s online activity to find cause of compromise
C) Find corporate policy violations
D) B and C

> **Answer:** D

2 - Browser extensions are not considered browser artifacts.

> **Answer:** False

## Acquisition

Forensic acquisition is the process of making a forensic copy of data from a computer's hard drive or other storage media. This process is  typically performed as part of a forensic investigation, in which the  copy of the data is used to extract and analyze evidence.

Forensic acquisition involves using specialized software and hardware to create a forensic copy of the data on the storage media. The  forensic copy is an exact duplicate of the original data, and it  preserves the integrity of the data, including any deleted or hidden  files. The forensic copy is then used to perform forensic analysis and  extract the relevant evidence. Forensic acquisition is an important step in a forensic investigation, as it allows investigators to preserve and analyze the evidence without altering or damaging the original data.  This helps to ensure that the evidence is admissible in court and can be used to support legal proceedings.

In a typical scenario, we would acquire a whole disk image of a  compromised or suspect endpoint to perform full disk analysis, not just  browser analysis. Tools like FTK imager, Autopsy, Axiom can help us take full copies of our disk, bit by bit . We can then carve out the browser artifacts from the browser storage locations from the disk image. It's  not recommended to perform forensic analysis on live image as data can  be corrupted or tampered unintentionally. We will not be discussing  acquiring disk images in this course as its out of scope, but we wanted  to discuss it here because it's the industry standard for forensics  investigations.

Browsers store user information like history, URLs visited, cache,  cookies, and etc. in sqlite databases and json format. We can parse  these to view the data relevant to us. 

For example below is the location where all the Firefox data like cache, cookies, bookmarks etc. are stored.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/2-+Acquisition/1.png)

Similarly Google Chrome has its own location where the user data is stored.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/2-+Acquisition/2.png)

Here are storage paths for some other common web browsers:

**Firefox:** “%USERPROFILE%\AppData\Roaming\Mozilla\Firefox\Profiles\”

**Edge:** “%USERPROFILE%\AppData\Local\Microsoft\Edge\User Data\”

**Opera:** “%USERPROFILE%\AppData\Roaming\Opera Software\Opera Stable”

We will discuss important artifacts found under Chrome storage  location (majority of our artifacts will be under the default folder  under the defined path), as to what they do, how they benefit us in our  forensic investigations, how to track user(s) activities in different  browsers using BrowsingHistoryView, how to manually analyze them using  database sqlite reader and how to do with automated tools like  Hindsight.

**Note:** We will only investigate Google Chrome browser artifacts in this course as it is the browser used the most, but the  techniques are applicable to any of the browser.

### Questions

1 - Forensics copy of data doesn't always need to be same of its original bit by bit.

**Answer Format:** True/False

> **Answer:** False

2 - What is the **full path** where majority of artifacts are stored?

**Note:** Firstly, connect to the LetsDefend lab machine.

> **Answer:** C:\Users\LetsDefend\AppData\Local\Google\Chrome\User Data\Default

## Browser Artifacts

Forensic artifacts are evidence or data that can be found on a  computer or other digital device. These artifacts can be used to help  identify who used the device, when it was used, and what it was used  for. Examples of forensic artifacts include temporary files, log files,  and deleted files, which can all contain important information that can  be used in a forensic investigation. In this lesson we will discuss  browser artifacts which helps investigating browser related activities  and in next lessons we will analyze these manually and use automated  tools.

Some common browser artifacts are:

- Search history
- Visited Websites
- Downloads
- Cookies
- Cache
- Bookmarks
- Favicons
- Sessions
- Form history
- Thumbnails
- Extensions

### Search History

Search history refers to information of any search terms used. This  information is important because it can uncover users' intentions on by  showing the exact URLs that the user typed in the search bar. The search history is saved in the SQLite database named “History” and is under  the “keyword_search_term” table.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/3-+Browser+Artifacts/1.png)

“Search History” Artifact is located at;  

- “**C:\Users\[username]\AppData\Local\Google\Chrome\User Data\Default\History**” on Chrome
- “**C:\Users\[username]\AppData\Roaming\Mozilla\Firefox\Profiles\[randomfoldername]\places.sqlite**” on Firefox
- “**C:\Users\[username]\AppData\Local\Microsoft\Edge\User Data\Default\History**” on Edge
- “**C:\Users\[username]\AppData\Roaming\Opera Software\Opera Stable\History**” on Opera

**Note:** It is worth mentioning that Microsoft Edge and Opera  have the same path and database names as Chrome. This is because these  browsers are all Chromium based meaning they have same backend engine.

### Visited Websites

This artifact refers to a person's browsing history, including the  URLs of websites visited, the dates and times of the sites visited. This information is a must for the browser investigations because we can  find users' online activity, only through this information which can  pinpoint the root cause of a compromise issue and speed up the  investigation. This data is also stored in the “History” SQLite database and is under the “visits” table .

“Visited Websites” artifact is located at; 

- “**C:\Users\[username]\AppData\Local\Google\Chrome\User Data\Default\History**” on Chrome
- “**C:\Users\[username]\AppData\Roaming\Mozilla\Firefox\Profiles\[randomfoldername]\places.sqlite**” on Firefox
- “**C:\Users\[username]\AppData\Local\Microsoft\Edge\User Data\Default\History**” on Edge
- “**C:\Users\[username]\AppData\Roaming\Opera Software\Opera Stable\History**” on Opera

### Downloads

This artifact stores the downloaded files, their names and the URLs  from where the resource was fetched. This is an excellent artifact as we can find out and investigate the file types that are downloaded which  can help identify any malicious executables. This data is also saved in  SQLite database named “History”, under the “downloads_url_chains” and  “downloads” table.

“Downloads” artifact is located at; 

- “**C:\Users\[username]\AppData\Local\Google\Chrome\User Data\Default\History**” on Chrome,
- “**C:\Users\[username]\AppData\Roaming\Mozilla\Firefox\Profiles\[randomfoldername]\places.sqlite**” on Firefox,
- “**C:\Users\[username]\AppData\Local\Microsoft\Edge\User Data\Default\History**” on Edge,
- “**C:\Users\[username]\AppData\Roaming\Opera Software\Opera Stable\History**” on Opera.

### Cookies

Cookies are small pieces of data that are stored on a users’ browsers by the websites they visit. Cookies help analyzing the websites that  set the cookies, the data stored in the cookies, and the expiration  dates of the cookies. These gives us information about the past web  sessions, domain names, and etc. This data is stored in SQLite database  “Cookies” (in network folder) and is under the “cookies” table.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/3-+Browser+Artifacts/2.png)

Cookies artifact is located at; 

- “**C:\Users\[username]\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies**” on Chrome,
- “**C:\Users\[username]\AppData\Roaming\Mozilla\Firefox\Profiles\[randomfoldername]\cookies.sqlite**” on Firefox,
- “**C:\Users\[username]\AppData\Local\Microsoft\Edge\User Data\Default\Network\Cookies**” on Edge,
- “**C:\Users\[username]\AppData\Roaming\Opera Software\Opera Stable\Network\Cookies**” on Opera.

### Cache

Web cache is a temporary storage location where the web-based data,  such as HTML pages and images, are stored. The goal of cache analysis is to identify, preserve, and analyze this data in order to reconstruct  the user's web browsing history and potentially uncover evidence. We can uncover frequently visited websites visited by users. This data is  stored in many data block files which are indexed using a separate index file.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/3-+Browser+Artifacts/3.png)

Cache artifact is located at; 

- “**C:\Users\[username]\AppData\Local\Google\Chrome\User Data\Default\Cache\Cache_Data**” on Chrome,
- “**C:\Users\[username]\AppData\Roaming\Mozilla\Firefox\Profiles\[randomfoldername]\webappsstore.sqlite**” on Firefox,
- “**C:\Users\[username]\AppData\Local\Microsoft\Edge\User Data\Default\Cache\Cache_Data**” on Edge,
- “**C:\Users\[username]\AppData\Local\Opera Software\Opera Stable\Cache\Cache_Data**” on Opera.

**Note:** Only Opera cache is saved under “\Appdata\Local\*”, the rest of Opera data is stored under “\Appdata\Roaming\”

### Bookmarks 

Bookmarks are common artifacts in browser forensics, as they are a  record of the web pages that users may have saved for later access. In  most web browsers, bookmarks are stored in a dedicated folder or list,  and they can typically be accessed by clicking on a "bookmarks" or  "favorites" button. In browser forensics, bookmarks can be an important  source of evidence, as they can provide information about the web pages  that a user visits on a regular basis and the topics they are interested in. Reviewing bookmarks help reconstruct users’ web browsing history  and identify patterns of behavior. Bookmarks are stored in a JSON file  named “Bookmarks” under default directory.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/3-+Browser+Artifacts/4.png)

Bookmarks artifact is located at; 

- “**C:\Users\[username]\AppData\Local\Google\Chrome\User Data\Default\Bookmarks**” on Chrome,
- “**C:\Users\[username]\AppData\Roaming\Mozilla\Firefox\Profiles\[randomfoldername]\places.sqlite**” on Firefox,
- “**C:\Users\[username]\AppData\Local\Microsoft\Edge\User Data\Default\Bookmarks**” on Edge,
- “**C:\Users\[username]\AppData\Roaming\Opera Software\Opera Stable\Bookmarks**” on Opera.

### Favicons 

Favicons, also known as favorite icons, are small graphical images  that are associated with a particular web page or website. These images  typically appear in the address bar of a web browser, next to the web  page's title or URL, and they are also often used as icons for  bookmarking a page. In browser forensics, favicons can be an important  source of evidence, as they can provide information about the web pages  that users visit on a regular basis and as sell as the websites they are interested in. Important thing about this artifact is that the domain  name of the website is recorded from where the favicon icon was loaded  at the time of the request. So if the history file is removed from  storage location, the websites names are still saved in favicon  database. It is worth noting that not every website may have a favicon  and especially the malicious ones. Also this artifact is a bit  inconsistent in newer versions of browsers so we cannot fully rely on  it. This is stored in a sqlite database named “Favicons” under default  directory.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/3-+Browser+Artifacts/5.png)

Favicon artifact is located at; 

- “**C:\Users\[username]\AppData\Local\Google\Chrome\User Data\Default\Favicons**” on Chrome,
- “**C:\Users\[username]\AppData\Roaming\Mozilla\Firefox\Profiles\[randomfoldername]\favicons.sqlite**” on Firefox,
- “**C:\Users\[username]\AppData\Local\Microsoft\Edge\User Data\Default\Favicons**” on Edge,
- “**C:\Users\[username]\AppData\Roaming\Opera Software\Opera Stable\Favicons**” on Opera.

### Session file 

Session files are artifacts that can provide information about users’ web browsing activities even though its deleted history file is removed from the disk. This file contains information about the web pages that  were open in the browser at a specific point in time during the last  session. This information can include the URLs of the web pages, the  titles of the pages, and any text that was entered into web forms. In  some cases, these files can also contain information about the users’  browsing history and any cookies that were stored by the browser.  Reviewing session and tab files can help reconstruct users’ web browsing history and identify patterns of behavior. In order to be useful, if  the user deletes history and closes the browser, the session file will  give valuable data as discussed. But if the user opens the browser for a new session, the previous session file will exist but its contents will be nullified and will be useless. This artifact can be useful for a  scenario when analyzing a terminated employee's data, his/her last  activities will be present in the sessions file. This is stored in a  SQLite database named “Sessions” under default directory.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/3-+Browser+Artifacts/6.png)

Sessions artifact is located at; 

- “**C:\Users\[username]\AppData\Local\Google\Chrome\User Data\Default\Sessions\***” on Chrome,
- “**C:\Users\[username]\AppData\Roaming\Mozilla\Firefox\Profiles\[randomfoldername]\sessionstore.jsonlz4**” on Firefox (1)
- “**C:\Users\[username]\AppData\Roaming\Mozilla\Firefox\Profiles\[randomfoldername]\sessionstore-backups\***” on Firefox (2)
- “**C:\Users\[username]\AppData\Local\Microsoft\Edge\User Data\Default\Sessions\***” on Edge
- “**C:\Users\[username]\AppData\Roaming\Opera Software\Opera Stable\Sessions\***” on Opera

### Form History 

Form history is an artifact that can provide information about the  text that a user has entered into web forms. Most web browsers have a  feature that saves users form data, such as the text they have entered  into search boxes or online forms, in order to make it easier for the  user to fill out similar forms in the future. In some cases, form  history can provide valuable information about a users web browsing  habits and interests, as well as any sensitive information that may have been entered into online forms. We can discover passwords, credit card  information and etc. through the “Form History”. This is stored in  SQLite database named “Web Data”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/3-+Browser+Artifacts/7.png)

This artifact is located at; 

- “**C:\Users\[username]\AppData\Local\Google\Chrome\User Data\Default\Web Data**” on Chrome,
- “**C:\Users\[username]\AppData\Roaming\Mozilla\Firefox\Profiles\[randomfoldername]\formhistory.sqlite**” on Firefox,
- “**C:\Users\[username]\AppData\Local\Microsoft\Edge\User Data\Default\Web Data**” on Edge,
- “**C:\Users\[username]\AppData\Roaming\Opera Software\Opera Stable\Web Data**” on Opera.

### Thumbnails 

Thumbnails are small, reduced-size version of a full-sized images or  videos that are typically generated by a web browsers. These thumbnails  are often used to help organize and navigate through large collections  of media files, and are commonly found in the cache or temporary files  of a web browser. They can provide valuable clues for forensic  investigators, as they can help identify the types of media that a user  has accessed or downloaded, and can also provide information about the  website or online service where the media is originated .

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/3-+Browser+Artifacts/8.png)

Thumbnails artifact is located at; 

- “**C:\Users\[username]\AppData\Local\Google\Chrome\User Data\Default\Top Sites**”on Chrome,
- “**C:\Users\[username]\AppData\Local\Microsoft\Edge\User Data\Default\Top Sites**” on Edge,
- “**C:\Users\[username]\AppData\Roaming\Opera Software\Opera Stable\Top Sites**” on Opera.

### Extensions 

Browser extensions , also sometimes referred as "Addons" is a small  piece of software that can be installed into a web browser to add  additional functionality or features. Extensions are typically used to  enhance the user experience, such as by providing tools for organizing  tabs, blocking ads, or saving passwords. Extensions can be malicious  either from a shady third party vendor , or it can be a case of supply  chain attack where legit extensions are hijacked and are made to do  malicious actions. This can be a good source of evidence in case  malicious extensions cause an incident. If you want to learn more about  malicious extensions you can [try to solve this](https://app.letsdefend.io/challenge/suspicious-browser-extension/) challenge on LetsDefend.io. Extensions metadata is stored under Extensions folder, and randomized named folders.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/3-+Browser+Artifacts/9.png)

Extensions artifact is located at; 

- “**C:\Users\[username]\AppData\Local\Google\Chrome\User Data\Default\Extensions\{randomfoldername}\***”on Chrome,
- “**C:\Users\[username]\AppData\Roaming\Mozilla\Firefox\Profiles\[randomfoldername]\extensions\***” on Firefox,
- “**C:\Users\[username]\AppData\Local\Microsoft\Edge\User Data\Default\Extensions\{randomfoldername}\***” on Edge,
- “**C:\Users\[username]\AppData\Roaming\Opera Software\Opera Stable\Extensions\{randomfoldername}\***” on Opera.

In next lessons we will explore these artifacts to gain invaluable experience vital for our investigations.

### Questions

**Note:** Please do not open Chrome browser in the lab as it can modify the data related to questions. Use the Microsoft Edge browser if  you need to use.

1 - What's the size of the favicon database?

**Answer Format:**  XX KB 

**Sample Answer:**  10 KB

> **Answer:** 44 KB

2 - What's the name of the first folder where extensions are stored?

> **Answer:** agohkbfananbebiaphblgcfhcclklfnh

## Tool: BrowsingHistoryView

In this lesson, we will be review a tool called “BrowsingHistoryView” by Nirsoft. BrowsingHistoryView is a utility that reads the history  data of different Web browsers (Mozilla Firefox, Google Chrome, Internet Explorer, Microsoft Edge, Opera) and displays the browsing history of  all these Web browsers in one table. The browsing history table includes the following information: Visited URL, Title, Visit Time, Visit Count, Web browser and User Profile. BrowsingHistoryView allows users to watch the browsing history of all user profiles in a running system, as well  as to get the browsing history from external hard drive. You can also  export the browsing history into csv/tab-delimited/html/xml file from  the user interface, or from command-line, without displaying any user  interface. BrowsingHistoryView tool is really helpful when it comes to  displaying information in a very friendly GUI view. It can parse  information from a live system or from disk image which is very  convenient for forensics investigations and it supports multiple  browsers. You can [download this tool](https://www.nirsoft.net/utils/browsing_history_view.html) at the following link for free.

We will be using the GUI version of this tool, but it is worth noting that there's a CLI version as well.

When we install and open the tool we see an advanced options menu  where we can apply filters according to our needs, select browsers we  want to target etc.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/4-+BrowsingHistoryView/1.png)

We can filter the web history by its age; by the date and time that  the URL visited exactly. You can see that we are setting the filter to  display data since the last 10 hours in the below example.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/4-+BrowsingHistoryView/2.png)

We can also specify the time range and the data to be displayed  during the specified timeline. This feature is particularly useful as a  Forensic Analyst or Incident Responder because if we know the time frame of when an incident occurs, we can apply date filters around those time frames to pinpoint the user activities before or after the incident.  This can help us find the cause of incident or objectives of the  attacker (in case of insider threats).

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/4-+BrowsingHistoryView/3.png)

Next, we have 2 types of string based filters:

### 1- Matching strings:

Matching Strings filter allows us to specify known strings which we  want to know if they exist in browser history or not. This can be useful if we have some known IOCs or domain names (Threat actor using multiple randomized subdomains) or we want to know if the user searched for  anything specific or not. We can specify multiple strings separated by a comma “,”.

Below example will display the URLs which have “letsdef” and “facebo” in the URL address. As you might have guessed, the below filter will  display all URLs which belong to letsdefend and/or facebook or have  these specified strings in URL (which is not likely).

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/4-+BrowsingHistoryView/4.png)

### 2- Non-Matching Strings

Non-Matching Strings filter allows us to specify known strings which  we don't want to be displayed. This can be useful if we want to cut down the noise and filter out known good URLs (Maybe common in organizations like company web portals etc.). We can specify multiple strings  separated by a comma “,”.

Below example will not display URLs which have “goog” and "githu"  string in URL address. We can guess that this filter will not display  any google or github domains.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/4-+BrowsingHistoryView/5.png)

We can use both these match/non-match filters concurrently which will make our analysis easier if we have large amount of data.

Next, we can select browsers from which to collect data;

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/4-+BrowsingHistoryView/6.png)

We can also select the user/profile to be analyzed on the system.  This can be very helpful in Active Directory environments or where  multiple users are sharing a workstation.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/4-+BrowsingHistoryView/7.png)

Now, lets explore this tool:

We selected everything default along with the Chrome browser only.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/4-+BrowsingHistoryView/8.png)

The tool displays the URL, the title of that page, the total number  of the connection to the site, the site where the traffic is redirected  from, as well as the total time that was spent on the URL.

Now let's apply a filter to display the URL related to letsdefend and cyberjunnkie sites.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/4-+BrowsingHistoryView/9.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/4-+BrowsingHistoryView/10.png)

In this lesson, we explored “BrowsingHistoryView” a very handy tool  to search through browser history with patterns of our preference. This  tool is mostly handy for Live machine analysis when the computer is used by more than one user like a shared workstation. 

In the next lesson we will cover the browser databases which we  discussed in the artifacts lesson and see what kind of data we can find.

### Questions

**Note:** Please do not open Chrome browser in the lab as it can  modify the data related to questions. Use the Microsoft Edge browser if  you need to use it.

**Note-2:** Make sure you set the date setting (Advanced Options) in  the "BrowsingHistoryView" tool to long enough. (For example, the last  1000 days.)

1 - How many times “github.com” was visited and the repository was not related to mimikatz tool?

> **Answer:** 9

2 - How many URLs are displayed when applying the matching filters for “google” and “youtube”?

> **Answer:** 16

3 - What is the YouTube channel name of the video streamed?

> **Answer:** LetsDefend

4 - How much time spent on visiting letsdefend blog?

> **Answer:** 00:07:26.104

## Manual Browser Analysis

In this lesson, we will manually analyze some of the artifacts we  previously discussed. We will use the "DB Browser for SQLite" tool to  read databases we discussed earlier. We will also use the strings tool  to read contents of session files which helps us recover online  activities even if history was deleted.

### DB Browser SQLite

DB Browser SQLite is a tool that helps viewing,  editing and deleting columns, tables, rows, etc. in a database  structure. It’s official descriptions says:

“DB Browser for SQLite (DB4S) is a high quality, visual, open source  tool to create, design, and edit database files compatible with SQLite.”

DB4S is for users and developers who want to create, search, and edit databases. DB4S uses a familiar spreadsheet-like interface, and  complicated SQL commands do not have to be learned.

You can download the tool at the [following link for free.](https://sqlitebrowser.org/dl/)

Once we install and run the tool, we first navigate to the folder  where most of our artifacts are stored:  “%USERPROFILE%\AppData\Local\Google\Chrome\User Data\Default”

**Note:** %USERPROFILE% is the user’s root location like “C:\Users\cyberjunkie\”

### Web History 

We will first analyze the “History” database and discuss what contents we can find.

Right click on the “History” file and select “Open with”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/1.png)

and then select “DB Browser for SQLite”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/2.png)

**Note:** If you can’t find “DB Browser for SQLite” here then you  can click on “More Apps” option and select the tool manually. Default  path of installation is “**C:\Program Files\DB Browser for SQLite\DB Browser for SQLite.exe**''

Now the file is open inside the tool.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/3.png)

“Database Structure” is the first tab that displays the name if the  tables and some more database metadata. Table names are useful for our  analysis because the name tells us what data is stored under the table.  Like in the above example the URLs table will have the URLs that the  users visited.

The data will be viewed in “Browse Data'' tab. Here we can view the columns and rows of each table.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/4.png)

In the Table dropdown menu, we can select the table which we want to analyze.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/5.png)

Let’s select the URL table and view the data.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/6.png)

We can see the visited URLs. Now let’s download a file using Chrome  browser and then view the downloads table of the history database.

**Note:** Remember that the database file should not be open while the browser is open as it can corrupt the database.

We downloaded an image to show you this artifact.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/7.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/8.png)

We can see the file location, and the URL where the file was  downloaded from in the referrer tab. This information can be useful in  determining malicious websites and downloads.

### Favicon 

Next, we will explore the “Favicon” database which gives us the  visited websites information. This artifact can be useful because if the history file is deleted, we can find visited URLs here. It is important to note that this table only displays websites which have favicons,  those without favicons will not be stored here. We need to select the  “favicon” table to be able to see the data stored here.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/9.png)

Some websites don't store their assets like favicons in their main  domain. They use subdomains or cloud storage. We can still have an idea  on what domain it belongs to by looking at the URL. For example the 4th  favicon URL“paypalobjects.com” indicates that the user visited PayPal  website. This way we can track what type of websites were visited by the user.

### Top Sites 

Another good source of gathering user online activity is the “Top  Sites” database. This also gives us information on the websites that the user visits if the history file is deleted.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/10.png)

### Web data 

This artifact can prove to be a goldmine for a forensics analyst.  Whenever a user fills login information, credit card information,  addresses or any other type of data that the browser can save the  browser asks us whether we want to save the information and when next  time we visit the same website, that data gets auto filled and user does not need to fill out the required information if we save them.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/11.png)

All this data gets saved in "web data" database. We can also retrieve the URL history, typed keywords in front this valuable artifact. Now  let's open this database and see:

We can get valuable information regarding websites visited, the favicon information etc. from the “keywords” table.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/12.png)

We can find emails, usernames etc. from the "autofill" table.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/13.png)

We can recover some of the credit card information like the card  number, and the expiration date and such. Credit card numbers are mostly encrypted depending on the payment gateway. If we are lucky we can get  our hands on the credit card numbers, CVV code, card expiration date.  Credit card forms do not store credit card numbers and CVV normally due  to the nature of the data, while the expiration date is stored since  it's not as sensitive in nature. However, it still depends on the  developer of the credit card payment gateway, the payment API being used etc. This also allows us to track the user's online transactions and  the type of the goods and services that the user has purchased.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/14.png)

We can find information like the address, and the phone numbers, etc. if the user saves these data on the browser. In the below image, we  input address in a form as "Letsdefend” and we can see that in table  “autofill_profile_addresses”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/15.png)

We can find more personal data depending on how the users’ usage  habits of the browser. The “web data” database is a very valuable  artifact as it can provide us vast amount of personal information about  the individual’s user habits.

### Extensions 

We have discussed extensions and how they hold the forensic value.  Now we will find information about extensions installed on our browser.

Go to the path “**C:\Users\[username]\AppData\Local\Google\Chrome\User Data\Default\Extensions\**”

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/16.png)

You will see randomized folders in this location. Each folder belongs to an extension/add-on installed on the browser. We will need to go  inside the folders and find the name of extensions by reading metadata  files or viewing the icon images etc. We can do this automatically using tools like Hindsight which we will discuss in the next lesson.

Let’s go to the first folder and take a look at the files to find information about the extension.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/17.png)

We can also determine the extension by the images.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/18.png)

Extension analysis and version information would really help us if  especially the system was compromised via a malicious extension. We can  perform the analysis for that extension and setup measures like blocking that extension etc.

As we can see, this FoxyProxy extension which is a handy proxy directly from the browser.

### Session file 

We will analyze the session files now. As previously mentioned, the  session file will provide us a good value only if the user deletes the  history and closes the browser. But if the user opens the browser as a  new session, the previous session file will still exist but its contents will be nullified and will be useless. We will delete the history of  the user session then close the browser, then analyze the latest session file (as there will be multiples of them). We will open this file with  the ‘strings’ tool from sysinternal to be able to read it as contents of the session file are not in a user friendly format to read. You can  download this tool from [here](https://learn.microsoft.com/en-us/sysinternals/downloads/strings).

Path for the session files is “**C:\Users\[username]\AppData\Local\Google\Chrome\User Data\Default\Sessions**”

We will use strings via cmd on this file.

**Note:** Remember to add the file path in quotes. The a (-a) switch stands for ASCII only.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/19.png)

For better visibility redirect the output to a file.

Full command will be:  

> **Command:** "strings64.exe -a  "C:\Users\[username]\AppData\Local\Google\Chrome\User  Data\Default\Sessions\Session_Filename" > filename.txt“

We get some information about the user activity even though the history was deleted.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/5-+Manual+Analysis/20.png)

In this lesson we explored how to navigate and utilize different type of browser data stored in SQLite databases using a simple database  viewer tool. This approach can help us dig deeper and find more  information that the automated tools may miss out due to the nature of  the data and the tool. Something that an automated tool won’t define as  important enough may be a deal breaker to help solve the case. The more  the data, the more context and evidence we have. But this doesn't mean  you shouldn't use automated tools as there's a very limited triage time  during incident investigations so automated tools are great for quick  analysis. Manual approach is suitable for forensics analysis where we  try to investigate deeply on how the incident occurred. 

**Note:** Please do not open Chrome browser in the lab  as it can modify the data related to questions. Use the Microsoft Edge  browser if you need to.

### Questions

**Note:** Please do not open Chrome browser in the lab as  it can modify the data related to questions. Use the Microsoft Edge  browser if you need to.

1 - What's the last visit time for LetsDefend blog page?

**Answer Format:**  number

> **Answer:** 13315307105586173

2 - What's the GUID value for download of the LetsDefend logo?

> **Answer:** ffd210b3-5770-45e2-af05-538a4ada5112

3 - What's the fourth top visited site? (Full URL)

**Answer Format:** https://www.........../

> **Answer:** https://www.youtube.com/

4 - What's the favicon URL for Youtube according to evidence found?

> **Answer:** https://www.youtube.com/s/desktop/25bf5aae/img/favicon_32x32.png

5 - What is the email address of the user?

> **Answer:** letsdefendisawesome@letsdefend.io

## Hindsight Framework

This tool is of great assistance to speed up the browser forensics  process. It automatically parses and displays valuable browser  information which we would typically do by browsing databases as  discussed in the previous lesson. Official description for Hindsight is  as follows:

Hindsight is a free tool for analyzing web artifacts. It started with the browsing history of the Google Chrome web browser and has expanded  to support other Chromium-based applications - with more to come!  Hindsight can parse a number of different types of web artifacts,  including URLs, download history, cache records, bookmarks, autofill  records, saved passwords, preferences, browser extensions, HTTP cookies, and Local Storage records.

You can get this tool [from here](https://github.com/obsidianforensics/hindsight/releases/tag/v2021.12).

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/6-+Hindsight/1.png)

We will use the GUI version which will let us interact with the tool on the local port.

When you run the binary, Windows smartscreen will prevent execution but run it anyway.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/6-+Hindsight/2.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/6-+Hindsight/3.png)

Now, access the tool in your browser through “http://localhost:8080” address. If you are analyzing Chrome present on your live system, we  suggest to run this tool on another browser like Microsoft Edge, or  Firefox. This is recommended so we don't tamper with potential artifacts and evidence by using the same browser on which analysis is to be  performed.

This is how the main interface looks like.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/6-+Hindsight/4.png)

First, we select the the browser we want to analyze in the input  type. This tool is still new in the wild and is actively developed so  for now it only supports Chrome and Brave browsers.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/6-+Hindsight/5.png)

Then, we need to input the storage location where the browser data is saved in “Profile Path” Input. This can be the default location which  we have been referring to since the beginning of this course or it can  be a custom path which can be used if you have imported disk image or  artifacts files from other computer under investigation.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/6-+Hindsight/6.png)

The plugin selector allows us to select plugins we want to use. For  most of the cases, all are recommended to be selected since we want as  much information as possible. If however you have some use case where  you only want to review some specific extensions you can only select the relevant plugin. We will use all plugins in this example.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/6-+Hindsight/7.png)

It also shows us the default Chrome data location for different operating systems which is convenient.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/6-+Hindsight/8.png)

Now we will just click “Run” on the lower right corner. We will be  redirected to a results page shortly where we will be given an overview  of type of artifacts that were found and parsed, and the plugins  produced valuable data.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/6-+Hindsight/9.png)

We can view the data as an Excel sheet, JSON or SQLite database and  analyze them just like we did in the previous lesson but in this case we will have correlated artifacts results under the same database saving  us a lot of time. It also has a convenient SQLite engine built in which  allows us to navigate the database right from the browser and also  execute SQL queries to get desired results in no time.

We can select the available tables to analyze the data.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/6-+Hindsight/10.png)

Here, we have “installed_extensions” table selected and it displays  the information about the plugins. We explored this same type of data in manual analysis but this time the tool has done it automatically.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/6-+Hindsight/11.png)

Next up, we have a “storage” table selected which displays  information parsed from cookies, cache, and "Web data'' database which  stores auto fills, and form history information.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/6-+Hindsight/12.png)

### Recovering Deleted Information

Another great feature of Hindsight is that it is capable of analyzing the “Site Characteristics” database. It is a feature of Chrome that  tracks different behaviors on websites, such as if the site changes the  title, favicons etc. It works by holding a key/value pair where the key  is MD5 hash of origin, website and value is a protobuf value. Protocol  Buffers (Protobuf) is a free and open-source cross-platform data format  used to serialize structured data. It was developed by Google to be  mainly used in Google products. We won't go in detail about what this  value is but we rather go over how this proves it is effective  forensically. Hindsight calculates MD5 sum of every origin URL it finds  from any of the artifacts and compares it with the key in the “Site  Characteristics Database”. If any match exists then that key in site  characteristics is replaced with the origin URL. For no matches the key  value remains as MD5 hash. We can prove that a user visited a particular website using this technique when history is deleted. This artifact can help us find origin of the URLs that have no trace in other artifacts.  If we want to find traces of specific websites we visit, then we can  calculate md5 sums of the URLs we want to find and compare them with the key MD5 values.

Let’s see this in action. Our third table was a timeline which  displays data in chronological order. Here we can see the data from  “History” database, "Top Sites" database, “Bookmarks” database, and etc. which shows us the URL information. The first row shows the above  procedure we discussed in action. We visited letsdefend website from the browser and deleted the history. But we can still find the evidence of  the domain.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/6-+Hindsight/13.png)

We can also use the “SQL queries” to see the type of column we want  to see. For example, if we only want to see the URLs in timeline table,  then we should enter this query: SELECT URL FROM 'timeline' LIMIT 0,30”  which basically means to display the URL column from a table named  ‘timeline’ and Limit the display to 30 rows on each page.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Browser-Forensics/6-+Hindsight/14.png)

We can also display multiple columns or data from different tables according to our needs.

In this lesson, we have discussed how quick and valuable using Hindsight in browser artifacts investigations.

### Questions

**Note:** Use Microsoft Edge to open localhost:8080 after running the Hindsight.

1 - What's the app_id for the found extension? (ag....)

> **Answer:** agohkbfananbebiaphblgcfhcclklfnh

2 - What's the extension name installed by the user? 

> **Answer:** CC Search

3 - What's the value of ‘key’ of Google website with sequence value of ‘45’?

> **Answer:** sb_wiz.zpc.gws-wiz.

4 - Which website (domain) was deleted from history?

**Answer Format:** XXX.XXX

> **Answer:** linkedin.com

## Practical Case: Corporate Policy Violation

In this lesson, you will test your practical skills on what you have learned so far through the previous lessons. 

### Scenario 

We have serious concerns for an employee’s performance as he is lagging  behind his tasks all the time. He spends 8 hours in the office on  working days, arrives on time but doesn't get the work done. Project  leader suspects that the employee wastes his time online. You are given  the browser data of the employee's computer to track users' activities.

### Questions

**Note:** You can use any of the tools and methods we discussed in  this course. Case 1 artifacts are located in a Folder named “Case 1  (Policy violation)” in the Desktop.

1 - In which department does the user work?

A) IT
B) Finance 
C) Marketing
D) SOC

> **Answer:** B

2 - Which entertainment website (domain) the user visited?

**Answer Format:** XXX.XXX

> **Answer:** netflix.com

3 - What's the user’s email address?

> **Answer:** cyberjunkie@letsdefend.io

4 - Which extension was used to bypass restricted content?

**Answer Format:** Full name

> **Answer:** Browsec VPN - Free VPN for Chrome

5 - What is the version of the extension from the previous question?

**Answer Format:** X.XX.X

> **Answer:** 3.60.0

6 - Which country does the VPN IP belong to?

**Answer Format:** Full name

> **Answer:** Netherlands

## Practical Case 2: Insider Threat

### Scenario 

SOC team found a spike in the network bandwidth that causes degraded  network performance. We noticed that large amount of data was uploaded  from an employee’s workstation within the IT department. You are given  the browser data of employee’s computer to track users' activities.

### Questions

**Note:** You can use any of the tools and methods we discussed in  this course. Case 2 artifacts are located in a Folder named “Case 2  (Insider threat)” in the Desktop.

1 - Which Programming language does the user seem he is interested in?

> **Answer:** rust

2 - Which domain is used to exfiltrate the data?

**Answer Format:** XXXX.XX

> **Answer:** mega.nz

3 - What's the **full URL** where the data was uploaded?

**Answer Format:** https://......

> **Answer:** https://mega.nz/folder/EbYzmArB#pGa20vWZiYjNxf-3plTiYQ

4 - What's the folder name where the data was uploaded?

> **Answer:** Exfiltrated

5 - What was the password with which exfiltrated data was encrypted?

> **Answer:** tuwngmlsicneguksnfgek74g0i1d







