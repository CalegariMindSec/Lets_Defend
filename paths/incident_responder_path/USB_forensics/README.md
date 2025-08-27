# USB Forensics

Dive  into the intricacies of USB forensics with this comprehensive course,  where you'll gain practical expertise in the extraction and analysis of  digital evidence from USB devices. Through a combination of theoretical  insights and hands-on exercises, participants will explore the  complexities of USB data storage, file structures. The curriculum covers forensic imaging, the identification of key artifacts, providing  essential skills for conducting effective investigations. Whether you're a seasoned professional or new to the field, this course ensures you  are well-prepared to navigate the challenges of USB forensics, including legal considerations and ethical best practices.

**Table of Contents:**

- [Introduction to USB Forensics](#introduction-to-usb-forensics)
- [USB Registry Key](#usb-registry-key)
- [USB Event Logs](#usb-event-logs)
- [Folder Access Analysis via Shellbags](#folder-access-analysis-via-shellbags)
- [File Access Analysis via Jumplists](#file-access-analysis-via-jumplists)
- [Automated USB Parsers Tools](#automated-usb-parsers-tools)

**Evaluate Yourself with Quiz**

- [USB Forensics](https://app.letsdefend.io/training/quiz/usb-forensics)

**Challenge**

- [USB Forensics](https://app.letsdefend.io/challenge/usb-forensics)

## Introduction to USB Forensics

Universal Serial  Bus(USB) flash drives, commonly known as USB flash drives are the most  common storage devices that can be found as evidence in Digital  Forensics Investigations. Using USB and external drives in the workplace may let nasty users remove/exfiltrate sensitive or confidential  information from a system without any authorization. To resolve this  issue, forensic examination of systems comes into the picture.

In this course, we will discuss how USBs can be used as evil and pose a  threat to your organization. We'll delve into the forensic analysis of  USBs, exploring methods to uncover comprehensive data and contextual  information related to the use of USB devices on Windows systems. We  will discuss how to find timestamps indicating the initial connection,  last connection, and disconnection of the USB to help create a forensic  timeline for the incident. We will also look through different kinds of  native event logs that can be leveraged as evidence in incidents.  Finally, we will discuss how to find the interacted files, how they are  placed in the USB, and the USB devices' full paths to understand the  suspect user's motivations.

## USB Registry Key

In this lesson, we will discuss few registry paths that store USB-related information.

The first location we  will discuss is the USBSTOR key which only holds information about  external storage media/drives like USB, hard drive, etc.

**Registry Key:** HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/2.USB+Registry+Key/image2_1.png)

USBSTOR is one of the  first pieces of evidence in common forensics analysis including USB  devices in the incidents. We can get information regarding the USB like  its model and version name, the Windows-assigned serial number, the last connected timestamp, etc. These elements are crucial and can  significantly contribute to determining the root cause of incidents,  shedding light on the potential role of the USB, if any, in the  occurrence.

Let's open up the SYSTEM  hive with Registry Explorer. If you don't know how to use Registry  Explorer, it is recommended to take this course:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/2.USB+Registry+Key/image2_2.png)

This subkey is located  under the USBSTOR key and is generated after connecting a USB to the  system. Upon expansion, this reveals a randomly named key, which  corresponds to the device's assigned serial number by the USB.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/2.USB+Registry+Key/image2_3.png)

If we click on this we see a wealth of information regarding this device.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/2.USB+Registry+Key/image2_4.png)

We can see the Friendly  Name of the attached USB. This can be important in investigations,  especially insider threat cases. Another thing to note is the container  ID which can be pivotal in contextual analysis from different data  sources.

Next, let's expand this  key further, then navigate to the 'Properties' key. From there, expand  the key that begins with '83daxxx'.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/2.USB+Registry+Key/image2_5.png)

This subkey will contain  additional subkeys. Look for the key labeled '0064,' which holds the  timestamp indicating when the USB was connected to the system.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/2.USB+Registry+Key/image2_6.png)

In the data section, we can see the timestamp in UTC.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/2.USB+Registry+Key/image2_7.png)

In the “0066” key we can find the timestamp when the USB was disconnected from the system.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/2.USB+Registry+Key/image2_8.png)

This is very important as it will help create a forensics timeline for analysis.

There's another Registry key we want to touch briefly on. The path to this is:

**Registry Key:**   HKLM\SYSTEM\CurrentControlSet\Enum\USB

This key contains information about all the devices connected through USB ports (For example keyboards, adapters, etc.)

Let's show an example from our case. This key follows the same hierarchy as discussed before.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/2.USB+Registry+Key/image2_9.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/2.USB+Registry+Key/image2_10.png)

As we can see this is a  Bluetooth adapter. Similarly, we can confirm the type of device from the Service Value. Here in this example it's BTHUSB which speaks for  itself.

In the previous USB  example, the service type was disk which confirmed whether it was a mini USB or an external drive attached via a USB port.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/2.USB+Registry+Key/image2_11.png)

In this lesson, we have  discussed artifacts from the Windows registry that could be found as  part of the analysis. In the next lesson, we will talk about artifacts  found in Windows events logs.

### Questions

**Note:** Use the "C:\Users\LetsDefend\Desktop\QuestionFiles\Acquisition.zip" file for solving the questions below.

1 - What is the serial number assigned by Windows to the USB device?

> **Answer:** 5639311262174133917&0

2 - What is the ClassGUID value for the USB device in question?

> **Answer:** {4d36e967-e325-11ce-bfc1-08002be10318}

3 - When did the USB Device connect first to the system? 

Answer Format: YYYY-MM-DD HH:MM:SS

> **Answer:** 2023-11-13 08:32:23

## USB Event Logs

While registry artifacts  offer substantial value in USB device investigations, we'll delve into  lesser-known log sources native to Windows, enriching our analysis with  additional context. In forensics it's always a good practice to have  multiple data sources pointing to the same fact/information, minimizing  room for error.

We will discuss these event logs:

1. Partition  
2. Kernel-PnP  
3. NTFS  

Open the event viewer and go to: “Application and Services Logs” -> Microsoft -> Windows.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/3.USB+Event+Logs/image3_1.png)

Now if you scroll you will find many different log sources, a few of which we will be discussing here.

### Partition

Now scroll to the partition log source from the above-mentioned log sources.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/3.USB+Event+Logs/image3_2.png)

We are interested in event ID 1006:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/3.USB+Event+Logs/image3_3.png)

If we go to the details  tab of the event corresponding to the timestamp identified in the  registry artifacts we can see detailed information about the connected  USB. Furthermore, the timestamp of this event aligns with the time of  the USB connection, further affirming the timestamp is 08:05:07 AM on  October 23, 2023.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/3.USB+Event+Logs/image3_4.png)

We can see all the  detailed information such as the Disk size of the USB in bytes, the  serial number, the manufacturer, and the model.

### Kernel-PnP

Go to the relevant log source.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/3.USB+Event+Logs/image3_5.png)

We are interested in Event IDs 400 and 410:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/3.USB+Event+Logs/image3_6.png)

Let's look closer into the event id 400:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/3.USB+Event+Logs/image3_7.png)

This event is logged when an external device like a USB is configured(backend term for connected) on the system.

We can see that the  Device name is the same as we found in our USBSTOR key. Another artifact that aligns with our registry findings is the Class Guid. If you  compare, you'll notice it matches the Guid present in the registry.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/3.USB+Event+Logs/image3_8.png)

The timestamp of the event is exactly the same as the previous event log we discussed, as well as the registry.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/3.USB+Event+Logs/image3_9.png)

This further provides evidence of when and which USB was connected to the system, and the metadata related to the USB device.

In the next lesson, we  are gonna talk about the Directory paths inside the USB device. These  can be used to understand for what purpose it was used and what kind of  data contains.

### NTFS

Open the NTFS operational event log and filter for event ID 142. Then look for this event at the  time when the USB was connected to the system, a time previously  identified from the registry artifacts and the event logs we previously  examined.

The NTFS event log is  useful for us as it allows us to identify the Disk drive letter that was given to the USB. This helps in further investigation; if we encounter  file paths starting with the disk letter assigned to the USB drive, we  can get the context and understand that these files belong to that  specific USB device.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/3.USB+Event+Logs/image3_10.png)

We accessed the event with ID 142, occurring at the time of the USB connection, as previously identified.

Looking at the general  tab of this event, we can note the volume name: "E:". This indicates  that the "E:" disk letter was assigned to this specific USB device, and  any file paths beginning with "E:" are associated with this device.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/3.USB+Event+Logs/image3_11.png)

This will help us in the next lessons as we will be dealing with file and folder paths.

In this part of the course, USB-related Event IDs are mentioned. In the next part of the course "**Folder Access Analysis via Shellbags**" will be explained

### Questions

**Note:** Use the "C:\Users\LetsDefend\Desktop\QuestionFiles\Acquisition.zip" file for solving the questions below.

1 - Analyze the Kernel PNP event logs to identify the relevant events for  the USB device discussed in previous lesson questions. What is the  timestamp indicating when the USB device drivers were configured on the  system?  

Answer Format: YYYY-MM-DD HH:MM:SS.MS

> **Answer:** 2023-11-13 08:32:23.69

2 - Analyze the NTFS operational event logs. What is the lowest value for free space in bytes?

> **Answer:** 9850167296

## Folder Access Analysis via Shellbags

In this lesson, we will  discuss the analysis of shellbags to determine what folders were present and accessed in the USB device by the suspect/attacker. This can be  very helpful as oftentimes folder names and folder hierarchy can reveal  much about the motivation or target of attackers. Let's first learn a  bit about shellbags.

Shellbags are artifacts  that are created when a user interacts with the shell, the user  interface for accessing the operating system, and its file system.  Interestingly, in Windows, this is a GUI-based file explorer (don't get  confused with shell referring to CLI). Shellbags contain information  about the state of a folder, such as its size, position, and the items  that it contains. This information is stored so that when the user  accesses the folder again, the folder can be displayed in the same state as it was when the user last interacted with it. For example, you may  have set your folder view to smaller or bigger or rearranged the order  in which folders are displayed in File Explorer. This information is  stored in shellbags so this configuration persists.

Shellbag artifacts can be useful in a variety of forensic contexts, including investigations of  cybercrime, employee misconduct, data breaches, and especially USB  forensics cases. It can provide insight into the user's activities and  the folders that they have accessed. For example, if a user has accessed a folder containing sensitive files in a USB, the shellbag for that  folder may contain information about the name and location of those  documents. They can be particularly useful for tracking the activities  of a user who is attempting to cover their tracks by deleting or moving  files. In these cases, the information stored in the shellbags may be  the only record of the user's activities and can provide valuable  evidence.

Shellbags are stored in the registry at the following locations:

- NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU  
- NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags  
- USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags  
- USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU  

We will use ShellbagExplorer by Eric Zimmerman to analyze this artifact. You can download the tool from here(It's free.):

**ShellbagExplorer**: https://ericzimmerman.github.io/#!index.md

Let's start analyzing and see it in action. First, run Shellbag Explorer as admin. Then go to  file and select either active registry or offline hive based on your  requirement. For now, we will use active registry but for the lab of  this lesson we will provide you with registry hives so you have to  select the offline hive and select the “NTUSER.dat” or the  “USRCLASS.dat” file in there.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/4.Folder+Access+Analysis+via+Shellbags/image4_1.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/4.Folder+Access+Analysis+via+Shellbags/image4_2.png)

Here we are interested in the “E:” drive which was assigned to the USB in the initial connection  to the system(Identified in the previous lesson). If we expand that:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/4.Folder+Access+Analysis+via+Shellbags/image4_3.png)

We see a directory named “Secret_Project_LD”. Let's click on this to get more information.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/4.Folder+Access+Analysis+via+Shellbags/image4_4.png)

Let's go over this information.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/4.Folder+Access+Analysis+via+Shellbags/image4_5.png)

Here we see the name of  this item (Directory) and the shell type indicating this is a directory. Below that we see the timestamps like when the directory was first  accessed, last accessed, etc. This all can be very interesting in  determining when a certain user accessed the directory.

You may be thinking, how  do we know which user accessed this directory? Just to clarify,  shellbags are stored under the “NTUSER.dat” hive and this hive is  user-centric, meaning each user on a system has their own unique  “NTUSER.dat” hive. So, whichever users hive we are analyzing accessed  that directory, which in our case is “letsdefend”.

Now, here's a bonus for  you: Shellbags aren't restricted to folders alone. They also record any  zip files found within a folder if accessed via Explorer. Moreover, they record folders contained within a zip file if explored through Explorer and the zip isn't password-protected. To demonstrate, we've reinserted  the USB and accessed it in File Explorer.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/4.Folder+Access+Analysis+via+Shellbags/image4_6.png)

If we expand the zip we can see the folder inside:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/4.Folder+Access+Analysis+via+Shellbags/image4_7.png)

It's important to note  that the folders under the zip only get stored in shellbags if it's  visited in Explorer. So the fact that we can see what folders were under the zip files means that the user visited that folder in Explorer and  we have evidence of access.

In this part of the  course, folder access analysis via shellbags for USB forensics is  mentioned. The next part of the course will cover "**File Access Analysis via Jumplists**".

### Questions

**Note:** Use the "C:\Users\LetsDefend\Desktop\QuestionFiles\Acquisition.zip" file for solving the questions below.

1 - What is the name of the directory in the USB device that was malicious and accessed by the user?

> **Answer:** C2Initialentry

2 - When was this directory accessed by the user? 

Answer Format: YYYY-MM-DD HH:MM:SS

> **Answer:** 2023-11-13 08:32:41

## File Access Analysis via Jumplists

In this lesson, we will  discuss what jumplists are and how they can be used to determine the  files accessed, the corresponding programs used, and the timestamps of  these activities. This amount of information gives us the upper hand  during investigations and determining who can access what and when.

The jumplists feature was first introduced with Windows 7 and continued in later versions of  Windows systems including Windows 11. The feature is designed to provide the user with quick access to recently accessed application files and  common tasks. 

The records maintained by jumplists are considered an important source of evidentiary information during investigations. The analysis of jumplist files can provide  valuable information about users’ historical activity on the system such as file creation, access, and modification. Examiners can utilize data  extracted from jumplist files to construct a timeline of user  activities. What makes this artifact more valuable is the fact that the  information is maintained on the system long after the source file and  application have ceased to exist.

This means that even if  the USB was inserted long ago, Jumplists maintain the information on the host system where the USB was connected.

There are 2 types of jumplists in Windows:

- Automatic destinations  
- Custom destinations  

Each file consists of a  16-digit hexadecimal number which is the AppID (Application Identifier)  followed by automaticDestinations-ms or customDestinations-ms extension. Note that these files are hidden and going through Windows Explorer  will not reveal them even if you turn on hidden items in Windows  Explorer. They can be viewed by entering the full path in the Windows  Explorer address bar.

The AutomaticDestinations jumplist files are located in the following directory: 

- **C:\%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations**    

The CustomDestinations jumplist files are located in the following directory:

- **C:\%UserProfile%\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations**  

Let's start analyzing  this. We will be using the “JumpList Explorer” tool by Eric Zimmerman to analyze jumplists. You can download the tool from here(It's free.):

**JumpList Explorer**: https://ericzimmerman.github.io/#!index.md 

Run the tool as  administrator and navigate to the path wherever your custom and  automatic destination files are. In the case of live analysis of the  system, they would be located in the path mentioned above. In the lesson lab, we will provide you with these acquired files so their path will  be changed and mentioned in the lab portion.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/5.File+Access+Analysis+via+Jumplists/image5_1.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/5.File+Access+Analysis+via+Jumplists/image5_2.png)

Select all these files and click open.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/5.File+Access+Analysis+via+Jumplists/image5_3.png)

Now do this again for custom destination files.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/5.File+Access+Analysis+via+Jumplists/image5_4.png)

If you face any error like this, ignore this and click ok.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/5.File+Access+Analysis+via+Jumplists/image5_5.png)

In our case, all of the custom destination files were empty and were not loaded automatically. It is normal behavior.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/5.File+Access+Analysis+via+Jumplists/image5_6.png)

Here we see detailed information.

We can see jumplist files for different applications.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/5.File+Access+Analysis+via+Jumplists/image5_7.png)

Here, we can observe the  quick access jumplist, which gives general information about all  recently accessed files on the system. If we click Notepad we see all  the files that were accessed using Notepad.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/5.File+Access+Analysis+via+Jumplists/image5_8.png)

Here we can see an  interesting file. Previously we identified that USB was assigned the  “E:” Drive. Now we can see that a file called “Dumped_Passwords.txt” was opened using Notepad from the drive. This means that the suspect opened the USB drive, navigated to the directory “Secret_Project_LD” and  accessed the “Dumped_Passwords.txt” file.

To see a more focused view, click on the relevant entry on the left.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/5.File+Access+Analysis+via+Jumplists/image5_9.png)

Now our information is more clear.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/5.File+Access+Analysis+via+Jumplists/image5_10.png)

We can see the timestamp when this file was accessed.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/5.File+Access+Analysis+via+Jumplists/image5_11.png)

We can also see the Local full path of the file.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/5.File+Access+Analysis+via+Jumplists/image5_12.png)

In this part of the  course, file access analysis with jumplists for USB forensics is  mentioned. The next part of the course will cover "**Automated USB Parsers Tools**".

### Questions

**Note:** Use the "C:\Users\LetsDefend\Desktop\QuestionFiles\Acquisition.zip" file for solving the questions below.

1 - What is the name of the binary that was executed from the USB?

> **Answer:** Entry_fix21.exe

2 - The SOC team confirms that this binary is a legitimate RMM tool. Can you find the original app name?

> **Answer:** AnyDesk

3 - When was this binary executed on the system? 

Answer Format: YYYY-MM-DD HH:MM:SS

> **Answer:** 2023-11-13 08:33:15

## Automated USB Parsers Tools

In this lesson, we will  take a look at an automated tool called “USB Detective”. This tool  automatically parses all the information and presents it in an organized way for analysis. All we have to do is provide the artifacts(Like the  registry hives etc.) to the tool and it parses and presents all the  information.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/6.Automated+USB+Parsers+Tools/image6_1.png)

You can download the community edition of the tool from here:  

**USB Detective**: https://usbdetective.com/community-download/

This tool will be already present in the lab environment for you.

First of all, we will  acquire all the artifacts using KAPE. We will not explain this step as  this is out of the scope of this course. If you want to learn more about it, please take the Forensic Acquisition and Triage course.

Here we have the acquired artifacts:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/6.Automated+USB+Parsers+Tools/image6_2.png)

Now let's open the “USB Detective” tool.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/6.Automated+USB+Parsers+Tools/image6_3.png)

This is the interface of the tool. We will select the First option “Select Files/Folders”.

This window will appear:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/6.Automated+USB+Parsers+Tools/image6_4.png)

We will enter the case  name and add a directory where the results will be stored. At the  bottom, we will add the USB artifacts acquisition folder which contains  our artifacts.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/6.Automated+USB+Parsers+Tools/image6_5.png)

In our example, we only have 1 USB drive connected to the system for analysis so we only get a single result.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/USB+Forensics/6.Automated+USB+Parsers+Tools/image6_6.png)

Feel free to play with the tool in the lab if you wish.





















