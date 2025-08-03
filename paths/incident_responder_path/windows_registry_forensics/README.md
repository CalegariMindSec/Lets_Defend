# Windows Registry Forensics

Microsoft Windows is one of the most used operating systems to date. It is widely used by home and enterprise users. This makes this platform a major  target for threat actors. So, it is important for cybersecurity  professionals to understand how to perform forensics investigations on  Windows systems. In this course, we will be discussing the Windows  Registry and the valuable artifacts and information it stores.

**Table of Contents:**

- [Introduction to Windows Registry Forensics](https://app.letsdefend.io/training/lesson_detail/introduction-to-windows-registry-forensics)
- [Acquiring Registry Hives](https://app.letsdefend.io/training/lesson_detail/acquiring-registry-hives)
- [Regedit and Registry Explorer](https://app.letsdefend.io/training/lesson_detail/regedit-and-registry-explorer)
- [System, Users and Network Information](https://app.letsdefend.io/training/lesson_detail/system-users-and-network-information)
- [Shellbags](https://app.letsdefend.io/training/lesson_detail/shellbags)
- [Shimcache](https://app.letsdefend.io/training/lesson_detail/shimcache)
- [Amcache](https://app.letsdefend.io/training/lesson_detail/amcache)
- [Recent Files](https://app.letsdefend.io/training/lesson_detail/recent-files)
- [Dialogue Boxes MRU](https://app.letsdefend.io/training/lesson_detail/dialogue-boxes-mru)

**Practice with SOC Alert**

- [50 - SOC117 - Suspicious .reg File](https://app.letsdefend.io/monitoring?channel=closed&event_id=50)

**Evaluate Yourself with Quiz**

- [Registry Forensics](https://app.letsdefend.io/training/quiz/registry-forensics)

**Challenge**

- [Windows Registry](https://app.letsdefend.io/challenge/windows-registry)

## Introduction to Windows Registry Forensics

Microsoft Windows is one of the most used operating systems to date.  It is widely used by home and enterprise users. This makes this platform a major target for threat actors. So, it is important for cybersecurity professionals to understand how to perform forensics investigations on  Windows systems. In this course we will be discussing the Windows  registry and the valuable artifacts and information it stores.

### What is the Windows Registry?

The Windows Registry is a central repository of information and  settings for the Windows operating system and its installed  applications. It is a hierarchical database that stores a wide range of  configuration data, including information about system hardware,  installed programs, user settings, recently accessed files, devices  connected , applications executed etc.

The registry is organized into a series of keys, with each key  representing a different aspect of the system's configuration. The keys  are organized in a hierarchical structure, with parent keys containing  child keys and values. Some of the most important keys in the registry  which we call root keys are:

- **HKEY_LOCAL_MACHINE:** This key contains information  about the system's hardware and installed programs, including details  about device drivers, startup programs, services installed, and system  settings etc.
- **HKEY_CURRENT_USER:** This key contains information  about the user's specific settings and preferences, such as desktop  background, applications executed, searched items, keyboard layout etc.
- **HKEY_USERS:** This key contains information about the users on the system, including their user profiles and settings.
- **HKEY_CLASSES_ROOT:** This key contains information  about the file associations and COM classes on the system, which  determine how different file types are opened and handled.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/1-+Introduction+to+Windows+registry+forensics/1.png)

Each key in the registry can contain various values, which are the  actual data stored in the registry. The values are organized into  name-value pairs, with the name identifying the value and the value  containing the actual data. For example, a value with the name  "WallPaper" stores the path of the desktop background. Windows loads the background image from the path found in the registry. In the below  example we see the name “WallPaper” with value of  "C:\Users\pc\Pictures\Wallpapers\LetsDefend.png". Windows know what  image to load as wallpaper from this registry location.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/1-+Introduction+to+Windows+registry+forensics/2.png)

### Registry Hives

The root keys we discussed above are supported by registry hives  which contain the actual registry data. A hive is a logical group of  keys, subkeys and values in the registry. Following important hives are  located at “C:\Windows\System32\Config\*”.

- **DEFAULT Hive:** This contains default settings for  the operating system and applications, and is used as a template when a  new user account is created.
- **SYSTEM Hive:** This contains settings for low-level system components, such as drivers and services.
- **SAM (Security Accounts Manager) Hive:** This contains information about user accounts on the local computer, including hashed versions of their passwords.
- **SOFTWARE Hive:** This contains information about the installed programs and their settings.
- **SECURITY Hive:** This contains security-related settings, such as access control information for system resources.

All of these hives except DEFAULT are plugged in to  HKEY_LOCAL_MACHINE Key, meaning we can find contents of SYSTEM Hive  under HKEY_LOCAL_MACHINE\SYSTEM subkey, contents of SAM hive under  HKEY_LOCAL_MACHINE\SAM and so on.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/1-+Introduction+to+Windows+registry+forensics/3.png)

For example the contents of SYSTEM hive can be viewed from:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/1-+Introduction+to+Windows+registry+forensics/4.png)

Another 2 important hives are user specific, meaning that every user  on a computer will have their own version of these hives. These hives  are plugged into the HKEY_CURRENT_USER key. The above discussed are  global and user independent. These 2 hives are:

- **NTUSER.DAT:** This hive contains the registry  settings for a specific user account on a Windows computer. This stores  information about the user's personal settings, such as desktop  background, start menu configuration, and application settings.  NTUSER.DAT is located in the user's profile folder, which is typically  found in the "**C:\Users\{username}**" or “**%USERPROFILE%**” directory.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/1-+Introduction+to+Windows+registry+forensics/5.png)

- **USRCLASS.DAT:** This hive contains the registry  settings for applications that are installed for a specific user account on a Windows computer. This stores information about the user's  installed programs and their settings. UsrClass.dat is located in “**%USERPROFILE%\AppData\Local\Microsoft\Windows**”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/1-+Introduction+to+Windows+registry+forensics/6.png)

**Note:** These files are hidden by default, so you may want to enable the view hidden files checkbox in file explorer.

- **Amcache Hive:** Another important hive is Amcache.  This is used by Windows to track changes to installed applications and  to improve the performance of the operating system. For example, when an application is installed or updated, the information about the change  is recorded in this hive. This allows Windows to quickly access the  information about installed applications without having to search  through the entire system for it.

Its located at **“C:\Windows\appcompat\Programs\Amcache.hve”.**

### Registry Backups and Transaction Logs

Windows automatically takes a backup of the whole registry structure in case of a failure. This is stored under **“C:\Windows\System32\Config\RegBack”**. This is critical to analyze as the backup registry can have the values  which aren't in the latest registry. This may help us in finding any  tampered registry keys by comparing the backup and current registry  values.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/1-+Introduction+to+Windows+registry+forensics/7.png)

Transaction logs are files in the same location as hives with  extensions “.LOG” , “.LOG1” , “.LOG2” and so on, depending on the state  of the registry. These are copies of the hives with latest changes in  values of registry keys, subkeys. Windows uses transaction logs to keep  the original hives from getting corrupted and to ensure proper working  of registry. These can contain the latest values that are yet to be  transitioned to original registry hives. Most of the forensic tools load the transaction logs alongside the original hive file automatically. We must acquire the transaction logs, if any, when acquiring registry  hives.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/1-+Introduction+to+Windows+registry+forensics/8.png)

So, in conclusion we learnt that hives are the files which contain  actual registry data. That's why it's important to know the types of  hives, their locations and what type of data they can provide us. During the investigation, we only have access to the disk image of the  computer most of the time so knowing the hive files and their locations  can allow us to extract and analyze them. On a live system, we can  directly navigate to the registry using the regedit tool which is a  built-in registry tool in Windows. We will discuss this in the next  lesson.

**"HKEY_LOCAL_MACHINE(HKLC)"** and **"HKEY_CURRENT_USER(HKCU)"** keys are the most important registry keys since most of the data of forensic value is stored under these keys.

Registry forensics can help us extract relevant information and  evidence. This can include identifying recently installed programs,  determining user activity and login history, and uncovering any  malicious or suspicious activity on the system.

To perform registry forensics, you must have a thorough understanding of the structure and contents of the registry, as well as the tools and techniques used to analyze it. After completing this course you will be able to perform registry forensics comfortably. We will discuss  important artifacts that can be found in registry hives, analyze them  with different tools and discuss scenarios in the context of digital  forensic investigations in the next chapter. At the end of course you  will have 2 practical cases to test your skills and practice.

In this lesson, we discussed the Windows registry, its structure, the hives, and why it's important for forensics investigations.

## Acquiring Registry Hives

In the previous lesson, we discussed registry hives and why they are  important. In this lesson, we will learn how to acquire hives from a  live system using FTK Imager.

During the incidents, we must acquire a full disk image for a proper  analysis. This image will also contain the hives and we can extract the  hives by mounting the disk image on our PC and navigating to the hives  location. However during incidents, acquiring disk images may take hours or days depending upon size of the disk, and time is of essence during  incidents so we don't want to waste any time. For this purpose, we can  acquire the registry hives only or the relevant disk locations according to our needs. 

This lesson will only showcase the acquisition process, as to avoid  confusions for beginners and you will be analyzing a live registry of  the LetsDefend lab to answer some questions. Live analysis is not  encouraged in real world investigations as it can tamper the evidence  but since this is for practice and demonstrative purposes we will be  exploring live registry hive. Please note that there's no difference  between live and offline hive analysis besides that in live analysis the registry is active and in use by the system. 

In practical cases at the end of the course you will be given offline hives acquired from the FTK imager so you will eventually experience  both types of analysis.

### FTK Imager

According to official description from Exterro;

“FTK® Imager is a data preview and imaging tool that lets you quickly assess electronic evidence to determine if further analysis with a  forensic tool such as Forensic Toolkit (FTK®) is warranted. Create  forensic images of local hard drives, CDs and DVDs, thumb drives or  other USB devices, entire folders, or individual files from various  places within the media.”

FTK imager allows taking full disk images to a single file  acquisition. We can create custom disk images by including only the  relevant files, and folders we think are important for investigation. It can also be used to mount disk images and navigate through it just like a local drive on your computer.

You can download FTK imager from “https://www.exterro.com/ftk-imager”. It is a free tool.

### Acquisition

Now you may be thinking why we need a tool to acquire the hives since they are just files present on the disk, we can copy them and perform  analysis on them. Windows locks the hive files when they are active as  they are critical system files. Locking down these files helps prevent  them from being modified or deleted by unauthorized users or malicious  software, which could cause serious problems for the system. These are  called system protected files. We can use specially designed tools like  FTK imager to acquire copies of these protected files. You may ask how  it is protected when they still can be retrieved or deleted using  special tools and attackers can use the same kind of tools. Well, these  tools require admin access to copy/delete these files as they are  sensitive files. If an attacker has admin level access to perform such  actions, then you already have bigger problems.

Launch the FTK imager as admin.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/1.png)

Now go to file, click add evidence item.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/2.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/3.png)

Select source means select the type of disk which we want to add evidence from.

1. **Physical Drive:** Drive attached to your computer  like HDD, SSD etc. This drive contains the full capacity of physical  hardware, and has allocated and unallocated space too. This is generally bigger in size but allows recovery of deleted files/contents.
2. **Logical Drive:** A logical drive is just like a  physical drive, except that this has only the files and allocated space. Unallocated space is not present.
3. **Image File:** We can use this source if we want to use an acquired disk image and carve out specific files/contents from it.
4. **Contents of a folder:** This allows us to acquire all data from a folder we want. This option only contains the logical space of the specified folder.

You can select physical, logical or the last one while acquiring from live systems. We will select logical as its organized and less tidy  then physical one. Then select the drive from which you want the data.  Windows is usually installed in “C:\” so we will select this drive.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/4.png)

On the left we will see the expandable drive under the Evidence tree.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/5.png)

Most of our data will be under [root].

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/6.png)

Now we will acquire the hives under “C:\Windows\System32\Config”.  Keep expanding the tree until you expand the config file. Then click on  the config folder so you can see the contents in the main screen. You  may see a lot of data but don't get overwhelmed. We will just retrieve  the hives we studied in the previous lesson.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/7.png)

We will retrieve only the SAM, SECURITY, SOFTWARE, SYSTEM hives, and their transaction logs. Ignore the “.FileSlack” files.

We can create a custom image and add all the hives in that image  file. We then will mount and analyze it or we can just export the files. We will create the custom image and will also show you how to mount  this. This demonstrates how to mount images using FTK which will come  handy in practical cases at the end of course. We will first create a  folder named “Evidence”. Right click on the file you want to add in  custom image and click “Add to Custom Content Image”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/8.png)

Now do this for all above mentioned hives and their transaction logs. You can see the added contents in the bottom left. Don't forget to add  NTUSER.DAT and UsrClass.dat hives too as wealth of data is under  NTUSER.DAT .

**Note:** Remember that NTUSER.DAT and UsrClass.dat hives are user specific so if you have 3 users on a computer, you would have to  collect these 2 hives from each user profile.

- NTUSER.DAT is stored at **“%USERPROFILE%”** or **“C:\Users\[username]”.**
- UsrClass.dat is stored at **“%USERPROFILE%\AppData\Local\Microsoft\Windows\”.**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/9.png)

Then click “Create Image” to start creating your imaging process.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/10.png)

Leave everything at default when prompted with the below window. Click Add button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/11.png)

After clicking add, we can either fill these fields or leave at default. Since we are demonstrating, just leave them empty.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/12.png)

We can select the folder where to save the custom image file and the  name of the file. Leave other options as default then click finish.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/13.png)

You will again see the first window with new information. Click start to create the image.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/14.png)

After the image is created, we will be given a report whether the  data was copied bit by bit and wasn't tampered with. This is verified by comparing hashes of original and acquired evidence.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/15.png)

We have successfully acquired the data, now let’s go ahead and mount  it on your computer. In real life scenarios you would acquire disk  images/custom images, then copy them to forensics workstation where you  will perform analysis. It’s highly important not to perform analysis on  the system under investigation. We perform these in courses/labs just  for the sake of accessibility.

Here's our disk image which we have just created.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/16.png)

### Mounting the Image

Go to “File” and click “Image Mounting”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/17.png)

Select the (.ad1) image file we created and leave everything else on default. Then click Mount.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/18.png)

After it is mounted you will see the location of the mounted image on your computer. Now you can navigate the mounted drive just like a  filesystem. In our case this drive will contain the files we selected.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/19.png)

Lets explore the mounted drive. In our case its disk “G:” but it can be any for you.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/20.png)

Navigate to the [root] folder. We should be able to see all the folders and files you would generally see under **C:\** if we are able to acquire the full copy of local drive **C:**.

Now let’s navigate to the config directory of this drive where some of our hives are stored.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/2-+Acquiring+registry+hives/21.png)

We can see that the hives are present.

In this lesson we discussed how to use FTK imager to acquire system  protected files, create custom images and mount images on the computer.  In the next lesson, we will discuss how to navigate live and offline  registry hives using built in and 3rd party tools.

### Questions

1 - What is the default extension of disk image created via FTK imager?

> **Answer:** ad1

## Regedit and Registry Explorer

In this lesson, we will show you how to navigate the registry and  explore the keys and hives we discussed in Lesson 1. We will first  explore the Regedit tool and then Registry Explorer. Throughout the  course the Registry Explorer will be used because of it's ease. However, you can use Regedit if you wish.

### Regedit

Regedit (Registry Editor) is a utility in the Windows operating  system that allows users to view and edit the registry. Using Regedit,  you can view, create, and modify registry keys and values, as well as  import and export data from the registry. It is a powerful tool that can be used to configure various settings in the operating system and  troubleshoot problems. However, it is important to be very careful when  using Regedit, as making changes to the registry can have unintended  consequences and can even cause serious problems with your system if not done correctly.

**Note:** Regedit is present in Microsoft Windows by default.

To open Regedit, you can go to “Search” on your taskbar and search for Regedit:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/3-+Regedit+and+Registry+Explorer/1.png)

We can see the root registry keys we discussed when the application opens.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/3-+Regedit+and+Registry+Explorer/2.png)

Remember that we discussed that most of the artifacts related to computers will be in **“HKEY_LOCAL_MACHINE**” and artifacts tied to specific users will be in “**HKEY_CURRENT_USER**”. When analyzing a live registry, the data which we will see under “**HKEY_CURRENT_USER**” will be fetched from "NTUSER.DAT" and “UsrClass.dat” of the user who's logged on (meaning us). Let's expand "**HKEY_CURRENT_USER**".

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/3-+Regedit+and+Registry+Explorer/3.png)

We can see different folders under **HKEY_CURRENT_USER**. We can refer to these as subkeys of the root key **HKEY_CURRENT_USER**. Similarly if we expand one of these subkeys, the folders under that  will be subkeys of that subkey. It is a hierarchical relationship.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/3-+Regedit+and+Registry+Explorer/4.png)

When we click on any key/subkey, we can see the values and the type of information that key stores on the right hand side.

In this example we are viewing the values inside the compression subkey, which belongs to 7zip software.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/3-+Regedit+and+Registry+Explorer/5.png)

We can also write the key path on the top search panel, which will  take us directly to our destination. This feature is very handy if you  have the paths of valuable registry keys holding valuable data written  down.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/3-+Regedit+and+Registry+Explorer/6.png)

**Note:** Taking notes and writing down valuable key paths is  encouraged. We will start discussing artifacts in registry from the next lesson.

### Registry Explorer by Eric Zimmerman 

Eric Zimmerman has a suite of tools usually referred to as EZ tools.  These tools are all related to digital forensics and incident response.  We will explore a few of those tools in this course. One of them is the  Registry Explorer. The reason why we choose Registry Explorer over  Regedit is because the Registry Explorer allows us to investigate live  hives as well as the offline hives. It also parses transaction logs  which enriches our hives to give full visibility. Also, Registry  Explorer has a more compact and cleaner GUI, and values are easily  readable and sorted conveniently.  

 You can download this tool from: https://ericzimmerman.github.io/#!index.md

**Note:** This tool is already installed for you on the lab machine for convenience. Run as administrator to avoid any issues.

Let's explore both live hives and the hives which we acquired in the previous lesson.

### Live Hives

The default landing menu is like this:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/3-+Regedit+and+Registry+Explorer/7.png)

Go to “File” and click “Live System”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/3-+Regedit+and+Registry+Explorer/8.png)

This allows us to load 1, 2 or all of the hives in the tool. The  users option allows us to select any of the user specific hives present  on the systems. I am currently logged in as user “pc” .

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/3-+Regedit+and+Registry+Explorer/9.png)

Lets load SAM hive for an example.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/3-+Regedit+and+Registry+Explorer/10.png)

Most of the data will be under the “ROOT” key. The associated deleted records should also be analyzed since this often contains the  deleted/modified values that are not present in the latest hive. The  data in associated deleted records is populated by comparing the live  hive and the hive stored as backup which we already discussed.

We try to read the user's subkey.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/3-+Regedit+and+Registry+Explorer/11.png)

We get the information about users, which groups they belong to in a  nice format. Now an interesting case is seeing the unassociated deleted  records. My account name was “pc” when I created it. Afterwards I  changed my username to “CyberJunkie”. This caused a conflict as this  change did not reflect fully across the system. My Home directory under  “c:\Users\” still shows as “pc” folder instead of “CyberJunkie”. In the  above screenshot we cannot see a user named "pc" but can see a user  named “CyberJunkie”. Now if we try to read the same key in deleted  records key, you will see that there will be a key named “pc” with a red cross which denotes that it is a deleted resource.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/3-+Regedit+and+Registry+Explorer/12.png)

Now let's discuss loading offline hives alongside their transaction logs.

### Offline Hives

In this part, we will load the hives which we acquired in lesson 2 and mounted using FTK Imager.

First we need to clear the already loaded hives from the previous  part. Go to “File” and click “unload all hives”. Now, again go to “File” and click “Load hive”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/3-+Regedit+and+Registry+Explorer/13.png)

Then navigate to the mounted image and to the path where the hives are stored.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/3-+Regedit+and+Registry+Explorer/14.png)

Select all the hives and their transaction logs and click “Open”.  Then you will get a prompt about a dirty hive being detected.  Transaction logs come to play here, and make the hives clean. Click  “Yes” then click “ok”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/3-+Regedit+and+Registry+Explorer/15.png)

It will prompt you to select the files again. These will be the  transaction logs. The program will prompt this dirty hive dialogue for  every hive you have loaded. As you can see in the above picture it asks  your verification “to replay transaction logs against this hive” for  security purposes. Select the security transaction logs while holding  the SHIFT button.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/3-+Regedit+and+Registry+Explorer/16.png)

**Note:** You will be asked to load transaction logs for all the hives you previously loaded in step 1. In this example, we  loaded 4 Hives (SECURITY, SAM, SYSTEM, and SOFTWARE) so it will give you the verification prompt for a total of 4 times. In the walkthrough we  only did it for the SECURITY hive. If you are following along then  complete the above process.

That's it for this lesson. We have discussed how to navigate around  the registry and explored its structure. We have also learnt how to  start analyzing live and offline hives. We will learn various artifacts  in the registry, their importance and what to make of the data in the  next lesson.

## System, Users and Network Information

In this lesson we will discuss how to retrieve information about the  users, groups, the system information like operating system version and  build number, network information like active interfaces, file shares  opened etc. Let's start with the User Information.

**Note:** Please load all the hives we discussed in lesson 2 in the Registry Explorer tool.

### User Information 

This information is stored in the SAM hive. Here we can find the  information stored for user accounts, user groups, login information,  password policies etc.

We have loaded all the hives so we have access to all of them.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/4-+System%2C+users+and+network/1.png)

Let's see the available users on the system. The path for the key is:

\- SAM\Domains\Account\Users

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/4-+System%2C+users+and+network/2.png)

We can see the list of active users as values of the key “Users”. We  can also view these names under the “Names” subkey under the users key  we discussed. It also gives us any deleted user information. This can be useful in case an attacker deleted any users etc.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/4-+System%2C+users+and+network/3.png)

We also see the group's information as the value in users key as seen above. If we create any additional groups then we would see them under  the separate groups key which is currently empty.

### System Information

Most of this information is stored in the SYSTEM, SOFTWARE hive. We  can find system configuration, operating system information, network  information, timezone information etc.

System configuration is stored in Control sets. We find 2 control  sets in the SYSTEM hive. Sometimes, we may find 2 different control  sets. They are numbered as “001” and “002”. The first control set refers to the configuration under use by the system and the second one refers  to the last working config. It can act as a backup in case of failure.  Control sets can be useful when investigating system failure incidents  or hardware failure incidents. We can also find the same key values of  "ControlSet001" in another key called "CurrentControlSet" which does not persist on disk but rather in memory. Unfortunately registry explorer  cannot mount this current key, but it is available on regedit.

Location of control set is

\- SYSTEM\ControlSet001

\- SYSTEM\CurrentControlSet

Lets explore ControlSet001 which is also the one in use by the system.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/4-+System%2C+users+and+network/4.png)

There is a vast amount of information that can be found here like  bootup services (which we will discuss in coming lessons), hardware  profiles, driver information etc. We won't go in details as it can be  very long.

Next information we can find is the operating system version. This  can help us as we can find important information such as the  architecture, build number of the computer, etc. This can help us in  case of exploits being used, we can find vulnerabilities for that  specific build no etc.

Location of this information is:

\- SOFTWARE\Microsoft\Windows NT\CurrentVersion

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/4-+System%2C+users+and+network/5.png)

### Network Information 

We can utilize the network information to find important information  like, usage of VPNs/Proxies, networks connected to in the past, current  TCP/IP configuration, interfaces etc. Let's start by finding the  networks the system has connected to.

Location of this information is:

\- SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/4-+System%2C+users+and+network/6.png)

We can find the network SSID(s), whether it was ethernet or wireless, the first time it was connected to the PC, the last time it was active  on the PC and the MAC address of the router providing that connection.  This can be fruitful evidence as we have proof with network names,  timestamps etc. For example an employee does not have permission to  connect to a specific LAN network because he/she doesn't have the  clearance. However the employee somehow manages to connect to the LAN  network which he/she does not have clearance for. We can use this  hypothesis to further investigate employee’s behavior to determine  whether he/she is an insider threat or not.

We can also see Open network shares on the system by reading the following key values:

\- SYSTEM\CurrentControlSet\services\LanmanServer\Shares

In the below example, the "WorkDrive" is an open Network share on my  computer. This information can help us for uncovering attacker lateral  movement techniques, which shares were accessible to/from the  compromised machine.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/4-+System%2C+users+and+network/7.png)

You can find TCP/IP configuration and interfaces information from below locations.

\- SYSTEM\CurrentControlSet\Services\Tcpip\Parameters

\- SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces

In this lesson, we have discussed some system artifacts, user related information and some network related information which can reveal very  much about the Computer activities which we are performing forensics on.

### Questions

1 - When was the user account “LetsDefend” created? 
Date format: (YYYY-MM-DD HH:MM:SS)

> **Answer:** 2021-08-07 12:18:27

2 - What is the releaseID of Windows installed in the lab?

> **Answer:** 1809

3 - When was the “Network 3” network connected for the first time? 
Date format: (YYYY-MM-DD HH:MM:SS)

> **Answer:** 2021-09-17 18:57:25

## Shellbags

Shellbags are artifacts that are created when a user interacts with  the shell (the user interface for accessing the operating system and its file system) which is the GUI based file explorer (don't get confused  with shell referring to CLI) in Windows. Shellbags contain information  about the state of a folder, such as its size, position, and the items  that it contains. This information is stored so that the folder can be  displayed in the same state as it was when the user last interacted with it when the user accesses the folder again. For example you may have  set your folder view to see its size by smaller or bigger, or rearranged it to the order with which folders are displayed in the file explorer.  This information is kept in shellbags so this configuration persists.

Shellbag artifacts can be useful in a variety of forensic contexts,  including investigations of cybercrime, employee misconduct, and data  breaches. It can provide insight into the user's activities and the  folders that they have accessed. For example, if a user has accessed a  folder containing sensitive files, the shellbag for that folder may  contain information about the name and location of those documents. They can be particularly useful for tracking the activities of a user who is attempting to cover their tracks by deleting or moving files. In these  cases, the information stored in the shellbags may be the only record of the user's activities and can provide valuable evidence.

Shellbags are stored in the registry at the following locations:

\- NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU

\- NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags

\- USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\Bags

\- USRCLASS.DAT\Local Settings\Software\Microsoft\Windows\Shell\BagMRU

If you navigate to any of the above paths, you will notice that you  can't read and understand the data present there because the values are  present in binary format. Windows keep this data format in binary for  efficiency by making this data less in size. However we can use many  tools which convert the binary data into human readable ASCII format. We will use ShellbagExplorer by Eric Zimmerman to analyze this artifact.

You can download the tool from: https://ericzimmerman.github.io/#!index.md for free.

When you open the tool, it will ask for an email optionally to keep  you notify you about their products and services. You don't need to sign up or give your email, it’s just optional, you can skip this part if  you like and the tool will start.

Go to “File” on the top left and click “Load Active Registry” or  “Load Offline Registry depending on your requirement. In our case we  will load an active registry.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/5-+Shellbags/1.png)

It will automatically parse the shellbags from the NTUSER.DAT and  UsrClass.dat hives. It will give you information about how many entities were found from shelbags and the time taken.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/5-+Shellbags/2.png)

You will get a nice and clean folder hierarchy.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/5-+Shellbags/3.png)

This will have all of the folder locations which are visited in the  file explorer. You can expand the “My Computer” folder and you will have access to all folder folders and drives on your computer in  alphabetical order.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/5-+Shellbags/4.png)

To see shellbags in action from a forensic perspective, let's create a folder named “LetsDefend_Shellbags” on our Desktop and then delete it.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/5-+Shellbags/5.png)

Now deleting the folder.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/5-+Shellbags/6.png)

Let’s reload the active hive on shellbags explorer. We can see the  folder name even though we had deleted it. This artifact also stores  paths for visited network shares, removable devices (USB etc.) which is  handy information on its own. We can find what type of data the user  browsed on network shares or USB.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/5-+Shellbags/7.png)

**Note:** It may take some time before shellbags are updated in the registry.

Another important thing to note is that shellbags also store the name of zip files and even if the folder(s) under the zipped files are not  password protected. This can be very useful incase of any malicious  archives downloaded by the user. See below screenshot.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/5-+Shellbags/8.png)

### A Scenario

Imagine that an employee at a company is suspected of leaking  sensitive company documents to a competitor. The company's IT department is tasked with investigating the matter and determines that the  employee in question has recently accessed a folder containing the  sensitive documents. However, the employee has deleted the documents  from the folder and claims to have never accessed them.

In this scenario, the IT department might turn to shellbag artifacts  to determine if the employee accessed the folder containing the  sensitive documents. By examining the shellbag artifacts for the folder  in question, the IT department may be able to find evidence that the  employee accessed the folder and potentially even identify the specific  documents that were accessed. This information could be used to support  the company's investigation and potentially provide evidence of the  employee's misconduct.

In this lesson we discussed shellbags, how they are critical from the forensic point of view, how to analyze them using shellbags explorer  and a forensic investigation scenario where shellbags help close the  case.

### Questions

1 - What is the full path of the directory named “LetsDefend_Shellbags”? 
Format: C:\Users\Letsdefend\*

> **Answer:** C:\Users\Letsdefend\Pictures\QWERTY\dir123\LetsDefend_ShellBags

## Shimcache

Shimcache, also known as the Application Compatibility Cache  (AppCompatCache) is a record of information about executable files that  have been running on the system, It usually keeps information like the  name and the path of the file, the timestamp when it is run, and other  metadata. This feature aims to prove backward compatibility for older  applications on the newer versions of Windows. In the older Windows  version like 7/8 this artifact had only a function that flags whether  the file was executed or not. However, in Windows 10, in addition to  this function shimcache also stores the executable names visible in the  File Explorer.

Let's suppose you have 20 different executables in a directory. You  open up that directory in the File Explorer and only 5 of those  executables are visible because your File Explorer is resized to a  smaller scale. During this scenario shimcache will save the information  of those 5 executables even though they are not executed. Now if you  maximize the explorer window and all 20 files are visible, then these 20 executables will be in shimcache data. In summary, there's no way that  we can prove an application was executed just by shimcache. It may have  been just browsed on the File Explorer. Shimcache is a valuable tool  forensically as it can prove an existence of a file, even though it is  deleted from the disk. Another value of this artifact is that it stores  the data we discussed above whether it is from local system or network  share or a USB device.

Shimcache can be used by forensic investigators to determine what  programs have been running on a system, the exact timestamps of their  execution, existence of executables even though they are not executed.  This stores executed applications information even if the file itself  was deleted long ago. This can be useful in a variety of situations,  including incident response, malware analysis, and digital forensics.

One use case for shimcache is to help identify malware that may have  been installed on a system. By analyzing the shimcache, an investigator  can determine which executables have been run on the system and when  they were run. If an executable is found in the shimcache that is not  associated with a known good program, it may be indicative of malware.  Another use case for shimcache is to determine the activity of a user on a system. By analyzing the shimcache, an investigator can determine  which programs were run by the user, and when they were run. This can be useful in determining the actions of a user for an incident or an event of interest.

This artifact is often confusing, as we can’t deduce whether an  application was executed from the shimcache alone. We can co-relate  shimcache evidence with other artifacts like amcache, which we will  discuss in next lesson. So shimcache stores:

1) Evidence of executable executions
2) Evidence of executable existence (If viewed from GUI. Listing the  file names from CLI will not be populated in this registry key.)

It is important to note that shimcache can be modified or deleted by  an attacker, so it is important to preserve the integrity of the  evidence when examining shimcache.

This artifact is located at

\- SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache

**Note:** If you don't see a key named  “CurrentControlSet” in SYSTEM hive, then you can select the  ControlSet001 as this and current one are virtually the same. Rest of  the path is the same.

### AppCompatCacheParser

Shimcache data is not in a human readable format just like shellbags. We can use another tool by Eric Zimmerman called AppCompatCache parser. You can download from: https://ericzimmerman.github.io/#!index.md for free.

This tool is CLI based. It will parse the artifact and create a CSV  file with output. We can use any CSV reader like Microsoft Excel or  another tool called Timeline Explorer designed by Eric Zimmerman which  we will use. Now let us run from CLI to see available arguments.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/6-+AppCompatCache-ShimCache/1.png)

Here's a summary of what arguments we will be using,

1) **-f :** Path for SYSTEM hive. If nothing is  specified, live hive will be used. We will use this in our example but  in case of offline hive analysis, a path must be given.
2) **--csv :** We have to provide a full path with quotes where the output file must be saved.
3) **--csvf :** Give name to the output file.

So our final command will be:

**Command:** AppCompatCacheParser.exe --csv "Path where to save" --csvf filename

**Note:** Run the command prompt with Administrator privileges.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/6-+AppCompatCache-ShimCache/2.png)

After the parsing is completed, it will display the entries it finds.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/6-+AppCompatCache-ShimCache/3.png)

Now, we will open the CSV with Timeline Explorer which displays the  information in more neat and cleaner format than Excel and sorts the  entries according to timestamps. Also, Timeline Explorer works in read  only mode. Excel files are editable and misclicks may cause our data to  be modified. Now open Timeline Explorer and click “File”, then “Open”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/6-+AppCompatCache-ShimCache/4.png)

When we open the CSV file which was created as output in the previous steps we see all the application paths and time stamps. Even if the  file itself was deleted or removed, the file name and path remains in  shimcache unless the shimcache data itself isn't deleted or tampered  with.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/6-+AppCompatCache-ShimCache/5.png)

We can find the application that was executed lat or browsed from the File Explorer and this can be of great value if we know what time the  incident was occurred. We can then look for applications executed around that time frame.

### A Scenario 

A company has experienced an incident in which sensitive data has  been exfiltrated from their systems. The incident response team is  called into investigate and determine the cause of the breach. One of  the first things that the team needs to conduct is to collect and  analyze forensic artifacts from the affected systems. By analyzing the  shimcache, the team is able to determine which programs were run on the  affected systems, and when they were run.

It is discovered that an executable file with a suspicious name was  run on the affected systems shortly before the data exfiltration  occurred. They are able to find the filename in the shimcache, along  with the timestamp when it was run.

The team then performs a detailed analysis of the suspicious  executable file and determines that it is malware that was used to  exfiltrate the data. They are able to use this information to track down the source of the attack and take appropriate actions to prevent  similar incidents in the future.

In this scenario, the shimcache played a crucial role in the  investigation by providing important information about the programs that were run on the affected systems. It helped the incident response team  identify the malware that was leveraged in the attack and understand the sequence of events leading up to the breach.

In this lesson we covered the AppCompatCache/ShimCache artifact, why  it is an important source of evidence and why it is often confused and  misunderstood. In the next lesson we will go over the amcache artifact,  which will support the evidence found from shimcache.

### Questions

1 - What’s the switch used in AppCompatCacheparser tool to parse the data only for a specific date(s)?

> **Answer:** --dt

2 - How many executables were visible in the “File Explorer” directory named “LetsDefend_ShimCache”?

> **Answer:** 12

3 - What is the executable name starting with letter “h” present in a folder named “LetsDefend_ShimCache”?

> **Answer:** hashcat.exe

## Amcache

The amcache hive is an artifact found on Windows systems that  contains information about the applications and programs that are  executed on the system. It is a part of the Windows Application  Compatibility Cache, which stores information about programs that are  run on the system to help them run more efficiently. From a forensics  point of view, it can be used to determine the programs running on a  system and their exact times that they are run. This information can be  useful for forensic investigators trying to determine a suspect's  activities. It can also be used to identify when software was installed  on a system, as well as the location of the installation files. This can be useful for identifying unauthorized software installations or for  tracking the deployment of software in an organization. Amcache hive  also stores executed applications data from external devices/sources  like network shares, USB devices etc.

Amcache is a hive which we briefly mentioned in lesson #1. It  contains key-value pairs, holding information like application path,  file metadata (description,publisher name), timestamps (Creation,  modification, and deletion) and SHA-1 hashes of the file.

This hive is located at:

\- C:\Windows\AppCompat\Programs\Amcache.hve

### Difference Between Amcache and Shimcache 

Amcache can be considered a more reliable evidence of execution in  contrast to shimcache which we discussed earlier. Amcache stores  additional data like first execution timestamp, deletion timestamp (if a file was deleted), hash values of the executables, etc. It also stores  the application publisher name, which may help us in finding suspicious  and untrusted files as they don’t have any publisher name. Although  adding a publisher name isn't difficult when creating an executable,  most malware generators like metasploit, empire don't have any metadata  when creating stagers.

In Windows 7 and older versions, amcache was named “RecentfileCache" and was located at:

 \- C:\Windows\AppCompat\Programs\recentfilecache.bcf

Let's explore this hive.

Evidence of execution is located at:

AMCACHE\{GUID}\Root\InventoryApplicationFile

The “InventoryApplicationFile” key stores detailed information about  executables executed on the system, even if the file is deleted.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/7-+AmCache/1.png)

If there's an incident, we can try to find applications executed  around the incident time frame. This can allow us to cut down the noise  and we can focus on only relevant data.

We can also view drivers data from the following key:

\- AMCACHE\{GUID}\Root\InventoryDriverBinary

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/7-+AmCache/2.png)

This helps us in uncovering malicious drivers acting as rootkits etc. One nice thing about this artifact is that it stores SHA-1 hash value  which allows us to verify the file's reputation very quickly unless it's an unseen malware.

Analyzing from the registry however, can be hectic if there's a lot  of data present. We can use another tool called AmcacheParser that Eric  Zimmerman designed. AmcacheParser creates CSV files just like we did in  shimcache lesson. Then, we can analyze the output in Timeline Explorer  and apply filters as we need. This is also a CLI tool.

### AmcacheParser 

You can download the Amcache parser from: https://ericzimmerman.github.io/#!index.md for free.

Let's start by seeing available options.

**Note:** Run CMD as Administrator.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/7-+AmCache/3.png)

Let's go over the arguments we will use:

1) **-f :** We will have to give a path to the amcache hive. Either path to live hive or an offline one.
2) **--csv :** Path where to save the output file. Remember to put the path in quotes “”.
3) **--csvf :** Output filename alongside the extension.

Notice these 2 switches.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/7-+AmCache/4.png)

We can specify a file containing SHA-1 hash values of known good  applications or applications allowed in your organization. By using the  -w switch we can exclude the known good applications found in amcache  and then analyze the rest of the files. This can help in cutting down  analysis time significantly as analysts won't waste their time on  legitimate allowed applications.

Similarly, we can also specify a file containing SHA-1 hashes of  known malware or malicious files. By using -b switch, we can find  amcache results only for the matching malicious files which will be very helpful during the investigations. For instance, if your organization  is being targeted by Emotet malware variants, you can collect all SHA-1  hash values of Emotet variants spotted in the wild and match them here  to see if they are successful.

These switches are handy features of this tool, and we wanted to go  over them briefly, but we will not use them in our case. Now let’s  execute the command.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/7-+AmCache/5.png)

**Command:** AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" --csv "Path where to save output" --csvf output.csv

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/7-+AmCache/6.png)

As you can see in the screenshots provided, we can see the execution  entries, shortcuts, and driver binaries it can find. We will only  analyze the file entries in this lesson as it is the main focus of this  artifact and this lesson.

We can see a number of CSV files, and we will be opening the “amcache_UnassociatedFileEntries” one in the Timeline Explorer.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/7-+AmCache/7.png)

Since there's so much data in the CSV file we can hide some of the irrelevant columns.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/7-+AmCache/8.png)

Go to the column name, right click and select “Hide the column”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/7-+AmCache/9.png)

Now we can see the relevant data.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/7-+AmCache/10.png)

Now let’s try to copy the hash value of one of the executable and run it on VirusTotal.com. Let’s select amcache parser which we just used to generate the output we are analyzing.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/7-+AmCache/11.png)

If we double click the hash, we get a new window open with the hash of amcache parser.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/7-+AmCache/12.png)

Let’s copy the hash value and run on VirusTotal.com. As you can see  it in the below screenshot, VirusTotal marked this as safe and it  recognizes this as amcacheparser.dll, which is present in the directory  where we downloaded the tool.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/7-+AmCache/13.png)

### A Scenario 

Imagine you are a forensics investigator trying to determine what  programs were run on an infected computer during a certain time period.  You could use the amcache to find a list of all the programs that have  been run on the system and the exact date and time information that they were run. You found a file with no publisher name under the user's  downloads directory. The creation timestamp also matches the incident  time frame. You then copy the hash value of the file and run it against  multiple threat intel platforms. You find out that this is a new variant of Emotet malware which has just surfaced on the internet 1 day before  the incident, so your antivirus software wasn't able to detect this. You can then perform further analysis and contain the endpoint.

In this lesson, we discussed the importance of amcache, how it  differs from shimcache, how it can help hunting persistent or undetected malwares. In the next lesson, we will be discussing a similar artifact  which has the capability to show evidence of access to all types of  files rather than just executable binaries.

### Questions

1 - What's the binary version of executable present in a directory named “LetsDefend_Amcache”?

> **Answer:** 2.2.0.0

2 - What’s the full path where the executable was stored?

> **Answer:** c:\users\letsdefend\downloads\cyberjunkie\76589\tyuij\letsdefend_amcache\mimikatz.exe

3 - When was the executable executed? 
Date format: YYYY-MM-DD HH:MM:SS

> **Answer:** 2023-01-02 13:27:40

4 - What's the SHA-1 hash value of that executable?

> **Answer:** 040fbf1325d51358606b710bc3bd774c04bdb308

## Recent Files

This is a feature in Windows which allows us to access our recently  used applications. When we open the “File Explorer” or the “Start Menu”, we can see some of our recently used files/applications. That data is  stored in the artifact which we will be going to discuss.

The “Recently Used Files” shortcut is located at: “%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Recent”

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/8-+Recent+Files/1.png)

The actual data is saved in NTUSER.DAT hive of a user. The key in which this data is stored is:

\- NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

The above mentioned key stores the name of the opened  file/application, shortcut file, last accessed time. It's important to  remember that this artifact has information of all kinds of files being  opened/modified. This can be classified as evidence of access rather  than evidence of execution.

If we change the contents of a file via command line or rename the  file, it will be populated in this registry key. We did not execute the  file but rather modified it and it was reflected upon this artifact. We  can use this artifact to establish interaction with files and submit it  as evidence. For example an employee reads the contents of a file he/she wasn't supposed to. This artifact can provide evidence that the file  was accessed at a specific time.

Now let’s explore this key from the “Registry Explorer”:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/8-+Recent+Files/2.png)

We can see the target name which is file name, Lnk name which is  shortcut for that file (which we saw in “Recent Items”), opened on which is the latest access time. Notice that in “Target Name” file name have  their extensions too. The values which don't have any extension are most probably a folder. For example, in the above image, the first entry in  Target Name is “Evidence” which is the folder we are saving our CSV  outputs, and disk images from this course.

Another important piece of information is that the key “RecentDocs”  from which we have analyzed all the above data, has subkeys for each  extension the machine ever opened.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/8-+Recent+Files/3.png)

This can be of great use when we are interested in a specific type of file. For example, if there was a mass phishing attempt at an  organization, and if this case the analyst would first want to see doc,  docm, xls files, etc. and here this "Recent Items" feature will be very  helpful.

In the image below we are only interested in files with xlsx extension which were recently accessed.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/8-+Recent+Files/4.png)

We can find accessed files by their extension type from the following key(s).

\- NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\{.extension}

Recent File artifacts can be valuable from a forensics point of view  as we could easily view the files which a particular user (insider  threat/misconduct/threat actor) was interested in a particular time  frame.

### A Scenario

An employee was suspected of leaking sensitive data to a competitor  company. Forensics investigators can analyze recent files artifacts to  determine what kind of files and documents the user interacted with for  the last few days. One of the document titles revealed that the relevant topic should not be something that the employee needs to know or see.  This way the employee was proven guilty of intellectual property theft  and the legal procedures will start immediately. During the court  trials, we can provide the evidence found from recent docs registry key  to prove that the user did in fact access the file at a given time.

In this course, we discussed the “Recent Files” artifact, how it can  provide evidence of access across multiple types of files and discussed a forensic investigation scenario.

### Questions

1 - What's the name of the jpg file which was recently opened?

> **Answer:** got4.jpg

2 - What's the html file name most recently accessed?

> **Answer:** Letsdefend.html

3 - When was the html file accessed? 
Date format: YYYY-MM-DD HH-MM-SS

> **Answer:** 2023-01-02 13:44:48

4 - What’s the “Value name” for filename “Letsdefend.txt”?

> **Answer:** 19

## Dialogue Boxes MRU

A "Dialog Box MRU" (most recently used) artifact is a record of the  file names, their timestamps and paths that have been accessed or  selected in a dialog box in a Microsoft Windows operating system.  Whenever an additional dialogue box is opened, like when uploading a  file on a website, a dialog box appears on file explorer to select the  file(s) to upload. From this artifact we can get valuable information  about the user's recent activity on the system, including the files and  folders that they have accessed or modified file paths. This can be used to help reconstruct the user's actions and provide context for other  forensic artifacts. This is a supporting artifact which proves results  of other artifacts like amcache, shimcache to be fruitful.

This information is stored in 2 keys in NTUSER.DAT hive.

\- NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU

\- NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU

Let's discuss these keys in detail while exploring their data.

### OpenSavePidlMRU

Whenever we need to open or load a file from another application we  are prompted with a file explorer window and we select the desired file  we want to load. The opened/loaded/saved file path is stored in this  key. For example, we are uploading a word document from Microsoft Word.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/9-+Dialogue+Boxes+MRU/1.png)

Now when we select the file and click open, it gets uploaded inside  the Microsoft word application. The file path for this document will be  saved in the OpenSavePidlMRU key. Let’s see if this document name is  present in the opensave key. Open the key in the “Registry Explorer”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/9-+Dialogue+Boxes+MRU/2.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/9-+Dialogue+Boxes+MRU/3.png)

**Note:** You may need to relaunch the Registry Explorer and then load the hive again in order to reflect the changes if done live.

There are also subkeys present inside the “Opensave” key, which is  similar to “Recent Docs” that have entries for many different  extensions. One important subkey to discuss is the “*” key present under OpenSavePidlMRU key. This subkey holds the recent 10 entries from the  dialog box MRU.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/9-+Dialogue+Boxes+MRU/4.png)

We can’t see the clean view from these subkeys like we saw in “OpenSavePidlMRU” key but we can see it in hex and ASCII format.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/9-+Dialogue+Boxes+MRU/5.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/9-+Dialogue+Boxes+MRU/6.png)

“OpenSavePidlMRU” key can be very useful in cases where we need to  find out what kind of applications were loaded by users using other  applications. For example if a user uploaded a file on a website, we can find out which file was uploaded by the user with this key.

### LastVisitedPidlMRU

This key is a supporting artifact of the previous key we discussed.  It tracks the application executable which would be responsible for  opening/saving the file from the Windows Explorer prompt we discussed  previously. This key does not store the path with the file name like  OpenSavePidlMRU, but rather store the executable used to open/save the  file and path of the folder from where file was opened/saved. In our  example from previous case, the file name was “LetsDefend MRU  demo.docx”, the folder path where it was saved was “F:\Letsdefend  courses\Windows Registry Forensics\Evidence”. We opened the document  using Microsoft Word, so the executable name in this key should be  “windword.exe”. Let's explore it in registry explorer.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/9-+Dialogue+Boxes+MRU/7.png)

This is the latest entry in this key, the path and the timestamp  matches our criteria. But the executable name seems to be a GUID value.  It turns out this artifact sometimes doesn't record proper data for some applications. In our case the Executable should be winword.exe which  would tell us that a document was opened from this path. We can explore  this artifact using another example which we did in our previous  lessons.

We used Timeline Explorer to open amcache CSV output from amcache  parser tool. Remember that we opened the Timeline Explorer, and selected the CSV file from the dialogue box which we are discussing in this  lesson. So here, we know that Timeline Explorer was used to open a file  under “F:\Letsdefend courses\Windows Registry Forensics\Evidence”. We  can correlate the data from this key and the previous keys we discussed  with timestamps to get to know the complete event.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Windows-Registry-Forensics/9-+Dialogue+Boxes+MRU/8.png)

In this lesson, we discussed the importance of the Windows dialogue  boxes, how they are important from the forensics point of view, how to  analyze and correlate the data found from these artifacts.

### Questions

1 - What's the name of the RTF  (rich text format) document which was opened from another application?  (Provide the filename with full path)

> **Answer:** C:\Users\LetsDefend\Downloads\Dialogue Boxes.rtf

2 - When was the document accessed?
Date format: YYYY-MM-DD HH:MM:SS

> **Answer:** 2023-01-02 13:40:23

3 - What's the binary name which was responsible for opening a file from "C:\Users\Letsdefend" directory?

> **Answer:** PickerHost.exe





















