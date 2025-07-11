# Forensic Acquisition and Triage

End  of this course, you will learn how you acquire evidence and triage  infected machines. With our hands-on labs, you can practice what you  learned. That way will be great to learn it.

**Table of Contents:**

- [Introduction to Forensics Acquisition and Triage](#introduction-to-forensics-acquisition-and-triage)
- [Acquiring Memory Image From Windows and Linux](#acquiring-memory-image-from-windows-and-linux)
- [Custom Image Using FTK and Mounting Image for Analysis](#custom-image-using-ftk-and-mounting-image-for-analysis)
- [KAPE Targets for Acquisition](#kape-targets-for-acquisition)
- [KAPE Modules for Triage and Analysis](#kape-modules-for-triage-and-analysis)
- [Triage Using FireEye Redline](#triage-using-fireeye-redline)
- [Acquisition and Triage of Disks Using Autopsy](#acquisition-and-triage-of-disks-using-autopsy)

**Evaluate Yourself with Quiz**

- [Forensics Acquisition Quiz](https://app.letsdefend.io/training/quiz/forensics-acquisition-quiz)

## Introduction to Forensics Acquisition and Triage

Forensics acquisition, also known as Forensics imaging or data  acquisition, is the process of creating an exact duplicate (or "image")  of data from a specific storage device or media for the purpose of  preserving the original data for legal or investigative purposes. The  image can then be analyzed and examined for evidence without altering  the original data. This process is used in criminal investigations,  civil litigation, and computer security incident investigations to  gather and preserve digital evidence.

Forensics acquisition typically involves using specialized software  and hardware to create a bit-by-bit copy of the entire storage device,  including deleted and unallocated space. This ensures that all relevant  data, including hidden or deleted files, is captured and preserved. The  acquired data is then hashed to ensure the integrity of the data, and  the original storage device is not modified. Another important aspect of forensics acquisition is the proper handling and documentation of the  original storage device and the acquired data. This includes identifying and labeling the device, and maintaining a chain of custody to ensure  that the integrity of the evidence is not compromised.

After the acquisition process, the next step is triage. The triage is the process of identifying and prioritizing the data that is relevant  to the investigation. This is done by analyzing the acquired data and  identifying files, emails, or other data that may contain evidence. This process can be conducted manually or by using specialized software.  Triage helps focusing the investigation and it saves time by eliminating unnecessary data analysis. In some cases, the amount of data that needs to be analyzed can be overwhelming. In such cases, automated triage  tools can be used to help filter out irrelevant data and identify  potential evidence. This can include keywords searches, filtering by  file type, and identifying specific file patterns. Automated triage  tools can significantly speed up the process and make it more efficient, however, it's important to note that they may not be able to find all  relevant data, so manual analysis is still necessary.

Triage is also an important way to identify and isolate any malicious software or malware that may be present on the storage device. This is  important for security incidents, as it can help prevent the malware  from spreading to other systems and causing further damage. Triage also  helps identify the scope and impact of an incident, which will help to  determine the appropriate response. Overall, forensics acquisition and  triage are critical steps in the process of collecting and analyzing  digital evidence.

The process of acquisition and triage go side by side. In triage, the data acquired from the acquisition is analyzed to identify any related  evidence to support in the incident investigation.

Let's take an example scenario:

### Scenario

In this scenario, the SOC Team receives an alert that their  production server has been compromised. They suspect that sensitive  customer data, including credit card information, has been stolen. The  SOC manager assigns a team of forensics and incident response analysts  to the case.

The first step in the investigation is the Forensics acquisition of  the server. The Forensics investigators use acquisition tools like  “KAPE”, “FTK imager”, “Magnet RAM Capture” to create a bit-by-bit copy  of the entire storage device and the memory. They also acquire all the  computers in the network and the servers to ensure that all relevant  data is captured and preserved. The acquired data is then hashed to  ensure the integrity of the data, and the original storage device is not modified.

After the acquisition process is completed, the next step is the  “triage”. The forensics investigators use tools like “KAPE”, “FireEye  Redline”, “Volatility” to analyze the acquired data and identify files,  memory or other data that may contain evidence. They also use keyword  searches and filtering by file type to identify potential evidence. The  investigators also manually review the data to ensure that all relevant  information is captured.

They found out that the hacker had gained access to a system via a  phishing email, and had been exfiltrating data for several weeks before  it was detected. They also found that the hacker had installed malware  on the system which was still active. The investigators needed to  isolate the malware where it was located to prevent it from spreading  further.

The investigation team should prioritize the data that is relevant to the case which eliminates unnecessary data analysis. They use the data  to identify the IP addresses used by the hacker and trace it back to a  specific individual. With the IOCs they gathered they were able to  identify some more compromised workstations in the network from where  the attacker laterally moved to, ultimately compromising the production  server.

The Forensics acquisition and triage process played a critical role  in the investigation by preserving the original data and identifying  relevant evidence, which ultimately led to the containing the incident  impact and reducing the damage.

It's important to note that the acquisition and triage step is very  crucial to an investigation as any tampering with the data can cause  false evidence and mislead the investigation. The goal is to acquire the data while leaving as much less footprint as possible. It's not  possible to acquire a disk image or memory from a device in the same  state when it was compromised. We need to interact with the system to  gather the data we need, so the less interaction the better. Commercial  acquisition tools like “Belkasoft Remote Acquisition”, “Magnet Axiom”  are excellent examples for the software that leave very minimal  footprint, leaving the evidence as close to the original state as  possible. Free tools also don't leave many footprints behind meaning  they work almost as well as the commercial tools too.

These acquisition and triage tools are often run from a USB attached  to the system, or from a network file share or in some other way  remotely. Running like this leaves less footprints as opposed to  directly installing tools on the device and then running them.

The tools we will be discussing in this course are all available for  free. Most of them can be run from a USB or remotely, but for practical  purposes and convenience, we will be using them directly from the system by installing it. The rest of the methodology will be the same only the medium from which software is run would be changed.

The tools we will discuss are:

1- FTK Imager (Windows)

2- Belkasoft Live RAM Capture (Windows)

3- AVML (Linux)

4- KAPE (Windows)

5- FireEye Redline (Windows)

6- Autopsy (Windows and Linux)

## Acquiring Memory Image From Windows and Linux

Acquiring memory is important in the incident response life cycle as  it can provide valuable information about an incident, such as what  processes were running at the time of the incident, what network  connections were established, and what files were accessed. This  information can be vital to help determine the root cause of the  incidents, identify malicious activities, and assess the damage.  Additionally, memory can also be used to identify and analyze any  malware that may be present on a system, which is crucial for containing and removing the threat.

Memory is often one of the first data sources acquired and analyzed  because of its smaller size compared to disks (going upto hundreds of  TBs) and volatile nature.

In this lesson we will acquire memory from both Windows and Linux. Let's start with Windows acquisition.

### Acquiring Memory Image From Windows 

We will capture memory images from Windows using “Belkasoft Live RAM  Capturer” and “FTK Imager”. Let's start by Belkasoft Live RAM Capturer.

### Belkasoft Live RAM Capturer 

Belkasoft Live RAM Capturer is a tiny free forensic tool that allows  to extract the entire contents of a computer's volatile memory reliably  even if it is protected by an active anti-debugging or anti-dumping  system. Separate 32-bit and 64-bit builds are available in order to  minimize the tool’s footprint as much as possible. Memory dumps captured with Belkasoft Live RAM Capturer can be analyzed with Live RAM Analysis in Belkasoft Evidence Center. Belkasoft Live RAM Capturer is compatible with all versions and editions of Windows including XP, Vista, Windows  7, 8 and 10, 2003 and 2008 Server.

Belkasoft Live RAM Capturer is designed to work correctly even if an  aggressive anti-debugging or anti-memory dumping system is running. By  operating in the kernel mode, Belkasoft Live RAM Capturer plays on the  same level with these protection systems, being able to acquire address  space of applications protected with the most sophisticated systems such as nProtect GameGuard correctly. Belkasoft Live RAM Capturer beats many popular memory dumping applications hands down due to the difference in design goals. Current versions of competing tools (AccessData FTK  Imager 3.0.0.1443, PMDump 1.2) operate in the system’s user mode, which  makes them susceptible to anti-dumping activities performed by active  debugging protection systems such as nProtect GameGuard.

An internal comparison between Belkasoft Live RAM Capturer and latest versions of competing RAM acquisition tools demonstrated the ability of Belkasoft Live RAM Capturer to acquire an image of a protected memory  set while the other tools returned an empty area (FTK Imager) or random  data (PMDump).

You can download the tool at https://belkasoft.com/ram-capturer for free. You need to register an account in Belkasoft in order to get the download link.

![install01](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/2-+Acquiring+memory+image+from+Windows+and+Linux/1.png)

Run “RamCapture64.exe” as administrator.

![install01](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/2-+Acquiring+memory+image+from+Windows+and+Linux/2.png)

Enter the path where you want to store the output and click Capture.

The output will be named randomly.

![install01](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/2-+Acquiring+memory+image+from+Windows+and+Linux/3.png)

This is an excellent tool to acquire memory with little footprint. This is recommended for most cases.

### FTK imager 

FTK® Imager is a data preview and imaging tool that lets you assess  the electronic evidence quickly to determine if further analysis with a  forensic tool such as Forensic Toolkit (FTK®) is warranted. It can  create forensic images of local hard drives, CDs and DVDs, thumb drives  or other USB devices, entire folders, individual files or capture  memory.

The tool can be downloaded at https://www.exterro.com/ftk-imager for free.

Let's open up the tool as administrator.

![install01](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/2-+Acquiring+memory+image+from+Windows+and+Linux/4.png)

The main interface would be empty and look like this.

![install01](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/2-+Acquiring+memory+image+from+Windows+and+Linux/5.png)

Now go to File -> Capture memory

![install01](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/2-+Acquiring+memory+image+from+Windows+and+Linux/6.png)

You will be prompted with a pop-up.

![install01](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/2-+Acquiring+memory+image+from+Windows+and+Linux/7.png)

Browse the path where you want to store the memory image in the  “Destination Path”. This can be a local folder like your desktop, or a  remote path like a network share or any externally connected device like a hard drive or a USB. In the “Destination filename” we can specify the name of the memory image we are capturing. Some extensions for memory  images can be “mem”, “bin” or “raw” file extensions. You can also check  the “Include pagefile” option if you want the Windows pagefile  information too. For our case, let's leave it as it is.

Lets review the parameters we just set.

![install01](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/2-+Acquiring+memory+image+from+Windows+and+Linux/8.png)

Destination path: G:\Lets_Defend_Acquisition

Destination filename: LetsDefend_Acquisition.mem

Now we click capture memory and the memory acquisition process gets started.

![install01](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/2-+Acquiring+memory+image+from+Windows+and+Linux/9.png)

It's important to note that FTK imager is not created just for the  purpose of memory acquisition so it is not the best memory acquisition  tool ever. It may have errors from time to time. So it's not perfect but gets the job done. That's why tools like MAGNET RAM Capturer or  Belkasoft RAM Capturer are better than FTK Imager when it comes to  acquiring memory.

### Acquiring Linux Memory Dump

We will be using AVML by Microsoft to acquire memory from a Linux  system/server. We know it's a little surprising that Microsoft has an  acquisition tool for Linux systems.

### AVML 

AVML is an X86_64 userland volatile memory acquisition tool written  in Rust, intended to be deployed as a static binary. AVML can be used to acquire memory without knowing the target OS distribution or kernel a  priori. No on-target compilation or fingerprinting is needed. Its memory sources are:

-/dev/crash

-/proc/kcore

-/dev/mem

If the memory source is not specified on the commandline, AVML will iterate over the memory sources to find a functional source.

This tool is very handy as it's shipped as a single binary with no  dependencies or kernel object creation needed. We just run the binary  and specify the output path and get a memory image. Let's see it in  action. AVML can be downloaded from: https://github.com/microsoft/avml/releases/download/v0.9.0/avml.

![install01](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/2-+Acquiring+memory+image+from+Windows+and+Linux/10.png)

First, we need to make this binary to be executable, so, run:

**Command:** “chmod +x avml”

![install01](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/2-+Acquiring+memory+image+from+Windows+and+Linux/11.png)

Now, we run the binary without any additional arguments and we can see its help menu.

![install01](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/2-+Acquiring+memory+image+from+Windows+and+Linux/12.png)

To acquire the memory image provide a file name along with desired  extension. The file can be saved locally on any path, or to remote  locations like network file shares etc. This feature is handy as  analysts can acquire and directly write to a remote file share without  making unnecessary changes to the compromised server. Lets see avml in  action.

![install01](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/2-+Acquiring+memory+image+from+Windows+and+Linux/13.png)

We run this command which will create a memory image named  "Linux_Acquisition.raw" in the same location. The prompt will be  complete shortly. You will not be given any output that AVML has done  its work.

Now that it has stopped running, let's list the contents to see whether memory was dumped or not.

![install01](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/2-+Acquiring+memory+image+from+Windows+and+Linux/15.png)

Here we can see the file name along with it’s size. The RAM of the Linux system was 5.6 GB from which it was acquired.

After the memory is acquired from Windows or Linux, analysts can  analyze them using tools like Redline or Volatility. Acquiring memory is important and easy and is forensically valuable that's why every  analyst must know how to do it.

In this lesson, we have discussed how to acquire memory on both  Windows and Linux systems properly, especially when running from a  remote location or running from USB. We have also discussed how  important not to interact with the compromised system as it can tamper  with the evidence (Memory or RAM) in our case.

**Note:** If you want to practice and explore these tools in the  lab, use the Local Disk "D:" to store any data. Please be aware of the  available disk space limitation as the acquisition process usually  requires lots of space and is not very practical for labs.

## Custom Image Using FTK and Mounting Image for Analysis

FTK Imager can be used to create custom images as well. Custom image  includes parts of the file system according to our needs. We can specify specific files or folder/paths which we are interested in for  acquisition instead of full disk acquisition. This is really important  as full disk images can take hours or even days to acquire due to their  sizes. Custom image can allow us to acquire relevant data for quick  triage and kick start the investigation until full disk is acquired.  Then full disk image analysis is necessary for in depth analysis.

Run FTK Imager as administrator.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/1.png)

Go to File -> Add Evidence Item .

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/2.png)

We will select the source of the image we are creating on the pop up window to create the custom image.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/3.png)

Select source means select the type of disk which we want to add the evidence from.

1-**Physical Drive:** Drive attached to your computer  like HDD, SSD, etc. This drive contains the full capacity of physical  hardware, and has allocated and unallocated spaces too. This is  generally bigger in size but allows recovery of deleted files/contents.

2- **Logical Drive:** A logical drive is just like a  physical drive, except that this has only the files and allocated space. Unallocated space is not present.

3- **Image File:** We can use this source if we want to use an acquired disk image and carve out specific files/contents from it.

4- **Contents of a folder:** This allows us to acquire all data from a folder we want. This option only contains the logical space of the specified folder.

You can select physical, logical or the last one while acquiring from live systems. We will select logical as it's organized and less tidier  than physical one. Then select the drive from which you want the data.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/4.png)

Select the Local disk image we want to add from. In a corporate and  active directory environments we would be interested in "C:\" as this is Windows root. Then click “Finish”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/5.png)

Then, we will see this under the Evidence Tree. Expand this as NONAME[NTFS] -> [root]

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/6.png)

We can add any number of files or folders we want from the file system. Lets add Documents folder of user “pc”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/7.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/8.png)

Right click the folder/file we want to add.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/9.png)

We can also add event logs, registry hives or any artifact that are  present on the Windows system. This is useful as this image can then be  mounted on a forensics investigator’s system for analysis. Let's add  registry hives to our image as an example. Registry hives are located  at:

%SYSTEMROOT%\config\

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/10.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/11.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/12.png)

Let’s right click on it and add it to the custom image.

Now, we will be adding a specific file. Let’s suppose we spot a powershell script on the user desktop.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/new/13-edited2.png)

Let’s right click on this and add it. We can see all the evidence  items we added in our image on the navigation menu on the left.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/14.png)

Now let’s create the custom image which will contain the files and  folders and the data we acquired so far. Click on the “Create Image”  button below.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/15.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/16.png)

We will be prompted with a pop up window. Then click “Add” to specify the destination location where the file is going to be stored. It can  be a remote network file share or a local path. After clicking “Add” we  will be prompted for more information which we can skip in our case but  it's highly recommended in real cases as it helps keep track of the  chain of custody.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/17.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/18.png)

Then, we can provide a destination location. It can be a remote  network file share or a local path. We can also provide names for the  custom image. The common naming format is the date and time of the  acquisition and the Computer Name/IP address.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/19.png)

Leave everything else unless needed. Let’s click Finish.

Now we are back to the first pop up window. Make sure to check the  “Verify images after they are created” option as this will verify that  the image is not corrupted or tampered with after the creation. The  option “Create directory listings of all files in the image after they  are created” creates the directory structure and places the added  evidence in its original location just like in a real file system. If  it's enabled, all file/folders will be placed in the same root  directory, otherwise they will exist under their original path. If you  have created a custom image which includes many files and folders, then  enabling this option will help categorize the data. Let's leave it  enabled to showcase you.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/20.png)

Click the “Start” button. It will show the progress and it depends upon how many items we have added and the data size.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/21.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/22.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/23.png)

The custom image is 191 MB in size and contains a lot of data. We  could have added more different artifacts, and data sources if we wanted but this was just to show the capabilities of FTK imager, so we are not adding data anymore.

### Mounting the Image 

Now let's discuss how to mount images using FTK Imager. FTK imager  can be used on the Windows systems to mount full disk images or custom  images like we just created. This process should not be done on the same machine from where you acquired the image. This should be done on a  forensics workstation where the analysis is done by the analysts.  Mounting the image allows you to browse through the contents of the  image just like you are browsing through your own computer.

Go to File -> Image Mounting

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/24.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/25.png)

In the “Image File” tab, we can add the custom image we want to  mount. We can add the full disk images too, but we will mount the image  we just created for the demo purposes. Full disk images may be hundreds  of GBs and are not practical for the course demonstration. The process  is the same as a custom image, just the size would be relatively much  larger.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/26.png)

Let’s click the “Mount" button to mount the disk image. After the  image is mounted, we can see the drive letter where it is mounted.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/27.png)

Let's open file explorer to see if we can spot the E: drive.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/28.png)

Let's open this up.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/29.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/30.png)

Our acquired data will be under the “[root]” directory.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/31.png)

Here we can see it just like we are browsing our own local file  system. Let's go to the documents folder we acquired from user “pc”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/32.png)

We also see the PowerShell script on the user's desktop.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/3-+Custom+image+using+ftk+and+mounting+image+for+analysis/33.png)

The mounting feature helps analysts perform their analysis on  disk-based data just like performing live analysis on the compromised  machine.

In this lesson, we have discussed how to acquire targeted data from  the Windows system and create a disk image relevant to our  investigation, instead of waiting days for full disk acquisition. We  have also discussed on starting the triage process by mounting the  acquired image and starting analysis of the data.

**Note:** If you want to practice and explore this tool in the  lab, use the Local Disk "D:" to store any data. Please be aware of the  available disk space limitation as acquisition process usually requires  lots of space and is not very practical for labs.

### Questions

**Note:** Firstly, disable Windows Defender on the Windows lab machine.

1 - Mount the Lesson3.ad1 image, available at  "C:\Users\LetsDefend\Desktop\Lesson 3\Lesson3.ad1" using FTK Imager.  What is the file name present in the users Desktop?

> **Answer:** reverse.exe

2 - What tool is the PowerShell script of in the Documents folder?

> **Answer:** Sharphound

## KAPE Targets for Acquisition

KAPE stands for “Kroll Artifact Parser and Extractor” and is used to  acquire and parse Windows artifacts. KAPE is a robust, free-software  triage program that will target a device or storage location, and help  find the most forensically important artifacts (based on your needs),  and parse them within a few minutes. Thanks to its speed, KAPE allows  investigators to find and prioritize the systems most critical for their case. Additionally, KAPE can be used to collect key artifacts prior to  the start of the imaging process. While the imaging is in progress, the  data generated by KAPE can be reviewed for leads, building timelines,  etc.

KAPE focuses on collecting and processing relevant data quickly,  grouping artifacts in categorized directories such as  EvidenceOfExecution, BrowserHistory, and AccountUsage. Grouping things  by category means an examiner no longer needs to know how to process  prefetch, shimcache, amcache, userassist, etc., as they relate to  evidence of execution artifacts.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/1.png)

KAPE has two primary phases – target collection and module execution:

\- Targets are essentially collections of file and directory specifications.

\- Modules are used to run programs, which can target anything,  including files collected via targets as well as any other types of  programs you may want to run on a system from the live response  perspective.

KAPE gives you access to targets and modules for the most common  operations required in the forensic exams, helping investigators gather a wider range of artifacts in a fraction of the time, and enriching  evidentiary libraries.

In this lesson, we will use KAPE target collection to acquire  artifacts and explore available targets and will cover module phase  which can be considered the triage phase in the next lesson.

You can download KAPE here: https://www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape for free. You will need to fill a form to get the download link.

### KAPE Target Collection 

From the official description,

Targets are essential collections of file and directory  specifications. KAPE knows how to read these specifications and expand  them to files and directories that exist on a target location. Once KAPE has processed all targets and has built a list of files, the list is  processed, and each file is copied from the source to the destination  directory. For files that are locked by the operating system and  therefore are not able to be copied by regular means, the file is added  to a secondary queue. This secondary queue contains all the files that  were locked or in use. After the primary queue is processed, the  secondary queue is processed and a different technique, using raw disk  reads, is used to bypass the locks. This results in getting a copy of  the file as it exists at the source. Regardless of how the file is  copied (either regularly or via raw access), the original timestamps  from all directories and the files themselves are reapplied to the  destination files. The metadata is also collected into log files as  well.

To summarize, KAPE has a number of config files in its “target”  directory. These contain paths, metadata and information about different important forensics artifacts that can be found on Windows systems. We  can use any of the targets along with its parameters to collect the kind of acquisition we want. For example there's a target for acquiring  “browser” related data which will collect the data relevant for browser  analysis. There's a target module made by SANS institute, which acquires the artifacts and data recommended by SANS. KAPE has its own  proprietary target created by the KAPE engineers, which also acquires  good and relevent artifacts for quick triage.

This is what the KAPE files look like when installed. Lets visit Targets directory to get an overview.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/2.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/3.png)

We can see that these are further categorized by directories. Let’s visit Antivirus directories.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/4.png)

Here, we can see that there are many target files for many different  antivirus vendors. This is extremely useful, for example we are  acquiring data from an endpoint which was running Avast antivirus. We  will select Avast target too as one of our targets during the collection phase as this will fetch relevant logs and files related to Avast  antivirus. Notice that the extension of files are labeled as TKAPE which stands for Target KAPE. Let's open the avast.tkape file in notepad.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/5.png)

We can see it specifies some common locations where Avast stores its  data. So when we run KAPE and specify Avast as one of the targets, KAPE  will go through the above paths and collect the data. Similarly there  were categories for browsers which will contain targets for different  browsers, logs targets which will contain paths for logs like Apache,  IIS, Nginx etc.

**Note:** It is encouraged to explore all target directories to get to know how many data sources are there.

The main target directories would be Windows and compound. Windows  target would contain many different targets targeted towards Windows  forensics artifacts like amcache, prefetch etc.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/6.png)

This would come handy when we want to acquire specific types of data  like if we only want event logs related to RDP, we will select  EventLogs-RDP target. Another important target category is known as  compound. These targets are configured to collect most of the important  forensics artifacts across the Windows system, not just for a specific  artifact. For example, SANS triage and KAPE triage are widely used as  they collect almost all the important types of artifacts needed in the  incident response.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/7.png)

Let's analyze the SANS Target file to see its structure.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/8.png)

As we can see in compound target files, the data source paths,  locations are not specified but the other target files are specified  which contains the actual locations path of relevent artifact. This  means that compound targets are made up of all the other individual  target files we previously explored briefly. You can also write your own custom target rule or modify an existing one if needed. However we will not do it in the course.

### Acquisition using KAPE targets 

Now that we have discussed the structure of KAPE and how it collects  the data and know what to look for, let's start the acquisition process. In the main KAPE directory, we see 2 .exe files, one named "kape.exe"  and the other one is "gkape.exe". We will be using gkape as it is GUI  version of it.

**Note:** Run the tool as administrator.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/9.png)

The landing interface of KAPE will be mainly empty because we haven't done anything yet.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/10.png)

Enable the “Use Target Options” to start acquiring data.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/11.png)

**Target Source:** Path from where you want to acquire data. Usually it's the file system root or Windows root.

**Target Destination:** Path where you want to store the artifacts acquired.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/12.png)

**Note:** Flush option deletes the directory data before collection. You can enable Add %d and Add %m checks if you want to name the acquisition directory with date. This is a handy feature to keep  track of acquisition.

Next, we can see the target option from where we can select the  targets. We can search or scroll to find all of the targets that are  present under Targets directory discussed above.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/13.png)

Let’s use SANS triage target to acquire the data.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/14.png)

There are more options right down below target options. Let's discuss these too.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/15.png)

\- Process VSCS: Acquire volume shadow copies too.

\- Container: Add the acquired data to a container like a Zip file. If selected, we need to input a name in “Base name” for the container  file.

Let's select Zip as a container as it becomes convenient to transfer the data if needed. Reviewing our options selected so far.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/16.png)

Let’s click “Execute” in the bottom right of KAPE.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/17.png)

We will see the command prompt open and KAPE collecting the data. GUI KAPE provides just an interface for ease of use, it uses the CLI in the backend.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/18.png)

The collection is completed.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/19.png)

Now let's go over and navigate the collected data.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/20.png)

Let's unzip it and navigate.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/21.png)

The main data will be under the “C” directory.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/4-+Understanding+KAPE+targeted+acquisition+and+Acquiring+Important+artifacts/22.png)

Now you may be thinking that we did something similar with FTK  imager. With KAPE, it automatically collected hundreds and hundreds of  important data sources and artifacts according to our target selection.  If we did this in FTK Imager, we would have to go over each artifact and add it to the custom image manually. KAPE conducted this for us in  under 5 minutes and contained many files and artifacts that we may not  even notice when implementing this in FTK Imager. The data which KAPE  just collected for us according to SANS triage, is just 2.52 GB in size  and contains almost all of the necessary artifacts and data sources we  would need for forensics investigation, whereas the full disk image  would have been in TBs in size. The true power of KAPE will be explored  in the next lesson where we also process the artifacts on the fly as  they are being acquired by KAPE, for quick triage.

In this lesson, we discussed what KAPE is, understanding the KAPE  Targets feature and how to acquire relevant data from your choice of  hundreds of data sources using KAPE targets.

**Note:** If you want to practice and explore this tool in the  lab, use the Local Disk "D:"  to store any data. Please be aware of the  available disk space limitation as acquisition process usually requires  lots of space and is not very practical for labs.

### Questions

1 - What is the full name of the target KAPE config file which tells KAPE where to find artifacts related to USB usage?

> **Answer:** USBDevicesLogs.tkape

2 - Who is the author of KAPE basic collection target?

> **Answer:** Phill Moore

3 - Use the Compound Target module “RecycleBin” to acquire artifacts related to Recycle Bin. Specify “C:\” as Target Source, and specify the Target  destination of your choice. Select ZIP as a container. Then Unzip the  file after successful acquisition. And go inside the unzipped folder.  What’s the Folder name inside the Folder “C”?

> **Answer:** $Recycle.Bin

## KAPE Modules for Triage and Analysis

Like targets, modules are also defined using simple properties and  are used to run programs. These programs can target anything, including  files collected via the target capabilities as well as any other kinds  of programs you may want to run on a system from a live response  perspective.

For example, if you collected jump lists, a tool like JLECmd could  dump the contents of the jump lists to CSV. If you also wanted to  collect the output of netstat or ipconfig, you could do so. Each of  these options would be contained in its own module and then grouped  together based on commonality between the modules, such as  "NetworkLiveResponse" for example.

In simpler words module files are also configuration files which  specify how to process/parse an artifact collected from targets. Modules can use any Windows built in application like PowerShell, notepad, etc. or any external downloaded program. In modules the path of the  programs/application is specified along with necessary arguments needed  to parse a specific artifact. Modules can also be used to collect direct information from a system without any other collected artifact. For  example a Scheduled Task module will query the system for scheduled  tasks and save the results in a spreadsheet automatically. This is done  by utilizing the “schtasks.exe” utility in Windows along with other  required arguments. We didn't need to run the command manually as KAPE  did it automatically. Module Kape files have extension “.MKAPE”. Let’s  visit the “Modules” directory.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/1.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/2.png)

The structure of modules is similar to that of targets, except the  “bin” and “EZtools” directory which we will soon discuss. First, let's  visit Windows modules and the scheduled tasks that we discussed above so you can get a basic idea.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/3.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/4.png)

This tells KAPE to run this tool along with specified arguments in  order to collect data about scheduled tasks present. Now let's discuss  bin and EZTools directories.

### EZTools Directory

This directory contains mkape config files which tells KAPE how to  use Eric Zimmerman tools to parse many of the Windows Artifacts. EZTools or Eric Zimmerman tools are awesome collection of tools which process  and parse almost all of the Windows artifacts. Let’s see an mkape file  under this directory.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/5.png)

This mkape file is focused on parsing amcache using AmcacheParser.exe which is one of the tools by Eric Zimmermen.

### bin Directory 

This directory contains all the Eric zimmerman tools themselves which are used by modules like EZTools or amcache etc. Let’s see the  installed tools in the bin directory.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/6.png)

These are the tools which will parse most of the valuable artifacts,  however we can add any application we want in here and then create a  mkape file for it.

### Compound Modules 

Just like in targets, Compound Modules also exist where we can  leverage multiple other modules all in one. Let's visit the “Compound”  directory and read mkape file for the “!EZParser” module which utilizes  all of the mkape files we just explored in EZTools directory.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/7.png)

We can see that it's referencing to mkape files named by EZtools and these can be found in the EZTools directory.

Modules can be executed along with the target acquisition, meaning as the artifacts are being collected they are also being triaged and  parsed by the selected modules. Let’s extend upon the example we did in  the previous lesson but now we will triage the data as it is collected.  This could save hours of time and manpower.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/8.png)

Here, we selected the same Compound Target “!SANS_Triage” which we  practiced in the previous lesson. This was only the target acquisition  part. Now on the right half of the GUI, we see a module portion which is locked out. Click “Use Module options'' to enable that portion.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/9.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/10.png)

The “Module Source” is the directory containing files to process. If  you have already acquired the data, then you can select the directory as Module Source and the selected modules will process the files under  that path. However what we are doing is acquiring and triaging the data  on the fly so we will leave module source empty as we have not yet  acquired the data. KAPE will automatically set the Module Source to the  Target Destination meaning where the data will be stored after the  acquisition, KAPE will automatically process the files there.

Module destination will be where we want to store the results of  triage. Let’s create a directory named triage in the path where data  will be acquired and there we will set the Module destination.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/11.png)

Next, we will select the “!EZParser Module” as this will be more  fruitful in our case. Most common and important artifacts would be  parsed and data would be ready to analyze for us.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/12.png)

Now let’s review the overall config of KAPE and start the Acquisition and triage process.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/13.png)

Click “Execute” on the right bottom.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/14.png)

Click OK on the pop up. If you deselect the flush option in target or module destination paths, this will not be prompted.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/15.png)

KAPE will begin acquiring and triaging the data. The artifacts data will be triaged and ready for analysis after it is complete.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/16.png)

The triage is completed. Here, we see the acquired data, it's just like what we acquired in the previous lesson.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/17.png)

The triage directory which we created and set as the destination where triaged data will be stored.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/18.png)

The data is categorized with the type of information it stores. Let’s visit the “ProgramExecution” folder.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/19.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/5-+KAPE+Modules+for+triage+and+analysis/20.png)

Now, analysts can analyze the results directly without needing to parse the artifacts manually. 

In this lesson, we learned the KAPE modules and discussed on how to  use them along with the targets. KAPE can be used to acquire and triage  the data quickly. This is why every Forensics Analyst must know how to  use KAPE.

**Note:** If you want to practice and explore this tool in the  lab, use the Local Disk "D:" to store any data. Please be aware of the  available disk space limitation as acquisition process usually requires  lots of space and is not very practical for labs.

### Questions

1 - Who is the author of KAPE compound module named “hayabusa”?

> **Answer:** Andrew Rathbun

2 - Uncheck the Target option section and only enable the use Module  options. Select the folder  “C:\Users\letsdefend\Desktop\Lesson5\practice” as Module source. Choose  the destination of your choice. Use the module named “EvtxECmd_RDP” and  select the  Export Format as CSV. What's the file size of this CSV file?

> **Answer:** 8323

## Triage Using FireEye Redline

Redline®, FireEye’s premier free endpoint security tool, provides  host investigative capabilities to users to find signs of malicious  activity through memory and file analysis and the development of a  threat assessment profile. Use Redline to collect, analyze and filter  endpoint data and perform IOC analysis and hit review. ([https://fireeye.market/apps/211364)](https://fireeye.market/apps/211364)

Redline helps analysts not only triage the endpoints data quickly but also allows them to scan the endpoints for specific IOCs (Indicators of Compromise). We can run a Redline collector on endpoints we want to  triage, and the data will be acquired and triaged all in one  application. A Mandiant file with “.mans” extension is created. We will  open it in the Redline application and analyze all the data acquired and parsed. The tool has a nice GUI and categorizes the data very neatly.  Redline can be run on Windows Operating Systems.

Redline can triage registry, running processes in memory, browser  data, scanning for known bad and suspicious strings across the system  etc. We can customize what to scan for before running redline  collectors. Redline collector is responsible for acquiring the data  which is configured by the user. Then a Mandiant session file is created which can be analyzed by analysts for a quick triage. This provides all in one stop for analysts to kick start the investigation.

Redline can be installed from here ([https://fireeye.market/apps/211364)](https://fireeye.market/apps/211364). You need to fill a form to get a download link. The tool will be conveniently placed in the lab for you.

Let's start using this tool. Run Redline as administrator.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/1.png)

The application landing menu looks like this.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/2.png)

For now, we are interested in the “Collect Data” part. There are 3 types of collectors in Redline.

**- Standard Collector:** The Standard Collector configures scripts to gather the minimum amount of data to complete an analysis.

**- Comprehensive Collector:** The Comprehensive  Collector configures scripts to gather most of the data that Redline  collects and analyzes. Use this type of Redline Collector if you intend  to do a full analysis or if you have only one opportunity to collect  data from a computer.

**- IOC Search Collector (Windows only):** The IOC  Search Collector collects data that matches selected Indicators of  Compromise (IOCs). Use this Redline Collector type when you are looking  only for IOC hits and not any other potential compromises. By default,  it filters out any data that does not match an IOC, but you can opt to  collect additional data. If you do not use an IOC Search Collector, you  can still analyze data collected with IOCs after the data has been  imported into Redline to create an analysis session. The effectiveness  of the IOC analysis depends on the data available in the analysis  session. 

We will go with the Standard Collector in this lesson as a  demonstration. In real investigations, if your goal is a quick full  triage analysis then Comprehensive collector is recommended. If you are  conducting threat hunting activities and looking for specific IOCs in  your network then IOC Search Collector is ideal for that.

Click “Create a Standard Collector”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/3.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/4.png)

Here we select the target platform from which we are acquiring and  triaging the data. We select Windows. Then click “Edit” your script  option as this is where we can configure he data types we are interested in. This is very helpful as we can remove unnecessary options that we  are not interested in for saving crucial time especially during the  incidents.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/5.png)

Here, we can see what information will be acquired from the memory.  We can also enable the checkbox “Acquire Memory Image” which will also  create a separate memory image which can then be used with any number of tools for analysis like volatility framework. When disabled, the data  acquired from the memory will be included in the “.mans” file created  which will contain all the data acquired and triaged from memory related data to the network related data. Let’s disable all memory related  options to save time.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/6.png)

Next up, we go to the “Disk” section. We select a few of the options as below for a quick and basic triage.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/7.png)

Then, we go to the “System” section. Here, we select the options as below.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/8.png)

Here we can select the event logs option to system restore points  which can be an excellent data source. It all depends on your needs and  how much time you can afford to spend during an incident.

Then, we go to the Network tab and select a few common options. We  can also select the browser data which can be an excellent source for  malicious browser activities.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/9.png)

The last remaining section is “Other” and is very useful for incident responders especially.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/10.png)

Here we can configure Redline to look for some anomalies and look out for any possible signs of persistence mechanisms on the system.

Click “OK” as now we have configured our collector. We will be back to this screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/11.png)

Now, go to the bottom and click browse. Here, we will select the  location where our collector script will be placed and our triaged data  will be stored after running that script. Let's demonstrate it so you  can get a better idea. We select a Directory named “LetsDefend_Redline'' that we have created for this lesson.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/12.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/13.png)

Now we can see the selected path on the same screen from where we configured it. Click “OK” in the lower right corner.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/14.png)

After a few seconds, you will be given a prompt:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/15.png)

Let's go to the location and see the collector scripts.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/16.png)

Here the batch script named “RunRedlineAudit'' is the main script  which we will execute and it will acquire the data and triage it from  the system. One very important and great thing about the collector  scripts is that we can save collector scripts on the network drives or  store them in USBs, and whenever there's an incident and we want to  triage an endpoint we can run the scripts from USB or from network drive directly. We can create different types of collectors by configuring  and saving them beforehand so we don’t need to create a new collector  all the time prior to triaging an endpoint. We did that for  demonstration and to show you how to use the tool.

Now, let's run the collector script “RunRedLineAudit” as an administrator.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/17.png)

A cmd prompt will open to show the progress of triage.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/18.png)

The path after switch “-o” is  “G:\LetsDefend_Redline\\Sessions\AnalysisSession1\Audits” which is where our mandiant file will be saved with extension “.mans”. That file will  contain all the triaged data ready to be analyzed in a categorized  manner. The XML file “MemoryzeAuditScript.xml” stores our configuration  when we edit the script and set our preferences above.

The cmd will exit when complete. Go to the folder where our collector script was installed. There we will see a “Sessions" folder.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/19.png)

Then there will be a folder named “AnalysisSession1". If we run the  collector script again, another folder will be created named  “AnalysisSession2” and so on.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/20.png)

Go to this folder here where we can see the .mans file (Mandiant Analysis).

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/21.png)

This is just a file from where we will open the triaged session file, the data is stored in Audits directory.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/22.png)

Now, open the file named “AnalysisSession1.mans”

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/23.png)

It will take about 10 minutes for the Redline to load the file, then we will see the below screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/24.png)

We will go for the second option “I am Investigating a Host Based on  an External Investigative Lead''. If we are interested in browser  forensics we would go with option 3. Similarly we are hunting for  threats using known indicators of compromise we would go for the last  option. The first option is useful if the organization is using FireEye  Endpoint Threat Prevention Platform (HX) then the whole process would be even faster and automated.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/25.png)

Click investigate.

Now, we will see the triaged data and it depends on the type of data we collected.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/26.png)

We could have seen more data if we had collected more data when  acquiring. Since we do this as a demonstration, we collected very  limited data just to showcase. Here, we see different information from  different data sources. If we selected memory triage, we would have a  very detailed tab about memory related data. If we did full filesystem  triage we would see data related to that.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/6-+Triage+using+FireEye+Redline/27.png)

We can check/uncheck any information according to our needs.

In this lesson, we explored how to use redline for quick collection  and triage of endpoints. We will explore autopsy, a very handy tool for  disk acquisition and analysis with a variety of good features, in the  next lesson.

**Note:** If you want to practice and explore this tool  in the lab, use the Local Disk "D:" to store any data. Please be aware  of the available disk space limitation as the acquisition process  usually requires lots of space and is not very practical for labs.

### Questions

1 - There's a Mandiant analysis file named “Lesson6.mans” placed in  “C:\Users\letsdefend\Desktop\lesson6\lesson6.mans”. Open this file in  Redline and start the triage process as discussed in the course. Visit  “hierarchical processes”. What is the process ID (PID) of cmd.exe?

> **Answer:** 2552

2 - Now visit the “Windows Services” tab. What's the name of the Service starting with “139”?

> **Answer:** 1394ohci

## Acquisition and Triage of Disks Using Autopsy

Autopsy® is the premier end-to-end open source digital forensics  platform. Built by Basis Technology with the core features you expect to have in commercial forensic tools. Autopsy is a fast, thorough, and  efficient hard drive investigation solution that evolves with your  needs. Autopsy can parse Windows, Linux and Android based file systems. (https://www.autopsy.com/)

Some of the features of this tool are:

\- Multi-User Cases: Collaborate with fellow examiners on large cases. 

\- Timeline Analysis: Displays system events in a graphical interface to help identify activity. 

\- Keyword Search: Text extraction and index searched modules enable  you to find files that mention specific terms and find regular  expression patterns. 

\- Web Artifacts: Extracts web activity from common browsers to help identify user activity. 

\- Registry Analysis: Uses RegRipper to identify recently accessed documents and USB devices. 

\- LNK File Analysis: Identifies shortcuts and accessed documents.

\- Email Analysis: Parses MBOX format messages, such as Thunderbird. 

\- EXIF: Extracts geo location and camera information from JPEG files.

\- Media Playback and Thumbnail viewer.

\- Robust File System Analysis: Support for common file systems,  including NTFS, FAT12/FAT16/FAT32/ExFAT, HFS+, ISO9660 (CD-ROM),  Ext2/Ext3/Ext4, Yaffs2.

\- Unicode Strings Extraction: Extracts strings from unallocated space and unknown file types in many languages.

\- File Type Detection based on signatures and extension mismatch detection. 

\- Interesting Files Module will flag files and folders based on name and path. 

\- Android Support: Extracts data from SMS, call logs, contacts, Tango, Words with Friends, and more.

(**Source:** https://www.cybervie.com/blog/introduction-to-autopsy-an-open-source-digital-forensics-tool/)

You can download the Autopsy at: https://github.com/sleuthkit/autopsy/releases/download/autopsy-4.19.3/autopsy-4.19.3-64bit.msi

Run the tool as administrator

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/7-+Acquisition+and+triage+of+disks+using+Autopsy/1.png)

The app will start with this screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/7-+Acquisition+and+triage+of+disks+using+Autopsy/2.png)

Select “New Case” to start a new investigation as in our case. Then  we will be prompted to give our case a name and directory where our case files will be stored.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/7-+Acquisition+and+triage+of+disks+using+Autopsy/3.png)

Then click next. We can then give additional information about the  case or investigation we are about to conduct. This is encouraged as it  keeps track of the proper chain of custody. This is to maintain tabs on  forensics investigations.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/7-+Acquisition+and+triage+of+disks+using+Autopsy/4.png)

We filled some data for demonstration purposes. Now, click Finish. Then, we will be prompted to another window as below.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/7-+Acquisition+and+triage+of+disks+using+Autopsy/5.png)

Data source would be the disk image or a hard drive which we want to  acquire or analyse. Click next in this window to select the data source  type.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/7-+Acquisition+and+triage+of+disks+using+Autopsy/6.png)

If we want to analyze a disk image which was already acquired and we  wish to analyze its content, we would leave it at the first option.  Let's say we want to analyze the local disk of the computer we are  analyzing/triaging during an incident. Then we will select the second  option and click next.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/7-+Acquisition+and+triage+of+disks+using+Autopsy/7.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/7-+Acquisition+and+triage+of+disks+using+Autopsy/8.png)

Here, we need to select the local disk we wish to analyze, and the  timezone for which we want to configure the forensics timeline. It's  recommended to set the timezone the same as the timezone which is  configured for the computer under investigation. If we need a disk image of the disk too, we can enable the option “Make a VHD image of the  drive while it is analyzed”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/7-+Acquisition+and+triage+of+disks+using+Autopsy/9.png)

Click next. Now the “Configure Ingest” is the core feature of Autopsy.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/7-+Acquisition+and+triage+of+disks+using+Autopsy/10.png)

Here, we can select what plugins we need for Autopsy to run against  our disk to parse the data. For example, the “Email Parser” will try to  find any emails found on the disk (maybe in the logs, files, programs,  deleted unallocated space, etc). Then, we click “Next” and the analysis  results start coming in.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/new/11-edited.png)

You can see how the data is categorized. Let’s see 1 or 2 examples  for a quick demonstration as forensics analysis is out of scope for this course, we will not go into much details.

In OS accounts, we can see present users on the system.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/new/12-edited.png)

We discussed “Recent Documents” artifact in “Windows Registry  Forensics” course. Here in Autopsy, we see an option to view this  artifact data.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/new/13-edited.png)

We can also view all images/videos present on the disk by going to the option “Images/Videos”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/7-+Acquisition+and+triage+of+disks+using+Autopsy/14.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/7-+Acquisition+and+triage+of+disks+using+Autopsy/15.png)

There's not much data in this disk because it's a virtual machine. If it were from a user's computer or a server, there would be much more  data available.

Live triage drive feature:

Autopsy has a feature which allows analysts to automatically setup  Autopsy tools in a removable media drive like a USB. It creates scripts  for triage mode, which then analysts simply need to run the script from  the USB and Autopsy will automatically triage and acquire data from the  computer to which removable drive is attached.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/7-+Acquisition+and+triage+of+disks+using+Autopsy/16.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Forensic-Acquisition-and-Triage/7-+Acquisition+and+triage+of+disks+using+Autopsy/17.png)

This lesson was in no way a detailed demonstration of the Autopsy  tool which is rich in features for disk analysis in a proper GUI. We  will cover Autopsy in detail in the future course(s). In this lesson, we have discussed the power of Autopsy and how to get started using it.







