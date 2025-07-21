# Memory Forensics

Sometimes you can not find evidence on disk during analysis. Learn how to do memory analysis and never miss any evidence.

Table of Contents

- What is Memory Forensics?
- [Memory Analysis Procedures]()
- [Practical Analysis 1: Masqueraded Process]()
- [Practical Analysis 2: Process Injection]()
- [Practical Analysis 3: DLL Injection]()

**Challenge**

- [Memory Analysis](https://app.letsdefend.io/challenge/memory-analysis)
- [Ransomware Attack](https://app.letsdefend.io/challenge/ransomware-attack)

## What is Memory Forensics?

Memory forensics refers to the analysis of volatile data in a  computer’s memory dump. Cyber Security Analysts conduct memory forensics to identify Indicators of Compromise (IOCs) and investigate malicious  activities, behaviors and malicious network traffic on corporate servers and critical computer systems that are in continuous operation. This  makes the computer systems high level targets for Cyber Criminals and  Hackers.

Memory is volatile which means the data is lost whenever the computer is shut down. When dealing with a compromised device, one of the first  reactions may be to turn the device off to contain the threat. If any  malware or command and control (C2) network connections are established, they will be running in memory and if the system gets shut down, that  information will be lost. This information would be critical which would help us in incident response and incident analysis. This is why Network containment (isolating the device from the rest of the network) is the  preferred option when isolating a compromised device.

Another reason is that when a system compromise occurs, large amounts of forensic evidence such as logs and disk images must be acquired for  in-depth investigation. Collecting this data takes hours or sometimes  days depending on the log size, hard disk size, etc. At the onset of an  incident, time is of the essence and we need to contain and respond to  the threat as quickly as possible. This makes the volatile memory (RAM)  an excellent artifact to quickly analyze and understand what happened at the endpoint since RAM size is relatively small and can be quickly  acquired.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/what-is-memory-forensics/1.png)

Memory forensics is an excellent way to quickly identify and  understand malware related attacks, as any indicators of compromise  (IOCs) such as malware, malicious files, and C2 network connections are  present in the memory. It provides unique insights into runtime  activity, including open network connections and recently executed  commands or processes. In many cases, critical data related to attacks  or threats will exist solely in system memory. For example, network  connections, account credentials, chat messages, encryption keys,  running processes, injected code fragments and internet history. Any  program must reside in memory to execute, making memory forensics  critical for identifying Cyber Attacks.

Memory can be acquired using multiple tools for different operating systems, such as:

1. FTK Imager
2. DumpIt
3. AVML
4. Belkasoft RAM Capturer

We will discuss Forensic acquisition in some other course.

In the image below, we can see where memory forensics fits in the Incident Response chain:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/what-is-memory-forensics/2.png)

In the next lesson, we will discuss baselines when analyzing memory  dumps; what to look for during memory analysis; and what tools can be  used to aid us in investigation.

This course prepared by [0xCyberJunkie.sh](https://www.linkedin.com/in/abdullah-bin-yasin-4b418119a) for the blue team community.

## Memory Analysis Procedures

In this lesson, we will be going through an analysis procedure on what to look for in order to identify any malicious activity.

### **1- Identifying Malicious Processes**

One of the first things we must see is the list of running processes  at the time of memory acquisition. Let’s say that a system was infected  with malware. In order to do what the malware was designed to do, it  must be executed and run. In order for programs to run, the program's  instructions and data must be transferred to RAM. For example, if you  open chrome.exe, the loader copies the instructions from the executable  file and writes it to memory (RAM). The processor then takes the  instructions from RAM and executes chrome.exe.

So, if a system is running something malicious, it will be present in memory. 

In Operating systems, processes are identified by Process ID (PID)  and given a unique number. No two different processes will have the same Process ID at a given point in time. Each process has a parent process, meaning that the process was spawned by or under the context of that  process (Parent Process). For example, if I open a ".txt" file with  notepad by double clicking the file, the process name will be  notepad.exe and its parent process will be explorer.exe. Windows has a  proper process hierarchy, and all the processes start from the process  name, System, which has a predefined process id of 4 and has no parent  process. We will discuss the importance of knowing windows process  genealogy to analyze malware where attackers use advanced techniques to  evade defense. See the image below for the general windows process  hierarchy and these processes are critical for the operating system to  work properly.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/memory-analysis-procedures/1.png)

To identify malicious processes we should look for: 

**Suspicious Process Names**

\- Look for any process with suspicious names or randomized names.  This is because automated tools and frameworks such as metasploit and  Empire at times create randomized executables in memory. Malware also  spawns such processes during post exploitation such as when installing  services or creating a backdoor. If we have such a process, then we can  further analyze that specific process and its activity.

**Process Relationship**

\- Look for parent-child process relations. We will discuss this  scenario with a practical example in task 3. We learned that knowing  Windows process genealogy is important and that’s what we will be  learning here. Threat actors often name their malware after legit  Windows programs. For example, lsass.exe is used to enforce security  policy on a system and this process is responsible for credential  management, Windows systems will not work without lsass. If an attacker  names his/her malware lsass.exe and a rookie analyst is analyzing the  memory dump, he or she may not investigate the malicious lsass, since  that is a legitimate Windows process. If we know the Windows genealogy,  there should always be only a single lsass.exe process with the parent  process of wininit.exe all the way up to the System process. In our  hypothetical scenario mentioned above, 2 lsass processes being present  will immediately catch our eye. We can easily identify the malicious  lsass by viewing its parent process id. If it isn’t wininit, then we  know something is wrong, and we would have narrowed down to a malicious  process. There's a great Cheat Sheet by Sans DFIR “https://www.sans.org/posters/hunt-evil/” which can be referred to during analysis in identifying evil processes. So, awareness of normal is critical to identifying the malicious.

**Suspicious Parent-Child Process Relation**

\- Look for odd parent-child relations. For example, we may see the  winword.exe process, which is for Microsoft Word, and it has a child  process of powershell.exe. This certainly is suspicious as the  legitimate use of Microsoft Word wouldn’t need PowerShell or cmd. This  is very common as attackers use Word documents or Excel sheets for  phishing. When a malicious document is opened, an attacker’s payload  gets executed and as PowerShell is very common among threat actors, a  reverse shell connection is made to the attacker’s machine via  PowerShell or cmd.

**Defense Evasions**

\- Now let’s discuss some advanced techniques used by attackers to  hide and evade defenses. Let’s say we have gone through the above  checklist and failed to identify malicious processes. Attackers use  advanced techniques like process injection, DLL injection, process  hollowing, and so on. These techniques inject shellcode or malicious  DLLs in a legit Windows process and let them do the dirty work for them. In this scenario, our aforementioned analysis method won’t work, as  every process belongs to a legitimate parent process, and nothing looks  suspicious from the surface. This is why these techniques are very  common among advanced threat actors. We will do practical analyses of  two of these methods in the upcoming tasks.

### **2- Identifying Malicious Network Connections**

Any active or recently closed network connections remain in memory.  We can potentially identify malicious IP(s) and domains contacted by the host. This can certainly help us in identifying any active or closed  Command and Control IPs and domains contacted (Potential malicious  domains, etc.). Sometimes, we can also get the process ID related to a  certain network connection which may help us in identifying malicious  processes. Now, you may be asking why we need to spend so much time  identifying processes if we can just identify malicious IPs and  associate them with relative processes. That’s because we can’t always  rely on network connections because we don’t know the type of malware  being run. It may even not contact any C2 IP or have any network  connections. Or, it hasn’t made a C2 contact at the time of memory  acquisition. Attackers design malware that connects to their  command-and-control servers after hours of execution or even days for  evading.

For example, we are analyzing a memory dump and we decide to see all  the network connections. We can manually look out for connections on  rare ports like 1234 or 8752, etc. Anything unusual must be  investigated. Ports 80 and 443 are common, and we can prioritize them  for later. If we see certain malicious ports like 4444, which is the  common default port of Metasploit framework, we can analyze that  further. Any connection that looks suspicious to us must be analyzed on  threat intelligence platforms like VirusTotal or Cisco Talos  intelligence. We can use the command line to parse out all the IPs and  submit the lists to see if they are on IP blacklists or not. We can also analyze domains associated with the IP addresses. Let’s say in our  scenario we found a potential atypical IP address. We go to VirusTotal  and submit it, but don’t get any malicious results. We then may see a  domain associated with that IP, its nameservers, and whois data. We find out that this domain is a newly registered domain and is very unlikely  for the employee (compromised account user) to visit. With this way, we  can analyze and deduce that this is a malicious network connection in  general. 

### **3- Detecting Memory Injections**

Whenever something unusual or suspicious happens in memory space, it  leaves some trail, because memory space is complex. While the systems  look perfectly fine from the surface, things are not normal at memory  level.

The KDBG is a kernel level data structure that exists for the purpose of allowing the Kernel Debugger to locate additional operating system  data structures. KDBG has an element called PsActiveProcessHead which is a pointer and points to a linked list of EPROCESS structures, which are active processes on the system. Every process has its own EPROCESS  structure which has another component called VAD-Root which points to  Virtual Address Descriptors or VADs which in turn corresponds to virtual memory in its virtual address space.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/memory-analysis-procedures/2.png)

These VADs are tampered whenever something is injected into the  memory space of a running process, and we can detect these changes made  in the virtual address space of a legitimate process. VADs include  information about memory address, memory ranges, allocated protections  and some OS flags.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/memory-analysis-procedures/3.png)

When a process is started, it is allocated a range of virtual memory  in case more memory would be required by the process. The additional  memory is mostly occupied by applications which have dynamic structures  and grow overtime. Whenever additional memory is occupied, a permission  is defined in VAD so when analyzing memory for injections, it's common  to see some false positives for critical windows programs like antivirus programs. So, when we inject shellcode in a process, it requires that  additional memory space which sets the EXECUTE_READWRITE permission.  Malware requires the read, write, and execute permissions to be able to  work in memory. Normal programs most of the time won’t require all three (read, write, execute) permissions so it's necessary to see programs  that are running in memory with all permissions. We will use a  volatility3 plugin called malfind which does exactly what’s explained  above and shows all processes with EXECUTE_READWRITE permission. It also displays some headers and hex data of the data which caused the  requirement of additional memory.

In the image below, we can see an output from malfind plugin. We can  see the EXECUTE_READWRITE permission, the filename and the data which  caused this. This is a false positive in this case, as MsMpEng.exe is a  Microsoft malware protection engine. It’s a dynamic program. You will  often see this, but we can identify its legitimacy by the headers of  code.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/memory-analysis-procedures/4.png)

### **4- Associated Files (DLL, EXE)**

Every program requires some additional files like dynamic link  libraries (DLLs) or other files to be able to execute and communicate  with the operating system to do its work. 

Whenever we find a malicious process, we must also retrieve and  analyze these additional files to understand the malware and what  function it has performed on infected systems.

We briefly discussed that DLL injection is an advanced method used by attackers to run their malicious commands, evading defenses. We will  discuss this further with a practical example in the 5th lesson.

### **5- Registry Keys** 

Windows registry contains information about almost everything  occurring in the operating system, and it stores the information as  keys. This is a valuable artifact and is one of the first artifacts  analyzed during Host Forensics as it has invaluable information and can  help understand what happened during the incident. We can also acquire  almost all registry keys via memory dump but it’s better to acquire  registry keys from disk. We will discuss this further in detail in a  Windows forensics course in the future.

In the image below, we can see a registry key via regedit which is a Windows tool to navigate through the registry:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/memory-analysis-procedures/5.png)

In this task, we discussed what to look for when analyzing memory dumps

1- Identifying malicious processes

2- Identifying malicious network connections

3- Detecting Memory injections

4- Associated files (DLL, EXE)

5- Registry keys

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/memory-analysis-procedures/6.png)

### Questions

1 - Which plugin in volatility3 aids us in finding memory injections?

> **Answer:** malfind

## Practical Analysis 1: Masqueraded Process

We have discussed parent-child process relations and how threat  actors can masquerade processes to look like legit processes from the  service. It’s very important to know common windows genealogy to know  what’s normal and what’s out of the ordinary. In our case, we can’t see  any process name which looks suspicious from the look of it.

During any windows session, it's common to see at least 8 to 9  svchost.exe processes which handle different windows services necessary  for normal operations. “svchost” is a child process of services.exe and  it should always have services.exe as a parent process.

Now we start our analysis for case 1.

We run the PsList command to see running processes:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-masqueraded-process/1.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-masqueraded-process/2.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-masqueraded-process/3.png)

We see services.exe has a parent of wininit.exe which is legitimate.  It has a Process ID of 604. Now we see 10+ svchost.exe processes and all of them have a parent process of "604" which it should be, except one.

### **Legitimate Process**

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-masqueraded-process/4.png)

### **Rogue Process**

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-masqueraded-process/5.png)

This svchost.exe has a Process ID of 5688 and a parent PPID of 3664.  This is suspicious because Parent PPID should be 604 in our case, as  already discussed. Now, we would proceed by seeing the parent which  spawned this suspicious process. We can grep for this parent PPID:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-masqueraded-process/6.png)

The svchost.exe in question was spawned by explorer.exe, which  indicates someone double clicked this file from file explorer which is  not good.

We have so far identified a possible malicious process. We can use  the CmdLine plugin in Volatility to see the command line arguments of  processes.

Command : python3 /home/analyst/volatility3/vol.py -f  /home/analyst/memorydumps/RogueProcessCase1.mem  windows.cmdline | grep  5688

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-masqueraded-process/7.png)

Here, we see that this file was present in the downloads directory of user CyberJunkie.

Our next step would be to dump this file and do a static/dynamic  analysis in a sandbox to determine its behavior. But first, we will see  any C2 connections or network sockets opened by this file. We will use  the netscan plugin in Volatility 3 which will list all active  connections/sockets at time of memory acquisition. This is very useful  as this allows analysts to find any malicious IPs/C2 connections. We  will grep with the Process ID of our malicious process to get the  desired outcome.

Command: python3 /home/analyst/volatility3/vol.py -f  /home/analyst/memorydumps/RogueProcessCase1.mem  windows.netscan  | grep 5688

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-masqueraded-process/8.png)

We see that connection is made to IP 192.168.230.128:53. This is an  internal IP address because this is a practice exercise, in real  scenarios we would go on threat intel platforms and find the reputation  of IPs to determine if they are malicious or not. Also, malware uses  higher random ports sometimes, or like Metasploit has a default port of  4444. We should observe such things to deepen our analysis.

Next, we can dump this binary to analyze or reverse engineer it. We  will not do that here as it's out of scope for this course. We can  upload the binary to VirusTotal or sandboxes like ANY.RUN in real  investigations.

Command: python3 /home/analyst/volatility3/vol.py -f  /home/analyst/memorydumps/RogueProcessCase1.mem  windows.pslist --dump  --pid 5688

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-masqueraded-process/9.png)

If we submit this binary to VirusTotal, we can see that it’s a Metasploit payload executable.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-masqueraded-process/10.png)

In corporate environments, after finding such a malicious file from  memory image, we would hunt for IOCs found (file, IP address, etc.) to  find any other infected devices across the network.

This is one of the common methods attackers used to use (in the past) and now it’s not so common as EDR and defenses are getting better. In  the next case, we will see an advanced method that is actively used,  even today.

### Questions

Connect to the machine and examine the memory dump (/root/Desktop/QuestionFiles/RogueProcessCase1.mem) 

1 - What’s the Process ID of the process "dllhost.exe"?

> **Answer:** 4108

2 - What are the command line arguments of Process ID "4204"?

Answer Format: "C:\Users\CyberJunkie\Desktop\cmd.exe" /test

> **Answer:** "C:\Users\CyberJunkie\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background

3 - To which IP address and port is Process ID “2696” connected?  

The answer starts with 23. 

Answer Format: IP:Port 
Sample Answer: 15.21.22.122:80

> **Answer:** 23.9.178.235:443

## Practical Analysis 2: Process Injection

In this case, we are going to discuss process injection. Process  injection is a technique in which some piece of code is run in the  address space of some other process. Attackers actively use this method  to run malicious shellcode in a legitimate process context. This way,  they can evade defense mechanisms and hide their tracks.

The case 2 file is stored at /home/analyst/memorydumps/ProcessInjectionCase2.mem

Volatility is installed under /home/analyst/Volatility3/vol.py

We will learn to detect if any possible memory injections occurred  using the Volatility framework. We start by seeing all running processes using PsList.

Command: python3 /home/analyst/volatility3/vol.py -f /home/analyst/memorydumps/ProcessInjectionCase2.mem  windows.pslist

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-2-process-injection/1.png)

In real analysis, we would first look for any odd parent-child  process relation, or any suspicious/random named process to detect any  rogue processes. Seeing the output of PsList, we cannot spot any  suspicious processes or any odd PID-PPID relations. We can also try to  see any suspicious command line arguments using CmdLine.

Command: python3 /home/analyst/volatility3/vol.py -f /home/analyst/memorydumps/ProcessInjectionCase2.mem  windows.cmdline

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-2-process-injection/2.png)

Now the plugin relative to this case is named “MalFind”. The MalFind  command helps find hidden or injected code/DLLs in user memory space,  based on characteristics such as virtual address descriptor flags and  permissions set on each process VAD. We have already discussed in detail how memory injection occurs in task 2. Here, we will focus only on  finding injections in memory image.

Now let’s try this plugin and see what we get as output.

Command: python3 /home/analyst/volatility3/vol.py -f /home/analyst/memorydumps/ProcessInjectionCase2.mem  windows.malfind

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-2-process-injection/3.png)

We immediately see the svchost.exe process on top. svchost.exe  shouldn’t show this behavior under normal circumstances. Let’s take note of this Process ID which is “1776”. We see some Hex code, its ASCII  equivalent, and below it, some assembly instructions. We will get back  to this, but first let’s scroll down

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-2-process-injection/4.png)

We see another process here but this is a false positive. Because  this process is a Microsoft Defender antimalware engine which shows such behavior because it runs in memory with full “EXECUTE_READWRITE”  permissions to work efficiently. It needs to read code in other  processes' memory space to detect possible intrusions like in our case.  You would see “MsMpEng.exe” in many cases in the output of the Malfind  plugin. Attackers can also abuse this by making their binary name as  this one. So it’s always better to validate that this indeed is a  legitimate binary. We can do that by either dumping this process or  trailing back the parent-child process relation.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-2-process-injection/5.png)

Now back to our svchost.exe process. We know something suspicious is  going on since a possible process injection occurred in a svchost.exe  process. To move further, we can dump this process, do reverse  engineering, or use online/offline sandboxes to learn about its  behavior. We will not do this as it's outside the scope of this course. The Hex and ASCII are the header information of this file. If we do  some research based on the Hex code or strings, we find that this  particular pattern is often found in C2 beacons/Meterpreter Shells. In  this example, Meterpreter shellcode was injected into the process for  demonstration. This can be any process, but I showcased svchost.exe  because we also discussed this in case 1. Now we know this is a C2  beacon. We can see any active/closed connections using the netscan  plugin. We will grep the results with 1776 as we have identified the  malicious process and suspect that it's a C2 beacon.

Command: python3 /home/analyst/volatility3/vol.py -f  /home/analyst/memorydumps/ProcessInjectionCase2.mem  windows.netscan |  grep 1776

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-2-process-injection/6.png)

We can see that the infected host communicated with the IP  “192.168.230.128” on port 4444 which is a Metasploit default port. This  confirms that C2 communication was made and in real scenarios we would  block this IP from our network and hunt for the IOCs found across the  network in case of network-wide infections.

So, from this analysis we have obtained the following IOCs

1- 192.168.230.128

2- svchost.exe (Process ID 1776) and it's hash

We can then perform an in-depth forensics investigation after containing the threat.

### Questions

Connect to the machine and examine the memory dump (/root/Desktop/QuestionFiles/ProcessInjectionCase2.mem) 

1 - What’s the process ID of dllhost.exe?

> **Answer:** 3912

2 - There can be false positives when looking for process injections. 

Answer Format: False/True

> **Answer:** True

3 - What is the command line argument of the process with PID 1236?

> **Answer:** C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted -p

4 - What is the end of the memory address of the injected process?

 Note: Answer is a memory address 

 Answer Format: 0xF2F1AC07

> **Answer:** 0x1e45a3d0fff

### Practical Analysis 3: DLL Injection

In this last case, we will look at DLL injection which is somewhat  similar to the process injection which we have already discussed. In  this technique, instead of injecting some code in other processes'  space, we inject a DLL in the context of the target process. Programs  use DLLs (dynamic link libraries) to work dynamically and according to  their use cases in different scenarios. Attackers use this technique to  force load a malicious DLL under the context of a process and that  process executes the code present in that DLL.

The case 3 file is stored at /home/analyst/memorydumps/DllInjectionCase3.mem

Volatility is installed under /home/analyst/Volatility3/vol.py

Note: Terminate the machine from previous lessons and connect to the  new machine for this lesson. Case 3 file is stored in this lab and is  not available in the previous connected lab.

We start with the PsList command as usual:

Command: python3 /home/analyst/volatility3/vol.py -f /home/analyst/memorydumps/DllInjectionCase3.mem  windows.pslist

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-3-dll-injection/1.png)

We look for rogue processes or suspicious looking processes to  kickstart our investigation. We have already discussed this methodology  so we will jump directly into finding the malicious DLL. We will make  use of Malfind again to find traces of an injection.

Command: python3 /home/analyst/volatility3/vol.py -f /home/analyst/memorydumps/DllInjectionCase3.mem  windows.malfind

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-3-dll-injection/2.png)

We see the process name spoolsv.exe on top. “spoolsv” is a print  spooler service in Windows which is responsible for handling print jobs. Whenever we want to print a document, the instructions are carried out  by this service. We again see Hex code, some assembly instructions, and  instead of file header info, we see a Windows path. This is because in  the process injection case, raw shellcode was injected into the process. Here, a file (DLL) is injected, so we see its path. Great, now we have  the name and path of a malicious file which we can use for threat  hunting.

So, we know there’s a DLL named Winsrvc.dll in the downloads  directory. The DLL name sounds like a legitimate DLL name, but no such  DLL exists natively in Windows. We have the Process ID of our malicious  process so we dump that process, or even better, we dump out all the  file(s) related to the process, including DLLs. We can also dump all  DLLs running at the time of acquisition. 

Command: python3 /home/analyst/volatility3/vol.py -f  /home/analyst/memorydumps/DllInjectionCase3.mem  windows.dlllist | grep  Winsrvc

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-3-dll-injection/3.png)

We only need this specific DLL, so we will dump this:

Command: python3 /home/analyst/volatility3/vol.py -f  /home/analyst/memorydumps/DllInjectionCase3.mem  windows.dlllist –pid  1656 –dump

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-3-dll-injection/4.png)

This command will dump all DLL(s) related to the process spoolsv.exe  with PID 1656. We know the name of the injected DLL, so we will rename  it to distinguish it from other DLL(s) and analyze it further.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-3-dll-injection/5.png)

In real investigations, we would analyze it in depth. For our exercise, we will upload this to VirusTotal to see the results:

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-3-dll-injection/6.png)

We can see that this is malicious. This malicious DLL was created  using the MSFvenom payload for this exercise and was used for a reverse  connection. We can now use the netscan plugin to see:

Command: python3 /home/analyst/volatility3/vol.py -f  /home/analyst/memorydumps/DllInjectionCase3.mem  windows.netscan | grep  rundll32

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Memory+Forensics/practical-analysis-3-dll-injection/7.png)

One interesting thing to note in this case is that we will see that  the C2 connection is being made by a legitimate process “rundll32.exe”  instead of our injected process “spoolsv.exe”. This is because execution of DLL(s) is handled by rundll32.exe in Windows. So, although the DLL  is executed in the context of the spoolsv.exe process, it is actually  being handled by rundll32.exe. We see the same attacker IP as in  previous cases.

So far, IOCs collected in this case are:

1- 192.168.230.128

2- Winsrvc.dll and its hash

We would hunt for these IOCs in a real scenario to find and stop any other infections.

### Questions

Connect to the machine and examine the memory dump (/root/Desktop/QuestionFiles/DLLInjection-Case3.mem) 

1 - What’s the name of the last DLL of the process with the PID "996"?

> **Answer:** DAVHLPR.dll

2 - What’s the malicious DLL full path?

> **Answer:** c:\users\CyberJunkie\Downloads\Winsrvc.dll

3 - What’s the port number on which C2 connection is made?

> **Answer:** 1234

4 - What would be the Volatility 3 command to dump hashes from LSASS?

Answer Format: python3 vol.py -f memory.dump XXX.XXX

> **Answer:** python3 vol.py -f memory.dump windows.hashdump
