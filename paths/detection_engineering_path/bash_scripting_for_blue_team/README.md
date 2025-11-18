# Bash Scripting for Blue Team

The  "Bash Scripting for Blue Team" course focuses on providing the essential scripting skills required for cybersecurity defense, specifically  tailored for the Blue Team. It aims to equip individuals with the  practical knowledge needed to proactively manage and defend against  security threats.

**Table of Contents:**

- [Security of the Bash Scripts - 1]()
- [Security of the Bash Scripts - 2]()
- [Security and Monitoring with Bash]()
- [Network Monitoring with Bash]()
- [System Security Audit with Bash]()
- [Forensic and Incident Response with Bash]()

Evaluate Yourself with Quiz

- [Bash Scripting for Blue Team](https://app.letsdefend.io/training/quiz/bash-scripting-for-blue-team)

## Security of the Bash Scripts - 1

The topic of our course is Bash Scripting for Security. But in order not to be hunted on the go, we must first be able to write safe scripts. For this, it is the right  way to progress first by learning how to write secure scripts and then  starting to do great work with these scripts in security.  

Just like a burglar finds a window to break into a house, an attacker can infiltrate your system  when they find a security flaw. In this case, the attacker may have the  power to steal, replace or even delete your data. This could mean the  loss of personal information, customer data, or important  business-related data, which can be a huge disaster.  

Also, a security bug can  affect the performance of your system. An attacker can slow down or  completely stop your system by consuming your system's resources or  installing malicious software. This can disrupt your business continuity and be very costly.  

### Common Mistakes 

Bash is in advanced interaction with the operating system due to its  structure and design. While this is a serious advantage when used  carefully, but otherwise, in case of its use carelessly, it can lead to  disasters. Without further do, let's review what we should do and how to implement them to be considered using the Bash carefully as well as  what we should not do and why we should not do.  

### Escaping Errors

When adding values of  variables directly to commands, there is always a risk that these values are manipulated and may cause a command to run differently than  expected.

The simplest way to avoid this error is to use double quotes when using the variable ("$variable" instead of $variable). Let's examine this with an example.

```bash
#!/bin/bash
drectory_name="lets defend"
cd $directory_name               
```

In this example, we do  not use double quotes when using our variable. Therefore, the “cd” command is misinterpreted and gives the error message you see below.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash34.png)

So why too many  arguments? Because we called the directory name variable without quotes  and executed a command just like the one below.

```sh
cd lets defend           
```

The cd command read the  word "defend" as an argument, but, because it did not expect such an  argument, it could not understand it and gave an error. So, what would  happen if we used it in the following way?

```bash
#!/bin/bash
drectory_name="lets defend"
cd "$directory_name"         
```

  In this case, when the script runs, the command we actually run would be as follows:

```sh
cd 'lets defend'             
```

And (if the 'lets defend' directory actually exists) the script would run just fine.  

Here, we have tried to  explain the subject as simply as possible. What you should not forget is that we create the values of the variables programmatically and we  cannot predict which values may come during the execution of the script  most of the time. It would be a great starting point to call our  variable names in double quotes to be prepared for any situation for  safe bash scripts.  

## Untrusted Inputs

Having your bash scripts  accept untrusted input allows attackers to execute malicious code. To  prevent this type of attack, we must always verify and sanitize user  inputs.

In the example code below, we ask the user for a file name and print the contents of the file with that name to the console.

```bash
#!/bin/bash
echo "Input file name:"
read file
cat $file           
```

However, this is an  untrusted script because the user input is not checked and it was used  directly in the “cat” command. A malicious user may attempt to wipe the  entire file system by entering a malicious command like “rm -rf /” to  the file variable. (This result may vary depending on the bash version  the script is running)  

Therefore, when receiving an input from the user, we must always filter the values that the input can take and accept only what we need. Let's rearrange the above  example as follows:

```bash
#!/bin/bash
echo "input file name:"
read file
if [[ -f $file && $file == *.txt ]]; then
    cat "$file"
else
    echo "Please input .txt file name"
fi
             
                  
```

In this example, the variable file checks for a file (-f $file) and checks if it has a .txt  extension ($file == *.txt). If these conditions are not met, an error  message is given to the user. This ensures that the user input is as  expected and prevents potentially malicious logins.  

Let's do another example:

In this example, the user-input variable filename is used directly in the cp command. A malicious user can change the target filename, causing unexpected  results.

```bash
#!/bin/bash
echo "input file name:"
read filename
cp $filename /tmp/backup           
```

The correct approach is to check and sanitize the user's input:

```bash
#!/bin/bash
echo "input file name:"
read filename
if [[ $filename =~ ^[a-zA-Z0-9_-]+$ ]]; then
    cp "$filename" /tmp/backup
else
    echo "invalid file name."
fi             
```

In this example, we are  checking that only alphanumeric characters, hyphen (-) and underscore  (_) characters are accepted using a regular expression for the filename  variable. In this way, we take an important step to prevent the user  from modifying the target file with malicious input.  

Now, let's do a final example:  

When working with bash  scripts, we often run some system commands from within the script. The  correct functioning of our script depends on the smooth operation of  these system commands. The outputs of these commands are actually inputs for our script and we need to check these inputs as well.

A very common mistake is  to continue the execution of the script without verifying whether these  commands are successfully executed or not. If not, our script may start  producing unpredictable results.  

In our example, we “scp” a file to a remote  server and then delete the local file. Although everything seems working fine, we actually have a faulty code because we have not checked  whether the required connection for “scp” is available or not, whether the “scp” suns successfully or not.

```bash
#!/bin/bash
remote_host="192.168.0.100"
remote_user="user"
filename="important.txt"

scp $remote_user@$remote_host:$filename /tmp/backup >/dev/null 2>&1
echo "File copied successfully."
rm -rf filename     
```

So how could we have we done it?  

First, we could have  tested the remote connection, and continued if the remote connection was healthy. We delete the local file after checking the status of the scp command to make sure  everything is fine. In fact, we could have taken this check one step  further and compared the hash of the local file with the hash of the  file on the remote system to make sure that the file transmitted without errors.

```bash
#!/bin/bash
remote_host="192.168.0.100"
remote_user="user"
filename="important.txt"

ssh $remote_user@$remote_host "ls -l $filename" >/dev/null 2>&1
if [ $? -eq 0 ]; then

    scp $remote_user@$remote_host:$filename /tmp/backup
    if [ $? -eq 0 ]; then
        echo "File copied, deleting orginal"
        rm -rf filename
    else
        echo “file not send”
else
    echo "Connection problem"
fi            
```

In these examples the use of [ $? The use of -eq 0 ] must have caught your attention. This usage in the bash script gives us the exit code returned by the operating system of the last command executed. The “0” code means that the command has run successfully and its lifecycle has ended normally.  

When writing bash scripts, other exit codes that might work for our scenario are as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/sec-table.png)

When we use these exit  codes in the right place and in the right way, we can ensure that the  script we write is resistant to all possible errors. For example: we can check for possible argument errors during scp command execution by using the expression as [ $? eq 2 ] instead of [ $? -eq 0 ].  

### Command Injection

When writing bash scripts, built-in bash commands such as   **eval**  ,   **system**  ,   **exec**   can be exploited by a  malicious user if not used carefully. For this reason, we should avoid  using these commands in the script as much as possible, and in cases  where we have to use them, we need to pass the inputs we provide to  these commands through very strict filters.

```bash
#!/bin/bash
echo "Enter a command:"
read user_command
eval $user_command           
```

In this script, the file name is taken from the user and requested to list this file with the `  **ls**  ` command. However, if a malicious user inputs this as: ` my_file; rm -rf  ` the `rm -rf *` command  is also run after the `ls` command and all files in the current  directory are deleted. We should still note that this may vary depending on the bash version running on the system.  

To prevent such malicious command injections, you must ensure that the input received from the  user is safe. One way to achieve this is to filter the input. For  example:

```bash
#!/bin/bash
echo "Input Command:"
read user_command

case $user_command in
  "ls")
    ls
    ;;
  "pwd")
    pwd
    ;;
  *)
    echo "Not Allowed"
    ;;
esac             
```

This script limits the  commands the user can enter to “ls” and “pwd”. This prevents the user  from running unexpected or potentially harmful commands. Although this  example is fairly simple, it is quite common to use this type of  approach to determine what kind of commands to run in a controlled  environment.

```bash
#!/bin/bash
echo "Input Command"
read user_command
user_command=$(echo $file_name | tr -dc '[:alnum:]\n\r' | tr '[:upper:]' '[:lower:]')
eval $user_command            
```

In this example, the `tr` command is used to ensure that the filename contains only alphanumeric  characters. This prevents command injection because special characters  and spaces are not included.  

We should still remind  that these are only basic examples and do not provide complete security. We may need to do more complex filtering or validation in cases where  we need certain characters or special characters when processing.  Ideally, it is recommended to test your own solutions for input  validation, error checking, debugging, and other security practices and  make sure everything is fine before you deploy your scripts.

### Questions

1 - What is the exit code returned by the operating system when the command is not found?

> **Answer:** 127

2 - What is running unexpected  commands that may occur if the inputs are not properly checked when  using commands such as eval, system, exec in a script?

> **Answer:** Command Injection

## Security of the Bash Scripts - 2

### Path Traversal Errors

If you accept file paths  as user input, you risk allowing an attacker to read or overwrite an  unwanted file. Using relative file path instead of absolute file path  may generate errors. In the example below, we will review the drawbacks  of running commands without checking the input adequately:

```bash
#!/bin/bash
echo "Please enter the name of the file you want to read:"
read file
cat $file               
```

This script looks simple  and innocent, which takes a filename from the user and prints the  contents of that file to the screen with the “cat” command. However, if  an attacker runs this script and enters “../../etc/passwd” as the  filename, this allows the attacker to be able to read the passwd file on the system. It is also possible that this error was used to delete a  file or change the content of an existing file.  

As you can see, these  errors, which resulted by just not validating and filtering the user  input correctly, can cause quite a headache. In order to prevent this  situation, we may restrict the incoming file path requests and allow  read operations of files under a certain directory. Also, checking if  the incoming file path contains ".." and rejecting such entries can be  another method of protection.  

Now let's make our script equipped with tighter controls that will eliminate these risks:

```bash
#!/bin/bash
echo "Please enter the name of the file you want to read:"
read file

# Let's check if the filename is trying to change the root directory
if [[ "$file" == *..* ]]; then
    echo "Unwanted input."
    exit 1
fi

# Let's check if the filename starts with “/”.
if [[ "$file" == /* ]]; then
    echo "Unwanted input."
    exit 1
fi

# Let's check if the filename is under a certain directory
base_directory="/var/myapp"
full_path="$base_directory/$file"
if [[ "$full_path" != "$base_directory/"* ]]; then
    echo "The file must be under a specific directory."
    exit 1
fi

# If all checks are passed we can print the file to the screen
cat "$full_path"           
```

We recommend that you pay attention to the comment lines for easier understanding. Undoubtedly,  this is just an example and you can use different techniques that can  serve this purpose. What we need to focus on here is to add controls to  our script that will restrict this input to only serve the purpose when  receiving an input. 

### Faulty Control Structures

Incorrect use of control  structures such as “if-else”, “switch-case”, “for” and “while” may cause the script to malfunction. These types of errors can often be avoided  by understanding the logic of the code and the control flow. Let's look  at our example:

```bash
#!/bin/bash

echo "Input Number: "
read number

while [ $number -gt 0 ]
do
    echo $number
    number=$((number-1))
done                 
```

This script takes the  number entered by the user and counts down from that number. However,  this script will throw an error if the user enters a string instead of a number because the size of the string cannot be compared to a number.  

To fix this error, we need to make sure that the user's input is a number. This can be done using "if" and "else" constructs:

```bash
#!/bin/bash

echo "Enter a number: "
read number

# Checks if the input is a number.
if ! [[ $number =~ ^[0-9]+$ ]]
then
    echo "Incorrect entry: You must enter a number."
else
    while [ $number -gt 0 ]
    do
        echo $number
        number=$((number-1))
    done
fi                 
```

With this fix, the script checks if the user's input is a number. If it's not a number, it  returns an error message and terminates the script. Although the error  in this example seems very simple, it can cause unexpected results in a  script that does a lot of work and makes decisions by outputting the  previous command. Therefore, we should always be extremely careful when  using control structures.  

### Race Condition Errors

These errors occur when  two or more processes or threads are trying to access the same resource and that resource's state changes unexpectedly. Let's take an example to understand better:

```bash
#!/bin/bash

file="/tmp/testfile"
if [ ! -e $file ]
then
    touch $file
    echo "File created."
else
    echo "The file already exists."
fi              
```

This script checks if a particular file exists. If the file does not exist, it creates the file. However, this script is open to "race condition" errors. If two copies  are run at the same time, both check if the file exists. If the file  does not exist, both try to create the file. In this case, while the  first script creates the file, the second script still thinks that the  file does not exist and tries to create the file.  

To resolve this error, we need to minimize the time interval between creating the file and checking the existence of the file:

```bash
#!/bin/bash

file="/tmp/testfile"
if ! touch $file 2>/dev/null
then
    echo "The file could not be created."
else
    echo "File created."
fi             
```

With this fix, the script tries to create the file directly instead of checking if the file  exists. If the file already exists or cannot be created, the “touch”  command returns an error and the script catches it.  

As we can see from the  examples, when writing a script on any subject, you should anticipate  the operations with the possibility of "race condition" and do this.

As we can see from the  examples, when writing a script on any subject, we should anticipate the operations with the possibility of "race condition" and write our  script in a structure that will manage this possibility correctly.  

### Faulty Error Management

One of the most important issues that are not focused much while writing Bash scripts is possible errors because it's easy to get the code that works flawlessly in our  development/test environment. The script that works fine in our test  environment may encounter incompatibilities when moved to production  environment. We may encounter problems if we haven't been able to  predict them while writing our script. Let's explain with an example:

```bash
#!/bin/bash

read -p "Which file would you like to copy? " file

cp $file /tmp/

echo "File successfully copied."              
```

This script takes the  filename entered by the user and copies it to the “/tmp/” directory.  However, if the file does not exist, the “cp” command returns an error  message. This script will not catch this error and still prints the  message that says "File copied successfully." to the screen. This is an  example of faulty error handling.  

To resolve this error, we have to check if the “cp” command was successful:

```bash
#!/bin/bash
read -p "Which file would you like to copy? " file
if cp $file /tmp/
then
    echo "File successfully copied."
else
    echo "File not copied."
fi                 
```

With this fix, the script checks if the “cp” command was successful. If it is successful, "File  copied successfully." message is displayed on the screen. If it is not  successful, "Failed to copy file." message will be displayed.  

### Signal and Exception Management Errors

A well-written script should also check for signals and requests from the operating system and manage them correctly.  

Let's say we have a  script that performs long-running operations, or certain operations  unless terminated. Under normal conditions, our script will stop  instantly when the user presses the   **CTRL+C**   keys. Although this is  not a problem most of the time, in some cases it can produce results  such as unfinished tasks. In order to prevent such situations, it is the best way to catch the situations where the operating system wants the  script to stop and to terminate the work of our script in a controlled  way.   

Our first code is our faulty example. It checks if a file has changed for 60 seconds, but does not listen for signals from the operating system:

```bash
#!/bin/bash

# Let's set the file and time limit to watch.
file_to_watch="/path/to/file"
limit=60

# Get original modified time
initial_time=$(stat -c %Y "$file_to_watch")

# Let's get the initial modification time of the file
while true
do
    current_time=$(stat -c %Y "$file_to_watch")
    if [ "$current_time" != "$initial_time" ]
    then
        echo "File changed."
        initial_time=$current_time
    else
        elapsed_time=$(($(date +%s) - $initial_time))
        if [ $elapsed_time -gt $limit ]
        then
            echo "File not changed for $limit seconds, terminating script."
            exit 1
        fi
    fi
    sleep 1
done               
```

This script does not  catch SIGINT (Ctrl+C) and SIGTERM (like kill command). Therefore, when  these signals arrive, the script is abruptly terminated and no cleanup  is performed.  

To resolve this issue here, we can set up a trap that catches these signals with the “trap” command.  

With this change, the  script catches the SIGINT and SIGTERM signals and executes the specified commands. In this case, "Script terminated, cleaning operations in  progress." message is displayed on the screen and terminates the script  (In our example, no action is taken, only a message is displayed).

```bash
#!/bin/bash

# Let's set the file and time limit to watch.
file_to_watch="/path/to/file"
limit=60

# Get original modified time
initial_time=$(stat -c %Y "$file_to_watch")

# Captures SIGINT and SIGTERM signals.
trap 'echo "Script terminated, cleaning operations are in progress."; exit 1' SIGINT SIGTERM

# Let's get the initial modification time of the file
while true
do
    current_time=$(stat -c %Y "$file_to_watch")
    if [ "$current_time" != "$initial_time" ]
    then
        echo "File changed."
        initial_time=$current_time
    else
        elapsed_time=$(($(date +%s) - $initial_time))
        if [ $elapsed_time -gt $limit ]
        then
            echo "File not changed for $limit seconds, terminating script."
            exit 1
        fi
    fi
    sleep 1
done                
```

### Questions

1 - What are the cases named when a situation where two or more processes or threads are trying to access the same resource and that resource's  state changes unexpectedly?

> **Answer:** Race Condition

2 - Which command allows us to capture the signals like SIGINT that occur in the operating system while our script is running?

> **Answer:** trap

3 - What is the error in the  bash script "/root/Desktop/QuestionFiles/script11.sh" on the linux lab  machine you accessed that allows the attacker to read unwanted files?

> **Answer:** Path Traversal

4 - When the bash script "/root/Desktop/QuestionFiles/script12.sh" is run  with the input "/etc/passwd" on the Linux lab machine you accessed, what is the last block of code executed before exiting the program?

> **Answer:** 3

5 - In how many code blocks in the "/root/Desktop/QuestionFiles/script12.sh" bash script on the Linux lab machine you accessed, a control structure  has been added to prevent path traversal errors?

> **Answer:** 2

6 - In the "/root/Desktop/QuestionFiles/script13.sh" bash script on the Linux lab  machine you accessed, it is desired to print the numbers on the screen  one by one from the number received from the user to zero. However, an  infinite loop occurs due to an error in the bash script. Which line of  code should be changed to fix this error?

> **Answer:** 4

## Security and Monitoring with Bash

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash41.png)

In this section, we will  try to give you an idea of how you can incorporate Bash scripts into  your security operations, with some examples on how to analyze and  report security events on the operating system with bash scripts.  

As with all business  processes, there are many advantages to using bash scripts in security  processes, but the most obvious ones are speed and automation  capability. Instead of manually typing a script each time, we can  automate this process by creating a bash script. This capability is a  huge time saver, especially for repetitive and time-consuming  operations.  

Now, let's talk about how we can use bash scripts in security operations.  

First, let's look at the  system logs. System logs provide valuable information about a system's  status and activities. However, manually reviewing these logs can be a  time-consuming and error-prone process. Using bash scripts, we can  detect certain events or behaviors automatically and even take action on these detections.  

For example, if you  detect too many attempts from a particular IP address, you can block  that IP address automatically using a bash script. Or, if you see a  specific error message, you can use a script to detect that error  automatically and implement an automated solution.

Secondly, we can use bash scripts to check the security status of our systems and run security  scans of them regularly. These scans can help us identify outdated  software, open ports, and other potential vulnerabilities.  

A bash script can  automatically run these scans at a specified time intervals and provide  us with a report. This allows us to monitor our security posture  constantly and take quick action against potential threats.  

Third, we can use bash  scripts to automate responses to security events. For example, when we  detect an attack, we can generate an automatic response using a bash  script. This response can secure our systems, collect traces of the  attack, and even block the attacker.  

We can also use bash  scripts for more complex tasks such as network monitoring and traffic  analysis. A script can be used to detect a specific network traffic  pattern, or it can be used to monitor traffic from a specific IP address or port. This can help us do complex network analyses faster and more  effectively.  

Finally, we can also use  bash scripts to run security tests and analyze the results of these  tests automatically. For example, during a penetration test, we can  perform various attacks automatically on target systems using a bash  script. This script can also collect and analyze the results of these  attacks, thus provide us valuable information.  

As a result, there are  many ways bash scripts can be used in security operations. However,  remember that although bash scripting is a powerful tool, we need to be  careful when using it. Bash scripts can cause serious damage to our  systems if misused. So, always be careful before running a bash script  and make sure you fully understand what the scripts are able to do.

We will also cover  advanced usage examples of commands such as “awk”, “grep” and etc. in  this section. Since these are not our subjects in this course, we will  not go into details, but we recommend that you research and learn them  in cases where you do not understand the way and purpose of use. 

### Analyzing Log Files

In a standard Linux  system, hundreds of thousands of lines of log can occur in dozens of log files, and it can be really difficult, sometimes even impossible, for  us to check them one by one. Bash scripts can come to our rescue in such situations and save us from this burden. Let's look at our example:  

We scan the “/var/log/auth.log” file for “Failed password for invalid user” statements and if this statement is found, we send an email to [security@letsdefend.io](mailto:security@letsdefend.io). We should pay attention to the fact that this pattern exists, that means, at least 1 "Failed  password for invalid user" has occurred.

```bash
#!/bin/bash

LOGFILE="/var/log/auth.log"
PATTERN="Failed password for invalid user"
RECIPIENT="security@letsdefend.io"
SUBJECT="Failed Login Attempts For Invalid Users"

if grep -q "$PATTERN" $LOGFILE
then
    echo "Error message found: $PATTERN" | mail -s "$SUBJECT" $RECIPIENT
fi            
```

Now let's make this script run at a certain time every day. To do this, let's first save our script, for example, under the   **/security**   directory with the name   **failed_login_check.sh**  .

Next, let's make our script executable with the following command: 

```sh
chmod +x /security/failed_login_check.sh      
```

Now we can make this script run without our intervention by adding a cronjob.

For this, first, we open the cron file with the   **crontab -e**   command and add the following line in it:

```txt
1 0 * * * /security/failed_login_check.sh          
```

We save and exit the cron editor with   **ESC+:wq.**  

From now on, our script will run at 00:01 every night, and we will receive a notification email if it finds "Failed password for invalid user" in the auth.log file.

It doesn't look bad, but I wonder if it would be easier for us to write which user made this attempt from which IP address?

So, let's improve our script a little more:

```bash
#!/bin/bash

LOGFILE="/var/log/auth.log"
PATTERN="Failed password for invalid user"
RECIPIENT="email@address.com"
SUBJECT="Invalid Login Attempts Detected"

while IFS= read -r line; do
    if [[ $line =~ $PATTERN ]]; then
        rhost=$(echo "$line" | awk -F'[= ]' '{print $(NF-4)}')
        user=$(echo "$line" | awk -F'[= ]' '{print $(NF-5)}')
        message+="rhost: $rhost, user: $user"$'\n'
    fi
done < "$LOGFILE"

if [[ -n $message ]]; then
    echo -e "Invalid User Login Attempts detected:\n$message" | mail -s "$SUBJECT" $RECIPIENT
fi        
```

When this script runs at 00:01 every night, it will send us an e-mail similar to the following content:

```txt
SUBJECT: Invalid Login Attempts Detected

Invalid User Login Attempts detected:
rhost: 192.168.207.1, user: letsadefenda
rhost: 192.168.207.1, user: letsadefenda
rhost: 192.168.207.1, user: letsadefenda
rhost: 192.168.207.1, user: letsbdefendb
rhost: 192.168.207.1, user: letsbdefendb
rhost: 192.168.207.1, user: letsbdefendb           
```

And, that means we will  be aware of each login attempts made with a user name that does not  exist in the system throughout the day. Have you noticed how important  content we can follow in a short time?

But we have a powerful tool like bash, we can't stop here, now let's block the IP addresses that get "Failed password for invalid user" error more than 3 times in a row.

```bash
#!/bin/bash

LOGFILE="/var/log/auth.log"
PATTERN="Failed password for invalid user"
RECIPIENT="email@address.com"
SUBJECT="Invalid Login Attempts Detected"
BLOCK_THRESHOLD=3
declare -A failed_attempts

while IFS= read -r line; do
    if [[ $line =~ $PATTERN ]]; then
        rhost=$(echo "$line" | awk -F'[= ]' '{print $(NF-4)}')
        user=$(echo "$line" | awk -F'[= ]' '{print $(NF-5)}')
        message+="rhost: $rhost, user: $user"$'\n'
        
        if [[ -n ${failed_attempts[$rhost]} ]]; then
            ((failed_attempts[$rhost]++))
        else
            failed_attempts[$rhost]=1
        fi
       if (( failed_attempts[$rhost] > BLOCK_THRESHOLD )); then
            ufw insert 1 deny from $rhost to any
        fi
    fi
done < "$LOGFILE"

if [[ -n $message ]]; then
    echo -e "Invalid User Login Attempts detected:\n$message" | mail -s "$SUBJECT" $RECIPIENT
fi          
```

Of course, there are  aspects that are still open to development, but our script is now ready  to serve us. We were not aware of what was going on in our system just  until about an hour ago, but now, we are able to receive daily reports  as well as take active action automatically. We feel more secure now.  

Let's do another example  about the system logs. In some cases, the applications in our system may exhibit unexpected/erroneous behavior, and we may not notice this  situation for hours, sometimes for days, until these errors affect our  critical processes. The example below analyzes the system logs and looks for “ERROR” statements and reports to us the applications that have  generated more alarms than the threshold we have given.

```bash
#!/bin/bash

LOGFILE="/var/log/syslog"
ERROR_THRESHOLD=5

declare -A app_errors

while IFS= read -r line; do
    if [[ $line =~ "ERROR" ]]; then
        app=$(echo "$line" | awk -F' ' '{print $5}')
        if [[ -n ${app_errors[$app]} ]]; then
            ((app_errors[$app]++))
        else
            app_errors[$app]=1
        fi
    fi
done < "$LOGFILE"

echo "Faulty Apps:"

for app in "${!app_errors[@]}"; do
    if (( app_errors[$app] > ERROR_THRESHOLD )); then
        echo "$app: ${app_errors[$app]} Errors"
    fi
done           
```

Our example currently  reports to the console only, but if we want an email sent to us, we can  simply do it as in the previous example. 

### Questions

1 - A task has been added to the cronjob so that log file analysis can be  done in an automated way on the linux lab machine you access. What is  the e-mail address to which logs are requested to be sent with this cron task?

> **Answer:** failedpassword@letsdefend.io

2 - In the bash script "/root/Desktop/QuestionFiles/script15.sh" on the  Linux lab machine you accessed, which Linux command blocks the IP  addresses of login attempts made with a non-existent username?

> **Answer:** ufw

## Network Monitoring with Bash

With bash scripts, we can automate network monitoring and develop tools to analyze and report  network traffic data. Let's do a few examples of this in this section. 

### Network Monitoring

In our first example, let's create a tool that instantly monitors our communication with the IP addresses we specify, over the ping times, with a bash script:

```bash
#!/bin/bash

IP_ADDRESSES=("8.8.8.8" "1.1.1.1" "192.168.1.3")
PING_INTERVAL=3

declare -A ping_results

while true; do
    for ip in "${IP_ADDRESSES[@]}"; do
        ping_result=$(ping -c 1 -W 1 $ip | grep 'icmp_seq=1' | awk -F' ' '{print $7,$8}')
        current_time=$(date +"%Y-%m-%d %H:%M:%S")
        if [[ -n $ping_result ]]; then
            ping_time=$(echo $ping_result | awk -F'=' '{print $2}')
            ping_results[$ip]="$current_time $ping_time ms"
        else
            ping_results[$ip]="$current_time Timeout"
        fi
    Done

    clear
    printf "%-15s \e[1;36m%-55s\e[0m\n" "Target IP" "Last Ping Time      Last Reply Duration"
    printf "=====================================================================\n"

    for ip in "${IP_ADDRESSES[@]}"; do
        result="${ping_results[$ip]}"
        printf "%-15s " "$ip"
        if [[ $result == *Timeout* ]]; then
            printf "\e[1;31m%-55s\e[0m\n" "${result% }"
        else
            printf "\e[1;32m%-55s\e[0m\n" "${result% }"
        fi
    done

    sleep $PING_INTERVAL
done               
```

Let's look at the output first, and then examine our script line by line to see what happens.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash42.png)

In the first step, a string named IP_ADDRESSES is defined and contains the IP addresses to be tracked. The PING_INTERVAL variable determines each ping interval.  

An associative array  named “ping_results” is defined. This array is used to store the last  ping time and ping response time for each IP address.  

An endless loop is started. This loop is used to monitor results by periodically pinging IP addresses.  

In each loop step, separate operations are performed for each IP address in the IP_ADDRESSES array with the “for” loop.  

A ping is performed using the ping command for each IP address.   **ping -c 1 -W 1 $ip**   sends an ICMP ping packet to the specified IP address. The grep 'icmp_seq=1' statement filters only the first response in the ping result. awk -F' ' '{print $7,$8}' gets the response time in the ping result.  

**The current_time variable** contains the current date and time.  

If a ping response is  received (checked by the -n $ping_result statement), the ping time is  retrieved and recorded in the ping_results array along with the IP  address. If no response is received, Timeout information is added.  

The clear command is used to clear the information on the screen.  

Output in the form of a  table is created using printf commands. Includes the IP address, last  ping time, and ping response time columns.  

With the if condition, the ping result is displayed in red if timeout is displayed, otherwise it will be displayed in green.  

The sleep command moves  to the next loop step, waiting for the specified time. This ensures that it is pinged at specific intervals.  

### Service Monitoring

Now, let's turn our example into an example that shows the status of the ports we've identified on the target systems:

```bash
#!/bin/bash

IP_ADDRESSES=("192.168.1.1" "192.168.1.2" "192.168.1.3")
PORTS=("80" "443" "22")
PING_TIMEOUT=1

declare -A port_results

while true; do
    for ip in "${IP_ADDRESSES[@]}"; do
        for port in "${PORTS[@]}"; do
            if nc -z -w $PING_TIMEOUT $ip $port >/dev/null 2>&1; then
                port_results["$ip:$port"]="Open"
            else
                port_results["$ip:$port"]="Closed"
            fi
        done
    Done

   clear
    printf "%-15s %-10s %-10s %-10s\n" "IP Address" "${PORTS[0]}" "${PORTS[1]}" "${PORTS[2]}"
    printf "============================================================\n"

    for ip in "${IP_ADDRESSES[@]}"; do
        printf "%-15s " "$ip"
        for port in "${PORTS[@]}"; do
            result="${port_results["$ip:$port"]}"
            if [[ $result == "Open" ]]; then
                printf "\e[1;32m%-10s\e[0m" "$result"
            else
                printf "\e[1;31m%-10s\e[0m" "$result"
            fi
        done
        printf "\n"
    done

    sleep $PING_TIMEOUT
done             
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash43.png)

This script uses two  arrays IP_ADDRESSES and PORTS. You can add the IP addresses you want to  monitor to the IP_ADDRESSES array. You can add the port numbers you want to control to the PORTS array.  

The script runs in an  infinite loop and performs port checks on the IP addresses and port  numbers specified in each loop step. Connection attempts are made to the specified IP address and port number using the “  **nc**  ” command. If the connection is successful, the port is marked "  **Open**  ", if unsuccessful, it is marked "  **Closed**  ".  

The results are displayed on the screen in a tabular form. The status of the respective ports  ("Open" or "Closed") is displayed in color for each IP address. Open  ports are shown in green and closed ports are displayed in red.  

When you run the script,  it regularly checks the status of the ports at the specified IP  addresses and displays the results in a tabular form. Port statuses are  updated periodically.  

### Bandwidth Monitoring

Let's do one last  example. In this example, let's instantly monitor the bandwidth of a  selected network interface and send notification by email when a certain value is exceeded:

```bash
#!/bin/bash

INTERFACE="eth0"
INTERVAL=5
THRESHOLD=1000000  # An example threshold value (in bytes)

declare -A bandwidth_results

send_email() {
    recipient="noc@letsdefend.io"  # Recipient email address
    subject="Bandwidth Threshold Exceeded"
    body="Interface: $INTERFACE, RX: $rx_speed bytes/s, TX: $tx_speed bytes/s"
    
    echo "$body" | mail -s "$subject" "$recipient"
}

while true; do
    rx_old=$(cat "/sys/class/net/$INTERFACE/statistics/rx_bytes")
    tx_old=$(cat "/sys/class/net/$INTERFACE/statistics/tx_bytes")
    sleep $INTERVAL
    rx_new=$(cat "/sys/class/net/$INTERFACE/statistics/rx_bytes")
    tx_new=$(cat "/sys/class/net/$INTERFACE/statistics/tx_bytes")

    rx_speed=$(( ($rx_new - $rx_old) / $INTERVAL ))
    tx_speed=$(( ($tx_new - $tx_old) / $INTERVAL ))

    current_time=$(date +"%Y-%m-%d %H:%M:%S")
    bandwidth_results["$INTERFACE"]="$current_time: RX: $rx_speed bytes/s, TX: $tx_speed bytes/s"

    clear
    printf "%-15s %-30s\n" "Interface" "Bandwidth"
    printf "========================================\n"

    for interface in "${!bandwidth_results[@]}"; do
        result="${bandwidth_results[$interface]}"
        printf "%-15s %-30s\n" "$interface" "$result"
    done

    if [[ $rx_speed -gt $THRESHOLD || $tx_speed -gt $THRESHOLD ]]; then
        send_email
    fi
done              
```

This script specifies the network interface to be monitored using the INTERFACE variable. The  variable INTERVAL determines each measuring range. With the THRESHOLD  variable, we define the traffic limit we allow in KB.  

Sure, here's a step-by-step explanation of the bandwidth monitoring script:  

In the first step, the variable INTERFACE represents a specific network interface. Here you can specify the network interface you want to monitor.  

The variable INTERVAL determines each measuring range. During this time, the bandwidth speed is calculated.  

The THRESHOLD variable represents the threshold value set to notify if the RX or TX speed exceeds.  

An associative array named bandwidth_results is defined. This array is used to store the bandwidth results for each network interface.

An endless loop is started. This loop is used to measure bandwidth at specific intervals.  

In each loop step, the  incoming and outgoing data amounts are read from the following files:  /sys/class/net/$INTERFACE/statistics/rx_bytes

/sys/class/net/$INTERFACE/statistics/tx_bytes  

This is used to get the amount of RX and TX bytes on the network interface.  

The sleep command switches to the next measurement step, waiting for the specified interval.  

After the new RX and TX  values are obtained, the difference from the previous values is  calculated to find the bandwidth speed (in bytes/second).  

The current_time variable contains the current date and time.  

The final bandwidth speed results are recorded in the bandwidth_results array. The keys of the  array represent the network interface and their values include the  timestamp at the time of measurement and the bandwidth speed.  

The clear command is used to clear the information on the screen.  

Output in the form of a table is created using printf commands that includes Interface and Bandwidth speed columns.  

The if condition checks whether the RX or TX speed exceeds the specified threshold. If exceeded, the   **send_email**   function is called and a notification email is sent.  

By returning to the   **while**   loop, a new measurement is made and the process is repeated.  

We now have proper tools  to monitor the traffic status on our network, as well as our services  and bandwidth. Now, let's take a look at the controls we can do on the  system.

### Questions

1 - What is the name of the array used to store the last ping time and ping  response time for each IP address in the  "/root/Desktop/QuestionFiles/script16.sh" bash script on the Linux lab  machine you accessed?

> **Answer:** p_results

2 - In the "/root/Desktop/QuestionFiles/script16.sh" bash script on the  Linux lab machine you accessed, how many ICMP ping packets are sent to  IP addresses in each command execution?

> **Answer:** 2

3 - What is the command used to parse the response time of the ping result  in the "/root/Desktop/QuestionFiles/script16.sh" bash script on the Linux lab machine you accessed?

> **Answer:** awk

4 - When the bash script "/root/Desktop/QuestionFiles/script16.sh" is run on the Linux lab machine you accessed (on the lab machine), for how many  IP addresses does the timeout value return?

> **Answer:** 5

## System Security Audit with Bash

System security audit is a process to detect potential security vulnerabilities in the system and  take necessary precautions. Bash scripts can be used to automate these  checks. Here are some steps to consider when performing a system  security check with bash scripts:

### Monitoring Security Violations

Previously, we wrote a script in the "analyzing log files" topic that reports  login attempts for users that do not exist in the system. Of course, we  can do much more with bash. This time, let's query the IP addresses of  the users who have successfully logged into the system in the AbuseIP  database, and write a script that generates an alarm if the reputation  of the IP address is high:

```bash
#!/bin/bash

API_KEY="YOUR_ABUSEIP_API_KEY"

get_abuse_report() {
    local ip=$1
    local result=$(curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$ip&maxAgeInDays=90" \
        -H "Key: $API_KEY" \
        -H "Accept: application/json")
    echo "$result"
}

analyze_report() {
    local report=$1
    local ip=$(echo "$report" | jq -r '.data.ipAddress')
    local abuse_confidence_score=$(echo "$report" | jq -r '.data.abuseConfidenceScore')
    local is_suspicious=false

    if [[ $abuse_confidence_score -gt 50 ]]; then
        is_suspicious=true
    fi

    echo "IP: $ip"
    echo "Abuse Confidence Score: $abuse_confidence_score"
    if $is_suspicious; then
        echo "Suspicious IP address detected: $ip"
        # You can add alarms or other actions here
    fi
}

last_logins=$(last | awk '!/wtmp/ && !/tty/ && !/boot/  {print $3}')
for ip in $last_logins; do
    report=$(get_abuse_report "$ip")
    analyze_report "$report"
done             
```

In order for this script to work, you need to obtain an api key from Abuseip.com and define it in “API_KEY="YOUR_ABUSEIP_API_KEY".

Then, every time you run  the script, you get a script that takes the IP addresses of the users  who have logged into your system last, queries them on the AbuseIP  service, and reports the reputations of these IP addresses to you.

In this example, we got  the IP addresses of the logged in users, but you can also get different  IP addresses in different logs. Or you can integrate it with a different intelligence source instead of AbuseIP.  

Finally, let's share the screenshot after the script is run:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash44.png)

### Checking for Security Updates

It is important to follow the security updates of the software installed on the system. Bash  scripts can check software on the system and detect software that is not updated or associated with vulnerabilities.  

In the example below, we  check for unapplied security updates on an Ubuntu system and, if  available, send a message to the Slack channel where you enter the  webhook url:

```bash
#!/bin/bash

HOSTNAME=$(hostname)
SLACK_WEBHOOK_URL="YOUR_SLACK_WEBHOOK_URL"

check_security_updates() {
    security_updates=$(apt list --upgradable 2>/dev/null | grep -i security)
    if [[ -n $security_updates ]]; then
        message="Pending security updates detected:\n$security_updates"
        send_slack_message "$message"
     fi
}

send_slack_message() {
    local message="$1"
    curl -X POST -H "Content-type: application/json" --data "{\"text\":\"[$HOSTNAME] $message\"}" "$SLACK_WEBHOOK_URL" >/dev/null 2>&1
}

check_security_updates            
```

This script checks for  security updates in the update list using the apt package manager. If  there are any unapplied security updates, it reports them to the Slack  channel.  

When you run the script,  it checks for security updates in the update list and sends them as a  message to the specified channel via the Slack Webhook URL, if any. The  apt command gets the update list with the   **--upgradable**   option. It filters only security updates with the grep -i security command. If unapplied security updates are found, it reports them to the Slack channel.  

Before using the script, you need to update the SLACK_WEBHOOK_URL variables with your own information.

### Strong Password and User Management

Bash scripts can audit  user accounts and password policies. It can detect weak passwords,  shared or disabled accounts, or accounts that do not comply with  security policies. 

With a simple example, let's write a script that detects accounts that are set to "never expire" which has actually no password change policy, on the system  where the script is running:

```bash
#!/bin/bash

check_never_expire_passwords() {
    echo "Users with Never Expire Password:"
    echo "======================================"
    awk -F: '($2=="*" || $2=="!" || $2=="!!") {print $1}' /etc/shadow
    echo ""
}

check_never_expire_passwords            
```

This script detects users with "never expire" password using the /etc/shadow file. Using awk command, $2 field (password field) "  *****  ", "  **!**  " or "  **!!**  " filters the users that are set to "never expire" password policy are displayed on the screen.  

When you run the script, it will list such users under the heading "Users with Never Expire Password".  

Please note that the /etc/shadow file contains sensitive  information on the system and should only be accessed by authorized  users. Use your script safely and make sure you have the necessary  permissions.  

### Network Security Audit 

Network security is  another critical component to system security. Bash scripts can identify network security issues by monitoring network interfaces, network  traffic, and open ports.

```bash
#!/bin/bash

get_listening_ports() {
    ss -tuln | awk 'NR>1 && $5 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:/ {split($5, a, ":"); print a[2]}' | sort -nu
}

get_process_for_port() {
    local port=$1
    local pid=$(lsof -i :$port | awk 'NR==2 {print $2}')
    local process=$(ps -p $pid -o comm=)
    echo "Port: $port, Process: $process"
}

echo "Open Ports on $(hostname):"
echo "======================"

listening_ports=$(get_listening_ports)

for port in $listening_ports; do
    get_process_for_port $port
done             
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash-audit.png)

Now, let's examine what this script does:  

The get_listening_ports function obtains the ports that are being listened to on the system using the ss command.

The   **ss -tuln**   command lists   **TCP (-t)**   connections and   **UDP (-u)**   connections. It also shows the ports that are being listened   **(-l)**   and numeric   **(-n)**   port numbers.

The   **awk**   command processes the rows in the output and filters the rows in column 5   **($5)**   that match a certain pattern.

Filtering checks the pattern   **(^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:)**   between the IP address and the port number.

**The split($5, a, ":")**   command parses the IP address and port number and assigns it to array a.

**The print a[2]**   command prints the port number.

The   **sort -nu**   command sorts port numbers uniquely.

**The get_process_for_port**   function detects the process belonging to a particular port.

The process uses the   **lsof**   and   **ps**   commands.

The   **lsof -i :$port**   command finds the process listening on a particular port.

The   **awk**   command processes the second line   **(NR==2)**   in the output and gets the process ID   **($2)**  .

The command   **ps -p $pid -o comm=**   gets the name of the process with a specific process ID.

Finally, the ‘  **echo**  ’ commands print the header and information messages.

Listening ports are obtained by calling the   **get_listening_ports**   function.

With the   **for**   loop, the   **get_process_for_port function**   is called for each port and the process information is printed with the port number.  

Let us remind you that this script must be run with root privileges to get the process information.  

### Checking File and Directory Permissions  

File and directory  permissions must be configured correctly. Bash scripts can check  permissions of files and directories and detect settings that allow  unauthorized access or lead to security vulnerabilities.  

Let's write a script that takes the uid and home directory fields from the passwd file, then  checks the permissions of the files and folders in each user's home  directory and reports the problematic ones:

```bash
#!/bin/bash

PASSWD_FILE="/etc/passwd"

check_directory_permissions() {
    echo "Auditing Home Directories:"
    echo "=============================="

    while IFS=: read -r username _ uid _ _ home _; do
        echo "User: $username"
        echo "----------------"

        user_directory="$home"

        find "$user_directory" \( -type d -not -perm 755 \) -print
        find "$user_directory" \( -type f -uid "+$uid" -perm /u=s \) -print
        echo ""
    done < "$PASSWD_FILE"
}

check_directory_permissions     
```

### Questions

1 - What parameter should the apt list command be run with to get the list  of packages ready to be updated in the operating system on Debian-based  distributions (i.e. Ubuntu)?

> **Answer:** --upgradable

2 - On Linux systems, which file under the /etc directory we can check if a user password is set to never expire?

> **Answer:** shadow

3 - What is the command that allows you to filter security updates among  updates in the "/root/Desktop/QuestionFiles/script17.sh" bash script on  the Linux lab machine you accessed?

> **Answer:** grep

4 - What is the command used to list open ports in the "/root/Desktop/QuestionFiles/script18.sh" bash  script on the Linux lab machine you accessed?

> **Answer:** ss

## Forensic and Incident Response with Bash

Forensic and incident  response processes often require analyzing large amounts of data and  identifying specific patterns, evidence, or specific situations. For  example, following a security incident, system logs, network traffic,  file changes, and many other data points should be examined. This is  where bash scripting would provide a great help.

A bash script can  automate such analysis and speed things up. For example, we can use bash scripts for tasks such as searching for network traffic from specific  IP addresses, monitoring changes to a specific file, or looking for a  specific error message in the system logs. Besides, we can use bash  scripts for much more complex analyses. For example, to timeline an  attacker's activities or to combine and analyze data collected from  multiple systems, and etc.

Of course, bash scripting is just a tool and success depends on how you use it. The strength of  Bash scripting lies in its flexibility and customizability. You can  create a customized scripts according to your needs and get the most  effective and efficient solution for a particular situation.

Also, bash scripting has a learning curve, so you should invest time and effort in improving your  bash scripting skills. However, you will reap the rewards of this effort with faster and more effective forensic analysis.

As a result, bash  scripting provides the ability to analyze large amounts of data quickly  and effectively when used as part of forensic processes. This can help  resolve cases faster, find more evidence, and achieve a more successful  outcome overall. Above all, bash scripting can help information security professionals do their jobs more effectively and efficiently,  especially on large and complex systems.

Now, let's take a look at how we can use bash scripts in these processes, with a few examples:

In our first example,  let's write a script to analyze a web server access logs. We will write a simple script that examines the access.log file of the apache2 web  server and finds out how many requests are received from which IP  addresses and which http methods.

```bash
#!/bin/bash

LOG_FILE="/var/log/apache2/access.log"
ver ve çık
if [ ! -f "$LOG_FILE" ]
then
    echo "$LOG_FILE not found!"
    exit 1
fi
awk '{
    split($7,method," ")
    count[method[1]" "$1]++
}
END {
    for (i in count)
        print i, count[i]
}' $LOG_FILE         
```

As you can see from the  output below, there are requests from the IP addresses 192.168.207.1 and 192.168.207.130 with the most incoming request being 34 POST requests  from 192.168.207.130 IP address.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash45.png)

Let's assume that we have experienced a security incident and a vulnerability has been exploited  in our web application via our "payment" URL, and let's extract the IP  addresses that made requests to this URL and how many times each one  made a request.

```bash
#!/bin/bash

echo "GET requests to /payment:"
awk '$7 ~ "/payment" && $6 ~ /GET/ {print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -nr

echo "POST requests to /payment:"
awk '$7 ~ "/payment" && $6 ~ /POST/ {print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -nr     
```

When we run the script, we get an output like this:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash-ir.png)

*Previously, we made an  example of querying the IP addresses with success login records through  AbuseIP's API Service and reporting their reputations. It would be a  great practice if you try to add the same feature to this script.*  

Yes, as we can see in the output, the IP address of 192.168.207.130 appeared here with 29 GET  Requests. Now let's write a script that checks if there is a failed or  success login to our system from this IP address:

```bash
#!/bin/bash


IP_ADDRESS='192.168.207.130'

# Check for successful logins
echo "Successful logins from $IP_ADDRESS:"
grep "$IP_ADDRESS" /var/log/auth.log | grep 'Accepted' | awk '{print $1,$2,$3}'

# Check for failed logins
echo "Failed logins from $IP_ADDRESS:"
grep "$IP_ADDRESS" /var/log/auth.log | grep 'Failed' | awk '{print $1,$2,$3}'              
```

When we run the script and examine the results, we see that there is a successful login record from a suspicious IP address. 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash46.png)

Now let's try to list the active connections between this IP address and our system.

We don't need a script to do this, rather we can run our command directly in the bash shell:

```sh
lsof -i -n | grep "192.168.207.130"              
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash47.png)  We can use the following  command to check how long the nc process, which is the process that  established this connection, has been active. This command will give us  an output in the format day:hour:minute:second.

```sh
ps -p 68724 -o etime=             
```

In our example, let this  output be 1:15:23, so 1 hour 15 minutes and 23 seconds. A script like  the following will help us with this:

```bash
#!/bin/bash

# Define the duration
DAYS=0
HOURS=2
MINUTES=30

# Prepare the date modifier string based on the provided days, hours, and minutes
DATE_MODIFIER=""
if [ $DAYS -ne 0 ]
then
  DATE_MODIFIER="${DATE_MODIFIER}-${DAYS} days "
fi

if [ $HOURS -ne 0 ]
then
  DATE_MODIFIER="${DATE_MODIFIER}-${HOURS} hours "
fi

if [ $MINUTES -ne 0 ]
then
  DATE_MODIFIER="${DATE_MODIFIER}-${MINUTES} minutes"
fi

# Calculate the date-time string for the given duration before now
PAST_DATE=$(date -d"$DATE_MODIFIER" --iso-8601=minutes)

# Find files and directories created after the past date
echo "Files and directories created after $PAST_DATE:"
find / -type f -newermt $PAST_DATE

# Find processes started after the past date
echo "Processes started after $PAST_DATE:"
ps -eo pid,lstart,cmd --sort=start_time | grep -v "grep" | awk 'BEGIN { command="date -d\""$5" "$4" "$3" "$2" "$6"\" +%Y%m%d%H%M.%S"; command | getline d; close(command); } $1 != "PID" && d > "'$PAST_DATE'"'               
```

Yes, as you can see, bash offers a highly competent and flexible scripting environment that  provides fast and effective solutions to every need. While it does have a bit of a learning curve, it's a great tool that will save you a lot of  time during your investigations once you learn it.

Happy coding ;)

### Questions

1 - What is the "ps" command parameter used to select only running processes? 

**Answer Format:** (only one character) 

**Example Answer:** p

> **Answer:** r

























































