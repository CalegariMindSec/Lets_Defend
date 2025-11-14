# Introduction to Bash Scripting

This  course is designed to provide detection engineers in the cybersecurity  field with a foundational understanding of Bash scripting, enabling them to bolster their capabilities in threat detection and incident  response.

**Table of Contents:**

- [Introduction to Bash]()
- [Setting up the Bash Environment]()
- [Basics of Bash Scripting]()
- [Loops]()
- [Functions]()
- [Error Handling]()

**Evaluate Yourself with Quiz**

- [Introduction to Bash Scripting](https://app.letsdefend.io/training/quiz/introduction-to-bash-scripting)

## Introduction to Bash

### History Of Bash

The Unix shell serves as  an interface that allows users to interact with operating systems. This  shell receives the user's commands and passes those commands to the  operating system. Shell is both a scripting language and a program  capable of interpreting commands.  

The first Unix shell was  developed by Stephen R. Bourne, one of the original creators of Unix, in 1979, and was therefore named Bourne Shell. The Bourne shell (`sh`)  became the most widely used shell on Unix and Unix-like systems.  

In the mid-1980s, Brian  Fox developed Bash (Bourne Again Shell) for the GNU project with the aim of replacing Bourne Shell. Bash is a shell that encompasses the  features of Bourne Shell but also provides more advanced features and a  user-friendly interface. Bash is used as the standard shell for many  Unix-like systems, including Linux and macOS.  

The development of Bash  continued with the fixing of various bugs as well as adding new features such as command line editing, shell job control, shell functions, and  many more.  

We can say that Bash is  the tool of choice by many system administrators and developers, as it  proves the importance and flexibility of the shell and also makes it  easy to write scripts. This has made Bash frequently used, especially in system administration and automated tasks.

### Cons and Pros

Because Bash was created in the UNIX systems, it has the inherent robustness and problem-solving  abilities of that environment. Let's take a look at the strengths that  characterize Bash:  

**Works Anywhere**

You can find Bash almost  anywhere. It works on Linux, Mac, and even Windows (thanks to the  Windows Subsystem for Linux). In fact, there is a BASH in your car and  on your TV at home, even if you don't see it. This means that the  scripts you write will work on almost any platform.

**Automation Capabilities**

Bash is the number one  method to automate tasks. It is a powerful tool which you can get  repetitive tasks done. Using Bash's capabilities is a great way to save  time and reduce errors.

**Productivity**

Thanks to Bash, you have  the ability to combine complex commands and perform many tasks at once.  This helps you to be more productive.

**Integration Capability with Many Different Tools**

Bash integrates with many Unix commands and tools perfectly. This allows you to perform more  complex operations and use many different tools in the same script.  

We've seen Bash's  strengths above. Unfortunately, it also has some weaknesses. Before  listing them, let's point out that Bash is actually excellent as a  system management tool, its disadvantages appear when compared to other  modern scripting languages:

**Complexity**

Bash can be a bit complex, especially for beginners. Its syntax can be a bit odd and difficult to remember from time to time.  

**Debugging:** Debugging Bash can be a  bit of a hassle. Bash usually does not display the line number with  error, and so this makes it difficult to find errors.  

**Performance**

Bash is a bit slower in terms of performance compared to other languages. While this is not  usually a problem, it may be from time to time when working with very  large datasets or when you need to perform tasks very quickly. 

**Advanced Features**

Bash does not have some  advanced features that languages like Python or JavaScript offer. For  instance, Bash lacks features like first-class functions, data  structures, etc.  

To summarize, Bash is a  great option in many cases, especially for tasks related to system  administration and automation. However, other languages may be more  suitable for certain situations and requirements.

### Terminology

In this section, let's explain some very basic concepts for those unfamiliar with the Unix  world. These will make the later stages of the course more  understandable. 

**Shell**

Shell allows users to  communicate with the operating system. Shell is a type of user interface and is usually text-based. Shells also feature a scripting language and allow users to save commands as a written script and run this script  automatically later. Bash is one of the most popular Unix shells and  often comes as the default shell on Linux and macOS.  

**Command Line (CLI)**

The command line is an  interface where users enter commands into the shell. It is usually  accessed via a terminal or console application. Users tell the operating system what to do by typing text-based commands and pressing “Enter”.

**Command**

A command is an  instruction given to the operating system to perform a certain action.  For example, `ls` is a Unix command that lists files and directories in  the current directory to the user. `cd` is another command and it  changes the current working directory.

**Script**

A script is an automated  set of commands. These commands are stored in a file and then  interpreted and executed by the shell. Bash scripts are usually stored  in files ending with the `.sh` extension and can contain a number of  command and control structures (if-else constructs, loops, etc.).  

**Pipelining**

Pipelining is the ability to use the output of one command as the input of another command. This  is done with the `|` symbol. For example, `ls | The grep .txt` command  passes the output of the `ls` command to the `grep` command and lists  only files with the `.txt` extension.  

**Environment Variables**

Environment variables  allow the shell and the programs it runs to store and access certain  values. For example, the `PATH` environment variable specifies which  directories the shell will check for commands. These environment  variables can be set system-wide or for a specific user.  

**STDIN, STDOUT ve STDERR**

These terms refer to  standard channels for the input and output of the shell and programs.  STDIN usually represents input from the keyboard, STDOUT represents  correct output and STDERR represents erroneous output. 

**Execution Permissions**

On Unix-based systems, it determines whether a file or script is executable. These permissions  can be changed with the `chmod` command.  

These terms are some of  the basic concepts you will encounter in the Bash and general Unix  world. Understanding them is an essential part of working effectively on a Unix-based system and writing Bash scripts.

### Hello World

Let's write a little bash script together:

First, open a text  editor. On Linux it can usually be `nano`, `vi` or `emacs`. On Windows  you can use Notepad or another text editor. Basically, what we're going  to do is create a text file with .sh extension  

Type the following two lines in the text editor:

```sh
#!/bin/bash
echo "Hello World"                
```

The `#!/bin/bash` line indicates that this script should be run in Bash.

The `echo` command, on the other hand, prints text to the screen.  

Save this file as   **hello_word.sh**  .  

Now we have to make sure the script is executable. We can do this by running the following command in terminal:

```sh
chmod +x hello_word.sh           
```

This command adds executable permissions to `hello_world.sh`.

Finally, we can run our script:

```sh
./hello_word.sh   
```

What do you see on the screen?  

We've made a basic example of creating and running a simple "Hello Word" script in Bash.  This script is a great starting point for demonstrating the simplicity and ease of use of the Bash scripting language.

### Questions

1 - What is a text-based user interface that allows users to communicate with the operating system?

> **Answer:** shell

2 - What is a snippet of code that consists of a series of commands, saved in a file, interpreted and executed by the shell?

> **Answer:** script

3 - What is the file extension that Bash scripts usually have?

> **Answer:** .sh

4 - What is the function of using the output of one command as the input of another command called?

> **Answer:** pipelining

5 - In which directory is the executable file for "bash" in Linux?

> **Answer:** /bin

## Setting up the Bash Environment

Bash comes installed on  almost all Linux, Unix, BSD, and MacOS platforms and is often the  default shell application. Some of these systems (i.e. Kali Linux)  default to ZSH etc. Although shell environments are used, all the  packages you need to use bash are available in the system, and you can  drop into bash shell by simply typing bash and pressing enter. We should also note that bash scripts will often run smoothly under shells like  “zsh”, and etc. 

In Windows environments,  bash is not included by default, but there are multiple ways to use bash on Windows operating systems. Let's take a look at them now:

### WSL (Windows Subsystem for Linux)

Microsoft offers the  Windows Subsystem for Linux feature on Windows 10 and later that lets  users run Linux operating systems directly. This feature is one of the  ways we can use Bash on Windows systems. In order to use this feature,  there are a series of installation and settings that we need to  configure.  

First, we need to open a  PowerShell console with Administrator rights and run the following  command and wait for the installation to complete:

```powershell
wsl --install              
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash49.png)

After the installation is complete, you can access your Linux environment by locating the Ubuntu  application from the Start menu and running it. However, in some cases,  you are likely to receive an error message like the one below.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash50.png)

If you are getting this  error message, you can try two things. First to find and activate the  "Virtualization Support" option in your computer's BIOS settings. If  your problem is not solved even after doing this, you can restart your  computer after running the following commands:

```powershell
DISM /Online /Enable-Feature /All /FeatureName:Microsoft-Hyper-V
bcdedit /set hypervisorlaunchtype auto             
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash51.png)

If everything went well  and your Ubuntu System started working fine on WSL, it will ask us to  define a username and password before it starts the bash console.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash52.png)

We need to make a file  system related reminder. Ubuntu WSL runs on its own virtual file system. It mounts the file systems of your Windows under the /mnt/ directory.  So, if you want to view the files and directories on the C:/ disk of  your Windows system, you need to run the ls /mnt/c command. This is an  important case you should consider while writing and running your  scripts.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash53.png)

On Windows, to access your home directory in Ubuntu WSL environment, you should use “explorer.exe” (note the dot at the end) in your home directory and press enter.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash54.png)

### CygWIN

Cygwin is a software  package designed to provide a POSIX compliant environment on Windows  operating systems. POSIX is a set of standards that define how an  operating system should work, and most Unix and Unix-like systems  (Linux, BSD, etc.) follow these standards.  

Cygwin includes a library (cygwin1.dll) that translates POSIX APIs to Windows APIs, and many GNU  and open-source applications which make these applications can run  natively on Windows.  

Many Unix/Linux commands  and services (for example, bash shell, ssh, tar, awk, make, grep, and  more) become available on Windows with Cygwin. You can also compile and  run Unix/Linux programs on Windows with Cygwin.  

To explain how Cygwin  works in details; Cygwin is a tool that allows Unix/Linux applications  that know how to perform Unix/Linux operating system calls (for example, opening a file or creating a process), and these applications convert  these to a format that Windows understands. 

This makes the  application feel "as if" it is running in a Unix/Linux environment.  However, this type of conversion may not always be perfect and can  sometimes cause applications to behave in unexpected ways.

To install Cygwin, you  need to download and run setup-x86.exe (for 32-bit systems) or  setup-x86_64.exe (for 64-bit systems) from the Cygwin website (https://www.cygwin.com). During the  installation, you can choose which packages to install. For the bash  shell and some basic tools, the default options are usually sufficient.  After the installation is complete, you can start Cygwin and use the  bash shell.

Now let's take a look at the installation steps:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash55.png)

After the welcome screen, we’ll see the options on how to download the files and how to install  them. We can proceed with the default option.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash56.png)

In the next step, we need to select where to install CygWIN. We recommend leaving it as default.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash57.png)

In the next step, we need to select the “Local Package Directory” settings. This’ll be the  directory where the packages will be downloaded. It is important for  your security that you select a directory where only your account can  access will provide you with security. If you don't need anything  different, you can also leave this as default:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash58.png)

In the next step, we need to select where we want to download the packages from. You can pretty  much select any download sites in the options but in cases where your  connection is slow, you may need choose a mirror within your own  country. Or if you have restricted access to some countries, you can  choose a mirror from a non-restricted country, usually just click on any of them:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash59.png)

In the next step, you  need to select the applications and packages you want to use with  CygWIN. Here, we have selected the current versions of Bash related packages under Shells. But keep it in mind that we will need many more packages for a comfortable workspace.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash60.png)

And now, the installation can begin:  

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash61.png)

When the installation process is complete, you can access your shell by clicking one of the   **Cygwin64 Terminal**   icons placed on your desktop and start menu.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash62.png)

As you can see, it is  possible to use Bash on Windows systems as well. It takes some time to  get used to it to be able to use it effectively, but considering its  capabilities, it's well worth it. 

Now let's go ahead and see what we can do with Bash.

### Questions

1 - What is the name of the feature in Windows 10 and later that allows you to run Linux operating systems? 

Note: Enter the short version of the answer.

> **Answer:** wsl

## Basics of Bash Scripting

In this section, we will see the basic concepts we need to know in order to write Bash scripts and how to use them.  

### Variables

As in all programming/scripting languages, the use of variables is critical in  Bash. You can think of variables simply as containers where we store  some data for later use. In Bash, we can handle variables under two  different headings:

### Normal Variables

Defining a variable in  Bash is pretty straightforward. All you have to do is specify the  variable name and assign a value with an equal sign (=). For example:  

In this example, we created a variable named `our_variable` and assigned the value "Hello World" to it.  

To use the value of a variable, we put a dollar sign (`$`) in front of the variable name:

This command prints the value of `our_variable` i.e., "Hello World".

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash1.png)

Note that this definition is valid throughout the console session we are working on. We cannot  access the value of this variable when we open a new console.

If we want to define a  variable that can be accessed from anywhere during a user's session, we  need to use environmental variables.

### Environmental Variables

Environmental variables are variables that exist throughout a particular shell session and  usually contain system information, user settings, or information needed for programs to run.

The names of  environmental variables are usually capitalized, although not required.  For example, the `PATH` environment variable specifies which directories the shell should check to look for commands.  

To read an environmental variable, we put a dollar sign (`$`) like a regular variable:

```sh
echo $PATH
```

This command prints the value of the `PATH` environmental variable to the screen.  

To create or modify an environmental variable, we use the `export` command:

```sh
export NEW_VARIABLE="Hello World, Again…"              
```

In this example, we created an environmental variable named `NEW_VARIABLE` and assigned it  the value "Hello World, Again...". This environment variable will be  available throughout the current shell session and can be read by other  programs.  

Variables and environment variables are some of the most important concepts in Bash scripts and  they make Bash scripts dynamic and interactive.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash2.png)

As you can see in the example in the screenshot, it is also possible to see a list of all  valid environmental variables in our active session with the "env" command in the Linux command line.  

### Scope in variables

The variables we use within a Bash script have scopes. These are “Local” and “Global” scopes.

“Global Variables” are variables that can be accessed from anywhere within a script.

“Local Variables” are variables valid only within the “Function” in which they are used.

In the future, we will refer to this subject again when we cover the “Functions” subject.  

### Control Structures

Bash is a very useful tool for automating our tasks. However, there are times when we want to  be able to do more than just do everything on a one-way, fixed path.  This is where control structures come into play! 

Control structures allow  our script to follow different paths for different conditions. Let's say you want to check if a file exists. Here you can use the "if" control  structure. The "if" constructs in Bash work just like any other  programming language. If a certain condition is true, it executes a  certain block of code.

Loops are also part of  control structures. Let's say you want to list all files in a directory and do a specific action for each one. You can use the "for" loop here.  This repeatedly runs a given block of code on an array element.  

Control structures which  make our scripts smarter and more flexible bring out the real power in  Bash scripts. They also allow us to automate more complex processes. So, control structures in Bash allow us to do things not only faster, but  also smarter!  

Now, let's examine the control structures in Bash one by one: 

### “if-else-if” Structure

This build checks whether a certain condition is true and runs different commands accordingly.

For example, in this  example, it asks the user to enter a number, assigns the user-entered  value to a variable, and then checks whether the value of this variable:

- is greater than 10,  
- is equal to 10, or,  
- is less than 10.  

Note that we're not yet checking if the value from the user is an integer or not here.

```bash
#!/bin/bash
echo "Please Input Number:"
read variable_number

if [ "$variable_number" -gt "10" ]
then
    echo "The number you entered is GREATER THAN 10"
elif [ "$variable_number" -eq "10" ]
then
    echo "The number you entered is EQUAL TO 10"
else
    echo "The number you entered is LESS THAN 10"
fi               
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash4.png)

In the example above, we  used the comparison operators "If Equal", "If Greater", and "If Less  Than". The table below lists all the standard comparison operators you  can use in Bash. You should pay special attention to the different ways  of checking for equality for data types "String" and "Integer":

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash-table-1.png)

### Questions

1 - What is the path in the PATH environment variable that starts with "/home/..." on the Linux lab machine you are accessing?

> **Answer:** /home/analyst/tools

2 - What is the output when you run the bash script "/root/Desktop/QuestionFiles/script1.sh" on the  Linux lab machine you accessed and type 45 as input?

> **Answer:** Blue Team178

3 - Which command can be used to view current environmental variables?

> **Answer:** env

## Loops

### “For” Loop

This loop executes certain commands on an array of elements. For example:

```bash
#!/bin/bash

for count_variable in 1 2 3 4 5
do
    echo "Current Value: $count_variable"
done                                  
```

In this example, we created a loop through the numbers 1 to 5 and print the value for each one.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash6.png)

“For” structure of the Bash scripting doesn't just use the integer arrays we used in this  example. For “for loop”, we can use strings, files and directories on  the filesystem, or the output of any command as a string.

```bash
#!/bin/bash
for count_variable in 1 2 3 4 5
do
    echo "Current Value: $count_variable"
done
for string_variable in Torvalds Stallman Raymond Linux Bash
do
    echo "$string_variable is Great"
done
for filesystem_variable in /home/letsdefend/ex*
do
    echo "Example File: $filesystem_variable"
done
for output_variable in $(cut -d: -f1 /etc/passwd)
do
    echo "User in Passwd File: $output_variable"
done                
```

Now let's look at the output of this script:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash8.png)

As you can see in this example, you can easily interact with the operating system from within Bash scripts.  

### “While” Loop

“While” loop runs certain commands as long as a certain condition is true. For example:

```bash
#!/bin/bash

our_variable=1
while [ $our_variable -le 5 ]
do
    echo "Value: $our_variable"
    ((our_variable++))
done            
```

In this example, we created a loop as long as the value of the variable is less than or  equal to 5. Then, in the "While" loop we started, we print the value to  the screen in each loop and increase the value of our variable by 1. And here is the result:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash10.png)

In the example above, we did only a numerical check with "While" and we can do even more.  

In the example below:

- First, we specify a “requested_value” (“Yes”)  
- Next, we start a loop that will continue as long as the "requested_value" value is "Yes".  
- We request an input from the user for each round of the loop.  
- The loop continues until the user provides an input other than "Yes"  

```bash
#!/bin/bash
requested_value="Yes"
while [ "$requested_value" = "Yes" ]
do
   echo "While is working..."
   echo "Do you want to continue? (Yes/No)"
   read requested_value
done            
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash12.png)

Let's do another example. For this example, let's create a loop that continues unless there is a  file named "test.txt" under the "/tmp" directory:

```bash
#!/bin/bash
while [ ! -f /tmp/test.txt ]
do
   echo "Loop Working..."
   sleep 10
done
echo "File Found, Done."                
```

When we run the script,  the loop continues until we create the "test.txt" file in the "/tmp"  directory and ends when we create the file:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash14.png)

### “Case” Structure

Now let's examine another control structure, the "case".

“Case” allows us to perform different operations according to the different values that a variable can take.

It is particularly useful in different circumstances, when we need to branch into different subroutines.

Note that we mark every case with a “*” that does not meet the conditions we set in the example below.

```bash
#!/bin/bash
echo "Please input value"
read our_variable
case $our_variable in
    1 )
        echo "our_variable value is Equal To 1"
        ;;
    2 )
        echo "our_variable value is Equal To 2"
        ;;
    * )
        echo "our_variable value is NOT Equal To 1 or 2"
        ;;
esac             
```

In this example, we check if the value of the variable is equal to 1 or 2, and display different messages accordingly:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash100.png)

These structures are the  basic control structures of the Bash scripting language and allow you to perform a wide variety of logical operations within a Bash script.

### Questions

1 - What values in the /etc/passwd file are printed when the bash script  "/root/Desktop/QuestionFiles/script2.sh" is run on the Linux lab machine you accessed? 

Note: Enter the short version of the answer.

> **Answer:** uid

2 - What should be entered as  input for the output of the "/root/Desktop/QuestionFiles/script3.sh"  bash script on the Linux lab machine you accessed to be "SOC Team"?

> **Answer:** 2

## Functions

In the Bash scripting language, functions represent the name of a block of code that performs a specific function. Thanks to their versatile capabilities, functions  help us organize our scripts, reuse our code, and generally make our  lives easier.

When we need to repeat an action multiple times, we can put it in a function and call it in  anywhere in our script. This way, we don't have to write the same code  over and over, which makes our code cleaner and more manageable. More  importantly, when we need to make a change, we only need to make it in  one place, in the function itself.

Bash functions can take  parameters and output them. In this way, they allow us to perform a  certain action based on a certain input or use the result of an action  elsewhere.

A Bash function can be defined as follows:

```bash
function_name() {
    Commands
}                
```

  For example, we could create a "hello" function and have it take a name parameter:

```txt
hello() {
    echo "Hello, $1!"
}                
```

To call this function, we can do as follows:

```bash
Hello "Bash"               
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash101.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash102.png)

As you can imagine, you  can create any number of functions in a script and call them whenever  you want. It is even possible to call a function from within another  function. Below is an example of this.  

- First, we define the “add” function. This function adds the two values sent to itself and returns the result.  
- Then, we define the "multiply" function. This function multiplies the two values sent to itself and returns the result.  
- Finally, we define the  "calculate" function. This function, on the other hand, sends the values sent to itself to both the "add" and "multiply" functions and writes  the results to the screen.  

```bash
#!/bin/bash
# A function that adds two numbers
add() {
    local result=$(( $1 + $2 ))
    echo $result
}
# A function that multiplies two numbers
multiply() {
    local result=$(( $1 * $2 ))
    echo $result
}
# A function that uses both add and multiply functions
calculate() {
    local sum=$(add $1 $2)
    local product=$(multiply $1 $2)
    echo "The sum of $1 and $2 is $sum."
    echo "The product of $1 and $2 is $product."
}
# Call the calculate function
calculate 5 3              
```

In the example code above, did you notice something?

You've seen the term  "local" for the first time. Those of you who are careful have noticed  right away that it is related with the "local" and "global" variables we talked about in "Variables".

```bash
#!/bin/bash
# Global variable
greeting="Hello, World!"

function displayGreeting {
    # Local variable
    local greeting="Hello, User!"
    echo $greeting # This will print "Hello, User!" because local variable takes precedence in this scope
}
# Call the function
displayGreeting
# Print the global variable
echo $greeting # This will print "Hello, World!" because the scope here has only access to the global variable 
```

First, we create a global variable called 'greeting'. This variable can be accessed from anywhere - inside or outside any function. We assign the "Hello, World!" value  to this variable. So whenever we say 'greeting', we will receive the  "Hello, World!" output.  

Then we create a function called 'displayGreeting'. Inside this function, we create another  variable called 'greeting'. But this time, we define the variable with  the 'local' keyword, which means it is valid only inside this function,  not outside of this function. We assign the "Hello, User!" value to this local 'greeting'.  

So what happens when we  call the 'displayGreeting' function? The 'echo $greeting' code inside  the function runs and says "Hello, User!" he greets us. Because the  local variable inside the function rises above the global variable with  the same name.  

After calling the  function, we say 'echo $greeting' once again. This time, however, we  receive the "Hello, World!" greeting as the 'greeting' variable is  global and the scope of the local version is just the 'displayGreeting'  function, so it takes the value of the global version:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash18.png)

To summarize, functions  are extremely useful tools in the Bash scripting language. We can write  more effective, efficient and organized scripts with the help of  functions.

### Questions

1 - What is the output of the bash script "/root/Desktop/QuestionFiles/script4.sh" on the Linux lab machine you accessed?

> **Answer:** 492

## Error Handling

As in all programming/scripting languages, error management is very important in Bash scripting and should never be ignored.  

Good error handling helps your script better handle unexpected situations, which increases its  overall reliability. You want your script to run properly, not when  everything is going well, but also when errors and unexpected situations occur.  

If your script generates  helpful error messages in the event of an error, it's easier to identify where and why errors occur. This can greatly facilitate debugging  especially large and complex scripts.  

It definitely creates a  better user experience for the end users if your script handles errors  properly and provides helpful error messages. Error messages can help  the user understand what went wrong and possibly what to do.  

In some cases, errors may lead to security vulnerabilities. For example, your script may run in  unpredictable or undesirable ways and produce unwanted results if it is  trying to read a file when a proper file is not available and if your  script is not able to exit properly in case of an error.  

An unexpected error can  stop or slow down automated business processes. This can affect large  number of users and business processes, especially in large-scale  systems or environment. For this reason, it is very important to  effectively manage errors to ensure the business continuity.  

### Error Catching

In the Bash scripting,  you can use the `$?` variable to check the status of your script and  catch errors. This variable stores the exit status of the last command  executed. Generally, `0` represents a successful exit, while any value  other than “0” indicates an error condition.

As an example, let's  consider a script that tries to delete a file. If you try to delete the  file without checking whether it exists, this may generate an error  condition. We can use the variable `$?` to control this situation:  

**#!/bin/bash**

```bash
#!/bin/bash

rm some_file.txt
if [ $? -ne 0 ]; then
    echo "Failed to delete the file"
    exit 1
fi              
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash19.png)

Some of you may wonder  why you need this in the script as we already get an error message when  the script is run. The answer is simple. We may not notice the “rm:  cannot remove 'some_file.txt': No such file or directory” message that  the operating system displays on the screen in our script and control  the flow of our program accordingly. But we can easily notice that an  error has occurred when we check the script for errors. For example, in  the code below, we create the file if there is none exists:

```bash
#!/bin/bash

rm some_file.txt
if [ $? -ne 0 ]; then
    echo "Failed to delete the file because it does not exist, creating the file now..."
    touch some_file.txt
fi               
```

### Debugging

There are several ways to debug in the Bash scripting. The simplest way is to add `echo` commands to the highlights of your script. This way you can see at what point  the script is and which variables have which values. However, this  method may cause to lose the control easily in complex scripts.  

Instead, you can use the debug mode of the Bash scripting. You can start bash in debug mode using the `-x` parameter:

```bash
#!/bin/bash
set -x # turn on trace mode

# some operations
echo "This is a test"
var="Hello, World!"
echo $var

set +x # turn off trace mode
                    
                  
```

In this mode, the Bash  prints each command to the screen and moves to the next line after the  command is executed. This allows you to follow what the script is doing  and identify where the errors occur step-by-step.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash20.png)

Another debugging method  is to use set -e (or bash -e). set -e (or bash -e) causes the script to  stop when the return value of any command in the Bash script is non-zero (it means if the script fails). This is helpful to prevent the  uncontrolled spread of bugs. Under normal circumstances, if an error  occurs in any line while executing a script, Bash continues from the  next line. “-e” is a life-saving option in cases where it is not wanted  for the script to continue despite the error.

```bash
#!/bin/bash
set -e  # stop script execution on failure

# This command will succeed
echo "This command will succeed"
var="Hello, World!"
echo $var

# This command will fail (assuming file_does_not_exist.txt does not exist)
echo "Trying to display the contents of a file that does not exist..."
cat file_does_not_exist.txt

echo "This message will not be printed because the script already exited"             
```

  As you can see, the script exits before the last line since we are using "-e":

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash103.png)

### Questions

1 - What is the bash command that stops the bash script from running in the case of "execute on failure"?

> **Answer:** set -e













