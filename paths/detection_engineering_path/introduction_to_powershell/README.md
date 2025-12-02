# Introduction to PowerShell

The  "Introduction to PowerShell" course is designed to provide participants  with a fundamental understanding of PowerShell, covering installation,  basic command usage, file and directory operations, optimization  techniques, and effective error handling for a well-rounded learning  experience.

**Table of Contents:** 

- [Introduction to PowerShell](#introduction-to-powershell-1)
- [Installing the Powershell Environment](#installing-the-powershell-environment)
- [Basics of Powershell Commands](#basics-of-powershell-commands)
- [Basics of Powershell Commands - 2](#basics-of-powershell-commands---2)
- [File and Directory Operations in Powershell](#file-and-directory-operations-in-powershell)
- [Optimization and Error Handling](#optimization-and-error-handling)

Evaluate Yourself with Quiz

- [Introduction to Powershell](https://app.letsdefend.io/training/quiz/introduction-to-powershell)

## Introduction to PowerShell

### What is Powershell?

PowerShell is a command  line shell and scripting language system developed by Microsoft and  running on the .NET Framework. Windows PowerShell is used primarily by  system administrators and is used to perform complex and automated tasks on both local and remote computers.

PowerShell includes many  features found in general-purpose programming languages. These include  structures such as variables, arrays, loops, and conditional statements  (if-then-else blocks). PowerShell also includes built-in commands called cmdlets that make many tasks easier, such as file operations and system and network administration operations.

PowerShell can be used  both as an interactive shell (receives commands from the user and  displays the results) and as a language for writing and executing  scripts (automated tasks).

Another powerful feature  of PowerShell is its ability to process outputs and inputs in an  object-oriented manner. This means that it can handle outputs and inputs not just as text, but also as objects with properties and methods. This feature significantly expands output processing and data processing  capabilities.  

### Advantages and uses of Powershell

PowerShell processes  output and input in an object-oriented manner. This capability makes it  possible to manipulate data not just as text but also as objects with  properties and methods. In this way, output processing and data  processing capabilities are significantly expanded.

PowerShell includes an  advanced scripting language used for scripting and automating. This  scripting language allows users to automate complex tasks and avoid  performing repetitive tasks frequently.

The “PowerShell Remoting” feature allows users to manage remote computers. In this way, managing a large number of computers becomes a very easy task.

PowerShell has a large  set of built-in commands that facilitate many tasks such as file  operations, system and network administration. These commands are known  as cmdlets and are often named in the "Verb-Noun" format (for example,  "Get-Process").

PowerShell is integrated  with the .NET Framework. This feature allows .NET classes, methods, and  properties to be used directly from PowerShell.

PowerShell 6 and later, also known as PowerShell Core, can run on a variety of operating systems, including Linux and macOS.

PowerShell has a variety of uses. Some of these are as follows:

- System management and automation  
- File and directory operations  
- Resource monitoring  
- Network management  
- Database operations  
- Security and permissions management  
- Analysis and processing of log files  
- Software distribution and backup operations  

PowerShell makes it easy to automate and manage a wide variety of tasks on both Windows and other operating systems.  

In this part of the  training, we have covered what Powershell is, its advantages and usage  areas. In the next part of our training, we will learn about the "Installing the Powershell Environment" topic.

## Installing the Powershell Environment

PowerShell comes with the Windows operating system and is usually pre-installed. However, if you  want to use the latest version or install PowerShell on a Linux or macOS operating system, you can follow the steps below.

### Installing PowerShell for Windows

PowerShell 5.1 comes with Windows 10 and Windows Server 2016. If you are using an older version  of Windows or want to use the latest version, PowerShell 7, you can  download it from Microsoft's official website.

1. Go to Microsoft's PowerShell GitHub page. (https://github.com/PowerShell/PowerShell).  
2. Go to the "Releases" section.  
3. Select the version you want to download. Generally, it is best to choose the latest stable version.  
4. Select the download link appropriate for your operating system. Download the ".msi" file for Windows.  
5. Run the downloaded file and follow the instructions of the installation wizard.  

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/2/ps5.png)

After installation, you can start the PowerShell console by clicking on the "Start" button, typing   **"PowerShell"**   in the field marked   **"1" (**  which is Windows search bar) in the image below, and then    clicking on any of the fields numbered   **"2"**   in the search results.  Later in our course, we will need to run PowerShell with administrator  rights from time to time, then we will need to use field number   **“3”**   to run the application as an administrator.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/2/ps4.png)

### Installing PowerShell for Linux

Besides Windows, PowerShell is also available for Debian, Ubuntu, CentOS, Fedora,  openSUSE and many more Linux distributions. Below are the installation  steps for Ubuntu:

1. Open terminal.  
2. Run the following commands:  

```bash
curl https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -             
sudo curl -o /etc/apt/sources.list.d/microsoft.list \ https://packages.microsoft.com/config/ubuntu/20.04/prod.list               
sudo apt-get update 
sudo apt-get install -y powershell   
```

In the first two lines, we add the Microsoft repo and package key to our system.

In line 3, we update the package database in our system so that our system is aware of the repo we just added.

And finally, we install the PowerShell packages.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/2/ps6.png)

Once the installation is complete, simply type the   **“pwsh”**   command in the terminal to start a new PowerShell session.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/2/ps7.png)

### Installing PowerShell for macOS

You can use the Homebrew  package manager to install PowerShell on macOS. If Homebrew is not  installed, you need to install it first:

1. Open terminal.  
2. Run the command below to install Homebrew.  
3. Once the installation is complete, type the `pwsh` command in the terminal to start a new PowerShell session.  

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"              
brew update                         
brew install --cask powershell            
```

In this part of the  training, we have covered the installation of Powershell in Windows,  Linux and macOS environments. In the next part of the training, we will  delve into “Basics of Powershell Commands”.

### Questions

1 - What is the command used to start the PowerShell console in Linux?

> **Answer:** pwsh 

## Basics of Powershell Commands

### What is cmdlet?

Now that we have PowerShell up and running, we can start looking at how things are going in the PowerShell world.

As we said in the  introduction, PowerShell is a powerful command line shell and scripting  language system that allows users to manage computers and networks.  PowerShell comes with a large set of commands or "cmdlets" to perform a  variety of system administration tasks.

Cmdlets are usually named in the "Verb-Noun" format and are used to perform a specific action.  For example, the "Get-Process" cmdlet returns a list of all running  processes, "Stop-Process" stops a specific process. For better  understanding, let's give examples of basic cmdlets that come by default with a standard PowerShell installation:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/3/ps-table-1.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/3/ps-table-2.png)

After starting the PowerShell console and run the “  **get-help cmdlet**  ”, we see the following output:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/3/ps8.png)

### Powershell Script?

Besides cmdlets, PowerShell also allows creating and running scripts. A PowerShell script is usually a .ps1 file and contains a set of cmdlets and other  PowerShell expressions.

PowerShell allows the  creation of scripts to automate complex tasks. A PowerShell script  contains a series of PowerShell commands in a file with a .ps1  extension.

To run a script, you can  use the name and path of the script along with .\. For example, the  command .\myScript.ps1 runs the script named "myScript.ps1" in the  current directory.

PowerShell scripts  support features found in many programming languages, such as variables, loops, and conditional statements. This allows scripts to perform  complex operations.  

### Data Types in Powershell

Like all scripting/programming languages, Powershell supports a number of data  types and variables. We have previously stated that PowerShell actually  provides direct support for the .NET framework, and that we can use all  the features in the .NET environment within PowerShell. When viewed from this perspective, PowerShell supports all data types supported by .NET. Let's take a look at the types of data we will use a lot in our daily  lives:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/3/ps-table-3.png)

You can see in the list  that the PSCustomObject data type, which is specially designed for  PowerShell, while other data types are data types we are familiar with  from programming and scripting languages and databases. This data type  allows users to create customized objects. A PSCustomObject is an object that has one or more properties of different types.

Used with @{} (Hashtable) to create a PSCustomObject.

```powershell
$myObject = [PSCustomObject]@{
FirstName = 'Lets'
LastName = 'Defend'
Rank = 1
}           
```

In this example, we created a **PSCustomObject**   with three properties named   **FirstName**   ,   **LastName**   , and   **Rank**   . These properties can be of different data types, for example,   **FirstName**   and   **LastName**   are   **strings**   (since we assign values in quotes), and   **Rank is**   an   **integer**   (since we are assigning a numerical value without using quotes).

Once we create this object, we can access it as follows:

```powershell
$myObject.FirstName
$myObject.LastName
$myObject.Rank        
```

### Variables in Powershell

In PowerShell, a variable is a name or label used to store data. In PowerShell, variables usually start with a $ sign. The = operator is used to assign values to  variables.

```powershell
$myVariable = "Hello World"
$myNumber = 42
$myArray = 1,2,3,4,5       
```

You will see that when  assigning values to our variable, we determine the data type of the  variable by the way we write the values after the assignment operator “   **= ”.**   For example, by enclosing the   **Hello World expression with " ", we stated that it is a String type data, by writing the number 42**   without using any  quotation marks, we stated that it is an Integer type value, and in the  last expression, we stated that it is an array by separating the values  with commas. Variables in PowerShell are dynamic, which means that the  data type of the variable depends on the assigned value and can be  changed.

So, how do we call the variables we have defined when we need to use them?

To use a variable later,  you can use the variable name (with the dollar sign). For example, you  can use the Write-Host cmdlet to print the value of a variable:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/3/ps9.png)

In PowerShell, variables  can store many different types of data, such as text, number, Boolean,  array, hashtable, and even custom objects. These are a result of  PowerShell being built on top of the .NET Framework, which means  PowerShell can support almost any data type supported by .NET.

In some cases, it may be  necessary to create a variable with a specific type. In this case, the  type can be specified when creating the variable:

```powershell
[string]$myString = "Hello World"
[int]$myNumber = 42
[array]$myArray = 1,2,3,4,5         
```

Such a definition ensures that the variable accepts only values of a certain type, and  assignments outside of that type will throw an error. This feature can  help prevent incorrect data type assignments. Below you can see an  example where we define a   **variable of type Int**   and assign a  **value of type String :**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/3/ps10.png)

In this part of the  training, we have covered the basics of PowerShell commands such as  cmdlet, powershell scripts, data types and variables in PowerShell. In the next part of our training, we will continue learning about the Powershell Commands.

### Questions

1 - What are PowerShell-specific commands in the "Verb-Noun" format called?

> **Answer:** cmdlet

2 - What is the PowerShell command that returns a list of running processes?

> **Answer:** Get-Process

3 - What is the file extension that PowerShell script files usually use?

> **Answer:** .ps1

4 - What is a PowerShell-specific data type that allows users to create customized objects?

> **Answer:** PSCustomObject

## Basics of Powershell Commands - 2

### Basic operators and Expressions

PowerShell supports various operators such as arithmetic, comparison, logical and assignment.  

#### Arithmetic Operators

The operators used in arithmetic operations are as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/4/ct1.png)

For example,   **$result = 5 + 2**   assigns the sum of 5 and 2 to the variable result.  

#### Comparison Operators

These operators are used to compare two values.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/4/ct2.png)

For example , $result = 5 -gt 2 checks if 5 is greater than 2 and assigns the result to the result variable. The result is a Boolean type value.

#### Logical Operators

These operators are used to perform logical operations.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/4/ct3.png)

For example , the expression   **$result = (5 -gt 2) -and (2 -gt 1)**   checks whether both conditions are true and assigns the result to the variable result. The result is a Boolean type value. 

#### Assignment Operators

These operators are used to manipulate the value of variables.



![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/4/ct4.png)

For example , $myVar = 5 assigns the value 5 to the variable myVar. The statement   **$myVar += 2**   adds 2 to the current value of the variable myVar.

#### Bitwise Operators

These operators are used to perform bitwise operations.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/4/ct5.png)

For example , $result = 5 -band 3 expression assigns the result of   **AND**   operation bitwise result of 5 and 3 to the result variable.

To see the result, let's first express the numbers in binary format: 

Binary form of 5: 101

Binary form of 3: 011  

The Bitwise AND operator  returns 1 when the corresponding bits are both 1, and 0 otherwise. In  this case, when we perform bitwise AND operation on 5 (101) and 3 (011), the binary version of the result will be 001. This corresponds to 1 in  the decimal system.

Shortly, the expression $result = 5 -band 3 assigns the value 1 to $result.  

#### String Operators

These operators are used to perform string operations.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/4/ct6.png)

For example, the expression $fullName = $firstName + " " + $lastName combines the variables of firstName and lastName and assigns the result to the variable of   **fullName**  .

```powershell
$name = "John"
$age = 30
$message = "Hello, my name is {0} and I am {1} years old." -f $name, $age
Write-Host $message    
```

When you run this code, the output will be:   **Hello, my name is John and I am 30 years old.**

Here, we replaced the  placeholders {0} and {1} with the values of the variables $name and $age with the -f operator. This is an easy way to use dynamic values within a string.

This type of formatting  is often used to present logs, error messages, and information to the  user. It is also useful for complex string manipulations. Especially in  cases where you need to create complex strings that contain a large  number of values, the -f operator can make your code more readable.

#### Type Conversion Operators

These operators are used to convert the type of a value to another type.

For example, [int]$myString converts the value of the variable myString to an integer.

### Loop Structures

#### For Loop

The for loop is used when you need to perform a certain number of loops. Its structure is as follows:

```powershell
for ($i=0; $i -lt 10; $i++) {
Write-Host $i
}          
```

In this example, the loop starts at 0 and continues by increasing $i by 1 at each iteration up to 10 (not including 10).

#### ForEach Loop

The ForEach loop is used  when you need to operate on each element of a collection (array, list,  etc.). Its structure is as follows:

```powershell
$array = 1,2,3,4,5
foreach ($item in $array) {
Write-Host $item
}         
```

In this example, a loop is performed for each element in the $array array and the value of each element is printed.  

#### While Loop

The while loop ensures that the loop continues as long as a certain condition is true. Its structure is as follows:

```powershell
$i = 0
while ($i -lt 10) {
Write-Host $i
$i++
}               
```

In this example, the loop continues as long as $i is less than 10.

#### Do-While Loop

The Do-While loop  guarantees that the loop occurs at least once. So the condition check is done at the end of the loop block. This loop continues as long as the  specified condition is true. That is, the code inside the loop block is  executed repeatedly as long as the condition is true. When the condition is false, the loop stops. Its structure is as follows:

```powershell
$i = 0
do {
Write-Host $i
$i++
} while ($i -lt 10)         
```

In this example, the loop continues as long as $i is less than 10. When $i reaches 10, the  condition becomes false and the loop stops.  

#### Do-Until Cycle

The Do-While loop, like  the Do-While loop, guarantees that the loop will occur at least once.  The difference from Do-While is that this loop continues as long as the  specified condition is false. That is, the code inside the loop block is executed over and over again as long as the condition is false. The  loop stops when the condition is true:

```powershell
$i = 0
do {
    Write-Host $i
    $i++
} until ($i -ge 10)             
```

In this example, the loop continues as long as $i is less than 10 (as long as the condition ($i  -ge 10 is false). When $i reaches 10, the condition becomes true and the loop stops.  

In this part of the  training, we have worked on the arithmetic operators, comparison  operators, logical operators, assignment operators, bitwise operators,  string operators, type conversion operators and loops. We will cover the “File and Directory Operations in Powershell” topic in the next part of our training.

### Questions

1 - What is the text expression of the “greater than or equal to” operator in Powershell?

> **Answer:** -ge

2 - One of the Do loops is Do-Until, what is the other?

> **Answer:** Do-While

## File and Directory Operations in Powershell

PowerShell is Windows' command line-based scripting language. It is used to manage and automate components of Windows. Throughout this lesson, we will learn how to use PowerShell on file operations.  

### Opening a File

We can use the “Get-Content” cmdlet to open a specific file in PowerShell. This cmdlet  is used to read the contents of the file. For example, we can use the  following code to open the file "example.txt":

```powershell
Get-Content -Path "C:\Path\To\Your\File\example.txt"              
```

### Reading File

If you want to read a  specific number of lines in the file, you can use the “-TotalCount” parameter. For example, you can use the following code to read the first 5 lines of a file:

```powershell
Get-Content -Path "C:\Path\To\Your\File\example.txt" -TotalCount 5      
```

### Writing a File

In Powershell, we can use “Set-Content”, “Add-Content” or “Out-File” cmdlets to write to files.

**Set-Content** allows you to write  content to a specific file. If the file already exists, it deletes the  existing content and writes the new content. For example:

```powershell
Set-Content -Path "C:\Path\To\Your\File\example.txt" -Value "LetsDefend is Great"      
```

**Add-Content**   allows you to add content to the end of an existing file. If the file does not exist, it creates the file. For example:

```powershell
Add-Content -Path "C:\Path\To\Your\File\example.txt" -Value "LetsDefend is Great"          
```

**Out-File** allows you to redirect  the output of a command to a file. If the file already exists, it  deletes the content and writes the new output. Appends can be made to  the end of the existing file using   **the -Append**   parameter. For example:

```powershell
Get-Process | Out-File -FilePath "C:\Path\To\Your\File\processes.txt"                        
```

For example, this command writes the list of Current processes to the processes.txt file.

In the example below, we see how we can use these features together.

```powershell
$filePath = "C:\example.txt"

# Read File Content
$content = Get-Content -Path $filePath
Write-Host "Original content:"
Write-Host $content

# Add Content to File
Add-Content -Path $filePath -Value "New line of text"

# Read New Content
$newContent = Get-Content -Path $filePath
Write-Host "Updated content:"
Write-Host $newContent           
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/5/ps11.png)

In this part of the  training, we have learned opening and reading a file and writing to a  file with the PowerShell. In the next part of the training, we will  cover the "Optimization and Error Management in Powershell Scripts" topic  **.**

### Questions

1 - What is the PowerShell command to read the contents of the file?

> **Answer:** Get-Content

2 - What is a PowerShell command that redirects the output of a command to a file?

> **Answer:** Out-File

3 - In the PowerShell script  "C:\Users\LetsDefend\Desktop\QuestionFiles\pshell_1.ps1" on the Windows  lab machine you accessed, to which variable is the original file content assigned?

> **Answer:** $filecontent

## Optimization and Error Handling

### Script Optimization

Powershell will offer  more than one way to do a job, thanks to the .NET framework support  behind it. While the multitude of these options often provide a  comfortable working environment, it is up to us to determine the methods that consume less system resources or produce faster results among the  options that do the same job, especially in complex jobs. After creating a PowerShell script, we always recommend that you consider the  following issues to improve its performance and make it more efficient:

### **Choose Commands Carefully**

Some PowerShell cmdlets  and operators require more processing power than others. Usually, there  is more than one way to perform an operation. Each of these pathways can have different performance profiles.  

### **Optimize Cycles**

Loops can significantly  impact the performance of the script. Whenever possible, consider using  For loops instead of foreach. Minimize the number and complexity of  variables used in loops.  

### **Use Variables Wisely**

PowerShell is a  dynamically typed language, which means the values and types of  variables can be changed in flight. However, this flexibility may  require additional processing power. Therefore, when writing your  scripts, choose variables and their types carefully and use as many as  necessary.  

### **Profile Script**

Profile the script to  determine which commands and blocks take the most processing time. This  will help you determine where we should focus your optimization efforts.

You can use the “Measure-Command” cmdlet to measure the execution of a command.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/6/ps14.png)

However, if you want to  do more detailed profiling, this process can be a little more  complicated. PowerShell, by default, does not have advanced profiling  tools. However, you can use the profiling tools available for .NET  applications because PowerShell is built on .NET.

Such tools usually come  with GUI and visualize various metrics. For example, professional tools  such as JetBrains dotTrace or Redgate ANTS can be used for such  operations. You can also use lower-level tools like Windows Performance  Toolkit.

As a result, profiling in PowerShell can be complex and often requires more advanced tools or  techniques. Therefore, if you plan to do more complex profiling, you may need to learn special tools to do it.

### Use Debugging Methods

Errors can significantly  impact a script's performance. Debugging helps you find and fix errors  in your code, which can improve overall performance. 

#### Try/Catch Structure

One of the important  issues we need to pay attention to when writing Powershell scripts is  the management of errors that may occur during the script's execution.  If we do not take care of for possible errors in advance, this may  result in the script ending unexpectedly or performing incorrect  operations, and these consequences can be a real headache.

PowerShell provides us with the Try/Catch/Finally structure to manage such situations.

**try**   block contains code that may cause errors. If an error occurs in the   **try block, the process moves to the catch**   block.   **The catch**   block contains the codes to be executed in case of error. The   **finally**   block contains the codes that will be executed whether there is an error or not. This   **finally**   block is often used to clean up resources and shut them down properly.

Let's do an example to understand better:

```powershell
try {
Write-Host "This is try block"
#FaultyOperation
$result = 1 / 0
}
catch {
    
Write-Host "This is catch block"
Write-Host "Error: $_"
}
finally {

Write-Host "and this is finally block"
}

                  
```

In this example, an error occurs in the try block because we cannot divide a number by zero. In  this case, the error message is captured and printed in the catch block. Then the code in the finally block runs and gives the "Operation  completed." message on the screen.

The $_ variable used in  the catch block contains the error details. Using this variable we can  inform the user what the error is.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/6/ps12.png)

### Debugging

PowerShell supports  debugging and offers a variety of cmdlets. Extracting provides the  ability to pause the execution of a particular command or script and  check the status of various variables or expressions.

Environments such as  “PowerShell ISE” and “Visual Studio Code” provide a graphical debugging  interface. However, you can also perform debugging operations from the  text-based command line. We can use a number of cmdlets for this.

- **Set-PSBreakpoint (sbp):** Sets a breakpoint for a given script, row and/or column.
- **Get-PSBreakpoint (gbp):** Lists available breakpoints.
- **Remove-PSBreakpoint (rbp):** Removes a specific breakpoint.
- **Enable-PSBreakpoint (ebp):** Enables a specific breakpoint.
- **Disable-PSBreakpoint (dbp):** Disables a specific breakpoint.
- **Get-PSCallStack:** Lists the current call stack. 

If these don't mean  anything to you, it probably means you've never worked with programming  before, but don't worry; We will see all of them in detail.

#### Set-PSBreakpoint

The Set-PSBreakpoint  cmdlet sets a debug breakpoint on a specific script, line, or command. A debug breakpoint pauses code execution when a certain condition is met. This allows you to examine the state of the code in a given situation  and perform debugging operations.

This cmdlet can be used in different ways.

To set a breakpoint on a specific line of a specific script:

```powershell
Set-PSBreakpoint -Path "C:\Path\To\Script.ps1" -Line 20         
```

To set a breakpoint when a specific command (for example, Write-Host) is run in a specific script:

```powershell
Set-PSBreakpoint -Path "C:\Path\To\Script.ps1" -Command "Write-Host"          
```

To set a breakpoint when a certain condition is met in a given script:

```powershell
Set-PSBreakpoint -Path "C:\Path\To\Script.ps1" -Line 20 -Action { if ($someVariable -eq $someCondition) { break } }             
```

In these three examples, the -Path parameter specifies which script the breakpoint belongs to.   **The -Line**   parameter specifies which line the breakpoint will be on.The -Command parameter triggers a breakpoint when a specific command is executed.   **The -Action**   parameter triggers the breakpoint when a certain condition is met.

#### Get-PSBreakpoint (gbp)

**The Get-PSBreakpoint**   cmdlet returns a list of available debug breakpoints. This cmdlet displays all breakpoints set in a PowerShell session.

It is quite simple to use. To get the list of breakpoints, you can run the following command:

```powershell
Get-PSBreakpoint        
```

This command returns a  list of all available breakpoints. For each breakpoint, displays  information about the breakpoint set in a given script, on a given line, or in a given command. If an   **-Action**   parameter is specified with   **Set-PSBreakpoint , it also displays that action.**

This cmdlet is useful for managing your existing breakpoints. Especially when you're working in a large script and you've set many breakpoints, you can use   **the Get-PSBreakpoint**   cmdlet to keep track of which breakpoints are active.

**The Get-PSBreakpoint**   cmdlet is also available abbreviated as   **gbp**   .  

#### Remove-PSBreakpoint (rbp)

**The Remove-PSBreakpoint**   cmdlet is used to remove one or more debug breakpoints set in PowerShell.

After you get the list of breakpoints by using the   **Get-PSBreakpoint**   or   **gbp command**  , you can then specify the ID of the breakpoint you want to remove.

Once you have determined the breakpoint you want to remove, you can remove the breakpoint using the   **Remove-PSBreakpoint**   or   **rbp command.**

```powershell
Remove-PSBreakpoint -Id 1  
```

#### Disable-PSBreakpoint (dbp)

**The Disable-PSBreakpoint**   cmdlet is used to disable a debug breakpoint in PowerShell and can also be abbreviated as   **dbp**   .

```powershell
Disable-PSBreakpoint -Id 1              
```

#### Enable-PSBreakpoint (ebp)

**The Enable-PSBreakpoint**   cmdlet is used to enable a debug breakpoint that is disabled in PowerShell. If you wish, you can  also use it by shortening it as   **ebp**   .

```powershell
Enable-PSBreakpoint -Id 1         
```

#### Get-PSCallStack

**The Get-PSCallStack**   cmdlet is used to  retrieve the call stack of scripts, functions, and scripts running in  the PowerShell session. This cmdlet returns a list of current calls by  retrieving the stack trace.

Each call contains  information including script name, line number, function name, and file  path. This shows which file, which function, and which line the code  went through.  

**The Get-PSCallStack**   cmdlet can be used in  scenarios such as debugging or analyzing script performance. Especially  in complex scripts, you can use this cmdlet to see which functions were  called in what order or which files caused errors.

For example, you can retrieve the call stack using the following command:

```powershell
$callStack = Get-PSCallStack
$callStack             
```

In this example, the call stack is assigned to the $callStack variable, and then the $callStack  variable is printed to the screen.  

**The Get-PSCallStack**   cmdlet helps you access your session's call stack and shows which code blocks PowerShell scripts are processing at runtime.

#### Example Usage

Now let's make an example where all these debugging functions are used together:

```powershell
#Function Sample
function Test-Function {
my money(
[int]$number
)

    # Set breakpoint
Set-PSBreakpoint -Command "Write-Host" -Script "example.ps1"

# Function in action
$result = 10 / $number

Write-Host "Result: $result"
}

# Set breakpoint
Set-PSBreakpoint -Script "example.ps1" -Line 6

# Call Function
Test-Function -number 0

# List Breakpoints
Get-PSBreakpoint

# Remove breakpoints
Remove-PSBreakpoint -Id 1

# List breakpoints
Get-PSBreakpoint

# Get callstack
$callStack = Get-PSCallStack
$callStack

# Enable all breakpoints
Get-PSBreakpoint | Enable-PSBreakpoint


# Disable all breakpoints
Get-PSBreakpoint | Disable-PSBreakpoint       
```

In this example, we first create an error when calling a function that has a breakpoint set.  Next, we perform debugging using the Set-PSBreakpoint, Get-PSBreakpoint, Remove-PSBreakpoint, Enable-PSBreakpoint, Disable-PSBreakpoint and  Get-PSCallStack cmdlets.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Powershell/6/ps13.png)

Notice in the above output that it automatically switches to DEBUG mode. You see the command line prompt start displaying as   **[DBG]: PS C:\LetsDefend>> .** To exit each breakpoint, simply execute the   **exit**   command.    When you exit each breakpoints Powershell will dump the information about the debug session and return to normal mode.  

In this part of the training, we have learned about the script optimization and debugging operations on Powershell.

### Questions

1 - What is the name of the block that will run when an error occurs in the Try Block in Powershell?

> **Answer:** catch

2 - What is the structure we use to keep the script where we specify?

> **Answer:** Breakpoint

3 - What is the cmdlet used to get the call stack of scripts, functions and scripts running in the PowerShell session?

> **Answer:** Get-PSCallStack









































































































