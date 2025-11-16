# Advanced Bash Scripting

The  "Advanced Bash Scripting" course is designed to improve participants'  knowledge and skills in using complex scripting techniques for  cybersecurity. It aims to enable individuals to effectively tackle  intricate security challenges by employing advanced scripting  methodologies.

**Table of Contents:**

- [Command Line Arguments](#command-line-arguments)
- [Shell Expansion - 1](#shell-expansion---1)
- [Shell Expansion - 2](#shell-expansion---2)
- [File and Directory Operations](#file-and-directory-operations)
- [RegEx and Bash](#regex-and-bash)

**Evaluate Yourself with Quiz**

- [Advanced Bash Scripting](https://app.letsdefend.io/training/quiz/advanced-bash-scripting)

## Command Line Arguments

If you have an opinion on what Bash Scripting is, that's good news. In this course we will try to take our Bash Scripting knowledge one step further.  

### Readings Arguments

On the Bash command line, arguments are the values given to the command line at the time a  command or a Bash script is run. Bash enumerates these arguments like  `$1`, `$2`, `$3`, etc. and makes them accessible. Here is more  information about bash command line arguments:  

- `$0`: Represents the name of the command or script.

- `$1`, `$2`, `$3`,...: these are used to access the first second, third, etc. arguments on the command line.

- `$@`: Represents all command line arguments as an array.

- `$#`: Represents the total number of arguments given on the command line.

- `$*`: Represents all command line arguments as an array, but the arguments are concatenated into a single string.

- `$?`: Represents the exit status of the last command executed.  

For example, we can print a message using command line arguments in the following script:

```bash
#!/bin/bash

echo "Arguments from command line:"
echo "Argument 1: $1"
echo "Argument 2: $2"
echo "Argument 3: $3"
echo "All Arguments: $@"
echo "Total Arguments Count: $#"              
```

To run this script, you can provide arguments on the command line like this:

```sh
./arguments.sh Hello World!            
```

In this case, the script will access the arguments given on the command line and produce the following output:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash22.png)

In this example, `$1`  gives us the first argument (`Hello`), `$2` the second argument  (`World!`), and `$#` gives us the total number of arguments.  

### shift

The shift command is used to shift command line arguments and change access. It is often used in  conjunction with loops. Each shift command causes command line arguments to shift to the next position (dropping the previous argument). This  allows us to access the arguments sequentially.

```bash
#!/bin/bash

echo "Arguments from command line:"
echo "Argument 1: $1"

shift

echo "After shifting"
echo "Argument 1: $1"              
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash23.png)

In this example, we first print the first command line argument, $1. Next, we shift the arguments one position using the shift command. The shift command shifts all  arguments one position to the left, and $1 now takes the previous $2  value. Therefore, in the second echo statement, the value $1 represents  the second element of the command line arguments.  

### Getopts

getopts is a structure  used in bash script to parse command line arguments and catch certain  flags or options. It is often used with a “while” loop. With getopts you can add certain flags or options to your script and have the user use  those flags or options in a certain way.

```bash
#!/bin/bash

while getopts ":a:bc" opt; do
  case ${opt} in
    a)
      echo "Option a is passed with value: $OPTARG"
      ;;
    b)
      echo "Option b is passed"
      ;;
    c)
      echo "Option c is passed"
      ;;
    \?)
      echo "Invalid option: -$OPTARG"
      ;;
  esac
done             
```

As those of you who have  worked in the Linux (or Unix) command line are familiar, we give some  parameters to the command we will run on the Linux command line, and we  do this by typing the parameter name (usually a letter) after the “-”  sign. As you will notice, in this example we also had the opportunity to understand how this structure works.  

In this example, we are  checking three separate options using the -a, -b, and -c flags. The  “getopts” loop captures each current flag as “$opt” and the value of the flag as “$OPTARG”. Then we act on certain flags with the case  statement.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash24.png)

Finally, let's show that  we can make the arguments alternative. In the example below, the user is allowed to use either "-o" or "--option" options.

This is a usage that provides comfort to the user when too many arguments are used.

```bash
#!/bin/bash

while [[ "$#" -gt 0 ]]; do
    case $1 in
        -o|--option)
            option_value="$2"
            echo "Option value: $option_value"
            shift 2
            ;;
        *)
            echo "Invalid Argument: $1"
            exit 1
            ;;
    esac
    shift
done              
```

### Questions

1 - What is the expression that represents the first argument in a bash script?

> **Answer:** $1

2 - What is the name of the value that represents the number of arguments in the bash script "/root/Desktop/QuestionFiles/script5.sh" on the Linux  lab machine you are accessing?

> **Answer:** value5

3 - What is the name of the  value that represents all arguments in the bash script  "/root/Desktop/QuestionFiles/script5.sh" on the Linux lab machine you  are accessing?

> **Answer:** value4

4 - In the bash script  "script6.sh" on the Linux lab machine you accessed, you want to print  the 5th argument on the screen after the "shift" commands. How many more shift commands should be added for the bash script to print the 5th  argument?

> **Answer:** 2

5 - Which command does it help us access options such as -a, b, -c given while our script is running?

> **Answer:** getopts

## Shell Expansion - 1

Bash shell expansion is a property used to expand or evaluate special characters or expressions  in a string. Expansion is performed immediately after a string on the  command line, allowing the string to be replaced with a new value or  otherwise manipulated.  

Bash shell expansion supports the following special characters or expressions:

**Tilde expansion**

(~): The tilde character  represents a user's home directory (`$HOME`). For example, we can  combine `~` with `~/Documents` to represent the user's "Documents"  directory.    

**Parameter expansion**

($): The `$` character represents the value of a variable. For example, we can get the user's home directory using `$HOME`.

**Arithmetic expansion**

(()): The expression `(( ))` is used to evaluate arithmetic expressions. For example, the  expression `(( x = 5 + 3 ))` assigns the value 5 + 3 to the variable  `x`.

**Conditional Expression Expansion**

The `(( ))` expression is used to evaluate conditional expressions. For example, with the  expression `(( x > y ))` we can check whether the value `x` is  greater than `y`.

**Brace Expansion**

(${ }): The `${ }` expression is used to retrieve or manipulate the values of variables or  string expressions. For example, with `${var}` we can get the value of  the variable `var`.

**Command Substitution**

(` ` or $( )): Command  substitution is used to output a command and can be performed in two  different ways by using backquotes (` `) or `$()`. For example, with the expression `result=$(date)` we can assign the output of the `date`  command to the `result` variable.

**Arrays Expansion**

(${[ ]}): The `${[ ]}`  expression is used to access the elements of arrays or perform  operations related to the array. For example, we can access the first  element of an array with the expression `${array[0]}`.

These special characters  and expressions allow working with string manipulation, arithmetic  operations, conditional expressions, values of parameters, and command  outputs in the Bash shell. Bash shell expansion makes scripts more  dynamic and flexible and allows us to do more powerful operations on the command line.  

Now, review the following sample code and its output carefully, understand what is happening in  each line and compare it with the output:

```bash
#!/bin/bash

# Tilde Expansion (~)
echo "Home Directory: $HOME"
echo "Documents Directory: ~/Documents"

# Parameter Expansion ($)
greeting="Hello, World!"
echo "Greeting: $greeting"

# Arithmetic Expansion (())
(( x = 5 + 3 ))
echo "x = $x"

# Conditional Expression Expansion (())
x=10
y=5
if (( x > y )); then
  echo "x is greater than y"
else
  echo "x is not greater than y"
fi

# Brace Expansion (${ })
name="John"
echo "Hello, ${name}!"

# Command Substitution (` ` or $( ))
current_date=$(date)
echo "Current Date: $current_date"

# Array Expansion (${[ ]})
numbers=(10 20 30 40 50)
echo "First Number: ${numbers[0]}"              
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash25.png)

Now, let’s review the expansion techniques in detail:  

Expansions are used to  modify the output of a particular command or code block. When bash  receives a command that a user types on the keyboard or comes from a  bash script, it splits it into words. In doing so, Bash can perform  seven different operations on words, which can change how they are  interpreted and thus the output. There are 7 different expansions that  we can use in Bash. Now let's examine them one by one:

### Brace Expansion

Brace Expansion is often used to create variations of a particular pattern in Bash:

```sh
touch file_{1..5}.txt               
```

This command creates five different files named file_1.txt, file_2.txt, file_3.txt, file_4.txt and file_5.txt.  

Here, the expression  {1.5} creates the numbers 1 to 5 using the brace expansion. The  file_{1..5}.txt statement takes each of these numbers and converts them  to filenames like file_1.txt, file_2.txt, ... file_5.txt.  

Thus, we can create a  series of files with a single command. This is very useful for  generating file and directory names. Also, this can be useful if a  command is run repeatedly with different parameters.  

Let's do another example:

```bash
#!/bin/bash
for i in {1..3}; do
    if [[ -r "file${i}.txt" ]]; then
        echo "You have read permission for file${i}.txt"
    else
        echo "You do not have read permission for file${i}.txt"
    fi
done             
```

This script checks  whether the files named "file1.txt", "file2.txt" and "file3.txt" are  readable, if you have read permission for the files. The user is  notified whether you have read permissions or not. When we run the  script, a table is created as you can see below. There are 3 files named file1.txt, file2.txt and file3.txt in the directory and file2.txt  belongs to the root user.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash35.png)

### Tilde Expansion

In the Bash shell, the  tilde symbol usually points to a user's home directory. In Bash, the  tilde (~) expansion is often used to easily access users' home  directories. In other words, a tilde expansion is actually replacing a  path that points to a user's home directory.  

Here, before we move on to the examples, let's do a brief rundown of the basics of Linux:

On Linux systems, the user's home directories are located under the   **/home**   directory by default.  But this is not an unchangeable rule; this can be changed when the user  is added to the system or afterwards and this information is basically  located in the   **/etc/passwd**   file.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash36.png)

As we mentioned above  this is not an unchangeable rule and the sysadmin can relocate/move a  user's directory to a different location.  

Since we cannot know the  home directories of all users in the system where the script will run,  especially in cases where we will interact with the   **home**   directories of users  while writing portable shell scripts, we leave this job to the tilde  symbol and instead of taking risks by expressing the directory of a user whose name we know as /home/<username>/ we can express it as  **~<username>**.  

Let's give a few examples of different scenarios when using the tilde expansion:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/shell-table.png)

Now let's make an example and examine the results:

```bash
#!/bin/bash
echo ~
echo ~root
echo ~/Documents
echo ~root/Documents
echo ~+
echo ~-              
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash37.png)

### Questions

1 - What is the name of the expansion technique used in the expression; result=$((5 + 2))

> **Answer:** Arithmetic expansion

2 - Which echo command in the "/root/Desktop/QuestionFiles/script7.sh" bash  script on the Linux lab machine you are accessing prints the current  user's home directory to the screen? 

Note: Enter the numeric form of the answer.

> **Answer:** 1

## Shell Expansion - 2

### Parameter and Variable Expansion

In Bash, parameter and  variable expansion are used to get the value of a variable. This  variable can be a variable that we define in the script, or it can be a  parameter that we give from the command line when calling our script.  Parameter and variable expansion begins with the symbol `$` and  continues with the name of the variable. For example, to create a  variable named my_var and get its value, you can write code like this:

```bash
#!/bin/bash
my_var="Hello, World!"
echo $my_var             
```

This piece of code will output the text, "Hello, World!".  

Bash offers some features to adapt the extension to more complex use cases:  

**Default Values:** If a variable is not defined, a default value can be assigned during expansion. We can use it as   **${var:-default_value}.**

```bash
#!/bin/bash
echo ${name:-"Unknown"}              
```

In this example, if the variable   **name**   is not defined, it will output "Unknown".  

**Error Checking:** If the ${var:?error_message} form is used and if the variable is not defined, it will generate an error message and stop the script.

```bash
#!/bin/bash
echo ${name:?"Name is not set."}              
```

In this example, if the variable “name”is not defined, an error will be generated and the script will be stopped. It is important to  understand the part that differs from the previous example. In the  previous example, if the variable had no value, the script would  continue by assigning a default value to it. In this example, the script will be stopped with the error message: “Name is not set.” and will not continue.

**Substring Replacement: ${var/find/replace}** usage replaces the “find” expression in the “var” variable with “replace”. 

```bash
#!/bin/bash
greeting="Hello, World!"
echo ${greeting/World/Earth}              
```

We start by assigning the "Hello, World!" value to the “greeting” variable. Then we replace the word "World" with "Earth" while the script is running. At the end, you will see the "Hello, Earth!" output after you run the script.  

After the Variable expansion topic, let's do some practices of parameter expansion. Before  moving on to the examples, let's remember that the concept of parameter  is the inputs taken from the command line in bash scripting when running the script.  

Adding parameters or  arguments to a bash script is pretty straightforward. We can add  parameters from the command line by leaving a space after the name of  the script. These parameters are represented with $1, $2, $3, etc. that  are special variables in the script. The first parameter is represented  with $1, the second one will be with $2, and so on.

```bash
#!/bin/bash
echo "First Parameter: $1"               
```

If you run this script as ./myscript.sh Hello, you will get   **First Parameter: Hello**  .  

So, what is the easiest  way to know how many different parameters were sent to us while the  script was running? If we do not know the number of arguments we receive and we want to control them all in the script, we can treat all  parameters as an array. And, we can do it by using $@ or $* expression.

```bash
#!/bin/bash

for prms in "$@"
do
  echo "Parameter: $prms"
done               
```

Let's look at the sample output below:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash38.png)

### Command Substitution

Command substitution in Bash allows to use the output of one command as the input of another  command. It is often used to assign the output of a command to a  variable or use it as an argument to another command. 

There are two ways to  change commands. In fact, it would be more accurate to say that the same function has two different uses, old and new. We will describe both but suggest you use the second method.  

**Grave Accents `...`** is the older method and often the newer method `$(...)` is preferred over this one due to its limitations in some cases.  

**Dollar Sign and Parentheses `$(...)`**   is the newer method and this method makes nested commands more readable and is generally preferred.

Although parentheses and quotes may seem confusing, they actually are not. Let's review them with examples:  

We can assign the output of a command to the value of a variable:

```bash
#!/bin/bash

now=$(date)
echo "The current date and time is: $now"             
```

Every time you run this script, the “now“ variable will be created with the current date and will produce a different output each time.  

We can use the output of one command as an argument to another command.

```bash
#!/bin/bash

echo "Directory contents: $(ls)"           
```

Notice that we do not define any variables and we output the ls command and use it at runtime.  

And the most exciting part is that we can use them together:

```bash
#!/bin/bash

echo "File sizes: $(du -h $(pwd))"          
```

In this example, we list the disk space used by the files in our current directory.  

Being able to use the  output of one command as the input of other commands can increase the  complexity and functionality of your scripts. Let us remind you that you should be very careful about the error checks when using these  features.  

### Arithmetic Expansion

Arithmetic expansion in Bash allows you to evaluate arithmetic expressions and use its result. You can use the $((arithmetic_expression)) syntax for this. Bash treats  this expression as an arithmetic expression and returns its result.

We can do this simply by enclosing arithmetic expressions in () and then using them in $():

```bash
#!/bin/bash

echo $((5 + 2)) # Output: 7
echo $((5*2)) # Output: 10
echo $((10 / 2)) # Output: 5
echo $((10 - 5)) # Output: 5


num1=15
num2=5
echo $((num1 / num2)) # Output: 3        
```

### Word Splitting

Word splitting in Bash is the process of converting a string into multiple values by splitting it according to a certain separator. It is often used when looping over an array or when you want to split the output of a command into multiple  values.  

Let's start with a simple example:

```bash
#!/bin/bash

my_string="LetsDefend is one of the best resources on cybersecurity"

for word in $my_string
do
  echo $word
done            
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash39.png)

One important thing to  note is how bash handles quotes. Word splitting does not occur when a  string is in double quotes. In the example above, let's enclose the  $my_string variable in the for line with “ “ and look at the output  again:

```bash
#!/bin/bash

my_string="LetsDefend is one of the best resources on cybersecurity"

for word in “$my_string”
do
  echo $word
done              
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash-split.png)

In this case, `my_string` is treated as a whole single word, because double quotes prevent word  splitting from occurring. That's why it's important to be careful when  doing word splitting in bash. Depending on how the quotation marks are  used, your results can vary significantly.

So, can we split a string only by spaces? No, we can customize it.  

In Bash, Internal Field Separator (IFS) is a special variable used to determine how to split an array.  

Using the IFS variable,  you can split a string in bash by a specific character or string of  characters. For example, you can set the IFS variable to a comma to  split a comma-separated array:

```bash
#!/bin/bash

my_string="LetsDefend is ,one of the ,best resources on cybersecurity"

IFS=','
for word in $my_string
do
  echo $word
done            
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash40.png)

One thing to note is that the IFS variable will be effective throughout your script. So, after  changing the IFS variable for a loop or a custom operation, it's usually a good practice to return it to its original value:

```bash
#!/bin/bash

my_string="LetsDefend is ,one of the ,best resources on cybersecurity"

old_IFS=$IFS
IFS=','
for word in $my_string
do
  echo $word
Done

IFS=$old_IFS            
```

By doing this we can  prevent the IFS variable from accidentally causing unexpected behavior  elsewhere. A good practice is to always keep the original value before  using IFS so it can be restored later.  

### Pathname Expansion

A feature called pathname expansion, or sometimes globbing, in Bash is the automatic mapping and  expansion of file or directory names that fit a certain pattern. This is one of the bash shell expansion features and is usually done on the  command line or in scripts.  

Bash uses various special characters and structures for pathname expansion:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/shell-exp-t.png)

```bash
#!/bin/bash

# It lists all txt files.
ls *.txt

# Lists all files with a single character name.
ls ?

# List all files with a, b or c in their name.
ls *[abc]*

# Lists all files whose names match a given number range (1-3).
ls *[1-3]*             
```

This feature allows you  to work very flexibly when specifying file and directory names. It is  especially useful when working with large amounts of files or when you  quickly want to find files that match a particular name pattern.  Pathname expansion is a core feature of many Unix-based operating  systems and shells and is also supported in the bash shell.  

Our example below,shows the .log files under the /var/log/ directory and how many lines of data are in them.

```bash
#!/bin/bash
dir_path="/var/log"
for file in $dir_path/*.log
do
  line_count=$(wc -l <"$file")
  echo "$file file has $line_count line log"
done             
```

Note that we use the wc (word count) command with the -l (only count lines) parameter to count the lines, assign the output of this command to the line_count variable, which we apply the variable expansion technique, and use this value in the next line.

### Questions

1 - What is the name of the method that is used as result=$(date) by running a command in the operating system and using its output?

> **Answer:** Command Substitution

2 - How many lines is the output of the bash script "/root/Desktop/QuestionFiles/script8.sh" on the Linux lab machine you accessed?

> **Answer:** 9

3 - How many lines is the output of the bash script "/root/Desktop/QuestionFiles/script9.sh" on the Linux lab machine you accessed?

> **Answer:** 7

## File and Directory Operations

### Creating Files and Directories

File and directory  operations are an essential component of Bash programming, and learning  about it is essential to develop and effectively use your Bash skills.  

Mastering file and  directory operations is critical to expand your Bash programming skills  and creating more complex and effective scripts. It's important to read  carefully, give examples, and practice while learning about this topic.  Remember, in real-world scenarios, automating daily tasks and managing  data using file and directory operations will be of great advantage.

It is important creating  files and directories in bash scripting for organizing data, managing  resources, and automating the workflow. Here are some methods of  creating files and directories in Bash:

**Touch**

The `touch` command is  used to update the timestamp of an existing file or to create a new  file. For example, the `touch file.txt` command creates a file named  `file.txt` or updates the timestamp of an existing file.

**echo ve redirection**

The `echo` command is  used to write text or content to a file. For example, `echo "Hello,  World!" > file.txt` command creates a file named `file.txt` and write "Hello, World!" text into it. You can use the `echo "New content"  >> file.txt` command to append to an existing file.

**cat and redirection**

The `cat` command is used to create or edit the contents of a file. For example, you can use the  `cat > file.txt` command to create a file and input content line by  line. You can use the `Ctrl + D` key combination to complete the entry.

**printf ve redirection**

The `printf` command is  used to generate formatted output. For example, the command `printf  "Line 1\nLine 2" > file.txt` creates a file named `file.txt` and  writes two lines of text in it. 

**mkdir**

The `mkdir` command is  used to create a directory with the specified name. For example, the  `mkdir directory` command creates a directory named `directory`. You can also use `mkdir directory1 directory2 directory3` to create multiple  directories.

**cp ve mv**

The `cp` command is used  to copy files or directories. For example, the `cp source.txt  target.txt` command copies the `source.txt` file with the name  `target.txt`. The `mv` command is used to move or rename files or  directories. For example, the `mv old.txt new.txt` command moves or  renames the `old.txt` file to `new.txt`.

These methods are common  methods of creating files and directories in Bash scripting. Using these processes, you can organize your data, automate your workflow, and  manage it more effectively in your Bash scripts. By practicing creating  files and directories, you can improve your Bash skills and successfully perform more complex tasks.  

In the example script below, you can see the practical use of all of these together:

```bash
#!/bin/bash

# Create a file using 'touch' command
touch file.txt

# Write content to the file using 'echo' and redirection
echo "Hello, World!" > file.txt

# Append more content to the file using 'echo' and redirection
echo "This is a sample file." >> file.txt

# Create a file and enter content using 'cat' and redirection
cat > another-file.txt << EOF
This is another file.
It has multiple lines of content.
EOF

# Create a file using 'printf' and redirection
printf "Line 1\nLine 2\nLine 3" > third-file.txt

# Create directories using 'mkdir' command
mkdir directory1 directory2

# Copy files using 'cp' command
cp file.txt directory1/copied-file.txt
cp another-file.txt directory2/copied-file.txt

# Move files using 'mv' command
mv file.txt directory1/moved-file.txt
mv another-file.txt directory2/moved-file.txt            
```

It is very important for  you to better understand the subject by making each of these examples in your own environment and watching the results.

### Reading Files

There are different  methods for reading files from within the bash script. Let's take a look at the most important of them together:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash26.png)

**while loop and read:**   The `while` loop and the `read` command are used to read file lines. For example:

```bash
#!/bin/bash

# File to read
file="file_for_read.txt"

while read -r line
do
    echo "Line: $line"
done < "$file"           
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash27.png)

In this example, the file `file_for_read.txt` is read line by line and each line is assigned to  the variable `$line`. Then, each line is printed to the screen with the  `echo "$line"` command.  

**grep:** The `grep` command is used to search for a specific pattern in a file. For example, the  command `grep "pattern to search" file_for_read.txt` searches for  "pattern to search" in `file.txt` and prints the matching lines to the  screen.

```bash
#!/bin/bash

# File to search
file="file_for_read.txt"

# Pattern to search for
pattern="Another"

# Use grep to find the pattern in the file
if grep -q "$pattern" "$file"; then
    echo "Pattern found in the file."
else
    echo "Pattern not found in the file."
fi           
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash28.png)

**awk:** The `awk` command is used to manipulate text files into rows, columns, and fields. For  example, the `awk '{print $1}' file.txt` command prints the first field  of each line in `file.txt`.

```bash
#!/bin/bash

# File to read
file="file_for_read.txt"

# Use awk to display the first word of each line
awk '{print $1}' "$file"              
```

As you can see in the output below, we have listed the first columns in our sample file.

We should also mention  that awk separates text from spaces, so if we used $3 instead of $1, we  would see the 3rd word in each line.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash29.png)

**Reading fields with IFS and while loop:** If there is data  separated by columns in the file, you can read the columns in the file  by setting the Internal Field Separator (IFS) variable and using the  `read` command. For example:

```bash
#!/bin/bash

# File to read
file="file_for_ıfs.csv"

# Read the file line by line
while IFS= read -r line
do
    echo "Line: $line"
done < "$file"             
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash-file.png)

In this example, the  columns are separated by commas in each row in the `file.csv` file. The  `IFS` variable is set as a comma and the `read` command reads the  columns individually and assigns them to the variables. Then the value  of each column is printed to the screen.

These methods are the  ones that are commonly used to read files within Bash script. It plays  an important role in many scenarios such as reading data from files,  text processing, data analysis and reporting.  

### Moving Files

We can move files and directories with the "mv" command (short for move) in bash script.  

Note that, in the  example, the use of "mv" is the same as in the Linux console. Likewise,  the use of Wildcard is also possible in the script. In the example code  below, we have used possible use scenarios.  

**Moving files without using a wildcard:**   Here we move the files file1.txt and file2.txt to the destination/ directory.  

**Moving files using wildcard:**   Using the *.txt wildcard pattern, we select all .txt files in the current directory and move them to the destination/ directory  

**Moving directories without using a wildcard:**   We are moving directories directory1 and directory2 to the target/ directory.  

**Moving directories using wildcard:**   Using the dir* wildcard  pattern, we select all directories starting with "dir" in the current  directory and move them to the target/ directory.  

This example shows you  how to move files and directories in Bash script using the mv command. It includes both the use of wildcards and carry operations without a  wildcard.

```bash
#!/bin/bash

# Moving files without wildcard
echo "Moving files without wildcard:"
mv file1.txt file2.txt destination/

# Moving files with wildcard
echo "Moving files with wildcard:"
mv *.txt destination/

# Moving directories without wildcard
echo "Moving directories without wildcard:"
mv directory1 directory2 destination/

# Moving directories with wildcard
echo "Moving directories with wildcard:"
mv dir* destination/        
```

### Questions

1 - What is the command used to manipulate text files into rows, columns and fields?

> **Answer:** awk

2 - In the bash script "/root/Desktop/QuestionFiles/script10.sh" on the  Linux lab machine you are accessing, there is a field filled with question marks (?) between single quotes. What should be written in the  "?" field to print the 3rd field for each line in the "file.txt" of the  bash script?

> **Answer:** {print $3}

## RegEx and Bash

Bash scripts are powerful tools for performing text-based operations.

One of the capabilities of these scripts is the use of regular expressions (RegEx).

RegEx is a set of  languages and techniques used to identify specific patterns in text and  perform operations such as searching, matching and replacing according  to these patterns.

In this course, we will explore the importance and different applications of using RegEx in Bash scripts.  

With your bash scripts, you can produce fast and effective solutions for the following issues with Regex:  

**Searching and matching text**

You can find and match texts with a certain pattern. For example, you can check if a particular word occurs in the text.

```bash
#!/bin/bash

# Check if a string matches a pattern
string="Hello, World!"
pattern="^Hello"

if [[ $string =~ $pattern ]]; then
    echo "Pattern matched!"
else
    echo "Pattern not matched!"
fi              
```

**Editing text**

You can find and replace  or delete specific patterns in the text. For example, removing  parameters from a URL or removing spaces in text.

```bash
#!/bin/bash

# Replace occurrences of a word in a string
string="I love cats. Cats are amazing."
pattern="cats"
replacement="dogs"

new_string="${string//$pattern/$replacement}"
echo "New string: $new_string"              
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash30.png)

**Data validation**

You can use RegEx to check the accuracy of text-based data. For example, checking the  validity of an email address or verifying the accuracy of a phone  number.

```bash
#!/bin/bash

# Function to validate email address using RegEx
validateEmail() {
    email=$1
    pattern="^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"

    if [[ $email =~ $pattern ]]; then
        echo "Email address is valid."
    else
        echo "Email address is invalid."
    fi
}

# Prompt user to enter an email address
echo "Enter an email address:"
read user_email

# Call the validateEmail function with the entered email address
validateEmail "$user_email"            
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash31.png)

**Data analysis**

You can use RegEx to analyze text-based data and extract or report data based on certain  patterns. For example, finding errors with a certain pattern in log  files or extracting data in a certain format.  

For example, let's have an "access.log" file of a web server like the one below:

```nginx
127.0.0.1 - - [28/May/2023:12:34:56 +0000] "GET /sayfa1 HTTP/1.1" 200 1234 "https://www.example.com" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
127.0.0.1 - - [28/May/2023:12:34:57 +0000] "GET /sayfa2 HTTP/1.1" 200 5678 "https://www.example.com" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36"
...             
```

Let's say we want to see the "User Agent" strings in this file in bulk:

```bash
#!/bin/bash

log_file="access.log"

# Check if log file exists
if [ ! -f "$log_file" ]; then
    echo "Log file $log_file not found."
    exit 1
fi

# Function to extract user agents from log file
extractUserAgents() {
    while IFS= read -r line; do
        user_agent=$(echo "$line" | awk -F'"' '{print $6}')
        echo "User Agent: $user_agent"
    done < "$log_file"
}

# Call the extractUserAgents function
extractUserAgents         
```

In this script, we define a function named "extractUserAgents". This function reads each line  from the log file and uses a combination of awk and RegEx to extract the user agent from each line. The user agent is then printed to the  console.  

The script first checks  if the log file exists. If the file is not found, an error message is  displayed and the script gets terminated.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash32.png)

Let's finish with a more complex example of using regex in Bash Script.

Let's say we want to find e-mail addresses in a text file, check for validity and generate a report.

```bash
#!/bin/bash

input_file="input_file.txt"
output_file="report.txt"

# Check if input file exists
if [ ! -f "$input_file" ]; then
    echo "Input file $input_file not found."
    exit 1
fi

# Function to validate email address
validateEmail() {
    email=$1
    pattern="^([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+)\.([a-zA-Z]{2,})$"

    if [[ $email =~ $pattern ]]; then
        echo "Valid Email: $email"
    else
        echo "Invalid Email: $email"
    fi
}

# Process input file and generate report
processFile() {
    while IFS= read -r line; do
        # Find email addresses using regex
        email_regex="[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
        emails=$(echo "$line" | grep -E -o "$email_regex")

        # Validate and write emails to output file
        for email in $emails; do
            validateEmail "$email" >> "$output_file"
        done
    done < "$input_file"

    echo "Report generated: $output_file"
}

# Call the processFile function
processFile            
```

As you will see, we are using a text file called inputfile.txt. The script will find the e-mail  addresses in this file, check for validity and create a report file  called report.txt.  

The script first checks  if the input file exists. If the file is not found, an error message is  displayed and the script gets terminated.  

A function named validateEmail is defined. This function uses a regex pattern to check if an email address is valid.  

A function named  processFile is defined. This function reads the input file line by line, finds email addresses using regex, validates each address, and writes  the results to an output file called report.txt.  

The script starts the  process by calling the processFile function and performs the operations  of finding email addresses, validating and generating reports.  

This is an advanced  scenario example that lets you find email addresses from a text file and report using regex. By running the script, you can process the text  file and get the validity status of the e-mail addresses as a report:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Bash-scripting/bash33.png)

