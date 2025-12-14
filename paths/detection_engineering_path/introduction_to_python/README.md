# Introduction to Python

The "Introduction to Python" course is designed to familiarize detection  engineers in cybersecurity with the Python programming language,  enabling them to effectively apply it in the context of threat detection and analysis.

Table of Contents:

- [Introduction to Python]()
- [Installing Python Environment]()
- [Configuring Python Environment]()
- [Control Structures in Python: Conditionals and Loops]()
- [Functions, Modules, and Packages]()
- [File Operations and Error Handling]()
- [Data Structures]()
- [Algorithms in Python]()
- [Object Oriented Programming (OOP) in Python]()

Evaluate Yourself with Quiz

- [Introduction to Python](https://app.letsdefend.io/training/quiz/introduction-to-python)

## Introduction to Python

### What is Python?

Python is a  general-purpose, high-level programming language with an easy-to-learn  and readable syntax. It was created by “Guido van Rossum” in 1991 and is widely used in artificial intelligence, machine learning, web  development, data analysis, automation fields and many more.

Python is a language that is easy to learn and with which you can quickly start developing  applications. But like all languages, it has its own Syntax, Operators  and Standard Data Types. Let's examine what these are:

### Python Syntax

- Python code continues until the end of the line, it does not need a special end-of-line character (for example, ';').  
- In Python, blocks  (functions, if else blocks, loops, etc.) are defined by indentation.  This indentation is usually made with a tab or 4 spaces.  
- Python is a case-sensitive language, for example, 'Variable' and 'variable' are considered two different variable names.  
- Comment lines begin with the '#' character and are not interpreted by Python.  

### Operators in Python

As in all languages,  various operators are used for various operations in Python. Learning  all these well and knowing their functions is the basic information we  need to develop working Python scripts:

**Arithmetic Operators**

Arithmetic operators are  operators with which we can perform arithmetic operations in Python, and they have very simple and understandable syntaxes:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Python/1/python1.png)

#### Assignment Operators

Assignment operators are used to assign a value to a variable. Normally, “   **=**   ” is   **sufficient**   to assign a value to a  variable, but Python also offers us some convenience during assignment.  In this way, we can easily perform some arithmetic operations while  assigning a value to the variable or changing its current value:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Python/1/python2.png)

#### Comparison Operators

Like all programming  languages, Python provides operators to compare two values. We can use  the following operators to see the status of two different values  relative to each other. The result of these operators always returns a  boolean type data (true or false, 1 or 0).

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Python/1/python3.png)

#### Logical Operators

Python supports the following three basic operators for logical operations:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Python/1/python4.png)

#### Bitwise Operators

Bitwise operators are available in Python to perform bitwise operations:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Python/1/python5.png)

#### Identity Operators

In Python, we use  identity operators to understand whether the two values we have  represent the same object. There are 2 identity operators as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Python/1/python6.png)

#### Membership Operators

Python has membership operators to check whether a value is in a particular collection (list, tuple, set, dict, str):

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Python/1/python7.png)

### Data Types in Python

Python is a very powerful language when it comes to data types and by default it supports almost  all data types we may need while coding. In cases where these are not  sufficient, it provides very easy support for us to define our own data  types and then use them:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Python/1/python8.png)

We'll cover defining and using our own data types later in the course.

In this part of the  training, we have briefly covered what Python is, its syntax, operators  and data types. We will learn about the "  **Establishing the Python Environment-1**  " topic in the next part of our training.

### Questions

1 - What year was the Python programming language created?

> **Answer:** 1991

## Installing Python Environment

Python can run on  multiple platforms, and Python scripts can be ported between platforms  except for very special cases. In other words, you can run your Python  code on multiple platforms regardless of where it was written  originally. The major platforms where you can write and execute Python  codes are Linux, MacOS, and Windows.  

### Linux

Now let's see how to make Python work in our Linux environment. As Python is installed in most of the latest Linux distributions, you will probably not need to make an  effort to install Python.

Package management systems used by Linux distributions exhibit different approaches to Python.

Please note that some of the Linux distributions name it as   **Python**  , and some others name it as   **Python3**  . You can find out  whether Python is installed on your Linux system or not, or if it is  installed you can check its version with one of the following commands:

```sh
python --version          
```

or 

```sh
python3 --version           
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Python/2/py10.png)

If things do not go as we expected and even if Python is not installed on our system, it is not a big deal, it is very easy to install. The package manager of the Linux  distribution you use will easily do this for you.  

**Redhat-based**   systems (Centos, Fedora, etc.) usually use   **RPM**   packages and   **DNF**   as a package manager while the older Redhat-based systems use   **YUM**  . To install Python on these systems, all you have to do is run the command below and then give the required confirmations.

```sh
sudo dnf install python3

                  
```

**Debian-based**   systems (Ubuntu, Kali, etc.), as you know,   **DEB**   packages are used and they use   **APT**   as the package manager. You can use the following command for the installation in these systems:

```sh
sudo apt-get update
sudo apt-get install python3

                  
```

That's it.

Happy coding ;)  

### macOS

There are multiple ways  to install Python on MacOS. One of these methods is to install it with  XCode. To do this, launch a Terminal by following the path  “Go->Applications->Utilities” from the top menu in Finder and run:

“  **python3 –version**  ”    command in the terminal  window. If Python is not installed, you will receive a message about it  and then you will see a pop-up that’ll start the Python3 installation.

With this method, XCode  will install the Python3 development environment. The disadvantage of  this method is that Xcode will install some additional features/plugins  other than Python3. The advantage is that you will have a ready-made  Python development environment in Xcode. If you are considering using  XCode as an IDE, this method will be ideal for you.

```sh
python3 --version

                  
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Python/2/py12.png)

Another method is to download the PKG file for MacOS from Python's site.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Python/2/py13.png)

  (Image Source:   [https://www.python.org/downloads/ ](https://www.python.org/downloads/)  )  

After downloading the PKG File, you can run the Python Installer by going to your Downloads  directory and double-clicking on the file you downloaded. After the  installer runs, you can easily complete the installation by following  the on-screen instructions.

Apart from this, if you are using HomeBrew, you can also install and start running Python with the “   **brew install python” command.**

```sh
brew install python

                  
```

Happy coding ;)

### Windows

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Python/2/py14.png)

When we double-click on the installer file we downloaded, and we will see the following screen:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Python/2/py15.png)

Select the "Add  python.exe to PATH" option just as it is shown in the above screenshot  and you can click on the "Install Now" button to start the installation.

The installer will  install the required files to make your system run Python. After this  installation is complete, open the command prompt and run the “  **python –version**  ” command, you should see an output like the following:

  

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Python/2/py16.png)

  

This output indicates that Python is now ready to run.

Happy coding ;)  

In this part of the  training, we have covered Python installation on Linux, MacOS, and  Windows environments. In the next part of the training, we will continue learning installation and configuring Python.

## Configuring Python Environment

### Integrated Development Environments (IDE) and Text Editors (PyCharm, VS Code, Jupyter, Atom, etc.)

Using an Integrated  Development Environment (IDE) really helps when coding, as it provides  many useful features that make your coding process more efficient and  enjoyable.

An IDE can be thought of  as a "code buddy" that is there for you while you code. For example, it  gives you autocomplete and error correction suggestions to avoid  mistakes, minimize typos, and allow you to type faster.

You can also debug your  program in the IDE before you run it. By following your code  step-by-step, you can find and fix problem lines. This helps you solve  problems faster and saves you time.

IDEs also help you  organize your projects. You can easily create projects to organize your  code and keep your files organized. This makes your code more  understandable and manageable.

Python is a very popular  language with many libraries and frameworks. IDEs allow you to easily  integrate these libraries and frameworks into your project and get more  done without spending too much time on external tools.

There are many IDEs that  you can use for Python, and they all have their advantages and  disadvantages compared to others. Therefore, our suggestion to you is to spend some time with all of them and continue with the IDE that you  feel more comfortable with. You can find basic information about the  most preferred IDE tools below.  

**PyCharm**

PyCharm is a Python  Integrated Development Environment (IDE) developed by JetBrains. It's a  powerful tool for Python programming, allowing you to write, debug,  test, and deploy code efficiently.

There are two versions of PyCharm:

- PyCharm Community Edition (free and open-source)  
- PyCharm Professional Edition (paid, with additional features)  

The Community Edition  offers the core development features for Python, while the Professional  Edition provides extra advanced features, such as:

- Support for Django and Flask frameworks  
- Integration with version control systems  
- Profiling and performance measurement tools  
- Support for multiple projects  
- Autocompletion for Python code  
- Advanced debugging and testing tools  
- Code distribution features  

PyCharm is available on Windows, macOS, and Linux, and is free to download and install.

To use PyCharm, you’ll  first need to install Python on your computer. After installation, you  can open PyCharm and start a new project. To do this, simply click the  "New Project" button and enter your project name. Once your project is  created, you can start writing code.

PyCharm offers many  helpful features to make coding easier, such as autocompletion,  debugging, and testing capabilities. Additionally, it provides plenty of documentation and resources for Python development.

**VsCode**

Visual Studio Code (VS  Code) is an open-source, free code editor developed by Microsoft. It  supports a wide range of programming languages, including HTML, CSS,  JavaScript, TypeScript, Python, Java, C++, C#, PHP, Node.js, Go, Rust,  PowerShell, F#, Visual Basic, and more.

VS Code is designed to  help you write, edit, debug, and test your code. It offers a variety of  extensions that allow you to customize the editor according to your  needs.

Some key features of VS Code include:

- Autocompletion for code  
- Debugging tools  
- Testing support  
- Integration with version control systems  
- Extensive documentation and Python resources  

VS Code is an excellent tool for Python development as it can be used to write, debug, test, and deploy Python code.  

**Jupyter Notebook**

Jupyter Notebook is an  interactive web application for writing Python code, analyzing data, and creating documents. It features a spreadsheet-like interface that  allows you to write and run code, then immediately view the output.

Jupyter is versatile and can be used for:

- Writing and executing code  
- Data analysis  
- Document creation  

To use Jupyter, you need  to first install the Jupyter Notebook on your computer. Once installed,  you can open a jupyter notebook and start coding.

Jupyter allows you to  write code in cells, which can be run individually or in bulk. The  output appears directly below the code cells.

You can also use Jupyter  to analyze data in Python by creating and manipulating data structures,  such as data frames and matrices. Additionally, you can visualize your  data using graphs and tables.

Jupyter is also great for creating documents that include text, code, and visual elements. You  can export these documents in formats like HTML and PDF.  

**Atom**

Atom is a free,  open-source text editor developed by GitHub. It supports multiple  programming languages, including Python, and allows users to write,  edit, and test code easily.

Atom offers various plugins to improve Python coding, including:

- Linter: Checks for errors in your code  
- Hydrogen: An interactive coding environment  
- Script: Allows you to run code from within Atom  
- Atom REPL: Provides an interactive Python shell  

These plugins make Atom a powerful and easy-to-use tool for Python development. With Atom, you  can write, edit, and test Python code quickly.

### Creating and Using Virtual Environments

A virtual environment is a tool used in Python development that isolates dependencies and avoids  conflicts between projects. It creates a separate Python installation  for each project, allowing you to use different Python versions and  libraries for different applications.

Advantages of Virtual Environments:

- Avoids conflicts between projects by isolating dependencies  
- Helps manage different versions of Python and libraries for each project  

Disadvantages of Virtual Environments:

- Requires additional disk space because each project gets a separate Python installation  
- Can add complexity when working on larger or more complicated projects    

### How to Create and Use a Virtual Environment

To create a virtual  environment, you can use the "virtualenv" module in Python. First,  install it using the following command in the Python command shell:

```sh
pip install virtualenv
virtualenv my_env

                  
```

After creating the  virtual environment, you need to activate it. To enable the virtual  environment, navigate to the virtual environment folder and run the  following command:

```sh
source bin/activate

                  
```

Once activated, your command shell will be prefixed with (my_env), indicating that the virtual environment is active.

```sh
letsdefend@letsDefend (my_env) :~$ source bin/activate

                  
```

To deactivate the virtual environment, simply run the “   **deactivate”**   command.  

### Package Management Systems (Pip, Conda)

- Pip is the default  package manager for Python. It allows you to download and install  libraries from the Python Package Index (PyPI). Additionally, Pip lets  you manage a local package repository and share libraries with other  users.  
- Conda is a more  comprehensive package management system that can handle Python and other software packages, including libraries for R, Julia, and more. Conda  also supports creating and managing virtual environments, which is  helpful when working with different Python versions and libraries.  

Both Pip and Conda are  powerful tools for managing Python libraries. The choice between them  depends on your needs: use Pip for Python-only projects, and Conda if  you need to manage multiple languages or environments.

For more information about Pip and Conda, please refer to the links below:

**Pip**   :   https://pip.pypa.io/en/stable/   

**Conda**   :   https://docs.conda.io/en/latest/     

In this part of the  course, we have covered some IDEs that can be used to write Python code, the creation and use of virtual environments, and some package  management systems for Python. We will learn about the “  **Control Structures in Python: Conditional Statements and Loops**  ” topic in the next chapter of our course.

### Questions

1 - What is the name of Python's default package management system?

> **Answer:** pip

2 - What is the name of the Python IDE developed by JetBrains?

> **Answer:** PyCharm

3 - What is the module used to create virtual environments in Python?

> **Answer:** virtualenv

## Control Structures in Python: Conditionals and Loops

Control structures are at the center of all work in Python, as in all programming languages. Now  let's start getting to know them from conditional expressions.  

### Conditional Statements: if, else, elif

**if**   in Python, is used to check if a particular condition is true. If the specified condition is true, the codes in the “  **if**  ”    block are executed.

```python
number1 = 10
if number1 > 5:
	print("number1 greater than 5.")

                  
```

This code checks if the  number is greater than 5, and if the number is greater than 5, the  "Number is greater than 5." message will be printed on the screen.

The   **else**   keyword specifies the block of code that is executed if the   **if**   condition is not true (  **False**  )

```python
number1 = 3

if number1 > 5:
	print("number1 greater than 5.")
else:
	print("number1 smaller than 5 or equal to 5.")

                  
```

We've improved our first  example a bit, and this time, we have printed the "Number is smaller  than or equal to 5." message on the screen if the number is not greater  than 5.

The   **elif**   keyword is used to check multiple conditions.   **elif**   is short for "  **else if**  " and specifies the block of code that will be executed if the condition is true.

```python
number1 = 5

if number1 > 5:
	print("number1 greater than 5.")
elif number1 < 5:
	print("number1 less than 5.")
else:
	print("number1 equal to 5.")

                  
```

Let's see what the final  version of our example does: First, it is checked whether the number is  greater than 5. If the number is greater than 5, the "The number is  greater than 5." message is printed on the screen. If the number is not  greater than 5, this time it is checked whether the number is less than  5. If the number is less than 5, the "Number is less than 5." message is printed on the screen. If the number is neither greater than 5 nor less than 5, then the "The number is equal to 5." message is printed on the  screen.

### Loops: For and While

Loops are one of the most powerful tools in Python, and they enable a particular block of code to be executed over and over again as long as a certain condition is met.  There are two main types of loops in Python:   **for**   and   **while**  .

**“For” Loop:**   The “  **for**  ” loop in Python is used to loop through an array (list, tuple, string) or using an iterator.

```python
for i in range(5):
	print(i)

                  
```

This code prints numbers from 0 to 4.

**“While” Loop:**   In Python, the “  **while**  ”    loop runs as long as a certain condition is true.

```python
i = 0
while i < 5:
    print(i)
    i += 1

                  
```

This code prints the numbers from 0 to 4, just like in our example  **.**  

### Loop control: break, continue

The “  **break**  ”    keyword, when used inside the loop, stops the loop completely and exits the loop. In some cases,  while writing code, we may need to terminate the loop early. In this  case, the “  **break**  ” keyword saves us:

```python
for i in range(5):
    if i == 3:
        break
    print(i)

                  
```

This code prints the numbers 0, 1, and 2. When the value of i is 3, the `break` command runs and the loop stops.

The “  **continue**  ”    keyword is used inside  the loop, and it stops the current iteration of the loop and moves on to the next iteration. Similar to the “  **break**  ”    example, in some cases we may want our loop to behave differently. Unlike the “break” keywords,  the “continue” keyword does not terminate the loop completely, it just  ends the current iteration and allows the loop to continue from the next control  **.**

```python
for i in range(5):
    if i == 3:
        continue
    print(i)

                  
```

This code prints the  numbers 0, 1, 2, and 4. When the value of i is 3, the `continue`  instruction runs, and the rest of this iteration is skipped. The cycle  continues with the next iteration.

The `break` and `continue` keywords are very important to provide loop control and make the code run more efficiently.  

In this part of the  training, we have covered the conditional statements, loops, and  keywords used for loop control and their uses in Python. We will be  learning about the “  **Functions, Modules and Packages in Python”**   topic in the next part of our training.

### Questions

1 - What is the keyword to stop the loop completely and get out of the loop?

> **Answer:** break

2 - What is the output when  running the Python script "/root/Desktop/QuestionFiles/python1.py" on  the Linux lab machine you accessed?

> **Answer:** False

3 - What is the output when  running the Python script "/root/Desktop/QuestionFiles/python2.py" on  the Linux lab machine you accessed?

> **Answer:** 5

4 - Create the Python code that calculates the sum of the whole numbers from 1 to 100 and enter the answer.

> **Answer:** 5050

## Functions, Modules, and Packages

Python is a language that can be used for many purposes and has many features. In this chapter,  we will go over some of the core features we need to know in order to  use Python effectively as a security professional.

### Functions

Functions are blocks of  code that group a set of instructions and are used to perform a specific task. Functions make the code more organized and reusable.

In Python, functions are  defined using the `def` keyword. A function definition is a block  containing the function name, parameters, and the function body.

Functions are called with parentheses following the function name. In parentheses, the parameters to be sent to the function are specified.

Functions can return a  value using the `return` keyword. After the `return` keyword, the value  that the function will return is specified.

Functions help us to  create codes that are more organized, readable, and understandable. We  can also create reusable codes with the help of functions.

```python
def number_sum(number1, number2): 
    sum = number1 + number2 
    return sum

                  
```

This function adds two numbers and returns the sum. We can use the following code to run the function:

```python
sum = number_sum(10, 20)
print(sum)


                  
```

This code will print the result 30 to the screen.

### Modules

Modules are code files  that group a number of related code blocks and are used to perform a  specific task. Modules make code more organized and reusable.

In Python, modules are  created with the `.py` extension files. To create a module, simply  create a new file using a text editor and add the `.py` extension to the file. Then, you can add the code to your module.

To use modules, you can use the “  **import**  ”    keyword. After the “  **import**  ” keyword, the name of the module is specified. For example, you can use the following code to import the   **letsdefend module:**

```python
import letsdefend

                  
```

Modules are a very  powerful tool to make code more organized and reusable. By using  modules, you can make your code more readable and understandable.  

### Packages

Packages are folders of  code that group a number of modules and are used to accomplish a  specific task. Packages make code more organized and reusable.

In Python, packages are  created with folders with `.py` extension. To create a package, create a new folder using a text editor and add the `.py` extension to the  folder. Then you can add modules to your folder.

To use packages, you can  use the import keyword. After the import keyword, the name of the  package is specified. For example, you can use the following code to  import package “my_package”:

After importing the “  **my_package**  ” package, you can use all modules in the package. For example, you can use the following code to use the “  **my_package.my_module**  ” module:

```python
from my_package import my_module

                  
```

This code will import the “  **my_module**  ” module. Then you can use all the functions in the “  **my_module**  ” module. For example, you can use the following code to use the “  **my_module.my_function**  ” function:

```python
my_module.my_function()

                  
```

This code will run the    “  **my_function**  ”    function inside the module. 

To share packages, save  your package in a folder and upload your folder to a code storage  platform such as GitHub. Then, other users can download and use your  package from the storage platform.

Packages are a very  powerful tool for making code more organized and reusable. By using  packages, you can make your code more readable and understandable.  

In this part of the  training, we have covered what the functions, modules, and packages are  in Python and their use. We will be learning about the “  **File Operations and Error Trapping in Python**  ” topic in the next part of our training.

### Questions

1 - What keyword is used to define functions in Python?

> **Answer:** def

2 - What is the file extension of modules in Python?

> **Answer:** .py

3 - In the Python script  "/root/Desktop/QuestionFiles/python3.py" on the Linux lab machine you  accessed, what should be written in the "?" section to square the last  number in the array?

> **Answer:** 3

## File Operations and Error Handling

### File Operations

File operations are  processes that allow a computer to interact with a file. File operations include reading, writing, modifying, and deleting the contents of the  file.

File operations in Python are done using functions such as open(), read(), write(), and close().  The open() function is used to open a file. The read() function is used  to read the contents of a file. The write() function is used to write  data to a file. The close() function is used to close a file.

Let's try to understand these better with an example:

```python
# To open a file
file = open("file.txt", "r")

# To read the contents of the file
content = file.read()

# To write data to the file
file.write("This is a text file.")

# To close the file
file.close()             
```

This code will open a  file named “file.txt”, read the contents of the file, and write the  “This is a text file.” text, and close the file.

File Operations are an  important topic in Python programming. By using file operations, you can enable a computer to interact with a file and perform various  operations on the files.  

### Error Catching and Debugging

Error catching is a  process used to detect and fix errors when a program makes an error  during its execution. It helps ensure that the program runs properly and users do not encounter error messages.

**What is Debugging?**

Debugging is a process  used to detect and correct errors that occur during the operation of a  program. Debugging is used in conjunction with error catching to  determine what caused the error and it will fix the error as well.  

**How to Catch Errors and Debugging in Python?**

Error catching and  debugging in Python is done using `try`-`except` blocks. `try`-`except`  blocks are used to detect and fix errors if a program makes an error  during execution.  

**How to Use Try-Except Blocks?**

Try-Except blocks are  created using the words “try” and “except”. The “try” word is the block  containing the code that may cause the program to make an error. The  “except” word is the block containing the code used to detect and  correct this error if the program makes an error.

Let's try to understand them with an example:

```python
# Catching errors with `try`-`except` block
try:
	print(10 / 0)
except ZeroDivisionError:
	print("Error: A zero division error occurred during the division operation.")

# Error fixing with `try`-`except` block
try:
	print(a)
except NameError:
	a = 10
	print(a)

                  
```

This code detects and corrects errors that occur during the program execution by using `try`-`except` blocks.

For more advanced and real-time Debugging needs, we can use the “  **pdb**  ” module.

The    “  **pdb**  ” module must be imported before you run your program. You can then stop the program from running by using the “  **pdb.set_trace()**  ”    command. When the program stops running, you can examine the status of the program while it is  running. Let's examine it with an example:

```python
import pdb

def function():
  a = 10
  b = 5
  c = a + b
  print(c)

if __name__ == "__main__":
  pdb.set_trace()
  function()

                  
```

Upon running this code,  we will see an output like the following, and then, the program will  stop running and wait for our command:

```txt
(Pdb) l

1     def function():
2         a = 10
3         b = 5
4         c = a + b
5         print(c)

(Pdb) n

(Pdb) p a

10

(Pdb) p b

5

(Pdb) p c

15

(Pdb) q

                  
```

You can advance to the next line of the program by using the “  **n**  ”    command. By using the “  **p**  ”    command, you can view the value of a variable. In this way, you can make your code healthier by  analyzing which variable takes which value at which step during the  operation of the program. Using the “  **q**  ”    command, you can close the “  **pdb**  ”    module.  

In this part of the  training, we have covered the file operations in Python, detailing what  error catching and debugging are as well as their usage examples. We  will be learning about the “  **Data Structures in Python**  ” topic in the next part of our training.

### Questions

1 - What is the function used to write data to a file in Python?

> **Answer:** write()

2 - What is the last value of  the variable "t2" in the Python script  "/root/Desktop/QuestionFiles/python4.py" on the Linux lab machine you  accessed? (After all code has been executed)

> **Answer:** 40

## Data Structures

Python offers us many  data structures that we can use within the code flow. Data structures  are used to store and manipulate data. Once we learn to use data  structures in the right place and in the right way, we can process large amounts of data with very high performance and consume fewer resources. These data structures are as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Introduction+to+Python/7/py-table.png)

### List Comprehension

List comprehension is a fast and readable way to create lists in Python. It usually combines a loop and one or more statements into a  single line. Its basic structure is as follows:

```python
[expression for item in list]
                  
```

Here, 'expression' is generally an operation related to 'item', and this 'item' represents each element.

To better understand the use of list comprehension, let's start  with an example. For example, let's say we want to square each element  of a list.

```python
numbers = [1, 2, 3, 4, 5] squares = [number**2 for number in numbers] print(squares) 

# output: [1, 4, 9, 16, 25]

                  
```

In the above example, 'number**2' squares each element, resulting in a new list of squared numbers.

List comprehensions also support conditional expressions which  we can create a new list by selecting elements that meet a certain  condition. For example, let's say we want to create a list of even  numbers of a list.

```python
numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9] 
even_numbers = [number for number in numbers if number % 2 == 0] print(even_numbers) 

# output: [2, 4, 6, 8]
                  
```

In this example, even numbers are filtered out with the  condition 'if number % 2 == 0' and a new list consisting of only these  numbers is created.

List comprehensions also support nested loops so we can return another list within a list. Let's see an example below.

```python
matrix = [[1, 2, 3], [4, 5, 6], [7, 8, 9]] 
flattened = [number for row in matrix for number in row] print(flattened) 

# output: [1, 2, 3, 4, 5, 6, 7, 8, 9]
                  
```

In this example, a 2-dimensional list (matrix) is reduced to a single dimension. Two “for” loops were used for this process.

In conclusion, list comprehension is a very powerful way to  create, transform, and manipulate lists in Python. They are short,  clear, and generally very readable. However, they can lose their  readability if they are made too complex, so it is important to use them with caution.

### Generator Expressions

Generator expressions have a structure similar to list  comprehension in Python and are generally used in the same way. However, there are important differences between generator expressions and list  comprehension.

```python
(expression for item in list)
                  
```

The expression above is an example of a generator expression. At first glance, we can see that this expression is very similar to a list comprehension. However, if we look carefully, we see that regular  parentheses are used instead of the square brackets of list  comprehension.

One of the main differences is that the generator expressions  return a generator object and the values are not calculated immediately. Instead, values are produced only when requested. This is called "lazy  evaluation" and can often significantly reduce memory usage when working with large data sets.

```python
numbers = [1, 2, 3, 4, 5]
squares = (number**2 for number in numbers)
print(squares)  

# output:  at 0x7f3d8c8a0300>
                  
```

In this example, 'squares' is a generator object. To use the  elements of this object, we usually use a “for” loop or the “next()”  function.

```python
for square in squares: 
    print(square)
                  
```

When we run this code, we take each frame one by one and print  it. However, after doing this, we cannot use the generator expression  again. Once you use its values, the generator expression gets emptied  out.

In contrast, “list” comprehension immediately computes all  values and returns a list. So when the “list” comprehension is used, we  keep all the results in memory.

Therefore, generator expressions are preferred when we work with large datasets and want to reduce memory usage if we are going to  process the dataset once or similar.  

### Dictionary Comprehension

“  Dictionary” comprehension in Python is similar to the “list”  comprehension but is used to create dictionaries. It allows us to write  an expression that will create a pair of keys and values in a single  line within a loop. Its basic structure is as follows:

```python
{key_expression: value_expression for item in iterable}
                  
```

Here 'key_expression' and 'value_expression' are generally operations related to 'item', where 'item' represents each element.

To better understand the use of the “dictionary” comprehension,  let's start with an example. For example, let's create a dictionary  containing pairs of each element of a list and their squares.

```python
numbers = [1, 2, 3, 4, 5] 
squares = {number: number**2 for number in numbers} 
print(squares) 

# output: {1: 1, 2: 4, 3: 9, 4: 16, 5: 25}
                  
```

In the example above, each element is squared with the  expression 'number: number**2' and a key-value pair is created with this number, resulting in a new dictionary of squared numbers.

Dictionary comprehensions also support conditional expressions  which helps us to create a new dictionary by selecting elements that  meet a certain condition. For example, let's say we want to create a  dictionary consisting of the even numbers of a list and the squares of  these numbers.

```python
numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9] 
even_squares = {number: number**2 for number in numbers if number % 2 == 0} 
print(even_squares) 

# output: {2: 4, 4: 16, 6: 36, 8: 64}
                  
```

In this example, even numbers are filtered with the condition  'if number % 2 == 0' and a new dictionary consisting of only these  numbers and the squares of these numbers is created.

Dictionary comprehension is a very powerful way to create,  transform, and manipulate dictionaries in Python. They are short, clear, and generally very readable. However, they can lose their readability  if they are made too complex, so it is important to use them with  caution.  

### Tuples

In Python, tuples are a data structure that stores elements of  different data types in an ordered manner. Tuples are similar to lists,  but there is one important difference: tuples are invariable which means that the contents of tuples cannot be changed once created.

To create a tuple, we separate the elements with commas and enclose them in regular parentheses. For example:

```python
my_tuple = (1, "two", 3.0) 
print(my_tuple) 

# output: (1, "two", 3.0)
                  
```

This data structure, which can hold a number of items, is useful in a variety of situations. A tuple can combine elements of different  types.

Making a tuple invariable prevents elements from being  accidentally changed. This feature is useful in cases where we need to  store constant values.

```python
my_tuple[0] = 2 

# Output:Error: 'tuple' object does not support item assignment
                  
```

Tuples can be used to store multiple values in a single  variable. For example, tuples are used when a function wants to return  multiple values.

```python
def min_max(numbers): 
    return min(numbers), max(numbers) 

numbers = [2, 3, 1, 4, 5] 
min_num, max_num = min_max(numbers) 
print(min_num, max_num) 

# output: 1 5
                  
```

In this example, the “min_max” function returns a tuple and we assign this tuple to two variables.

Tuples can also be used to quickly swap values between variables.

```python
a = 5 
b = 10 
a, b = b, a 
print(a, b) 

# output: 10 5
                  
```

In this example, we are interchanging the values of variables a  and b. This process is actually carried out with the help of tuples.

In conclusion, tuples are a very useful and powerful data  structure in Python. They play an important role in certain situations,  especially due to their unchangeable stuctures.  

### Clustors (Sets)

In Python, clustors or sets are important data structures and  have the properties of sets in mathematics. They don’t contain repeated  elements and the order of the elements does not matter. Sets are created using curly braces {} or with the set() function.

Sets are used to store a set of unique elements and also provide various set operations: union, intersection, difference, and symmetric  difference.

**Union**  : The union of two sets contains all unique elements in both sets. | It is used with the operator or union() method.

```python
set1 = {1, 2, 3} set2 = {3, 4, 5} 
print(set1 | set2) # output: {1, 2, 3, 4, 5} 
print(set1.union(set2)) 

# output: {1, 2, 3, 4, 5}
                  
```

**Intersection**  : The intersection of two sets includes elements that are in  both sets. It is used with the & operator or the intersection()  method.

```python
set1 = {1, 2, 3} set2 = {3, 4, 5} 
print(set1 & set2) # output: {3} 
print(set1.intersection(set2)) 

# output: {3}
                  
```

**Difference**  : The difference between two sets includes the elements in the  first set and not in the second set. It is used with the - operator or  the difference() method.

```python
set1 = {1, 2, 3} set2 = {3, 4, 5} 
print(set1 - set2) # output: {1, 2} 
print(set1.difference(set2)) 

# output: {1, 2}
                  
```

**Symmetric Difference**  : The symmetric difference of two sets includes only one of the  elements in both sets. It is used with the ^ operator or the  symmetric_difference() method.

```python
set1 = {1, 2, 3} set2 = {3, 4, 5} 
print(set1 ^ set2) # output: {1, 2, 4, 5} print(set1.symmetric_difference(set2)) 

# output: {1, 2, 4, 5}
                  
```

Cluster operations facilitate a number of tasks such as  combining, comparing and analyzing data. These operations are especially important in fields such as mathematical and statistical analysis, data science and machine learning.  

### Trees

In Python, a “Tree” is a structure consisting of Root and Child  nodes. In this data structure, each root refers to 2 children: Left  Child, Right Child. As we always do, let's proceed with an example and  first create a class for our tree:

```python
class Node: 
    def __init__(self, val): 
        self.left = None 
        self.right = None 
        self.val = val
                  
```

Now that our class is ready, we can start creating a tree using this class:

```python
root = Node(1) 
root.left = Node(2) 
root.right = Node(3) 
root.left.left = Node(4) 
root.left.right = Node(5)

                  
```

This code allowed us to create a tree like this:

```txt
   1 
  / \ 
 2  3 
/ \ 
4  5

                  
```

Now, we can navigate within this tree. For this, we can use ready-made algorithms that come with Python:  

**Inorder (Infix) Navigation: Left Child / Root / Right Child**

```python
def inorder_traversal(node): 
    if node: 
        # Left Child 
        inorder_traversal(node.left) 
        # Root 
        print(node.val) 
        # Right Child 
        inorder_traversal(node.right)

                  
```

**Preorder (Prefix) Navigation: Root / Left Child / Right Child**

```python
def preorder_traversal(node): 
    if node: 
        # Root 
        print(node.val) 
        # LeftChild 
        preorder_traversal(node.left) 
        # RightChild 
        preorder_traversal(node.right)

                  
```

**Postorder (Postfix) Navigation: Left node / Right node / Root**

```python
def postorder_traversal(node): 
    if node: 
        # Left Child 
        postorder_traversal(node.left) 
        # Right Child 
        postorder_traversal(node.right) 
        # Root 
        print(node.val)

                  
```

These navigation  operations are very important for processing the tree structure and  obtaining the values in the tree. Each is used according to different  situations and needs.

Trees are very useful for data organization and fast data access. Many algorithms in computer  science are based on tree data structures.

Well, you're still  wondering on "what did we solve in this structure that we couldn't do  with a ‘list’?". The first benefit of tree algorithms is to quickly  access the data we are looking for.  

For example, we have a  list containing 1,000,000,000 items and we want to find the phrase  “LetsDefend” in this list. What we need to do is compare and check each  item with LetsDefend. But in the Tree data structure, we can find what  we are looking for with much less effort by first moving forward until  we find the node starting with   **L**   , and then continuing with   **e**   in the children under   **L**  :

```txt
          A 
        /   \ 
     B        L 
    /  \     /  \
    C   L    V    E
   / \ / \  / \  / \
   D E F G  H I  J  T

                  
```

Similarly, imagine if you want to delete the "LetsDefend" statement in the number 500,000 in a  1,000,000,000 rows of data, you would have to change the line numbers of all those lines before it.  

In this part of the training, we covered data structures and their uses in Python and we will be learning about the “  **Algorithms in Python**  ” topic in the next chapter of our training.

## Algorithms in Python

Algorithms are  step-by-step instructions used to solve a problem. The postorder and  preorder we used in the Tree data structure in the previous lesson are  actually algorithms.

Algorithms are used together with data structures to ensure that programs run smoothly.

Some common algorithms used on data types in Python are:

- Array Sort  
- Array Search  
- Dictionary Search  
- Set Union  
- Set Intersection  
- Set Difference  
- Set symmetric difference  
- Graph search  
- Tree Search  

Now let's try to understand them better with examples:

Let's assume we have an array like the one below.

arr = [64, 34, 25, 12, 22, 11, 90]

Our task is to sort the values in this array from smallest to  largest. How would you do it? There is no doubt that there are different ways to do this. But when it comes to programming, the goal is often to do things as quickly as possible and with the least resource  consumption. When we tried dozens of methods mentioned above and looked  for the fastest method that would solve this problem with the least  amount of resources, we came up with the algorithm name:   **Bubble Sort.**

```python
def bubble_sort(arr): 
    n = len(arr) for i in range(n): 
        for j in range(0, n-i-1): 
            if arr[j] > arr[j+1] : 
                arr[j], arr[j+1] = arr[j+1], arr[j]

arr = [64, 34, 25, 12, 22, 11, 90] 
bubble_sort(arr) print ("Ordered Array:", arr)

# Output: Ordered Array: [11, 12, 22, 25, 34, 64, 90]

                  
```

As you can see, we compared each element to the adjacent element and swapped them if the order was wrong. This process continued until  the end of the list and repeated until the list was sorted correctly.

As mentioned above, there may be more than one  approach/way/algorithm to solve a problem. Let's solve the same problem  this time with the algorithm called   **Quick Sort**   :

```python
def partition(arr, low, high): 
    i = (low-1) 
    pivot = arr[high] 
    
    for j in range(low, high): 
        if arr[j] <= pivot: 
            i = i+1 
            arr[i], arr[j] = arr[j], arr[i] 
            arr[i+1], arr[high] = arr[high], arr[i+1] 
            return (i+1) 

def quick_sort(arr, low, high): 
    if len(arr) == 1: 
        return arr 
    if low < high: 
        pi = partition(arr, low, high) 
        quick_sort(arr, low, pi-1) 
        quick_sort(arr, pi+1, high) 


arr = [64, 34, 25, 12, 22, 11, 90] 
n = len(arr)
quick_sort(arr, 0, n-1) 
print ("Ordered Array:", arr)

# Output: Ordered Array: [11, 12, 22, 25, 34, 64, 90]

                  
```

In this method, we select the pivot element, place the elements smaller than the pivot to the  left of the pivot, and the elements bigger than the pivot to the right  (this means that the position of the pivot is fixed). Then, we sort the  subarrays on the left and right, regardless of the pivot.

As we practiced in these  examples, there is more than one solution to the problems we encounter  when writing code in Python. Although each of them leads us to a  solution, it is crucial to determine the method that best fits our  purpose and continue with this method which means more performance and  less system resource consumption for us. Therefore, when there is a  problem that you have not encountered before, researching the algorithms for solving this problem and using the appropriate parts will save you  time.  

In this part of the  training, we have covered some algorithms that can be used in Python and their uses. We will be learning about the “  **Object Oriented Programming (OOP) in Python**  ” topic in the next part of our training.

## Object Oriented Programming (OOP) in Python

Object Oriented  Programming (OOP) is an approach used in programming where the programs  are divided into independent units called objects in this approach. Each object has its own data and behavior. Objects perform the functions of  the program by interacting with each other.

Python is a language that supports OOP. In Python, objects are created using the class keyword.  After the class keyword, the name of the object and the properties and  methods of that object are specified.

For example, the following code defines a class named “Car”:

```python
class Car:
  color = ""
  make = ""
  model = ""
  year = 0

  def __init__(self, color, make, model, year):
    self.color = color
    self.make = make
    self.model = model
    self.year = year

  def drive(self):
    print("The car is driving.")

  def stop(self):
    print("The car is stopping.")

                  
```

The Car class defines four properties, color, make, model, and year. The Car class also defines two methods,   **__init__()**   and   **drive(). The __init__()**   method is called when a  “Car” object is created and is used to set the object's properties. The  drive() method allows a Car object to be driven.   **The stop()**   method causes a Car object to stop.

OOP has cons and pros. Some of the advantages of OOP are:

**Code reusability**

OOP makes code reusable.  Once a class is created, multiple objects can be created from that  class. Objects share the same codes, which prevents code rewriting.  

**Code readability**

OOP makes code more readable. Objects have their own data and behavior, making the code easier to understand. 

**Code testability**

OOP makes code more testable. Objects can be tested as independent units, making the code more reliable.  

**Code extensibility**

OOP makes code more extensible. By adding new properties and methods to objects, the code can be made more flexible.

Besides all these advantages, OOP also has some disadvantages:

**Code complexity**

OOP can make code more  complex. OOP code can be difficult to understand and maintain,  especially when it comes to large programs.

**Performance**

OOP can reduce  performance. Especially in the case of programs containing a large  number of objects, the performance of OOP code may decrease.  

**Learning curve**

OOP can be a difficult concept to learn. Learning OOP can be difficult, especially for beginners. 

We will not go into OOP  details much, but it would be appropriate to examine how to use the  three essential features of OOP with Python:

### Inheritance

This is a feature where a class inherits properties and methods from another class. For example:

```python
class Animal: 
    def __init__(self, name): 
        self.name = name 

    def speak(self): 
        raise NotImplementedError("Subclass must implement abstract method") 

class Dog(Animal): 
    def speak(self): 
        return self.name+' says Woof!' 

class Cat(Animal): 
    def speak(self): 
        return self.name+' says Meow!' 

fido = Dog('Fido') 
isis = Cat('Isis') 

print(fido.speak()) print(isis.speak())

                  
```

### Encapsulation

This is a property that holds together the state and behavior of the object and hides this state and behavior from the outside world.  Encapsulation in Python is done using private instance variables and  methods.

```python
class Computer: 

    def __init__(self): 
        self.__maxprice = 900 

    def sell(self): 
        print("Selling Price: {}".format(self.__maxprice)) 

    def setMaxPrice(self, price): 
        self.__maxprice = price 

c = Computer()
c.sell() 
# change the price 
c.__maxprice = 1000 
c.sell() 
# using setter function 
c.setMaxPrice(1000) c.sell()

                  
```

### Polymorphism

This is a property that allows an interface to be used by many  different types of objects. Polymorphism in Python allows a function or  class to operate in varying ways on different objects.

```python
class Parrot: 
    def fly(self): 
        print("Parrot can fly") 

    def swim(self): 
        print("Parrot can't swim") 

class Penguin: 
    def fly(self): 
        print("Penguin can't fly") 

    def swim(self): 
        print("Penguin can swim") 

# common interface 

def flying_test(bird): 
    bird.fly() 

#instantiate objects 

blu = Parrot() 
peggy = Penguin() 
# passing the object 
flying_test(blu) 
flying_test(peggy)

                  
```

It is very important that we understand and reinforce these  features both to write more readable codes and to reduce code  repetition.  

In this part of the  training, we have covered what Object Oriented Programming (OOP) is, its advantages, disadvantages, basic features, and usage examples.

### Questions

1 - Which code block in the  Python script "/root/Desktop/QuestionFiles/python5.py" on the Linux lab  machine you accessed creates a tree structure?

> **Answer:** 1

2 - According to the Python  script "/root/Desktop/QuestionFiles/python6.py" on the Linux lab machine you accessed, what is Michael's last age?

> **Answer:** 65













































