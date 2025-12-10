# PowerShell for Analysis

The  "PowerShell for Analysis" course is designed to equip cybersecurity  professionals with the skills to leverage PowerShell's scripting  capabilities for thorough and effective analysis of data, enabling  robust threat investigations within cybersecurity.

**Table of Contents:**

- [Analysis of Log Files with PowerShell]()
- [Windows Event Log Analysis with PowerShell]()
- [What is Web Scraping?]()
- [PowerShell and Web Scraping - 1]()
- [PowerShell and Web Scraping - 2]()

Evaluate Yourself with Quiz

- [PowerShell for Analysis](https://app.letsdefend.io/training/quiz/powershell-for-analysis)

## Analysis of Log Files with PowerShell

Powershell provides us  with very useful tools for performing security tasks. In this course, we will discuss these and examine how we can benefit from Powershell at  various stages of security.

First, let's see how we can perform research/examination on log files of different products/services using PowerShell:

PowerShell is a very useful tool for analyzing log files. You can read, search and manipulate log files using cmdlets such as   **Get-Content**   ,   **Select-String**   ,   **ConvertFrom-Json**   and   **ConvertTo-Json .**

In the next part of our training, we will work on the log file of our IIS Web server. Let's first read the content of this file:

```powershell
Get-Content -Path "C:\inetpub\logs\LogFiles\W3SVC1\u_ex230629.log"     
```

When we run this cmdlet, it will read the log file in the path we give as a parameter and print its contents to the screen.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/1/ps15.png)

What if our goal was to  list the lines containing the phrase “letsdefend” instead of the entire  file? Yes, there is a simple way to do this:

```powershell
Get-Content -Path "C:\inetpub\logs\LogFiles\W3SVC1\u_ex230629.log" | Select-String -Pattern "letsdefend"
```

When we run this command, it will print only the lines containing the phrase “letsdefend” in the entire log file:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/1/ps16.png)

When we want to monitor the changes on this file in real time, we can use the   **-Wait**   parameter. When we execute the command below,   **the Get-Content**   cmdlet first dumps the  contents of the current file to the screen and then starts waiting  instead of falling back to the command line. If new content is added to  the file (in our example, since we are examining the access logs of a  web server, if a new request comes to the server whose logs we are  examining), it adds this content to the dump on the screen.

```powershell
Get-Content -Path "C:\inetpub\logs\LogFiles\W3SVC1\u_ex230629.log" -Wait | Select-String -Pattern "letsdefend" 
```

When we combine this feature with the   **Select-String**   example we used in the  previous example, we will be able to see when a log that hits the  pattern we are looking for is written to the log file we are monitoring.

We can see this in the  screenshot below. When we first run the command, it dumps the lines  containing "letsdefend" in the relevant log file and then starts  monitoring the log file. When we send the “   **waitExample=letsdefend**   ” parameters to the web server's index file with get, the last line is added.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/1/ps17.png)

Let's write a script on the same log file that counts how many requests came from the same IP address:

```powershell
# log file location
$filePath = "C:\inetpub\logs\LogFiles\W3SVC1\u_ex230629.log"

# Get 'c-ip' (client IP) field index from log file header
$ipFieldIndex = (Get-Content -Path $filePath | Where-Object { $_ -match "^#Fields:" }).Split(' ').IndexOf('c-ip') -1

# Skip informational lines
$logContent = Get-Content -Path $filePath | Where-Object { $_ -notmatch "^#" }

$ipCount = @{}

foreach($line in $logContent) {
	$ip = $line.Split(' ')[$ipFieldIndex]
	if ($ipCount.ContainsKey($ip)) {
		$ipCount[$ip]++
	} else {
		$ipCount[$ip] = 1
	}
}

$ipCount          
```

In our script, we first  find the order of the c-ip column by reading the Fields line, which is  included as standard in IIS Log files. This way, we know which columns  in the log rows we need to read.

You can see these details in the screenshot of the log file below:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/1/ps18.png)

We then create a  hashtable ($ipCount) and add each IP address we see for the first time  to this hashtable. If an IP address already exists in the hashtable, we  increase its number by one. If it does not exist in the hashtable, we  create a new key-value pair and set its number to 1. When the script is  finished, we print the $ipCount hashtable and show how many requests  each IP address made.

Finally, let's look at our output:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/1/ps19.png)

By changing the fields in the #Fields line, we can extract their counts in the requesting URLs  instead of the source IP address, for example:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/1/ps20.png)

Now, let's work on the DHCP log file this time and use the PowerShell Object structure in this example:

Let's have a log file like below. This log file is usually found on DC Servers with the DHCP  Server role installed and keeps a record of DHCP operations.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/1/ps21.png)

The purpose of the script below is to examine this log file and record the activities of the MAC address we have given:

```powershell
$macAddress = "00-10-22-01-23-45"
$logPath = "dhcp.log"

$events = Get-Content -Path $logPath |
Where-Object { $_ -match $macAddress } |
ForEach-Object {
	$fields = $_.Split(',')
	$eventDate = [DateTime]::ParseExact($fields[1], "MM/dd/yy HH:mm:ss", $null)
	$eventType = $fields[2]
	$ipAddress = $fields[3]
	$deviceName = $fields[4]
	$mac = $fields[5]

	if ($mac -eq $macAddress) {
		New-Object -TypeName PSObject -Property @{
			EventDate = $eventDate
			EventType = $eventType
			IPAddress = $ipAddress
			DeviceName = $deviceName
			MACAddress = $mac
			}
		}
}

$events | Sort-Object -Property EventDate        
```

  Let's detail what we did in which line of this script:

```powershell
$macAddress = "00-14-22-01-23-45"          
```

  In this line, we give the mac address that we will be searching in the log file as a value to the   **$macAddress**   variable.

```powershell
$logPath = "dhcp.log"       
```

  In this line, we assign the path of the log file we will examine as a value to the   **$logPath**   variable (in this  example, since the script and the log file are in the same directory, we only need to write the name of the log file).

```powershell
$events = Get-Content -Path $logPath |
Where-Object { $_ -match $macAddress } |
ForEach-Object { …      
```

In this part, we add the  **$logPath**   variable we have just defined to   **the Get-Content**   cmdlet with   **the -Path**   parameter.    We then assign the content that reads with | to the   **Where-Object**   cmdlet with the -   **match $macAddress**   parameter.    Our goal here is to search for the value we previously defined in the   **$macAddress**   variable in the data coming from the log file.

In the next step, we assign the output that we obtained by using a second | to the   **ForEach-Object**   cmdlet. Now we have the row(s) containing the MAC addresses we specified. Now we can process this data:

```powershell
ForEach-Object {
$fields = $_.Split(',')
$eventDate = [DateTime]::ParseExact($fields[1], "MM/dd/yy HH:mm:ss", $null)
$eventType = $fields[2]
$ipAddress = $fields[3]
$deviceName = $fields[4]
$mac = $fields[5]     
```

In this part, we divide each incoming row into columns using the   **“,” character**   and    add each piece to the   **$fields**   variable as an array item.

Next, we assign the fields to variables for later use. Notice that here we have converted the data that is in the   **$fields[2]**   field as a string into   **DateTime**   type data.    We do this so that we can sort the output correctly in chronological order when printing it to the screen.

We continue by checking whether the data we are processing contains the MAC address we are looking for or not:

```powershell
if ($mac -eq $macAddress) {
	New-Object -TypeName PSObject -Property @{
		EventDate = $eventDate
		EventType = $eventType
		IPAddress = $ipAddress
		DeviceName = $deviceName
		MACAddress = $mac
		}
} 
```

If the MAC address found in the line (the value of the   **$mac**   variable)    is equal to the MAC address (  **$macAddress**  ) we defined at the beginning of the script (  **-eq**  ), we write the content of this line to a new powershell object.

```powershell
$events | Sort-Object -Property EventDate
```

In our last line, we assign the events we have (content of the $events variable) to the   **Sort-Object -Property**   cmdlet    to sort them according to the   **EventDate**   column.

And when we run our script, the result we get is as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/1/ps22.png)

While converting the data we were looking for into the powershell object data type, we said that  we did this to sort the data by date. Once we convert the data to object type, it is now very easy to use it in different ways. For example,  let's say we want to convert this data to JSON format. To do this, we  just need to deliver the data we have to the   **ConvertTo-Json**   cmdlet:

```powershell
$events | Sort-Object -Property EventDate | ConvertTo-Json
```

When we do this our output will look like this:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/1/ps23.png)

If we need different types of output, you can also use cmdlets such as   **ConvertTo-Csv, ConvertTo-Xml, ConvertTo-Html**   instead of   **ConvertTo-Json .**

If we want to write the  output we obtain in any format to a file rather than to the screen, all  we have to do is assign the output to the   **Set-Content**   cmdlet and specify which file we want to write to with the   **-Path**   parameter:

```powershell
$events | Sort-Object -Property EventDate | ConvertTo-Json | Set-Content -Path "result.json"
```

In this part of the  training, we have covered how to analyze log files with Powershell  through powershell codes. In the next part of the training, we will  learn about the "Windows EventLog Analysis with Powershell" topic.

### Questions

1 - Which cmdlet is used to read the content of a file in PowerShell?

> **Answer:** Get-Content

2 - What is the PowerShell command to search for a specific pattern in content?

> **Answer:** Select-String

3 - According to the  "C:\Users\LetsDefend\Desktop\QuestionFiles\pshell_2.ps1" PowerShell  script on the Windows lab machine you accessed, which code block is the  one that retrieves the client IP address?

> **Answer:** 2

## Windows Event Log Analysis with PowerShell

Windows Event Logs is a  feature of the Microsoft Windows operating system that logs information  about various events of operating system components and applications.  These events can include starting or stopping services, application  errors, security alerts, and more. Windows Event Logs provides system  administrators or IT professionals with the ability to understand what  is happening on a system and diagnose potential problems.

Windows Event Logs are generally divided into three main categories:

**Application logs**

These logs track errors,  warnings, and other events of Windows applications. Applications can  write information to this log about situations that require notifying  users or system administrators. 

**System logs**

These logs track the  events of operating system components. System logs may include hardware  errors, driver installations, system errors, hardware failures, and  other system-related events. 

**Security logs**

These logs record  security-related events. Security logs may include login and logout  attempts, file and object access, user and group management, security  policy changes, and other security-related events.

There are also some other event log types depending on the Windows configuration, actively set  audits, etc. in addition to these.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/2/ps24.png)

The Event Viewer tool is used to view and analyze these logs as you can see on the above screenshot of the tool.

Although the Event Viewer tool is a powerful tool, it is not a useful tool to establish  relational analysis between different events in different log titles and create reports out of those. In such cases, PowerShell offers powerful  options that allow us to work on eventlogs very flexibly and quickly.

To search Windows event logs in PowerShell, you can use   **Get-EventLog**   or the more up-to-date and more comprehensive   **Get-WinEvent**   cmdlet.

Before moving on to the examples, let's take a closer look at   **the Get-WinEvent cmdlet.**   Thanks to this powerful  tool, we can do many tasks on the command line that we can do in the  graphical interface with EventLogs Viewer.

For example, we can get a list of available log sources when we run the following command:

```powershell
Get-WinEvent -ListLog * | Select-Object LogName, RecordCount, IsClassicLog, IsEnabled, logMode, logType | Format-Table -AutoSize        
```

When you run this command, you will see output similar to the following:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/2/ps27.png)

In this output ,   **the RecordCount**   column shows how many logs are in that entry at the time we pull the list.

**The IsClassicLog** column indicates whether  this record is kept in the classic style or the new style. While logs in the classical style in Windows were kept in a   **.mc**   file, in the new style they are replaced by   **.xml**   files.

**IsEnabled** column provides information whether the system is configured to collect logs on this resource. If the column value   **is False**  , this means that the logs are not collected.

**The LogMode** column determines how the system behaves when the disk size allowed for logging is exceeded. It has three values:

- **Circular:** The oldest record is deleted and overwritten.  
- **Retain:** Stops logging until space is provided.  
- **AutoBackup:** Automatically creates and continues archives.  

**The LogType**   column determines the log category of the relevant field. Here we can see the definitions of   **Administrative**   ,   **Analytical**   ,   **Debug**   and   **Operational**  . 

Okay, now let's see how  we can list the logs in any field. With the following command, we list  the last 100 Event records in the Application Category, with columns   **TimeCreated, ID, ProviderName, LevelDisplayName, Message :**

```powershell
Get-WinEvent -LogName 'Application' -MaxEvents 100 | Select-Object TimeCreated, ID, ProviderName, LevelDisplayName, Message | Format-Table -AutoSize           
```

Our output will be as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/2/ps28.png)

Since the Get-WinEvent  cmdlet and EventLogs are not the subject of this course, let's stop here and continue examining what we can do with Powershell scripts.

Let's do an example and write a script that lists the login records of the   **LetsDefend**   user in our system. As  you know, successful logins in the Windows operating system are recorded with Event ID 4624. We can also list 4624 Event IDs related to the user we specified in the given date range:

```powershell
# Set Username
$username = "LetsDefend"
# Set start and end dates
$startDate = Get-Date "2023/01/01 00:00:00"
$endDate = Get-Date "2023/12/31 23:59:59"

# Get 4624 Events into HashTable
$events = Get-WinEvent -FilterHashTable @{
	LogName = 'Security'
	ID = 4624
	StartTime = $startDate
	EndTime = $endDate
}

# Print data to screen
foreach ($event in $events) {
	$xml = [xml]$event.ToXml()
	$eventUsername = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
	if ($eventUsername -eq $username) {
		Write-Host "User $username, Login Date: $($event.TimeCreated)"
		}
}          
```

When we run our script, we will get an output like this:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/2/ps25.png)

Now, let's take a closer look at our script:

```powershell
# Set Username
$username = "LetsDefend"
# Set start and end dates
$startDate = Get-Date "2023/01/01 00:00:00"
$endDate = Get-Date "2023/12/31 23:59:59"          
```

We have assigned the  username and the start and end dates of the search to the relevant  variables. We will use these in later parts of the script.

```powershell
# Get 4624 Events into HashTable
$events = Get-WinEvent -FilterHashTable @{
	LogName = 'Security'
	ID = 4624
	StartTime = $startDate
	EndTime = $endDate
}           
```

In this block, we  retrieve events within a specific date range and with a specific event  ID (in this case 4624; i.e. user login events) using the Get-WinEvent  cmdlet. We can filter events according to certain criteria with the  -FilterHashTable parameter of this cmdlet. Here, we capture all Security 4624 Events on the start and end dates we selected. Did you notice that we did not use the username at this stage?

```powershell
# Print data to screen
foreach ($event in $events) {
	$xml = [xml]$event.ToXml()
	$eventUsername = $xml.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'
	if ($eventUsername -eq $username) {
		Write-Host "User $username, Login Date: $($event.TimeCreated)"
	}
}              
```

And we come to our last block where we first parse the events that we have just stored in the   **$events**   variable into XML, and then, if the value of the   **TargetUserName**   field in these XML objects is   **LetsDefend,**   we print it to the screen with the   **Write-Host cmdlet.**

As we noted above, in  this example, we first pull all 4624 events and then detect the ones  with the username we are looking for. Although this usage can be used  for small log files with a small number of log records, it will cause  serious resource consumption in cases where there are too many logs. To  avoid this, we can still use the   **Get-WinEvent cmdlet**  , but the worst part is that there is no field like   **“SubjectUserName”**   directly in this cmdlet.    To do this, we can use the XPath feature, which those of you who have worked with XML before will be familiar with.

```powershell
$username = "LetsDefend"
$startDate = Get-Date "2023/01/01 00:00:00"
$endDate = Get-Date "2023/12/31 23:59:59"

$query = @"



*[System[(EventID=4624) and TimeCreated[@SystemTime>='{0}' and @SystemTime<='{1}']]]
oath
*[EventData[Data[@Name='TargetUserName'] and (Data='{2}')]]



"@ -f $startDate.ToUniversalTime().ToString("o"), $endDate.ToUniversalTime().ToString("o"), $username

$events = Get-WinEvent -FilterXml $query

foreach ($event in $events) {
	Write-Host "User $username, Login Date: $($event.TimeCreated)"
}          
```

This script directly  retrieves the login events of a specific user within a specific date  range using the XPath query. In this way, we reduce resource usage by  only receiving the events we are interested in instead of receiving  unnecessary events.

The -f operator replaces  the {0}, {1} and {2} placeholders in the string with the values of the  $startDate, $endDate and $username variables, respectively. The  ToString("o") method converts dates to ISO 8601 format because the XPath query expects dates in this format.

The output of this script will still be the same as the output of our previous script, but when  you run both of them, you will see that our second example runs much  faster and consumes much less system resources.

Yes, we can finish  eventLog analysis with Powershell here. We think that you have  understood that in order to work on this issue, you need to know the  structure and content of the event IDs you target, and recognize the  field names and values they carry.

In this part of the  training, we have covered how to perform Windows EventLog analysis with  Powershell through powershell codes. In the next part of the training,  we will learn about the “Web Scraping” topic.

### Questions

1 - To which cmdlet can you  sort the contents of an Array type variable according to the data in the EventDate column by adding the -Property EventDate parameter?

> **Answer:** Sort-Object

2 - In which EventLog folder are the “Failed Login” records store in Windows Systems?

> **Answer:** Security

3 - In the "C:\Users\LetsDefend\Desktop\QuestionFiles\pshell_3.ps1"  PowerShell script on the Windows lab machine you access, logs with Event ID 4624 are desired to be listed. Which command should be written in  the "?" section in the PowerShell script?

> **Answer:** Get-WinEvent

## What is Web Scraping?

### What is Web Scraping and Why Should We Know?

Web scraping is the  process of parsing the HTML content of a website and extracting data  from that content. Web scraping is usually done using automated software or scripts. These scripts typically do the same thing a web browser  might do: open a website, find certain information, and collect or store that information in some way.

Web scraping is very  useful and widely used in many scenarios. Its use in the security  perspective is already our topic, but it would be eye-opening to give  examples of other issues where it can be useful:

**Data Science and Machine Learning**

Most machine learning  models need data, and web scraping can be used to collect this data. For example, a person may want to analyze sentimental analysis from social  media comments and use web scraping to collect these comments.

**Market Research**

Companies and individual  researchers can use web scraping to gather information about online  products, such as prices, features, consumer reviews, and more. This can be used to track trends, analyse competitors, or perform market  analysis.

**Web Content Scraping**

A person or company may  use web scraping to gather information about a particular topic. For  example, a person can collect all recipes and put them together in a  single database.

**Data Integration**

Web scraping can also be  used to collect data from different sites and combine it in one place.  This can be used to create a news portal or a price comparison site that provides information from different sources.

Before continuing with  the topic, we should note that Web Scraping practices may cause legal  responsibilities. For example, a website's terms of use may prohibit  scraping on that site. Additionally, the use of collected data may also  be subject to various data protection and privacy laws. Therefore, when  starting a web scraping project, it is important to consider these  aspects.

In this part of the  training, we have covered what web scraping is. In the next part of the  training, in the next chapter of our training, we will about the “PowerShell and Web Scraping-1” topic.

### PowerShell and Web Scraping - 1

PowerShell offers very  powerful and useful tools for Web Scraping, thanks to the .NET power  behind it. Web Scraping generally consists of the steps of making a  request, parsing the incoming response, extracting the data we need,  standardizing and storing the extracted data. PowerShell offers tools to make our job easier for each of these steps. Let's examine these:  

### HTTP Requests

PowerShell supports HTTP requests with   **the Invoke-WebRequest**   and   **Invoke-RestMethod**   cmdlets. These cmdlets allow sending a GET or POST request to a website and processing the server's response.  

**Invoke-WebRequest**

Using the  Invoke-WebRequest cmdlet, you can create an HTTP request and receive the web server's response. This very powerful tool allows us to customize  our work with many parameters, as we are familiar with from the cmdlets  we have examined so far.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/4/w-table-1.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/4/w-table-2.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/4/w-table-3.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/4/w-table-4.png)

Now let's see how we can make the simplest web request:

```powershell
Invoke-WebRequest -Uri "https://letsdefend.io"         
```

This request was made  with the GET method because the default method is GET and we did not  specify otherwise. Below, we make our request with POST, not GET:

```powershell
Invoke-WebRequest -Uri "https://letsdefend.io" -Method 'POST'         
```

Now, let's add username and password to our request:

```powershell
$body = @{
	'username' = 'admin'
	'password' = 'p@ssw0rd'
}
Invoke-WebRequest -Uri "https://letsdefend.io" -Method 'POST' -Body $body          
```

  Finally, let's add a token to the header of our request:

```powershell
$token =”LetsDefendisGreat/andThisIsToken”
$headers = @{
	'Authorization' = 'Bearer ' + $token
}
$body = @{
	'username' = 'admin'
	'password' = 'p@ssw0rd'
}
Invoke-WebRequest -Uri "https://letsdefend.io" -Headers $headers -Method 'POST' -Body $body            
```

We made our request with Invoke-WebRequest. Now all we have to do is to process the incoming response.  

### HTML Parsing

**the Invoke-WebRequest**   cmdlet contains the HTML content of the web page, which can be accessed via   **the .Content**   or   **.ParsedHtml**   properties. These properties can be used to parse HTML content and access specific HTML tags, classes, and IDs.

The simplest way to do this is to assign our request to a variable as follows and then call the   **.Content**   property of this variable.

```powershell
$token =”LetsDefendisGreat/andThisIsToken”
$headers = @{
	'Authorization' = 'Bearer ' + $token
}
$body = @{
	'username' = 'admin'
	'password' = 'p@ssw0rd'
}
$response = Invoke-WebRequest -Uri "https://letsdefend.io" -Headers $headers -Method 'POST' -Body $body
$response.Content              
```

When we run this script,  the response from the web server at letsdefend.io will be printed on the screen, as you can see in the screenshot below. Notice that the answer  is in HTML format.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/4/ps29.png)

The simplest thing we can do to save this output to a file is to use    the   **Out-File**   cmdlet. When we change the last line of our code as follows, the output will be saved in the   **LetsDefendResponse.html**   file in the directory where our script runs:

```powershell
$token ="LetsDefendisGreat/andThisIsToken"
$headers = @{
	'Authorization' = 'Bearer ' + $token
}
$body = @{
	'username' = 'admin'
	'password' = 'p@ssw0rd'
}
$response = Invoke-WebRequest -Uri "https://letsdefend.io" -Headers $headers -Method 'POST' -Body $body
$response.Content | Out-File -FilePath "LetsDefendResponse.html"             
```

The Powershell Invoke-WebRequest cmdlet stores responses in a   **BasicHtmlWebResponseObject**   object.    We have accessed the  .Content property of this object above, but this object has other  properties as well. You can see them in the table below:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/4/pws1.png)

Now let's take a look at how to use these features. First, let's rearrange our script as follows:

$response=Invoke-WebRequest -Uri "https://google.com" -Method 'GET'

```powershell
$response=Invoke-WebRequest -Uri "https://google.com" -Method 'GET'

Write-Host "BaseResponse : " $response.BaseResponse
Write-Host "Encoding : " $response.Encoding
Write-Host "RawContentLength : " $response.RawContentLength
Write-Host "RelationLink : " $response.RelationLink
Write-Host "StatusCode : " $response.StatusCode
Write-Host "StatusDescription : " $response.StatusDescription
Write-Host "Images : " $response.Images
Write-Host "InputFields : " $response.InputFields
Write-Host "Links : " $response.Links
Write-Host "Reply Headers"
Write-Host "================================= ="
$response. Headers            
```

  And now let's look at the result:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/4/ps30.png)

As you can see in the screenshot, also BasicHtmlWebResponseObject object has fields where  it stores not only the content of the response but also the header  information of the HTTP protocol. In this way , we can check whether the page we are calling is valid or not (Code: 200 vs 404) without  processing the content at all, for example, by using the   **StatusCode**   feature. Another useful  feature is that it automatically parses the content we may need, such as Links and Images, within the page we are processing and stores them in  the   **Images, Links, InputFields**   fields.    If it wasn't doing this  for us, we would have to first take the Content, as we did in our first  example above, and then search and parse the fields within it, such as   **a**   ,   **img, input,**   etc. in our code.

On the other hand, as you can see in the screenshot, the outputs are still a bit complicated. For example, if you look at the Links output, you will see a huge block of  HTML code.

```txt
Links: @{innerHTML=Search; innerText=Search; outerHTML=Search; outerText=Search; tagName=A; id=gb_1; class=gbzt gbz0l gbp1; href=https://www.google.com.tr/webhp?tab=ww} @{innerHTML=Images; innerText=Images; outerHTML= Images; outerText=Images; tagName=A; id=gb_2; class=gbzt; href=https://www.google.com/imghp?hl=tr&tab=wi} @{innerHTML=Maps; innerText=Maps; outerHTML=Maps; outerText=Maps; tagName=A; id=gb_8; class=gbzt; href=https://maps.google.com.tr/maps?hl=tr&tab=wl} @{innerHTML=Play; innerText=Play; outerHTML=Play ; outerText=Play; tagName=A; id=gb_78; class=gbzt; href=https://play.google.com/?hl=tr&tab=w8} @{innerHTML=YouTube; innerText=YouTube; outerHTML=YouTube ; outerText=YouTube; tagName=A; id=gb_36; class=gbzt; href=https://www.youtube.com/?tab=w1} @{innerHTML=News; innerText=News; outerHTML=News ; outerText=News; tagName=A; id=gb_426; class=gbzt; href=https://news.google.com/?tab=wn} @{innerHTML=Gmail; innerText=Gmail; outerHTML=Gmail; outerText=Gmail; tagName=A; id=gb_23; class=gbzt; href=https://mail.google.com/mail/?tab=wm} @{innerHTML=Drive; innerText=Drive; outerHTML=Drive ; outerText=Drive; tagName=A; id=gb_49; class=gbzt; href=https://drive.google.com/?tab=wo} @{innerHTML=More more; innerText=More; outerHTML=More ; outerText=More; tagName=A; aria-haspopup=true; id=gbztm; class=gbgt; aria-owns=gbd; href=https://www.google.com.tr/intl/tr/about/products?tab=wh} @{innerHTML=Calendar; innerText=Calendar; outerHTML=Calendar; outerText=Calendar; tagName=A; id=gb_24; class=gbmt; href=https://calendar.google.com/calendar?tab=wc} @{innerHTML=Translation; innerText=Translation; outerHTML=Translation; outerText=Translation; tagName=A; id=gb_51; class=gbmt; href=https://translate.google.com.tr/?hl=tr&tab=wT} @{innerHTML=Books; innerText=Books; outerHTML=Books; outerText=Books; tagName=A; id=gb_10; class=gbmt; href=https://books.google.com.tr/?hl=tr&tab=wp} @{innerHTML=Shopping; innerText=Shopping; outerHTML=Shopping; outerText=Shopping; tagName=A; id=gb_6; class=gbmt; href=https://www.google.com.tr/shopping?hl=tr&source=og&tab=wf} @{innerHTML=Blogger; innerText=Blogger; outerHTML=Blogger; outerText=Blogger; tagName=A; id=gb_30; class=gbmt; href=https://www.blogger.com/?tab=wj} @{innerHTML=Finance; innerText=Finance; outerHTML=Finance; outerText=Finance; tagName=A; id=gb_27; class=gbmt; href=https://www.google.com/finance?tab=we} @{innerHTML=Photos; innerText=Photos; outerHTML=Photos; outerText=Photos; tagName=A; id=gb_31; class=gbmt; href=https://photos.google.com/?tab=wq&pageId=none} @{innerHTML=Documents; innerText=Documents; outerHTML=Documents; outerText=Documents; tagName=A; id=gb_25; class=gbmt; href=https://docs.google.com/document/?usp=docs_alc} @{innerHTML=Even more »; innerText=Even more »; outerHTML=Even more »; outerText=Even more »; tagName=A; class=gbmt; href=https://www.google.com.tr/intl/tr/about/products?tab=wh} @{innerHTML=< SPAN id=gbi4s1>Sign in; innerText=Sign in; outerHTML= Sign in; outerText=Sign in; tagName=A; onclick=gbar.logger.il(9,{l:'i'}); id=gb_70; class=gbgt; href=https://accounts.google.com/ServiceLogin?hl=tr&passive=true&continue=https://www.google.com/&ec=GAZAAQ; target=_top} @{innerHTML=; innerText=; outerHTML=; outerText=; tagName=A; aria-haspopup=true; id=gbg5; title=Options; class=gbgt; aria-owns=gbd5; href=http://www.google.com.tr/preferences?hl=tr} @{innerHTML=Search settings; innerText=Search settings; outerHTML=Search settings; outerText=Search settings; tagName=A; class=gbmt; href=/preferences?hl=tr} @{innerHTML=Web History; innerText=Web History; outerHTML=Web History; outerText=Web History; tagName=A; class=gbmt; href=http://www.google.com.tr/history/optout?hl=tr} @{innerHTML=Advanced search; innerText=Advanced search; outerHTML=Advanced search; outerText=Advanced search; tagName=A; href=/advanced_search?hl=tr&authuser=0} @{innerHTML=Advertisement; innerText=Advertisement; outerHTML=Ad; outerText=Advertisement; tagName=A; href=/intl/tr/ads/} @{innerHTML=Business Solutions; innerText=Business Solutions; outerHTML=Business Solutions; outerText=Business Solutions; tagName=A; href=http://www.google.com.tr/intl/tr/services/} @{innerHTML=About Google; innerText=About Google; outerHTML=About Google; outerText=About Google; tagName=A; href=/intl/tr/about.html} @{innerHTML=Google.com.tr; innerText=Google.com.tr; outerHTML=Google.com. tr; outerText=Google.com.tr; tagName=A; href=https://www.google.com/setprefdomain?prefdom=TR&prev=https://www.google.com.tr/&sig=K_EgsQi_VqHUnTVfTtru1YxCgPIis%3D} @{innerHTML=Privacy; innerText=Privacy; outerHTML=Privacy; outerText=Privacy; tagName=A; href=/intl/tr/policies/privacy/} @{innerHTML=Terms; innerText=Terms; outerHTML=Terms; outerText=Terms; tagName=A; href=/intl/tr/policies/terms/}    
```

In fact, most of the time, we need the link section like       ***https://play.google.com/?hl=tr&tab=w8\***    , not the entire output. In this case, we still have work to do to extract the data we need.

### Data Extraction

After parsing the HTML  content, you can extract the data you are interested in. For this  process, we usually need to find a specific tag, class or ID and read  the `innerText` or `innerHTML` properties of this element. Now let's go  back to our example above and try to remove only the parts of the Links  and Images that will be useful to us.

You see that the Links are stored in the Powershell object and this object has properties such as   **innerHTML, innerTEXT, outerHTML, outerTEXT, tagName and href**  .    We only need the value of the   **href**   property.

Similarly, for Images, it will be enough to use the   **src**   property.

```powershell
$response=Invoke-WebRequest -Uri "https://google.com" -Method 'GET'
Write-Host "---------------------------------------------- ------------------"
Write-Host "Links"
Write-Host "---------------------------------------------- ------------------"
$response.Links.href
Write-Host "---------------------------------------------- ------------------"
Write-Host "Images"
Write-Host "---------------------------------------------- ------------------"
$response.Images.src   
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/4/ps31.png)

What do we do if what we are looking for is in   **Content**  , in other words, if it is not kept in one of the special fields defined on the   **BasicHtmlWebResponseObject**   object?

In this case, what we need to do is to look for what we need in   **Content**  . In the example below, we are looking for the content of the   **span tags**   present in the Content field of the response:

```powershell
$response=Invoke-WebRequest -Uri "https://google.com" -Method 'GET'
$response -match ''
$matches         
```

When we run it, we search for span tags in the response with REGEX and write the content if we find it.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/4/ps32.png)

Is there anything that catches your attention? We did not define a variable named   **$matches**   at any stage, but we obtained the results of our search with   **$response -match**   through this variable.

This is because the   **$matches**   variable is an automatic variable. This variable automatically stores the results of   **-match**   and   **-notmatch regex**   searches that are made immediately before they are called.

Now, we are able to  access to the content of a web page such as headers, images, and links,  we can make searched within all these data and find what we want easily. Now we can move on to cleaning and storing the data.

In this part of the  training, we have covered the how to perform web scraping operations  with PowerShell. We will keep working on this topic on our next part of  the training.

### Questions

1 - What is the name of the cmdlet used to create web requests with PowerShell?

> **Answer:** Invoke-WebRequest

2 - What is the name of the feature we can use to get the list of images in the Response package?

> **Answer:** Images

## PowerShell and Web Scraping - 2

### Refining and Storaging the Data

Extracted data usually  goes through refining (for example, removing unnecessary spaces or  special characters) and storing it properly (for example, writing to a  CSV file or a database).

Let's continue with the  example, in the example in the previous lesson, we listed the Links in  the answer. Now let's parse only the FQDN parts, not all of the links,  and write the results we get to a file.

To get started, we will first need to extract the FQDNs from the URLs from the href property. So, we need to get   *the*       ***accounts.google.com section\***     from a data like       ***https://accounts.google.com/ServiceLogin?hl=tr&passive=true\***    *.*

There are many ways to do this; for example, we can do it using regex, or we can get the part between “   **https://**   ” and “   **/ ” with string functions.**

First, we will use .NET's   **Uri**   data type and then get the FQDNs by accessing the   **Host**   property of the   **Uri**   object :

```powershell
$response=Invoke-WebRequest -Uri "https://google.com" -Method 'GET'
foreach ($link in $response.links.href) {
	([System.Uri]$link).Host
}              
```

We assign the data coming from   **the Invoke-WebRequest**   cmdlet to the   **$response**   variable. Then, start a loop in which we will assign every single href value of each link in the   **$response**   variable to the   **$link**   variable.

In this loop, we turn each incoming $link value into a   **Uri**   object    with   **[System.Uri]$link**  .

A   **Uri**   Object looks like this:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/5/ps33.png)

In this list, the   **OriginalString**   property carries the URL in the $link variable, and when we cast this string to the   **Uri**   type, a HashTable is created by calculating the other fields just as we see in the screenshot above. What we need is the   **Host**   property among them.

We write this value to the screen with the following usage:

```powershell
…
([System.Uri]$link).Host
…             
```

Let's do the same example with REGEX:

This time, we first create an array named   **$links**  .    We pass each URL in the   **Links**   Hashtable in the   **$Response**   object through a REGEX pattern with the -match function and add the results to the   **$links**   array we just created. Finally, we print the contents of the   **$links**   array to the screen.

***Note:\***     *Please note that the*       ***$links\***     *we created and*       ***Links\***     *property of the*       ***$Response\***     *object are different.*

```powershell
$response=Invoke-WebRequest -Uri "https://google.com" -Method 'GET'

$links = @()

foreach ($link in $response.links.href) {
	$link -match '(?<=\/\/)[^\/]+(?=\/)'
	$links += ($matches[0])
}
$links           
```

Okay, now we can write the data we have to a file. To do this, we can convert it to a suitable format using   **ConvertTo-Csv, ConvertTo-Xml, ConvertTo-Html, ConvertTo-Json**   cmdlets that we have examined before and write the result to a file:

```powershell
$response=Invoke-WebRequest -Uri "https://google.com" -Method 'GET'

$links = @()

foreach ($link in $response.links.href) {
	$link -match '(?<=\/\/)[^\/]+(?=\/)'
	$links += ($matches[0])
}
$links | ConvertTo-Json | Set-Content -Path "links.json"             
```

In our example, we converted our output to JSON format and then saved it in the links.json file. Our result file is as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/5/ps34.png)

We wrote the data we  obtained in our example to a text file in JSON format. Depending on the  needs of your application, it is also possible to write this data to a  disk space in a remote location, send it via FTP, for example, or write  it to a database.

### Invoke-RestMethod

In today's software world, a significant part of web services operate using REST APIs.

**Invoke-RestMethod** is basically a cmdlet  that works with similar logic to Invoke-WebRequest. Its difference is  that it offers different support options that facilitate operations for  REST API Services.

The most important of  these supports is that Invoke-RestMethod automatically parses the  response. For example, it automatically converts JSON data into  PowerShell objects. Let's examine it with an example to understand  better:

```powershell
$response = Invoke-WebRequest -Uri "https://my-json-server.typicode.com/typicode/demo/comments"
$response

Write-Host "---------------------------------------------- --"
$response = Invoke-RestMethod -Uri "https://my-json-server.typicode.com/typicode/demo/comments"
$response

Write-Host "---------------------------------------------- --"
$response = Invoke-RestMethod -Uri "https://my-json-server.typicode.com/typicode/demo/comments"
$response.body          
```

In our script, we first  call the same URL with the classic Invoke-WebRequest Method. Then, we  call it with the Invoke-RestMethod cmdlet and write the entire response  object to the screen. Finally, we call the same URL with  Invoke-RestMethod and write only the “body” fields in the response to  the screen.

Our output is as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/5/ps35.png)

As you can see, we were  able to use the JSON Format response returned from a GET Request to a  REST Service as a PowerShellObject without any extra processing.

The list of parameters you can use with Invoke-RestMethod is as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/5/w2-table1.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/5/w2-table2.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/5/w2-table3.png)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Powershell-for-Analysis/5/w2-table4.png)

### Error Handling

As with any script in PowerShell, error handling is also important in web scraping scripts.  `Try/Catch` blocks can be used to catch potential errors and handle them appropriately.

We have covered this  topic in our previous powershell trainings. If you do not remember the  details, it is time to go back and repeat it to reinforce it. You can  access the relevant training from the link below:

**Error Handling:** [Optimization and Error Handling](https://app.letsdefend.io/training/lesson_detail/optimization-and-error-handling)

In this part of the training, we have covered the rest of the subject of web scraping with PowerShell.

### Questions

1 - What is the name of the cmdlet used to create Rest API requests with PowerShell?

> **Answer:** Invoke-WebRequest

2 - In the PowerShell script  "C:\Users\LetsDefend\Desktop\QuestionFiles\pshell_4.ps1" on the Windows  lab machine you accessed, what format is the output written to?

> **Answer:** json





















































