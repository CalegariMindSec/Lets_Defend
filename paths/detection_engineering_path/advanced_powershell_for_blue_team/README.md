# Advanced PowerShell for Blue Team

The  "Advanced PowerShell for Blue Team" course is designed to improve  participants' knowledge of using advanced PowerShell techniques. This  course is specifically customized to enhance cybersecurity defense  strategies for the Blue Team.

**Table of Contents:**

- [Creating Security Tools with PowerShell]()
- [Using TI Resources with PowerShell]()
- [Checking for Updates]()
- [Creating Multiplatform Scripts]()
- [Forensics and Incident Response with PowerShell - 1]()
- [Forensics and Incident Response with PowerShell - 2]()

Evaluate Yourself with Quiz

- [Advanced PowerShell for Blue Team](https://app.letsdefend.io/training/quiz/advanced-powershell-for-blue-team)

## Creating Security Tools with PowerShell

In previous powershell  tutorials, we have seen how to access Eventlogs and Log files and search for their contents. In this section, we will learn how to take these a  little further and turn them into automations.

Powershell can be used in almost every aspect of security-related processes and can produce very  effective solutions. One of the most important security-related  processes is password security. One of the biggest problems, especially  when doing scripting-related work, is that passwords are stored in clear text within scripts or on the command line. Let's create a useful  solution to this problem with Powershell in our first example:

### SecureString

You may want to save the  password to a file and read it from that file later. However, if you  store the file in plain text, anyone can read it. Therefore, we can use  PowerShell's `ConvertFrom-SecureString` and `ConvertTo-SecureString`  cmdlets to save a SecureString to a file.

The following PowerShell code creates a SecureString, encrypts it, and saves it to a file:

```powershell
$securePassword = Read-Host -Prompt "Enter your password" -AsSecureString
$securePassword | ConvertFrom-SecureString | Set-Content mysecurestring.txt     
```

When we run this script and are asked for a password,   **p@ssw0rd!!**   Let's enter its value and look at the content of the “mysecurestring.txt” file:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/advanced+powershell+for+blue+team/1/ps36.png)

Now, without having to  use a cleartext password in any file, within our script, or on the  command line, we can use our password by referring to our encrypted file when necessary:

```powershell
# Read SecureString from Saved file
$securePassword = Get-Content mysecurestring.txt | ConvertTo-SecureString

# Convert SecureString to PSCredential
$credential = New-Object System.Management.Automation.PSCredential ("username", $securePassword)

# Use Credential for web request
$webRequest = Invoke-WebRequest -Uri $url -Credential $credential   
```

In this example, we read the file using the   **Get-Content**   cmdlet and recycle the encrypted string with   **ConvertTo-SecureString**  . We then convert this   **SecureString**   into    a   **PSCredential**   object and send this object as authentication information to a web service.

Now that we know how to keep our passwords safe, we can start working on how to automate security-related tasks.  

### Track important EventIDs

Windows eventlogs are the area where almost all the records about almost everything that happens  in the operating system are kept. Therefore, monitoring here means being aware of what is happening in our operating system.

From a security  perspective, there are some activities on EventLogs that need to be  constantly and carefully monitored. Five of the most important of these  eventids can be listed as follows:  

**Event ID 4625**

This eventid is triggered when there is a failed account login attempt. This could be a sign that an attacker is trying to take over the account.  

**Event ID 4648**

This eventid indicates  that a user has performed explicit authentication (specifically for a  service or task) for another account. This may be normal, but it can  also be a sign that an attacker has taken over an account and is trying  to use it to gain more access.  

**Event ID 4703**

This eventid indicates  that a task's security settings have been changed. This could be a sign  that an attacker is trying to exploit something.  

**Event ID 1102**

This eventid indicates that a log has been deleted. This could be a sign that an attacker is trying to cover his tracks.  

**Event ID 7045**

This eventid indicates  that a new service has been installed. This could be a sign that an  attacker is trying to add a malicious service to the system.  

Now, let's write a script that scans the EventLogs for these events every hour and notifies us by e-mail if any of them are triggered:

```powershell
# SMTP Server Settings
$smtpServer = "smtp.letsdefend.io"
$smtpUser = "labuser"
$smtpPassword = "**********"

# Sender and Recipient Mail Addresses
$from = "alerter@letsdefend.io"
$to = "admin@letsdefend.io"

# Determine Start Time
$lastHour = (Get-Date).AddHours(-1)

#EventIDList
$eventIDs = @(4625, 4648, 4703, 1102, 7045)

#ControlEvents
foreach ($id in $eventIDs) {
	$events = Get-WinEvent -FilterHashtable @{Logname='Security'; ID=$id; StartTime=$lastHour}
	if ($events) {
		$subject = "Alert: Detected Event ID $id"
		$body = "Detected event ID $id on the following system: $($events[0].MachineName) at $($events[0].TimeCreated)"
				
		# Create Credential Object for SMTP
		$smtpCred = New-Object System.Management.Automation.PSCredential -ArgumentList $smtpUser, $($smtpPassword | ConvertTo-SecureString -AsPlainText -Force)
				
		# Send Email Notification
		Send-MailMessage -SmtpServer $smtpServer -From $from -To $to -Subject $subject -Body $body -Credential $smtpCred -UseSsl
	}
}     
```

This script assumes that  the SMTP server supports SSL and requires username and password for  authentication. These values should be set according to the requirements of your own SMTP server.

We just need to save this script with the name “securityTest.ps1” and add it as a Scheduled Task  to run every hour and with an account that has access to eventlogs.

Once it starts running,  it will examine the events that occurred 60 minutes before the running  time and send us an e-mail if one of the events we specified in the  $eventIDs string has occurred.

As you will notice, we  have created a tool that is likely to have a high False Positive rate in its notifications. For example, 4625 (Logon Failed) events will be  triggered even if the user accidentally enters the wrong password even  once. So, how can we do this if we set a threshold value for each event  id and ask it to send us an e-mail if a number of events occur above  this value? Let's take a look together:

```powershell
# SMTP Server Settings
$smtpServer = "smtp.letsdefend.io"
$smtpUser = "labuser"
$smtpPassword = "**********"

# Sender and Recipient Mail Addresses
$from = "alerter@letsdefend.io"
$to = "admin@letsdefend.io"

# Determine Start Time
$lastHour = (Get-Date).AddHours(-1)

# EventID and Threshold List
$eventLimits = @{4625=10; 4648=5; 4703=3; 1102=1; 7045=2}

#ControlEvents
foreach ($entry in $eventLimits.GetEnumerator()) {
	$id = $entry.Key
	$limit = $entry.Value
	$events = Get-WinEvent -FilterHashtable @{Logname='Security'; ID=$id; StartTime=$lastHour}
	if ($events.Count -gt $limit) {
		$subject = "Alert: Detected Event ID $id"
		$body = "Detected $($events.Count) instances of event ID $id on the following system: $($events[0].MachineName) at $($events[0].TimeCreated)"
				
		# Generate SMTP credentials
		$smtpCred = New-Object System.Management.Automation.PSCredential -ArgumentList $smtpUser, $($smtpPassword | ConvertTo-SecureString -AsPlainText -Force)
				
		# Send email notification
		Send-MailMessage -SmtpServer $smtpServer -From $from -To $to -Subject $subject -Body $body -Credential $smtpCred -UseSsl
	}
}     
```

There is a threshold value named   **$eventLimits**   that we set for each event id inside the   **Array**   named   **$eventLimits**

We add each   **$eventLimits**   element to the   **$entry**   variable as a key & value pair and start the loop.

In this case, our initial values will be as follows:

$id = $entry.Key (4625)

$limit = $entry.Value (10)

In the line of: 

**$events = Get-WinEvent -FilterHashtable @{Logname='Security'; ID=$id; StartTime=$lastHour}**   which is next line, we call   **the Get-WinEvent**   cmdlet with the   **-FilterHashtable**   parameter and define three filters: LogName, ID, StartTime. 

In this case, we are capturing the events that occurred in the security channel within the last hour with the EventID of 4625.

In the   **if ($events.Count -gt $limit) {**   line, we check whether the number of events is more than the limit we have set   **(-gt)**   and if this comparison is   **True**   which means the number of the events are more than the limit we have defined, we then proceed to the Email sending stage.

In this part of the  training, we have covered how to store passwords securely with  Powershell using securestring and how to monitor eventlogs automatically with Powershell. The next part of the training will be about “Using Threat Intelligence (TI) Resources with Powershell”.

### Questions

1 - What is the name of the feature that allows us to store our passwords encrypted with PowerShell?

> **Answer:** SecureString

2 - In the "pshell_5.ps1"  PowerShell script on the Windows lab machine you accessed, which code  block is the one that creates the credential object for SMTP?

> **Answer:** 6

3 - In the PowerShell script  "pshell_5.ps1" on the Windows lab machine you accessed, which code block is the one that sends the e-mail notification?

> **Answer:** 7

## Using TI Resources with PowerShell

Threat Intelligence  sources are the sources that provide intelligence information on items  such as Hash, Domain, IP Addresses. For example, by querying the HASH of an application running on our system, we can question whether this  application is a malicious application, or whether an IP address  connecting to our system has a previous record of malicious activity.

### Example 1: IP Reputation Check

Now let's have an  exercise about this. In our example, let's list the Usernames and IP  Addresses of the users who have successfully logged into our system in  the last hour and check whether there is an IP address with a malicious  record among these IP addresses:

```powershell
# Event ID 4624 indicates a successful user login attempt.
$events = Get-WinEvent -FilterHashtable @{Logname='Security';ID=4624;StartTime=(Get-Date).AddHours(-1)}

# We loop through the events we obtain
foreach ($event in $events) {
	# We get the XML version of the event
	$eventXML = [xml]$event.ToXml()

	# We get relevant information from XML.
	$ipAddress = $eventXML.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
	$userName = $eventXML.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'

	# We print the username and IP address on the screen
	Write-Output "User $userName has logged in from IP address $ipAddress"
}

                  
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/advanced+powershell+for+blue+team/2/ps37.png)

In the output, we see  that there have been 14 successful logins in the last hour, 3 of them  belong to the Administrator user, and the Administrator user logged in  from 2 different IP addresses.

Let's improve our script a bit and query the real IP addresses from a threat intelligence (TI)  source. Our criteria when querying is whether the IP address is a known  Proxy service IP address.

We should create two  functions to be able to get effective results. The first function will  query the IP address received as input in the IP Query service, and if  the IP Address belongs to a known Proxy Service, it will call the  sendMail function and transfer this information to the sendMail  function. The second function, the sendMail function, will send the  string received as a parameter to the defined address as an e-mail.

After defining our  functions, we will start our script. Just like in the previous example,  let's query the EventLogs and pull the list of Windows event ID 4624 in  the last hour.

In Windows, if the Login activity is performed locally, the phrase "   **-**   " is included in the IP Address section of the relevant event record. While we are converting the IP Address information to   **the System.Net.IPAddress**   data type in our script in order to pass it through various checks, the string in the form of "   **-**   " cannot be parsed as an IP address, which causes an error and our script does not work properly.

Also, if we don't have an IP address, we don't need to check it. Therefore, we start a   **try … catch**   block here and use the   **continue**   command in the   **catch**   part of this block, allowing the script to go to the beginning of the loop and move on to the next action in case of an error.

If there is an IP address in the query, no error will occur and our script will continue to run.  However, there is another problem waiting for us here; Local IP Address  Blocks. If you remember the TCP/IP course, we talked about class A, B,  and C blocks of IP addresses reserved for local use. If the IP address  in the Login Success record is in one of these blocks, there is no need  to query this IP address in the TI Service, because TI services keep  records for Real IP addresses.

We also implement this check for the   **if … elseif… elseif**   blocks    in our script and check whether the IP address we obtained is in the scope of one of these three blocks.

If the IP address we have is in these blocks, we continue without taking any action, but if the  IP address is not in these blocks, we send it to the IpCheck function to be queried in the TI source.

```powershell
function IpCheck($ip){

	$body = @{'fields' = 'status,proxy'}

	$ipInfo = Invoke-RestMethod -Uri "http://ip-api.com/json/$ip/" -Body $body
		
	if ($ipInfo.proxy -eq 1) {
		Write-Output "IP address $ipAddress has been marked as malicious!"
		sendMail("Logged In IP address $ipAddress has been marked as malicious!")
	} else {
			Write-Output "IP address $ipAddress has been marked as clean!"
		
	}
}


function sendMail($message) {

	$smtpServer = "smtp.letsdefend.io"
	$smtpUser = "labuser"
	$smtpPassword = "**********"

	$from = "alerter@letsdefend.io"
	$to = "admin@letsdefend.io"

	$smtpCred = New-Object System.Management.Automation.PSCredential -ArgumentList $smtpUser, $($smtpPassword | ConvertTo-SecureString -AsPlainText -Force)
			
	Send-MailMessage -SmtpServer $smtpServer -From $from -To $to -Subject $subject -Body $body -Credential $smtpCred -UseSsl
}



$events = Get-WinEvent -FilterHashtable @{Logname='Security';ID=4624;StartTime=(Get-Date).AddHours(-1)}
foreach ($event in $events) {

	$eventXML = [xml]$event.ToXml()


	$ipAddress = $eventXML.Event.EventData.Data | Where-Object {$_.Name -eq 'IpAddress'} | Select-Object -ExpandProperty '#text'
	$userName = $eventXML.Event.EventData.Data | Where-Object {$_.Name -eq 'TargetUserName'} | Select-Object -ExpandProperty '#text'


	try {
		$ipBytes = [System.Net.IPAddress]::Parse($ipAddress).GetAddressBytes()
		if ($ipBytes[0] -eq 10) {
			# This is Local Block, Do Nothing
			continue
		}
		elseif ($ipBytes[0] -eq 172 -and $ipBytes[1] -ge 16 -and $ipBytes[1] -le 31) {
			# This is Local Block, Do Nothing
			continue
		}
		elseif ($ipBytes[0] -eq 192 -and $ipBytes[1] -eq 168) {
			# This is Local Block, Do Nothing
			continue
		}
		else {
			# This is Real IP
			Write-Output "User $userName has logged in from external IP address $ipAddress"
			ipCheck ($ipAddress)
		}
	}
	catch {
		# This is Local Login Success
		continue
	}
}

                  
```

After running the script, if we detect logins from a real IP address, we will check these IP  addresses in the TI service and if the IP address belongs to a known  Proxy Service, we will notify it by e-mail.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/advanced+powershell+for+blue+team/2/ps38.png)

### Example 2: Hash Reputation Check

Let's give an example  about File Hashes. We can calculate the hashes of all files in the file  system using different algorithms. This hash information is like a  snapshot of the current state of a file, and even if a single bit  changes in the file, the hash value also changes. TI sources use this  feature to classify all the files they review. For example, when we  calculate the hash value of the “winlogon.exe” file running on your  system with the   **-Algorithm SHA256**   parameter in the   **Get-FileHash**   cmdlet , we get an output as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/advanced+powershell+for+blue+team/2/ps39.png)

When we query the hash value we obtained;       ***24263FE01C799F690318EC99688DFD2355277D7CD4618E77E7F2A3F20D9FC87C\***    *,*   on VirusTotal, a TI Service, we get the following output:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/advanced+powershell+for+blue+team/2/ps40.png)

What we see is a good  news. The VirusTotal service also reports that the hash value we  obtained hasn’t involved in any malicious activity and there is no  problem with the “winlogon.exe” we use. If our winlogon.exe had any  malicious activity recognized by VirusTotal, the hash value would be  different from what we currently get and VirusTotal would report it to  us.

Below you can see the VirusTotal result of the eicar.com file used to test Endpoint Security products:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/advanced+powershell+for+blue+team/2/ps41.png)

So, how can we utilize  Powershell on scanning the TI sources? Of course, there is a lot that  can be done on this. But to get an idea and consolidate what we've  learned, let's do an example. When this sample script is run, it  extracts the hash values of the executable files (.exe etc.) of actively running processes. So, let's check whether a malware is running on our  system using these hash values:

```powershell
# Get running process list
$processes = Get-Process

# Start Foreach loop for process list
$results = foreach ($process in $processes) {
	# Find current process path
	$filePath = $process.MainModule.FileName
		
		
	if ($filePath) {
		# Calculate Hash Value with SHA256 Algorithm
		$hash = Get-FileHash -Path $filePath -Algorithm SHA256
		# Add FileName,Path and Hash values into PSObject
		[PSCustomObject]@{
			'Process Name' = $process.Name
			'File Path' = $filePath
			'SHA256 Hash' = $hash.Hash
		}
	}
}

# Groups array by SHA256 hash value and returns only unique values
$results | Group-Object -Property 'SHA256 Hash' | ForEach-Object {
	$_.Group | Select-Object -First 1
}

                  
```

In the script above, we  first got a list of actively running processes in the system. Then, we  found each process Path in this list and calculated its hash by giving  this Path to the Get-FileHash cmdlet.

We saved the values we  found into a PSOBject instead of listing them directly. The reason why  we do this is so that we can run multiple copies of the same executable. Since this would cause unnecessary crowding and confusion, we first  accumulated the values we obtained in a PSObject and finally, using the   **Group-Object**   cmdlet, we made our output unique by taking only 1 of those with the same hash value.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/advanced+powershell+for+blue+team/2/ps42.png)

As you can see in the  output, despite all our efforts, we still have a large list and it will  take time to query them one by one. But that's what powershell is for,  right?

Let's develop our script a little more and query the hash values we obtained on Virus Total, and  if we find a malicious process, let's report it to a Slack channel:

```powershell
# Slack webhook URL and VirusTotal API key values
$slackWebhookUrl = ""
$virusTotalApiKey = ""


# Get running process list
$processes = Get-Process

# Start Foreach loop for process list
$results = foreach ($process in $processes) {
    # Find current process path
	$filePath = $process.MainModule.FileName
		
		
	if ($filePath) {
		# Calculate Hash Value with SHA256 Algorithm
		$hash = Get-FileHash -Path $filePath -Algorithm SHA256
		# Add FileName,Path and Hash values into PSObject
		[PSCustomObject]@{
			'Process Name' = $process.Name
			'File Path' = $filePath
			'SHA256 Hash' = $hash.Hash
		}
	}
}

# Groups array by SHA256 hash value and returns only unique values
$results | Group-Object -Property 'SHA256 Hash' | ForEach-Object {
	$_.Group | Select-Object -First 1
}

foreach ($result in $uniqueResults) {
	$hash = $result.'SHA256 Hash'
	# VirusTotal Hash Control
	$vtResponse = Invoke-RestMethod -Method 'Get' -Uri "https://www.virustotal.com/api/v3/files/$hash" -Headers @{"x-apikey" = $virusTotalApiKey}
	if ($vtResponse.data.attributes.last_analysis_stats.malicious -gt 0) {
		# If mailicus found, send to slack via webhook
		$slackMessage = @{
			text = "Suspicius Process Found! Process Name: $($result.'Process Name'), Executable Path: $($result.'File Path'), SHA256 Hash: $hash"
		}
		Invoke-RestMethod -Method 'Post' -Uri $slackWebhookUrl -Body (ConvertTo-Json -InputObject $slackMessage)
	}
}

                  
```

We can run this script whenever we need it, or we can run it as a scheduled task at certain periods.

In this part of the training, he have covered how to query TI resources using Powershell. We will learn about the “  **Checking for Updates with Powershell**  ” on the next chapter of our training.

### Questions

1 - What does the TI abbreviation stand for?

> **Answer:** Threat intelligence

2 - What is the name of the cmdlet we can use to calculate the hash value of a file?

> **Answer:** Get-FileHash

3 - In the "pshell_6.ps1"  PowerShell script on the Windows lab machine you accessed, which code  block is the one that gets successful login attempts?

> **Answer:** 1

4 - In which format are Event logs received in the "pshell_6.ps1" PowerShell script on the Windows lab machine you accessed?

> **Answer:** xml

5 - In the PowerShell script  "pshell_6.ps1" on the Windows lab machine you accessed, which code block prints the username and IP address to the screen?

> **Answer:** 4

## Checking for Updates

With PowerShell, we can  check if there are any updates that need to be applied on our system and report the results. You can see how we can use the Update Session  feature for this in the example below:

```powershell
$updateSession = New-Object -ComObject Microsoft.Update.Session
$updateSearcher = $updateSession.CreateUpdateSearcher()

$updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl

$searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")

if ($searchResult.Updates.Count -eq 0) {
	Write-Output "No updates to install."
} else {
	Write-Output "$($searchResult.Updates.Count) updates to install."

	$searchResult.Updates | ForEach-Object {
		Write-Output ("Title: " + $_.Title)
		Write-Output ("Description: " + $_.Description)
		Write-Output ("IsDownloaded: " + $_.IsDownloaded)
		Write-Output ("------------------")
	}
}

                  
```

When we run this script, we get the output as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/advanced+powershell+for+blue+team/3/ps43.png)

As we did it in the  examples above, we can run it periodically through a scheduled task and  ask it to notify us, for example, through the Slack channel, if there is an update that has not been installed. For this, we just need to make a small change in the script:

```powershell
# Slack webhook URL
$slackWebhookUrl = ""

$updateSession = New-Object -ComObject Microsoft.Update.Session
$updateSearcher = $updateSession.CreateUpdateSearcher()

$updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl

$searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")

if ($searchResult.Updates.Count -eq 0) {
	Write-Output "No updates to install."
} else {
	Write-Output "$($searchResult.Updates.Count) updates to install."

	$searchResult.Updates | ForEach-Object {
		Invoke-RestMethod -Method 'Post' -Uri $slackWebhookUrl -Body (ConvertTo-Json -InputObject $_.Title)
	}
}

                  
```

In this part of the  training, we have seen the basic approaches on how we can automate the  security checks on our systems using PowerShell. You can apply what you  learn here to the features and needs in your own environment.  

The next part of the tutorial will cover “  **Creating Multiplatform Scripts**  ”.

### Questions

1 - In the PowerShell script  "pshell_7.ps1" on the Windows lab machine you accessed, how many fields  of update information are printed on the screen?

> **Answer:** 2

## Creating Multiplatform Scripts

PowerShell is a command  line shell designed and developed by Microsoft to support Windows, MacOS and Linux operating systems. This specifically means that it is  possible to write a single PowerShell script and run it on different  platforms. However, you need to consider some important factors when  creating cross-platform scripts.

The most important factor that you should consider when creating cross-platform scripts, is the  architectural differences of the operating system on which your script  will run. For example, the naming of file and directory paths in the  Windows operating system is different from Linux and MacOs systems.  Also, the authorization levels required for certain tasks are different  in each operating system. For example, in Windows operating systems, you can access the list of running processes with user rights, while in  Linux systems, administrator rights may be required in some cases.

You should take these  into account in Powershell scripts when you design to run on multiple  platforms, and predict how the operations you will perform in your  script will react on which operating system. You can develop portable  scripts by adding various controls for this type of critical operations.

Let's see these important points in detail:  

### Checking PowerShell Version

The version of PowerShell affects the features and cmdlets available. While PowerShell 5.1 was  released as part of Windows, PowerShell 7 (formerly PowerShell Core) is  Microsoft's open source version that runs on a variety of platforms.  Cmdlets that perform some tasks may be named differently in different  Powershell versions. Some cmdlets may not be available in every  Powershell version. Another version-related issue is the parameters we  use in cmdlets. Some parameters may not be accepted in different  Powershell versions.

This may require ensuring that a specific PowerShell version is used, such as:

```powershell
# Check Powershell Version
if ($PSVersionTable.PSVersion.Major -lt 7) {
	Write-Output "This script requires PowerShell 7 or Greater"
	exit
}

                  
```

### Checking Platform-Specific Commands

Some PowerShell cmdlets  or features only work on a specific operating system. In this case, it  is important to check the operating system and create scripts  accordingly.

```powershell
#Check OS
if ($IsWindows) {
    # Windows specific code
} elseif ($IsLinux) {
    # Linux specific code
} elseif ($IsMacOS) {
    # macOS specific code
}

                  
```

Let's try to understand it better with an example.

In the previous sections, we wrote a script for Windows that takes the list of processes running  in the system, checks their hash values in VirusTotal, and if it finds a suspicious hash value, sends it as a notification to the Slack channel. Now let's rearrange this script to work multiplatform.

```powershell
# VirusTotal API key
$apiKey = 'YourVirusTotalApiKey'

# Check Os
if ($IsWindows) {
   # Windows Style Process List
	$processes = Get-Process | Where-Object { $_.Path } | ForEach-Object { $_.Path }
} elseif ($IsLinux -or $IsMacOS) {
    # Unix Style Process List
	$processes = bash ps -eo cmd | ForEach-Object { $_.Trim() }
} else {
	Write-Output "Unknown Operating System. Script ended."
	exit
}

foreach ($process in $processes) {
    # Get File Hash
	try {
		$hash = Get-FileHash -Algorithm SHA256 -Path $process
	} catch {
		Write-Output "An error occurred while retrieving the file hash: $_"
		continue
	}

	# VirusTotal Query
	try {
		$uri = "https://www.virustotal.com/api/v3/files/$($hash.Hash)"
		$headers = @{ 'x-apikey' = $apiKey }
		$response = Invoke-RestMethod -Method 'Get' -Uri $uri -Headers $headers

		# Check file score
			if ($response.data.attributes.last_analysis_stats.malicious -gt 0) {
			Write-Output "Suspicious file found: $process ($($hash.Hash))"
		}
	} catch {
		Write-Output "An error occurred during VirusTotal Query: $_"
	}
}

                  
```

Let's do another example. This time, let's get the list of Ports in the listening state on the system where the script runs:

```powershell
$os = $PSVersionTable.OS
$report = @()

if ($os -match 'Windows') {
    #WindowsStyle
	$connections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Listen' }
		
	foreach ($conn in $connections) {
		$process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
		$report += New-Object PSObject -Property @{
			Protocol = $conn.Protocol
			LocalAddress = $conn.LocalAddress
			LocalPort = $conn.LocalPort
			ProcessName = $process.Name
		}
	}
} elseif ($os -match 'Linux' -or $os -match 'Darwin') {
    # UnixStyle
	$connections = bash -c "sudo netstat -plnt" | Where-Object { $_ -match 'LISTEN' }
		
	foreach ($conn in $connections) {
		if ($conn -match '\s*(\S+)\s+\S+\s+(\S+):(\S+)\s+\S+\s+\S+\s+(\S+).+') {
			$report += New-Object PSObject -Property @{
				Protocol = $Matches[1]
				LocalAddress = $Matches[2]
				LocalPort = $Matches[3]
				ProcessName = ($Matches[4] -split '/')[1]
			}
		}
	}
} else {
	Write-Error "This script is designed to run on Windows, Linux and MacOS."
}

$report | Format-Table

                  
```

As you can see from the  examples, the key to writing error-free portable scripts is to master  the commands in the operating systems where our script is likely to run, and to proceed by checking them within the script when necessary.  

### File Path and Separators

Different operating  systems may differ in file path delimiters and file structure.  PowerShell offers some features for cross-platform compatibility in this regard. For example, the   **Join-Path**   cmdlet allows you to use the correct file path separator across different platforms.

```powershell
$filePath = Join-Path -Path $env:USERPROFILE -ChildPath 'Documents\file.txt'

                  
```

The   **Join-Path**   cmdlet is very useful  when creating cross-platform scripts because it understands your  operating system's file path format. That means it avoids cross-platform incompatibilities, especially those you might encounter when manually  merging file paths.

For example, in Linux the file path separator character is “  **/**  ”, while in Windows it is “  **\**  ”. The   **Join-Path**   cmdlet uses the correct separator character depending on the operating system it is running on.

Let's start with a simple example. Let's say you need to generate the full path to a particular  file. We know that this file is on the “C:” drive, in the “users”  folder, in the “Admin” subfolder, and the name of the file is  “document.txt”.

```powershell
$drive = "C:"
$folder = "Users\Admin"
$file = "document.txt"

$path = Join-Path -Path (Join-Path -Path $drive -ChildPath $folder) -ChildPath $file

                  
```

This script sets the `$path` variable to `C:\Users\Admin\document.txt`.

The   **Join-Path**   cmdlet is often used in  conjunction with other PowerShell cmdlets that operate on file paths, as well as creating complex file path hierarchies. These cmdlets include   **Get-Content**  ,   **Set-Content`**  ,   **Copy-Item**  ,   **Remove-Item**   and many more. When you  work with these cmdlets using `Join-Path`, you can create file paths in a neater and less error-prone manner.

Let’s make a more specific exercise and understand the use and importance of   **Join-Path**   in detail. In Linux,  Windows and MacOS operating systems, the hierarchy of users' Home  directories on the disk is different. However, by using   **Join-Path**  , we can read the  content.txt file in the Home directory of the user running the script,  regardless of the system on which our script runs, without being  affected by these changes:

```powershell
# Get User Home Path
$homeDirectory = Resolve-Path ~

# Find content.txt under Documents
$filePath = Join-Path -Path (Join-Path -Path $homeDirectory -ChildPath "Documents") -ChildPath "content.txt"

# Read content.txt under Documents
$content = Get-Content -Path $filePath

# Print content.txt under Documents
$content

                  
```

### Conclusion

Powershell is a scripting language with different versions that can run on different operating  systems. However, in order to use the ability to work on these different platforms, we need to know how to make checks such as the Operating  System and Powershell version, as well as the commands and features  specific to the operating system on which our script will run. If we  know about all these details and differences we should better be able to create scripts that are capable of running multiple platforms. We wish  you all trouble-free scripts.  

In this part of the  training, we have covered creating multi platform PowerShell scripts to  run on different operating systems. In the next part of the training, we will learn about the "  **Forensic Analysis and Incident Response with Powershell-1**  " topic.

### Questions

1 - Which automatic variable does provide us with the Powershell version?

> **Answer:** $PSVersionTable

2 - What is the PowerShell cmdlet suitable to create platform-independent Paths?

> **Answer:** Join-PATH

## Forensics and Incident Response with PowerShell - 1

Computer forensic  analysis is the process of collecting and evaluating digital evidence.  This process is often used to identify illegal activities or policy  violations. PowerShell is a powerful tool for forensic analysis on  Windows-based systems. In this lesson, we will see some techniques and  tools you can use to understand PowerShell's forensic analysis  capabilities and apply them to your own forensic analysis processes.  What you should not forget is that although the Forensic Analysis  process has best practices, each digital forensic incident has different dynamics.

For this reason, in this course we will try to examine the methods and tools that can be used in almost every case as possible.  

### EventLog Analysis

Forensic analysis usually begins with examining system logs. Windows Event Log is an important  source of information that can be accessed with PowerShell's  Get-WinEvent cmdlet. For example, we can filter events by a specific  Event ID to find suspicious user activity:

```powershell
Get-WinEvent -FilterHashTable @{LogName='Security'; ID=4625}

                  
```

PowerShell can also be  used to analyze files and folders. The Get-ChildItem cmdlet is used to  list the files in a folder, and these files can be routed to the  pipeline to act on them. For example, we can find files with a specific  file extension:

```powershell
Get-ChildItem -Path C:\ -Include *.exe -Recurse -ErrorAction SilentlyContinue

                  
Get-ChildItem -Path C:\ -Include *.locked -Recurse -ErrorAction SilentlyContinue

                  
```

### File system analysis

Identifying files  created/modified within a certain date range during forensic analysis is a very important step, and powershell offers us capable tools in this  regard:

```powershell
$StartDate = Get-Date -Year 2023 -Month 6 -Day 1 -Hour 8 -Minute 0 -Second 0
$EndDate = Get-Date -Year 2023 -Month 6 -Day 30 -Hour 17 -Minute 0 -Second 0

Get-ChildItem -Path C:\ -Recurse |
Where-Object {$_.CreationTime -gt $StartDate -and $_.CreationTime -lt $EndDate} |
Select-Object FullName, CreationTime

                  
```

With the above script, we can get a list of files created within the date and time range we provide.  

### System Information

Forensic analysis  requires collecting detailed information about the target system. This  may include operating system version, network configuration, running  processes and services, installed programs and more. PowerShell can be  used to collect much of this information. For example, we can use the   **Get-ComputerInfo**   cmdlet to collect system information:

```powershell
Get-ComputerInfo

                  
```

The   **Get-ComputerInfo**   cmdlet provides very detailed information about the system, as you can see in the screenshot below:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/advanced+powershell+for+blue+team/5/ps44.png)

The last time the system  was rebooted is an important information for Forensic Analysis. Because  we have a higher chance of obtaining findings about the attacker and his activities in a system that has not been rebooted after the attack. We  can find out the last reboot time of the system with the following  command:

```powershell
[System.Management.ManagementDateTimeconverter]::ToDateTime((Get-WmiObject -Class Win32_OperatingSystem).LastBootUpTime)

                  
```

### Running Applications and Services

PowerShell offers a  variety of cmdlets to support memory analysis. For example, the  Get-Process cmdlet returns information about all running processes.  However, more advanced memory analysis will require third-party tools.  But as for what to analyze, we can easily get the list of running  processes and services with powershell.

```powershell
Get-Process

                  
Get-Service

                  
```

Additionally, PowerShell  can integrate with tools that can perform more complex operations such  as memory dumping and analysis. For example, SysInternals and Debugging  Tools for Windows tools such as "procdump" and "WinDbg" can be operated  using PowerShell scripts.

However, memory analysis  often requires more complex tools and techniques. For example, memory  analysis tools such as Volatility can perform various analyses on a  given memory dump file. Such tools can analyze running processes, open  files, network connections, installed drivers, services, registry  information and many other details. However, these are typically  accomplished through separate tools other than PowerShell.  

### Users

Another important issue  is the users who are actively logged into the system at the time of the  review. We can get the list of them with the following command:

```powershell
Invoke-Expression -Command 'query user'

                  
```

The output of this command will be as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/advanced+powershell+for+blue+team/5/ps45.png)

For the forensic analysis process, how a user is logged has critical importance. In order to get  information about how the relevant user is logged, we need to find the  last log record of this user with EventID 4624 in EventLogs and check  the Logon Type Value there. Let's write the script that will achieve  this purpose together:

```powershell
Invoke-Expression -Command 'query user'

$LoggedUsers = (Invoke-Expression -Command 'query user') -replace '^>', '' | ForEach-Object {
	if ($_ -match '(?\S+)\s+console') {
		$Matches['username']
	}
}

$LoggedUsers | ForEach-Object {
	$username = $_

	$logEvents = Get-WinEvent -FilterHashtable @{Logname='Security'; ID=4624} |
	ForEach-Object {
		$xml = [xml]$_.ToXml()

		if (($xmlEventUsername = $xml.Event.EventData.Data | ? { $_.Name -eq 'TargetUserName' } | % { $_.'#text' }) -eq $username) {
			[PSCustomObject]@{
				Username = $username
				LogonType = $xml.Event.EventData.Data | ? { $_.Name -eq 'LogonType' } | % { $_.'#text' }
			}
		}
	}

	$logEvents | Select-Object -Last 1
}

                  
```

In our script, we first  get a list of active users. Then, by taking the usernames in the  USERNAME section of this list one by one, we find the last 4624 events  of these usernames in the EventLogs, and finally, we extract the Logon  Type data from this record.

What we need to know when interpreting this data is Windows' logon types. For example, 2 means  interactive (console) login, 3 means network login, 10 means remote  desktop login.

Now our output is as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/advanced+powershell+for+blue+team/5/ps46.png)

### LSASS Accesses

On Windows systems, LSASS (Local Security Authority Subsystem Service) memory dump is often  associated with malicious activities aimed at extracting credentials  from memory. A good starting point is usually to check system logs and  running processes to determine if LSASS has memory dumped.

In Windows, when a  process memory dump is taken, an event is raised with Event ID 1000  (Application Error). So, the first step may be to control such events.  This can be done using PowerShell as follows:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Application';ID=1000}

                  
```

This output will probably have a high False Positive ratio because many application errors are  logged with this event ID. Therefore, you may need to filter the results further.

### WMI Activities

Windows Management  Instrumentation (WMI) is often used to retrieve system information,  perform actions on processes and services, and even run code. Malicious  actors can abuse these capabilities, which is why WMI incidents are  often scrutinized when responding to a cybersecurity incident.

Windows' WMI event logs  contain many different types of events, but generally the most  interesting are the events recorded when a new process is created via  WMI activity, or when a service is stopped or started via WMI activity.  The PowerShell `Get-WinEvent` cmdlet can be used to examine the WMI  event log:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'}

                  
```

Use of this command  returns the 'Microsoft-Windows-WMI-Activity/Operational' log. However,  this log can often be very large and contain large amounts of  information, so it is often a good idea to filter the results further.  For example, you can only search for events with a specific EventID or  events within a specific time period.

Additionally, processes created via WMI typically use the   **Create method of the Win32_Process**   WMI class . This is  typically recorded in an event log when a transaction is created. To  look for such events, you can use a command to filter events in the WMI  event log and return only events containing   **Win32_Process**   and   **Create**  .

Finally, many malicious  WMI activities are associated with a specific process, such as  PowerShell or cmd.exe. Therefore, it is often useful to look for WMI  events involving such operations. However, this type of search can often return a large number of false positives because these processes are  often used for legitimate activities as well.

As a result, reviewing  WMI event logs is often useful when responding to a cybersecurity  incident. However, this type of analysis must often be combined with a  number of other forensic analysis techniques.

When scanning WMI events  with PowerShell, we can focus on some of the most common and most abused event IDs. For example, 5861 and 5859 are typically triggered when a  WMI activity type is started and completed.

The following PowerShell code snippet can be used to detect suspicious WMI events:

```powershell
# Event IDs
$suspiciousEventIDs = 5861, 5859

#GetEvents
$events = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-WMI-Activity/Operational'; ID=$suspiciousEventIDs} -ErrorAction SilentlyContinue

#CreateLoop
foreach ($event in $events)
{
	# Set format to XML
	$xml = [xml]$event.ToXml()

		# If event found…
	if ($xml.Event.EventData.Data -contains 'Win32_Process' -or $xml.Event.EventData.Data -contains 'Create')
	{
		Write-Output ("Time: " + $event.TimeCreated)
		Write-Output ("Event ID: " + $event.Id)
		Write-Output ("Description: " + $event.Message)
		Write-Output ("--------------------------------------------- ----")
	}
}

                  
```

This scripts pulls events from   **the Microsoft-Windows-WMI-Activity/Operational log**   with specific event IDs (here; 5861 and 5859). Of these events, those involving   **Win32_Process**   or   **Create**   are considered potentially malicious events and are displayed.

This script identifies  suspicious events by translating each event into an XML object and then  looking at specific data in the XML. XML allows you to examine the  content of an event in more detail.

There is no guarantee  that this snippet will detect all suspicious WMI activity from all logs  of any system. Instead, it can be used as a starting point to identify  the most common types of suspicious activity. Specifically, it looks for events containing the terms   **Win32_Process**   and   **Create**  .    This is typically  triggered when a new process is created via a WMI event. However, this  search may miss other potentially suspicious WMI activity. Therefore,  this code snippet should be used as a starting point and customized to  the specific situation or threat model.

In this part of the  training, we have covered how to conduct forensic analysis processes  with PowerShell and made some practical exercises. In the next part of  the training, we will continue on the "  **Forensic Analysis and Incident Response with Powershell**  ".

### Questions

1 - What is the name of the cmdlet that allows us to search event logs?

> **Answer:** Get-WinEvent

2 - What is the name of the cmdlet used to list a specific path and subsequent files and directories?

> **Answer:** Get-ChildItem

3 - In which EventLog directory are WMI Activities stored? (Microsoft-Windows-WMI-Activity/………..)

> **Answer:** Operational

4 - Which cmdlet is used to get the list of available services?

> **Answer:** Get-Service

## Forensics and Incident Response with PowerShell - 2

### Applications

Another important  information about forensic analysis is the applications installed in the system and their details. We can access these with WMI via Powershell.  What we need is to pay attention to here is that some applications may  not appear in the "Installed Apps" list due to the way how they are  installed. So it's important to do a second check by looking at the  “Uninstall Registry” section in the Registry:

```powershell
Get-WmiObject -Query "Select * from Win32_Product" | Select-Object -Property Name,Vendor,Version

                  
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate

                  
```

The output of these two commands will be similar to the following:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/advanced+powershell+for+blue+team/6/ps47.png)

Another important issue  when performing forensic analysis is the status of updates on the  system. It would be helpful to get a list of installed updates.

```powershell
Get-HotFix | Format-Table -AutoSize

                  
```

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/advanced+powershell+for+blue+team/6/pws4.png)

When it comes to forensic analysis, the list of uninstalled updates is as important as the  installed update packages. Because this list will give us very valuable  information about which vulnerability the attacker may have exploited.

With Powershell, we can  check if there are any unapplied updates on our system and report the  results. You can see how we can use the Update Session feature for this  in the example below:

```powershell
$updateSession = New-Object -ComObject Microsoft.Update.Session
$updateSearcher = $updateSession.CreateUpdateSearcher()

$updatesToDownload = New-Object -ComObject Microsoft.Update.UpdateColl

$searchResult = $updateSearcher.Search("IsInstalled=0 and Type='Software'")

if ($searchResult.Updates.Count -eq 0) {
	Write-Output "No updates to install."
} else {
	Write-Output "$($searchResult.Updates.Count) updates to install."

	$searchResult.Updates | ForEach-Object {
	Write-Output ("Title: " + $_.Title)
	Write-Output ("Description: " + $_.Description)
	Write-Output ("IsDownloaded: " + $_.IsDownloaded)
	Write-Output ("------------------")
	}
}

                  
```

When we run this script, we get output as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/advanced+powershell+for+blue+team/6/ps43.png)

### Automatically Running Applications

There are many ways to  enable some applications to run automatically at system startup in the  Windows operating system, and attackers often use these ways to gain  persistence in the system. The following script outputs a list of  executable applications programmed for this type of autorun in areas  that we can control with powershell:

```powershell
# Startup Items
Get-CimInstance -Class Win32_StartupCommand
# Startup Folder
Get-ChildItem -Path "$env:USERPROFILE\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
#Services
Get-Service | Where-Object {$_.StartType -eq 'Automatic'}
#Drivers
Get-WmiObject Win32_SystemDriver | Where-Object {$_.StartMode -eq 'Auto'}
# Registry
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce'
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce'

# Scheduled Tasks
Get-ScheduledTask | Where-Object {$_.Settings.StartWhenAvailable -eq $true -and $_.State -ne "Disabled"}

                  
```

When we run the script we get a list similar to the following:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/advanced+powershell+for+blue+team/6/ps48.png)

We should bear in mind  that the areas that attackers can use to gain persistence in the Windows operating system are not limited to these and it is not possible to  control all of them with PowerShell. There is enough content in this  list to start with, but in cases where we need to deepen the  investigation, you may need to include tools that allow more detailed  analysis, such as the Autoruns tool from SysInternals tools.  

### Conclusion

As we mentioned at the  beginning, each event has its own unique structure and therefore each  event may contain different inputs and outputs specific to that event.  Powershell is a powerful tool that will benefit us in this process. For  example, we can combine what we did above and more into a script like  the one below and quickly create an archive as we start examining:

```powershell
# Analyze-System.ps1

# Download and Prepare procdump
# Note: EndPoint protection tools may consider procdump.exe as malicious.
# So you may need to define exception
Invoke-WebRequest -Uri "https://download.sysinternals.com/files/Procdump.zip" -OutFile ".\Procdump.zip"

Expand-Archive -Path ".\Procdump.zip" -DestinationPath ".\Procdump"


my money(
[DateTime]$StartTime = (Get-Date).AddDays(-1),
[DateTime]$EndTime = (Get-Date)
)

# Prepare export folder
$hostname = $env:COMPUTERNAME
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$outputPath = ".\$($hostname)_$($timestamp)_analyze"
New-Item -ItemType Directory -Force -Path $outputPath | Out-Null

# Function to export data to CSV
function ExportToCSV($data, $fileName) {
$data | Export-Csv -Path (Join-Path -Path $outputPath -ChildPath "$fileName.csv") -NoTypeInformation
}

# Get event logs
$eventLogs = Get-WinEvent -FilterHashTable @{LogName='Application'; StartTime=$StartTime; EndTime=$EndTime}
$eventLogs += Get-WinEvent -FilterHashTable @{LogName='System'; StartTime=$StartTime; EndTime=$EndTime}
$eventLogs += Get-WinEvent -FilterHashTable @{LogName='Security'; StartTime=$StartTime; EndTime=$EndTime}
ExportToCSV -data $eventLogs -fileName "EventLogs"

# Get LSASS memory dump
# Note: This requires procdump.exe to be available on the system, and the script to be run as administrator
& .\procdump\procdump.exe -ma lsass.exe lsass.dmp
Move-Item -Path .\lsass.dmp -Destination $outputPath

# Get active process hashes
# Note: This requires Sysinternals suite to be available on the system
$processes = Get-Process

# Start Foreach loop for process list
foreach ($process in $processes) {

    # Find current process path
$filePath = $process.MainModule.FileName
if ($filePath) {
	$hashes= {Get-FileHash $filePath}
}
}

ExportToCSV -data $hashes -fileName "ProcessHashes"


# Get DLL and EXE hashes
$files = Get-ChildItem -Path C:\Windows, C:\Windows\System32 -Include *.dll, *.exe -Recurse -ErrorAction SilentlyContinue
$hashes = $files | ForEach-Object {Get-FileHash $_.FullName}
ExportToCSV -data $hashes -fileName "FileHashes"

# Get directory metadata
$directories = Get-ChildItem -Path C:\Windows, C:\Windows\System32 -Recurse -Directory -ErrorAction SilentlyContinue
ExportToCSV -data $directories -fileName "DirectoryMetadata"

# Get listening ports and applications
$ports = Get-NetTCPConnection | Where-Object {$_.State -eq 'Listen'}
ExportToCSV -data $ports -fileName "ListeningPorts"

# Get logged in users and login types
# Note: This requires the 'logon' module to be available on the system
$loggedInUsers = Get-LoggedOnUser | Where-Object {($_.LogonTime -ge $StartTime) -and ($_.LogonTime -le $EndTime)}
ExportToCSV -data $loggedInUsers -fileName "LoggedInUsers"

# Get installed applications
$installedApps = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*
ExportToCSV -data $installedApps -fileName "InstalledApps"

# Get installed updates
$installedUpdates = Get-Hotfix
ExportToCSV -data $installedUpdates -fileName "InstalledUpdates"

# Get pending updates
# Note: This requires the 'PSWindowsUpdate' module to be available on the system
$pendingUpdates = Get-WUList
ExportToCSV -data $pendingUpdates -fileName "PendingUpdates"

# Get auto-start applications
$autoStartApps = Get-CimInstance -Class Win32_StartupCommand
ExportToCSV -data $autoStartApps -fileName "AutoStartApps"

# Get computer info
$computerInfo = Get-ComputerInfo
ExportToCSV -data $computerInfo -fileName "ComputerInfo"

# Compress output folder
Compress-Archive -Path $outputPath -DestinationPath "$outputPath.zip"

# Delete output folder
Remove-Item -Path $outputPath -Recurse -Force

                  
```

When our script runs, it  first creates a directory with the name of the system it is running on  and date and time information, saves the collected information in the  form of files in this directory, and it compresses the folder in zip  format, and deletes it upon completion. You can move the resulting zip  file to any environment you want and continue your analysis there.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/advanced+powershell+for+blue+team/6/ps49.png)

As you can guess, all the scripts we use in this course, including this script, are not scripts  that we recommend you use directly in the production environment, our  aim is only to give an idea about what can be done.

We hope that by the end of this training series, you will be able to incorporate powershell into your skillset.  

In this part of the  training, we have covered the forensic analysis processes with  PowerShell and made some practical exercises to consolidate what we have learned.

### Questions

1 - Which command is used to access WMI objects with PowerShell?

> **Answer:** Get-WmiObject



















































































