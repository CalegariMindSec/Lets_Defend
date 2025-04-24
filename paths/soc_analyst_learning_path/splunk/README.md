# Splunk

Use Splunk as a SOC member and be comfortable to search data.

**Table of content:**

- Introduction to Splunk

- Splunk Installation on Windows
- Splunk Installation on Linux
- Splunk Universal Forwarders
- Add Data to Splunk
- Search on Splunk
- Splunk Reports
- Alerts on Splunk
- Dashboards
- Splunk Health Status Check
- User Management on Splunk

## Introduction to Splunk

What is Splunk?

Splunk is the data platform that powers enterprise observability,  unified security, and limitless custom applications in hybrid  environments. Splunk is one of the most popular security solutions in  the cybersecurity industry. This is why we'll show you how this product  works.

### Requirements

### Sizing

To help you define your Splunk Server's sizing, you can use Splunk Sizing on [this website.](https://splunk-sizing.soclib.net/)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/sizing1.png)

### System Requirements

The official documentation gives you the system requirements for Splunk Enterprise on-premises here: [ Splunk Requirements](https://docs.splunk.com/Documentation/Splunk/9.0.1/Installation/Systemrequirements)

### Ports

Don't forget to open ports on your firewall. The default ports needed are:

-9997 for forwarders to the Splunk indexer
 -8000 for clients to the Splunk Search page
 -8089 for splunkd (also used by deployment server)

If needed more check this: [Splunk Common Network Ports v2.0.3](http://downloads.jordan2000.com/splunk/Splunk-Common-Network-Ports-v2.0.3.png)

NOTE: After 60 days you can convert to a perpetual free license

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/licence.png)

This course was produced by Julien Garcia. You can find his social media accounts below.

[LinkedIn](https://www.linkedin.com/in/jgarcia-cybersec?miniProfileUrn=urn%3Ali%3Afs_miniProfile%3AACoAAAm8kPsBMOkUKt0Gf5YN4EFjqsUutwLlGD0&lipi=urn%3Ali%3Apage%3Ad_flagship3_search_srp_all%3BLtbfvD1MTimA%2B0PeSDH24Q%3D%3D) [Twitter](https://twitter.com/geekmunity_FR)

### Questions

1 - How many days do you have for the free trial? 

> **Answer:** 60

## Splunk Installation on Windows

For the training, we are gonna install Splunk on a Windows Server 2022 virtual machine.

1- Go to the [Splunk Site](https://www.splunk.com/en_us/download/splunk-enterprise.html?locale=en_us)
2- Create an account
3- Download the MSI installer

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/Install1.png)

4- Read the Licence Agreement I know, this seems useless and no one  will do it, but YOU need to read it and understand it. It will contain  all your enterprise information. You need to know what will be done with your data"

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/Install2.png)

5- Accept the Licence Agreement For the training, we going to customize options, so press "Customize  Options" even if we don’t change the default configurations.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/install3.png)

6- Select where you want to install Splunk
 7- Install Splunk as a local System
 8- Set the credentials

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/install4.png)

9- Launch this install and wait
10-Check the Splunk Installation
After the job is done, try to connect to: https://127.0.0.1:8000

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/Install5.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/install6.png)

Congratulation, you have installed Splunk!

### Supervision

If you go to services.msc you will find a "Splunkd Service" which has a startup type "automatic" and it must be in running status. You can  monitor this service and status to check your Splunk state.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/service1.png)

### Questions

1 - What's the service **display name** for Splunk on Windows?

> **Answer:** Splunkd Service

## Splunk Installation on Linux

For this part, we will use an Ubuntu 22.04 Desktop computer. It will work  with other distributions and a server one, but since I used the VM for  other things it will be easier.

### Installation via GUI

1- Go to the Splunk Site
2- Create an account
3- Download the .deb file

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/linux1.png)

4- Go to your Downloads folder

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/linux2.png)

5- Right Click on it > Open with Other Applications > Software Install

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/linux3.png)

Click on the "Install" button and wait.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/linux4.png)

Then it will install successfully.

### Installation via CLI

1-Go to the Splunk Site
2-Create an account
3-When you try to download it, check the upper right corner

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/linux_cli1.png)

4-Click on "Command Linux Wget", it will give you the command you need to download it.
5-For this section, I will use the tgz format

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/linux_cli2.png)

6-Open your terminal
7-Go to your installation folder (/opt for me)
8-Paste the command given a few steps ago
9-Add "sudo" if needed

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/linux_cli3.png)

10-Go to root user
11-Extract it with this command:

> tar xvzf splunk-9.0.1-82c987350fde-Linux-x86_64.tgz

12-Launch it: /opt/splunk/bin/splunk start --accept-license
13-Answer the questions

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/linux_cli4.png)

14-Try to connect to the link given

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/linux_cli5.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/linux5.png)

15-Check The Splunk Installation

By default, Splunk on Linux doesn't run at the system startup. To make it start, run this command in root: 

> /opt/splunk/bin/splunk enable boot-start

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/linux_cli6.png)

Restart and check the status: 

> /opt/splunk/bin/splunk status



![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/linux_cli7.png)

If you look at the output, Splunk started successfully.

### Questions

1 - Which command to check the Splunk status on Linux?

Answer Format: /x/x/x/x status

Note: You must answer according to this lesson's installation instructions.

> **Answer:** /opt/splunk/bin/splunk status

2 - Does Splunk start on Linux startup by default?

Answer Format: Y/N

> **Answer:** N

## Splunk Universal Forwarders

For the training, we are going to install the universal forwarder in the  default configuration. Our goal is to send Windows logs to Splunk.

\- Go to the Windows computer
\- Download the [setup file](https://www.splunk.com/en_us/download/universal-forwarder.html)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/install7.png)

\- Read the Splunk General Terms - Download the MD5

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/install8.png)

\- Open the md5 file to have the checksum: at this time is: 83a09c64537832701320609e665e3e7 
\- Check your MD5  with this PowerShell command "Get-FileHash  .\splunkforwarder-9.0.0.1-9e907cedecb1-x64-release.msi -Algorithm md5"  to confirm you've got the right installer.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/install9.png)

Launch the setup
Read the Licence Agreement

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/install10.png)

Accept the Licence Agreement
Select "an on-premises Splunk Enterprise instance" because we have to install Splunk on an on-premise server.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/install11.png)

Once again, we use the default configuration. Maybe in your company,  you will use a service account to run the Universal Forwarder. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/install12.png)

\- Give a username to Universal Forwarder.
\- Give the server IP or Hostname and the port to the receiving indexer. I use the IP because I have no DNS in my lab. We don't have to change any configuration during Splunk installation so the port used is 9997

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/install13.png)

Why do we give IP in receiving indexer and not in the deployment  server? Because we don't have a Deployment server. A deployment server  is a server that can send a configuration for your universal forwarder.

\- Launch the install

### Check Universal Forwarder for Windows Installation

\- Go to services.msc
\- Check if "SplunkForwarder Service" is up.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/install14.png)

\- Check if communication is open with Powershell command: "Test-NetConnection -Computername Splunk_IP -port 9997"

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/install15.png)

Congratulation, you have installed Splunk!

### Check on Splunk

\- Go to your Splunk Server
\- Go to Settings > Forwarder management

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/forwarder1.png)

You must see your Windows Computer on this page.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/forwarder2.png)

If you don't see your computer after a few minutes, try to restart  the Splunk Universal Forwarder service, and check if the connection  between client and server is okay.

## Add Data to Splunk

In Splunk, you can add data in different ways. Here we are going to see  the forwarder installed on the Win10 computer and with the upload of a  log file.

### Add Data from Forwarder

\- Go to Settings >Add Data

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/forwarder3.png)

\- Select "Forward" at the bottom

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/forwarder4.png)

Add the computer to the selected host and give it a Server Class Name

Click "Next"

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/data1.png)

Select what you want to monitor, in this case, we want to collect the local event log from this computer.

Select which log you want

Click "Next"

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/data2.png)

Select the index where the logs need to be put.

I choose to create a new one named "WinLog_clients". For this, click on "create a new Index"

Click Review to check and then submit.

Now, you can click "start searching" to try to find your last connection on the client's computer.

### Check Your Indexes

Go to Settings > Indexes

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/indexes1.png)

Search the index you create previously

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/indexes2.png)

As you see there is no incoming event, you are going to configure it now. 

### Add Receiver

Go to Setting > Forwarding and receiving

Click to add new receiving

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/receive2.png)

Add the 9997 port (it's the default one, remember it in the previous document)

Wait a few minutes and check your indexes again, you will see new values

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/indexes3.png)

Try a quick search 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/search1.png)

### Add Data From Uploaded Logs

Go to Settings > Add Data

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/forwarder3.png)

Select "Upload" in the bottom left corner

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/upload1.png)

Push the file you want to upload, then click "Next"

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/upload2.png)

Check how Splunk will read your file, then press Next if everything is okay

Select a host field value if needed, and the index which is going to be used (left default in the exercise)

Continue to the end, and start searching on it

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/upload3.png)

## Search on Splunk

Let's take a tour on the Search page. As you see, there is a lot of information to learn, let's try to clarify them.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/search_all.png)

### Traps and Tips

\- Field names are case sensitive

\- Field values are not case sensitive

\- The wildcard is available (use *)

\- You can use operators such as AND, OR, NOT

### Date Selection

The first thing to do is to select the data range.  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/date1.png)

From here you can choose:

\- Presets (today, last week, last year, last 24 hours, etc.)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/date2.png)

\- Relative (beginning of the hour, X minutes ago, X weeks ago, etc.)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/date3.png)

\- Real-time

\- Date range (between 00:00 DD/MM/YYYY and 24:00 DD/MM/YYYY)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/date4.png)

\- Date & time range (same but you can choose an hour)

### Timeline

When you perform a search, Splunk displays a Timeline

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/timeline1.png)

### Search Mode

There are three modes, you will use mostly the Smart Mode.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/mode1.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/mode2.png)

### Search Bar

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/searchbar1.png)

This is where you make your request. As we said previously, you can use  the wildcard character ("*") and operators. You can mix it all!

\- Search for a username with "Je" on it. Try "Username=Je*" You will find username like Jeanne, Jean, etc.

\- Search for connection on the computer named computer1. Try "eventid=4624 AND computername=computer1"

\- Search for every connection on the computer except the domain controller. Try "eventid=4624 NOT computername=domaincontroller"

\- Remember to use "Search History"

### Fields

Fields are available on the left. Here you have each field available in your search.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/field1.png)

Select the field to have information about it.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/field2.png)

### Save As

In this menu, you can choose to save your request as a report, alert, or dashboard.

### Questions

**NOTE:** In order to answer the questions below, you must have  uploaded the "tutorialdata.zip" data found in the previous topic to  Splunk. All questions cover data whose Source is "tutorialdata.zip"  only.

1 - How many different client IPs are there requesting the "/productscreen.html" path?

> **Answer:** 65

2 - What is the path where the client IP address "128.241.220.82" sends the most web requests?

> **Answer:** /cart.do

## Splunk Reports

### What is a Report?

Basically, reports are saved search results. Reports can be scheduled or can be executed when needed.

### Exercise

For this part, we are going to use a simple request to find connections failed with account that contain admin. Our request is: *source="WinEventLog:\*" index="winlog_clients" EventCode=4625 AND Nom_du_compte=Admin*

Maybe you need to change the "Nom_du_compte" to "accountname".

\- Try your request in the search bar 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/report1.png)

\- Goes to the Save As menu and select 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/report2.png)

\- Give a title and a description of your report 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/report3.png)

\- Save and go to View 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/report4.png)

### Edit or Delete an Existing Report

\- From the Search App, go to the Reports sections  

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/report5.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/report6.png)

Here you can find all existing reports.

\- Select the report created a few minutes ago. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/report7.png)

\- From here you can see information about your report.

\- Select the Edit button 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/report8.png)

### Exercise

We are going to schedule this report for every day at 08 AM to have the connections fail yesterday.

\- Select "Edit Schedule"

\- Check "Schedule Report"

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/schedule1.png)

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/schedule2.png)

\- Configure it. 

In this exercise, you don't use trigger actions, but I invited you to  check what you can do when your report is generated (like sending an  email, launching a script, etc.)

\- Save and review the information in your report. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/schedule3.png)

### Questions

1 - Can you send an email when a report is generated? 

Answer Format: Y/N

> **Answer:** Y

## Alerts on Splunk

### What is an Alert?

Alerts are saved searches that trigger when certain conditions are  met. They can be scheduled or in real-time. In that case, be careful not to overload your Splunk server.

### Exercise

Use the same request as in the report section and save it as an alert. 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/alert1.png)

As you see, you have more information to display than a simple  report. You will need to select the type of alert (scheduled or in  real-time), when it must be run (if you have more than 35 connections  failed for example), and the action.

## Dashboards

A dashboard is nothing more than a dashboard. Here you can find a lot of  information you need. You can make one for analysts, and one for your customers, with  different types of information. If you use always the same requests and  always need the same information, then making a Dashboard is a good  idea.

### Exercise

Use the same command as previously used and save it as a New  Dashboard called "SOC L1". Because it's for all people in SOC, you must  share it.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/dash1.png)

Here we have only one panel, but you can add other panels to this dashboard

## Splunk Health Status Check

When you're connected to Splunk, click near the Administrator menu.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/status2.png)

On the left control panel, you have the status of each part of Splunk Server. On the right control panel, you have the description of each  signal.

## User Management on Splunk

### Roles

By default Splunk give you some roles, to find or create a new role, go to Settings > Roles

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/role1.png) 

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/role2.png) 

From here you can edit or add a new role. A role can give you  permission on the Splunk server, Splunk request, on which events you can see or which events you can not see, etc.

### Users

When you install it, Splunk gives you only one user, which is admin. A good practice is to create another administrator account and use admin  only in emergency cases. Thus, if you see an admin connection you can  see there is a problem.

To find the users list and create a new one, go to Settings > Users.

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/user1.png) 

Every user must have a role.

### Password Management

When you install Splunk, they only ask for an 8 character password,  no matter the complexity. You can modify it on Settings > Password  Management

![img](https://ld-images-2.s3.us-east-2.amazonaws.com/Splunk/images/pwdman.png) 

### Questions

1 - How many users do we have on our Splunk?

> **Answer:** 1

2 - How many roles do we have on our Splunk?

> **Answer:** 5