# Advanced SOAR

The  "Advanced SOAR" course is designed to further develop and expand  Security Orchestration, Automation, and Response (SOAR) skills,  providing in-depth insights into sophisticated strategies, tools, and  techniques to optimize security operations and incident response.

Table of Contents

- [SOAR & SIEM Integration](#soar--siem-integration)
- [Alerts, Case, and Management](#alerts-case-and-management)
- [Creating a Playbook](#creating-a-playbook)
- [Alert Management](#alert-management)
- [Automation in SOAR](#automation-in-soar)

Evaluate Yourself with Quiz

- [Advanced SOAR](https://app.letsdefend.io/training/quiz/advanced-soar)

## SOAR & SIEM Integration

In TheHive training, we learned how to prepare a working SOAR product. Next is to bring the logs to SOAR.

SOAR products can collect logs from many sources. For example, you can send the logs of a  firewall device to your SOAR product, or you can send the logs of your  Email Gateway product to SOAR. But the main purpose of the SOAR product  is not to collect logs, but to provide automation by analyzing logs from various sources and establishing relationships between them. For this  reason, logs are generally collected in a SIEM product, that is, log  collection, normalization and semantics are solved on SIEM, and the logs processed in SIEM are sent to SOAR. We will follow this path in this  lesson.

You must have installed a Wazuh in the SIEM course. (If you haven't taken that course yet, we  recommend you take a break here and finish that course.)

The way each SOAR product works is different. Again, the integration of SOAR with each product is different, and this issue is essentially the responsibility of the  relevant people we explained under the title "Human Resources for SOAR"  in the SOAR Fundamentals training. However, in this study, we will  integrate Wazuh and TheHive together. What we need to know here is that  these integrations are generally PULL (where the SOAR Product asks the  product it is integrated with, "Is there anything new?" via API Call,  etc.), or PUSH (where the product to be integrated asks SOAR, "I have a  new thing?" via API Call, etc.). "There is something".) It happens with  one of the methods.

Wazuh and TheHive  communicate with the PUSH method. So Wazuh sends information to TheHive  API. For this, Wazuh needs an API Key. Generating this API Key is quite  easy.

After clicking on the “Organization” (1) link in the upper  right corner of the menu, we will see the screen where we added the  user, which we will remember from the last stage of the installation: 

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/1/soar39.png)

**+Create New User**   button in the upper left corner, we add a user as follows. (Make sure the user's profile is org admin.)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/1/soar40.png)

Next is to create an API Key for our new user. (We will not create a password for this user.)

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/1/soar41.png)

You will need to copy the API key you see above to a safe place, because Wazuh will use this API  key and we will need this key when configuring Wazuh.

Now let's move on to the  Wazuh side. We will need to make a few adjustments to your Wazuh  machine. For this, you need to initiate a console access on your Wazuh  machine.

The first thing we need  to do is add the TheHive4Py Python library that will allow Wazuh to  communicate with TheHive. To do this, simply run the command below:

```sh
sudo /var/ossec/framework/python/bin/pip3 install thehive4py==1.8.1            
```

If everything is OK, you should see output similar to the following:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/1/soar42.png)

Now it's time to put the integration scripts in place. First, a file like   **/var/ossec/integrations/custom-w2thive.py**   is created:

```sh
touch /var/ossec/integrations/custom-w2thive.py             
```

and the following script is added into it:

```python
#!/var/ossec/framework/python/bin/python3
import json
import sys
import os
import re
import logging
import uuid
from thehive4py.api import TheHiveApi
from thehive4py.models import Alert, AlertArtifact

#start user config

# Global vars

#threshold for wazuh rules level
lvl_threshold=0
#threshold for suricata rules level
suricata_lvl_threshold=3

debug_enabled = False
#info about created alert
info_enabled = True

#end user config

# Set paths
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
log_file = '{0}/logs/integrations.log'.format(pwd)
logger = logging.getLogger(__name__)
#set logging level
logger.setLevel(logging.WARNING)
if info_enabled:
    logger.setLevel(logging.INFO)
if debug_enabled:
    logger.setLevel(logging.DEBUG)
# create the logging file handler
fh = logging.FileHandler(log_file)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
logger.addHandler(fh)



def main(args):
    logger.debug('#start main')
    logger.debug('#get alert file location')
    alert_file_location = args[1]
    logger.debug('#get TheHive url')
    thive = args[3]
    logger.debug('#get TheHive api key')
    thive_api_key = args[2]
    thive_api = TheHiveApi(thive, thive_api_key, cert=False )
    logger.debug('#open alert file')
    w_alert = json.load(open(alert_file_location))
    logger.debug('#alert data')
    logger.debug(str(w_alert))
    logger.debug('#gen json to dot-key-text')
    alt = pr(w_alert,'',[])
    logger.debug('#formatting description')
    format_alt = md_format(alt)
    logger.debug('#search artifacts')
    artifacts_dict = artifact_detect(format_alt)
    alert = generate_alert(format_alt, artifacts_dict, w_alert)
    logger.debug('#threshold filtering')
    if w_alert['rule']['groups']==['ids','suricata']:
        #checking the existence of the data.alert.severity field
        if 'data' in w_alert.keys():
            if 'alert' in w_alert['data']:
                #checking the level of the source event
                if int(w_alert['data']['alert']['severity'])<=suricata_lvl_threshold:
                    send_alert(alert, thive_api)
    elif int(w_alert['rule']['level'])>=lvl_threshold:
        #if the event is different from suricata AND suricata-event-type: alert check lvl_threshold
        send_alert(alert, thive_api)


def pr(data,prefix, alt):
    for key,value in data.items():
        if hasattr(value,'keys'):
            pr(value,prefix+'.'+str(key),alt=alt)
        else:
            alt.append((prefix+'.'+str(key)+'|||'+str(value)))
    return alt



def md_format(alt,format_alt=''):
    md_title_dict = {}
    #sorted with first key
    for now in alt:
        now = now[1:]
        #fix first key last symbol
        dot = now.split('|||')[0].find('.')
        if dot==-1:
            md_title_dict[now.split('|||')[0]] =[now]
        else:
            if now[0:dot] in md_title_dict.keys():
                (md_title_dict[now[0:dot]]).append(now)
            else:
                md_title_dict[now[0:dot]]=[now]
    for now in md_title_dict.keys():
        format_alt+='### '+now.capitalize()+'\n'+'| key | val |\n| ------ | ------ |\n'
        for let in md_title_dict[now]:
            key,val = let.split('|||')[0],let.split('|||')[1]
            format_alt+='| **' + key + '** | ' + val + ' |\n'
    return format_alt


def artifact_detect(format_alt):
    artifacts_dict = {}
    artifacts_dict['ip'] = re.findall(r'\d+\.\d+\.\d+\.\d+',format_alt)
    artifacts_dict['url'] =  re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+',format_alt)
    artifacts_dict['domain'] = []
    for now in artifacts_dict['url']: artifacts_dict['domain'].append(now.split('//')[1].split('/')[0])
    return artifacts_dict


def generate_alert(format_alt, artifacts_dict,w_alert):
    #generate alert sourceRef
    sourceRef = str(uuid.uuid4())[0:6]
    artifacts = []
    if 'agent' in w_alert.keys():
        if 'ip' not in w_alert['agent'].keys():
            w_alert['agent']['ip']='no agent ip'
    else:
        w_alert['agent'] = {'id':'no agent id', 'name':'no agent name'}

    for key,value in artifacts_dict.items():
        for val in value:
            artifacts.append(AlertArtifact(dataType=key, data=val))
    alert = Alert(title=w_alert['rule']['description'],
              tlp=2,
              tags=['wazuh', 
              'rule='+w_alert['rule']['id'], 
              'agent_name='+w_alert['agent']['name'],
              'agent_id='+w_alert['agent']['id'],
              'agent_ip='+w_alert['agent']['ip'],],
              description=format_alt ,
              type='wazuh_alert',
              source='wazuh',
              sourceRef=sourceRef,
              artifacts=artifacts,)
    return alert




def send_alert(alert, thive_api):
    response = thive_api.create_alert(alert)
    if response.status_code == 201:
        logger.info('Create TheHive alert: '+ str(response.json()['id']))
    else:
        logger.error('Error create TheHive alert: {}/{}'.format(response.status_code, response.text))



if __name__ == "__main__":

    try:
       logger.debug('debug mode') # if debug enabled       
       # Main function
       main(sys.argv)

    except Exception:
       logger.exception('EGOR')      
```

Then,   **the custom-w2thive**   file is created in the   **/var/ossec/integrations**   directory :

```sh
touch /var/ossec/integrations/custom-w2thive        
```

And the following script is added into it:

```bash
#!/bin/sh
# Copyright (C) 2015-2020, Wazuh Inc.
# Created by Wazuh, Inc. .
# This program is free software; you can redistribute it and/or modify it under the terms of GP>

WPYTHON_BIN="framework/python/bin/python3"

SCRIPT_PATH_NAME="$0"

DIR_NAME="$(cd $(dirname ${SCRIPT_PATH_NAME}); pwd -P)"
SCRIPT_NAME="$(basename ${SCRIPT_PATH_NAME})"

case ${DIR_NAME} in
    */active-response/bin | */wodles*)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/../..; pwd)"
        fi

    PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
    */bin)
    if [ -z "${WAZUH_PATH}" ]; then
        WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
    fi

    PYTHON_SCRIPT="${WAZUH_PATH}/framework/scripts/${SCRIPT_NAME}.py"
    ;;
     */integrations)
        if [ -z "${WAZUH_PATH}" ]; then
            WAZUH_PATH="$(cd ${DIR_NAME}/..; pwd)"
        fi

    PYTHON_SCRIPT="${DIR_NAME}/${SCRIPT_NAME}.py"
    ;;
esac


${WAZUH_PATH}/${WPYTHON_BIN} ${PYTHON_SCRIPT} $@     
```

Now, we need to set the permissions and ownership of these newly added files:

```sh
sudo chmod 755 /var/ossec/integrations/custom-w2thive.py
sudo chmod 755 /var/ossec/integrations/custom-w2thive
sudo chown root:wazuh /var/ossec/integrations/custom-w2thive.py
sudo chown root:wazuh /var/ossec/integrations/custom-w2thive       
```

Our next step is to make  some adjustments to Wazuh's config file. To do this, open the  “/var/ossec/etc/ossec.conf” file with a text editor and add the  following lines to a suitable place in the config file, between the  <ossec_config> and </ossec_config> tags:

  <integration>

​    <name>custom-w2thive</name>

​    <hook_url>  **https://TheHive_Server_IP**  </hook_url>

​    <api_key>  **TheHive apiKey**  </api_key>

​    <alert_format>json</alert_format>

  </integration>

When adding, do not  forget to place the IP address of your TheHive Server and the API Key we created for the API User in TheHive in the correct places.

The sample screenshot below will help you:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/1/soar43.png)

After saving and closing this change, we will need to restart the Wazuh Service for the changes to take effect:

```sh
sudo systemctl restart wazuh-manager            
```

If we did everything right, our first alerts should be starting to appear in TheHive:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/1/soar45.png)

Now that we have alerts on SOAR, we can now look at how to manage them.  

In this part of the  training, how SOAR & SIEM integration can be done is mentioned. In  the next part of the training, the topic “Alerts, Case and Management” is explained.

### Questions

1 - What is the name given to  the method by which the SOAR product receives data by making API calls  to the product it is integrated with?

> **Answer:** PULL

2 - What is the name given to the method by which other security products send data to TheHive API via POST?

> **Answer:** PUSH

## Alerts, Case, and Management

Now that we have alarms, we need to manage them. Before moving on to management, let's see how to review alarms:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/2/soar46.png)

When we log in to TheHive with a user account, we are greeted by   **the Alerts**   screen. When we are anywhere in the application, we can go to this screen by clicking on   **the Alerts**   link in the area indicated by   **(1) .**   The number in parentheses next to the Alerts link indicates how many unprocessed alerts there are.  

Field   **(2)**   is an area where we can filter the alarms in the alarm list below.  

**(3)**   is where we can see  summary information about the alarm. Here we see the Title/Description  given to the relevant alarm in the Log source (SIEM in our example), the tags defined by the Integration module, the severity value defined by  the integration module, and whether the alarm has been processed or not. The tag and severity values in this section are calculated by the  following section in our integration script above:

```txt
    tlp=2,
    tags=['wazuh', 
    'rule='+w_alert['rule']['id'], 
    'agent_name='+w_alert['agent']['name'],
    'agent_id='+w_alert['agent']['id'],
    'agent_ip='+w_alert['agent']['ip'],],
    description=format_alt ,
    type='wazuh_alert',
    source='wazuh',
    sourceRef=sourceRef,
    artifacts=artifacts,)


                  
```

What catches your  attention here is that the integration script sends 2 as the tlp value.  For this reason, the alarm is classified as Medium Level by TheHive. In a real scenario, it would be a correct approach in terms of best practice to differentiate and send the TLP value according to the severity value of the alarm in the log source.  

**(4)**   will be filled with the  number of this Case by TheHive if the alarm is turned into a case, and  since we have not done anything at the moment, it is waiting as "None".  You must have noticed that we sent the type and source values in the  same field by the integration script. By using these fields correctly,  it is possible to design a very useful structure to classify, prioritize and process alarms on TheHive.

In field   **(5) , we see the dates Created (C), Opened (O), Updated (U).**   Among these dates, "C"  will give the date of arrival of the alarm to SOAR, "O" will give the  date it was opened by the analyst, and "U" will give the date of the  last transaction.

**(6)**   perform the following functions:

- **Preview & Import:** Allows the analyst to see the details of the alarm. This is the part where the analyst will raise the alarm to Case if he deems it necessary. We will talk about the  details of this in a moment.
- **Ignore new updates:** This option is the option we will use in cases where we no longer want similar alarms to be processed.
- **Mark as Read:** This is the option we will use for alarms that we will not take any action on for any reason and want to mark as read/seen.
- **Run Responder:** This option is where we  interact with Cortex. It ensures that the responders related to the  artifacts present in the alarm are run in the background and the outputs are processed into the alarm detail. We will discuss this issue in more detail when explaining the subject of Responders.

TheHive has a flexible  case structure. We can decide what to turn into a case. For alarms that  are once converted into cases, we can determine case templates and run  the cases through these templates.  

At this point, TheHive  leaves the operation to you. For example, you can define Case Templates  (PlayBook) according to the severity of the alarms and determine that  the incoming alarms will be processed by the relevant Case Templates  according to their severity.

Or you can determine Case Templates according to alarm sources (Linux Audit, Windows Audit, Linux System, Windows System, etc.) and associate incoming alarms with these  templates.

Or, you can run Case Templates according to the Mitre Att&ck Framework Technical/Tactical numbers in the alarms.

Or, you can create Case Templates according to the event type (EndPoint Attack, Phishing Attack, SQL Injection Attack, etc.).

It is up to you to  increase these options. What we need to understand here is that TheHive  does not interfere with the operation here, and you have to decide what  to do and how to do it.

In this part of the  training, it is mentioned how an alert should be examined and managed.  In the next part of the training, the subject of “Creating a Playbook” is explained.

### Questions

1 - What is the name given to the log that has been sent to TheHive by automation but has not yet been read by the analyst?

> **Answer:** Alert

## Creating a Playbook

You must be an orgAdmin  to create a Case Template with default settings. If you have “orgAdmin”  authority, you can create, delete and edit Case Templates for the tenant to which this authority is assigned.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/3/soar47.png)

First, we click   **Organizations (1)**, then Case Templates (2) , and then   **+New Template (3)**   . The following screen will greet us:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/3/soar48.png)

First we need to give a  name to our Case template. Then we need to determine the Display Name.  There is no harm in keeping the Display Name and Template Name the same,   **Display Name**   is the name that will be displayed in the places where we will call our template within the application.

**The Title Prefix** Section is a useful area where you can add an identifier before the Alarm Title. How you use it is entirely up to your planning.

You can make the default settings for this Case Template in   **the Severity**   ,   **TLP**   and   **PAP sections.**   The analyst can change these later.

**the Tags** section, you can define tags that may be useful when searching/reporting/filtering within the product.

Now that the basic definitions of our template are finished, we can move on to   **the Tasks**   section. This will be the heart of our template. In this section, where we will operate the  Playbook logic, we will define the tasks we want to be executed after  this template is selected. You can check out the example below.

You saw that we did not  make any selection in the Assignee section. The reason for this is that  we expect the Analyst to operate the relevant Task, which converts it  into a Case. If we had Assigned to any user, as soon as we imported the  Alarm into Case, the relevant task would be automatically assigned to  the user we selected and the user would receive a notification about it.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/3/soar49.png)

In the example, something must have caught your attention. We asked the user to fill in the  relevant custom field. However, when we go to   **the Custom Fields tab, there is no Custom Field**   we can add there yet .  

Let's fix this. First, let's save our Template in its current form by clicking   **the Save Template button**   in the lower right corner . Now, we will need to log out of TheHive and log in with the admin account.(admin@thehive.local)  

After logging in, we click on the Admin Link in the upper right corner, and from the PullDown that opens, click on the “Case Custom Fields”** link:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/3/soar50.png)

On the screen that opens, we will define our   **Custom Field**   . First we give it a  name. Then we give a brief definition. We chose string from the Field  Type options. Therefore, a field was opened where we could enter  possible options, and we entered the possible options. We also checked  the “Is Mandatory” option because we do not want the analyst to close  the alarm without filling in this field. We saved the change by clicking   **Save Field**   and finished our work.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/3/soar51.png)

Now, after logging out  from the admin account and logging in with our orgAdmin account, we can  go to Case Templates and click on the edit button of our Case Template.  What we need to do next is to click on   **the Custom Fields**   tab, first click on the   **+Custom Field**   button, and then select the Field we just created from the list and save the change by clicking "Save Template".

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/3/soar52.png)

In this part of the  training, the process of creating a playbook is mentioned. In the next  part of the training, the subject of “Alarm Management” is explained.

### Questions

1 - What are the extra fields added to Case Templates in TheHive when needed?

> **Answer:** Custom Field

## Alert Management

In our previous lesson,  we learned how to create a playbook. Now that we have a playbook, we can go to the Alerts menu, select an alarm and turn it into a case. To do  this, we start by going to the Alarm list and clicking on the icon we  indicate with   **(1)**   on the left in the relevant alarm line :

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/4/soar52.png)

In the window that opens, we will be able to see all the details of the alarm. When we scroll  down the page and reach the end, we will see the import option in the  lower right corner. We need to select the Template we just created from  the list next to the button and click “Yes, Import”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/4/soar53.png)

TheHive will automatically convert the Alert into a case and go to the case screen to display our Case.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/4/soar54.png)

**(1)**   , there are tasks that must be completed before this Case is closed.

**(2)**   , there is a list of  Observables objects extracted from the alarm. These are also important  because they are objects we can send to responders.

**(3)**   , we see the view in the Case of the Custom Field that we just created and added to the Case Template.

In area   **(4) , there are actions we can take.**   We can share the case,  close it, flag it, or delete it. Of course, the necessary conditions  must be met for some of these actions.  

if you select   **Close**   at this stage , you will receive a warning like this:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/4/soar55.png)

In this case, what we  need to do is go to the Tasks tab and run the relevant task. When we go  to the Tasks tab and press the play button of the relevant task, we will be greeted with a screen like the following:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/4/soar56.png)

On this screen, you can  add notes/records for the relevant task and also add documents to the  task. When the Task is completed, all we need to do is click on the  Task's Close button.

We only had one task in  this Case Template. If there was more than one Task, we would need to  close those tasks in order to close the Case. Now, when we want to close the case, we will see a screen like the following:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/4/soar57.png)

On this screen, we need to determine the evaluation result of the alarm.

Next, we need to add our  notes about the actions taken and finally make a selection in the  UserConfirmation Field, which is the CustomField we added before.

After completing all these, we can click on the   **"Close case"**   button and set sail for new adventures.  

In this part of the training, how to manage an alarm on SOAR is mentioned. The next part of the training covers the topic “Automation in SOAR”.

## Automation in SOAR

### Analyzers & Responders

We mentioned that all  SOAR products have advanced integration capabilities and thus make  things easier. All manufacturers may give different names to their  automation capabilities. On TheHive side, these capabilities are called  “Analyzers & Responders” and TheHive uses Cortex for its integration capabilities.

So what exactly does  Cortex do? So far, we have talked about Responders and Observables when  converting the alarm to Case. TheHive can automatically classify the  artifacts it detects (observes) from incoming alarms. It can divide them into types such as IP Address, hostname, FQDN, URL, Hash. Then, it can  send them to Cortex's responders and let Cortex process them.

Let's make it a little  more concrete: TheHive receives a "Multiple SSH Logon Fail" alarm. Let  1.23.4.5 be present as the source IP address in this alarm. TheHive  sends this information to Cortex and can collect information about the  IP Address through the Responders we set and write it into the alarm.  That is, we can go to the analyst's place and collect information such  as geolocation and reputation of the IP address.

So how does he do this?

As you may remember,  during the installation, we created an organization for ourselves on  Cortex, and then we created a user with   **Read, Write, orgAdmin privileges for this organization (in our example**   , the user named   **letsdefend ). Now it is time to go to Cortex and log in with this user.**   After logging in, we click on the   **Organizations link**   in area   **(1)**   :

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/5/soar70.png)

**the Analyzers** tab (1) from the screen that  opens . In the incoming list, we see that a total of 217 Analyzers are  waiting for us, ready to work. We will use the analyzer for Abuse IP.  Now we can click on the   **+Enable button**   in field   **(2)**   .

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/5/soar71.png)

In the popup that opens,  there are parameters that we can set to use AbuseIPDB Analyzer. Among  these, the mandatory ones are indicated with (   *****   ). Since the Key value is indicated by   *****   , we will need an AbuseIPDB API Key.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/5/soar72.png)

To get the AbuseIPDB API Key, we first log in to our Abuse IP Account. Then we click on   **the API (1)**   tab and click   **Create Key (2)**   . It asks us to give a  name to our key, and when we do that, our key is ready. Now we can paste this key into the field in Cortex.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/5/soar73.png)

We set the Max TLP and Max PAP values   **to None , set the Rate Limit to 1000/Day, then save and exit.**   If everything is OK, it should look like this:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/5/soar74.png)

Yes, now our Analyzer is  ready. AbuseIPDB Analyzer can analyze IP type artifacts. We will use an  alarm from the IDS product called Suricata to perform this test.

First, let's understand  the journey of our alarm: We have a Suricata IDS product that listens to the Mirror of traffic at a point just before the internet exit of our  lab environment. This product takes a copy of all traffic passing  through the network, examines it, and turns it into an alarm when it  sees a suspicious package. It writes its alarms to a file named  “eve.json”.

The log line written in this file is as follows:

```json
{"timestamp":"2023-09-27T17:44:56.662683+0300","flow_id":2071045031861403,"in_iface":"ens3f0","event_type":"alert","vlan":31,"src_ip":"172.16.31.138","src_port":25393,"dest_ip":"218.92.0.105","dest_port":53,"proto":"UDP","tx_id":0,"alert":{"action":"allowed","gid":1,"signature_id":2018918,"rev":2,"signature":"ET POLICY possible Xiaomi phone data leakage DNS","category":"Potential Corporate Privacy Violation","severity":1,"metadata":{"updated_at":["2020_09_15"],"created_at":["2014_08_11"]}},"dns":{"query":[{"type":"query","id":38425,"rrname":"api.account.xiaomi.com","rrtype":"A","tx_id":0}]},"app_proto":"dns","flow":{"pkts_toserver":1,"pkts_toclient":0,"bytes_toserver":86,"bytes_toclient":0,"start":"2023-09-27T17:42:56.662683+0300"},"payload":"lhkBAAABAAAAAAAAA2FwaQdhY2NvdW50BnhpYW9taQNjb20AAAEAAQ==","payload_printable":".............api.account.xiaomi.com.....","stream":0}             
```

Wazuh, which we use as  SIEM, constantly monitors the "eve.json" file in which Suricata writes  its logs and makes sense of the logs there. The output of the raw log  you see above after being decoded by Wazuh is as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/5/soar76.png)

As you can see, after  Wazuh parses this log, it turns it into a Level 3 alarm. Since we tell  it to send Level 3 and above alarms to SOAR (TheHive), it sends the  alarm to TheHive.

TheHive brings us the alarm as follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/5/soar75.png)

Let's see what's on this screen before continuing:

1. In the field no., there is the title information of the Alarm.  
2. In field no., there are line details of the alarm.  
3. There are artifacts removed from the alarm in area no. and we will use them in a moment.  
4. In field no., we see the information that there is another alarm similar to this alarm.  
5. In area no., there is  the Import Case (Run Playbook) option, which we have used before. As you may have noticed, this time we chose the “Suspicious DNS Request”  Playbook.  

**the Yes, Import**   Button, this alarm will turn into a Case and we will go to the Case Management Screen:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/5/soar77.png)

**Observables**   tab indicated by   **(1)**   on this screen , you will see the automatically observable artifacts in the field   **(2) .**   If you wish (in our example, these are of IP type), you can add other artifacts to your case by using field   **(3) .**   Observables types supported by TheHive are as shown in the image below:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/5/soar78.png)

Let's not add any new content now and continue with what we have. When we click on the artifact shown in number   **(2),**   we will go to the detail page for this artifact:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/5/soar79.png)

On this page:

  **(1)**   .

  **(2)**   , there is information that we have not run an Analyzer on this IP address before.

  **(3)**   , there is information that this IP address does not occur in another Case.

  **(4)**   , there is information that we have an Analyzer (AbuseIPDB_1_0) ready to process this IP type data.

Let's click on the icon under   **the Actions heading**   in area   **(4) .**

TheHive will send this IP Address to Cortex, Cortex will ask AbuseIPDB for information about this IP and after a while the relevant line will start to be displayed as  follows:

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/5/soar80.png)

Now we can see the report by clicking on the date information under   **the Last analysis column:**

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/Advanced+SOAR/5/soar81.png)

Actually the report  consists of several hundred rows and many HoneyPots etc. Suspicious  activities have been reported by. The fact that the AbuseConfidenceScore value is 100 says it all.

Yes, we can now use the responder on the same page for "Firewall Block", for example.

Responders work just like Analyzers. After selecting and configuring the Responders related to  your own products from the responders page in Cortex, you can take  actions (for example, IP block on your firewall device) with a single  click.  

### Last word

When SOAR is positioned  and configured correctly, it provides its users with great advantages in cyber warfare. This advantage also has some challenges: Product  selection, correct and competent human resources, correct developments  and integrations.  

As you can guess, we did  not go into the capillaries of SOAR in this lesson. Our suggestion to  you is to run tests in your own lab environment whenever you have the  opportunity and try different combinations. Because SOAR is not a  product, it is a starting point, and to use it truly effectively, you  need to master its capabilities and limitations.

In this part of the training, it is mentioned how automation operations on SOAR can be carried out.























































































































