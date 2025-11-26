# SIEM Alert Tuning

The  "SIEM Alert Tuning" course focuses on developing specialized skills in  fine-tuning Security Information and Event Management (SIEM) alerts to  reduce false positives and enhance the accuracy of cybersecurity  incident detection and response. This course delves into strategies to  optimize alert configurations, ensuring precise and effective threat  identification within SIEM systems.

**Table of Contents:**

- [False Positive Alert](t)
- [Why is False Positive Alert Tuning Necessary?]()
- [F/P Alert Tuning with IBM QRadar]()
- [F/P Alert Tuning with IBM QRadar - 2]()

Evaluate Yourself with Quiz

- [SIEM Alert Tuning](https://app.letsdefend.io/training/quiz/siem-alert-tuning)

## False Positive Alert

SIEM projects are of  critical importance to ensure the digital security of modern  organizations. However, managers and security analysts of these projects have to deal with a number of concepts that they frequently encounter  in their daily work. These concepts form the basis of the tools and  processes used to detect and address security threats. In this lesson,  we will talk about what these concepts are and how action can be taken.  

- **False Positive**: False positive refers  to the situation where alerts or alarms coming to a security system or  SIEM solution are not actually a security threat. This is a false alarm  and can cause unnecessary waste of time and resources for the security  team.
- **False Negative**: False negative refers  to a situation where a real security threat to a security system or SIEM solution is not detected or ignored. This could lead to a real threat  being missed and a potentially serious security breach.
- **True Positive**: True positive refers to a situation where a security system or SIEM solution correctly detects a real threat and generates an alarm or alert.
- **True Negative**: True negative refers to a situation where a security system or SIEM solution does not  accurately detect a real threat and does not produce any false alarms.

False Positive Alarm  Tuning means adjusting and optimizing the rules or correlations used to  detect security events. It is a process that aims to increase the  accuracy of alarms and warnings produced by the SIEM system. It is the  mechanism by which we can prevent false alarms from occurring. It is one of the workflows that must be performed periodically by organizations  using SIEM.

In this part of the training, some concepts about alarms are mentioned. In the next part of the training, “Why is False Positive Alert Tuning Necessary?” topic is explained.

### Questions

1 - What concept describes the situation where a security threat is not detected by the SIEM solution?

> **Answer:** False Negative

2 - What is the name given to the situation where the SIEM solution correctly detects a real threat and generates an alarm?

> **Answer:** True Positive

3 - What is it called when the SIEM solution does not detect a threat and does not produce a false alarm?

> **Answer:** True Negative

## Why is False Positive Alert Tuning Necessary?

- **False Alert Fatigue:** F/Ps can weaken security  analysts' ability to respond to real threats due to the high number of  false alarms. This can cause real threats to be missed.
- **Resource Usage:** Time and resources spent on false alarm corrections can reduce the efficiency of the organization.
- **Reliability and Focus:** F/Ps can reduce  reliability and operational efficiency. It is important that SIEM users  can focus on real threats and reduce false alarms.

As a result, False  Positive Alarm Tuning helps organizations make their security operations more efficient. This allows security analysts to respond more quickly  and accurately to real threats, and also increases the likelihood of  detecting real dangers lost in piles of data.  

In this part of the  training, the importance of False Positive Alarm Tuning is mentioned. In the next part of the training, the subject "F/P Alarm Tuning with IBM QRadar" is explained.

## F/P Alert Tuning with IBM QRadar

False Positive (F/P)  Alarm Tuning with IBM QRadar refers to the process of optimizing the  rules or algorithms used to detect QRadar's security events. This  process aims to increase the accuracy of alarms and warnings produced by the QRadar system and makes the security operations of organizations  more effective.  

### QRadar False Positive Offense Tuning

After examining the  offenses occurring on QRadar SIEM, if it is determined to be False  Positive and this offense occurs too much, it would be appropriate to  tune it. To perform this operation;  

### Example-1: Exclude Source IP Address

The QRadar -> Offenses screen opens. The offense to be tuned is selected and the “Tune” button is clicked.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Tuning/image2-1.png)

The screen that opens  shows the details about this offense. By clicking the "Edit in rule  wizard" button on this screen, the relevant rule is edited to be tuned.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Tuning/image2-2.png)

The value to be tuned is entered on the screen that opens. This value;  

These may be values such as Username, IP Address, Domain, URL.  

In our example, “Suricata Alert” is to prevent the occurrence of an offense by excluding the IP  address of the Nessus scanning tool with the IP Address “172.16.8.1”,  which causes the offense to occur.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Tuning/image2-3.png)

The Source IP filter is added and the IP address of Nessus is added.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Tuning/image2-4.png)

The tuning process is completed by pressing the Next and Finish buttons.  

In this part of the training, an example of F/P alarm tuning via IBM QRadar is given. In the next part of the training, "F/P Alarm Tuning-2 with IBM QRadar", which is the continuation of this part, is explained.

## F/P Alert Tuning with IBM QRadar - 2

### Example-2: Excluding IP address from User Create Activity  

The QRadar -> Offenses screen opens. The offense to be tuned is selected and the “Tune” button is clicked.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Tuning/image2-5.png)

If the user account  creation activity is done by a known source (source_ip: 192.168.1.30),  tuning can be done by adding the Source IP filter as “and NOT”.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Tuning/image2-6.png)

### Example-3: Excluding users starting with TE- in Multiple Login Activities  

“Rule Wizard” is opened  over the relevant rule or offense and the “when the event matches”  filter is added, “Username” is selected from the filter section,  “matches any of expressions” is selected and ^TE\- is added as the  value.

![img](https://letsdefend-images.s3.us-east-2.amazonaws.com/Courses/SIEM+Alert+Tuning/image2-7.png)

### Conclusion/Summary

  False Positive Alarm  Tuning with IBM QRadar focuses on optimizing rules and algorithms to  detect security events more accurately and effectively. This process has the goal of reducing QRadar false alarms and thus improving the overall effectiveness of security operations. In particular, it may be  necessary to include or exclude certain values to prevent potentially  harmless situations, such as certain IP addresses or user activities,  from causing false alarms. In summary, the right tuning approaches allow organizations to take full advantage of the benefits QRadar offers.







































































































































