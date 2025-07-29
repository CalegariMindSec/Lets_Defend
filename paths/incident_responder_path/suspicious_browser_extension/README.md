# Suspicious Browser Extension

A person working in the accounting department wanted to add a browser  extension, but it was deleted from his device because it was perceived  as harmful by AVs.

Can you analyze the situation by analyzing this suspicious browser extension? We are waiting for information from you.

**File link:**  /root/Desktop/ChallengeFiles/FinanceEYEfeeder.crx 

This challenge prepared by [@DXploiter](https://twitter.com/DXploiter)

**Writeups:**

- [Suspicious Browser Extension — WriteUp ](https://drive.google.com/file/d/1Yh2z6dL_cOaAqtPLO-mgAQZjSIKvAptC/view?usp=sharing)
- [LetsDefend’s Malware Analysis: Suspicious Browser Extension Walk-Through](https://cybergladius.com/letsdefends-malware-analysis-suspicious-browser-extension-walk-through/)
- [Malware Analysis - Suspicious Browser Extension](https://www.youtube.com/watch?v=MSpkmJ0OO-Y)

### Questions

1 - Which browser supports this extension?

> **Answer:** Google Chrome

2 - What is the name of the main file which contains metadata?

> **Answer:** manifest.json

3 - How many js files are there? (Answer should be numerical)

> **Answer:** 2

4 - Go to crxcavator.io and check if this browser extension has already been analyzed by searching its name. Is it known to the community? (Yes/No)

> **Answer:** No

5 - Download and install ExtAnalysis. Is the author of the extension known? (Yes/No)

> **Answer:** No

6 - Often there are URLs and domains in malicious extensions. Using  ExtAnlaylsis, check the ‘URLs and Domains’ tab How many URLs &  Domains are listed? (Answer should be numerical)

> **Answer:** 2

7 - Find the piece of code that uses an evasion technique. Analyse it, what type of systems is it attempting to evade?

> **Answer:** virtual machine

8 - If this type of system is detected what function is triggered in its response?

> **Answer:** chrome.processes.terminate(0)

9 - What keyword in a user visited URL will trigger the if condition statement in the code?

> **Answer:** login

10 - Based on the analysis of the content.js, what type of malware is this?

> **Answer:** keylogger

11 - Which domain/URL will data be sent to?

> **Answer:** https://google-analytics-cm.com/analytics-3032344.txt

12 - As a remediation measure, what type of credential would you recommend all affected users to reset immediately?

> **Answer:** password







