# Memory Analysis

**Link:** https://app.letsdefend.io/challenge/memory-analysis

A  Windows Endpoint was recently compromised. Thanks to our cutting-edge  EDR/IDS solution we immediately noticed it. The alert was escalated to  Tier 2 (Incident Responders) for further investigation. As our Forensics guy, you were given the memory dump of the compromised host. You should continue to investigate. 

**File location:** /root/Desktop/ChallengeFile/MemoryDump.zip

**File Password**: infected

**Volatility2 Command**: vol.py

**Volatility3 Command**: vol

This challenge prepared by [0xCyberJunkie.sh](https://www.linkedin.com/in/abdullah-bin-yasin-4b418119a)

**Walkthrough:**

- [LetsDefend — Memory Analysis Challenge Walkthrough](https://stumblesec.medium.com/letsdefend-memory-analysis-challenge-walkthrough-with-volatility-3-f19472849453)
- [Memory forensics Challenge (Letsdefend)](https://cyberjunnkie.medium.com/memory-forensics-challenge-letsdefend-80ebbf6e40b2)
- [DFIR - Memory Analysis](https://www.youtube.com/watch?v=RpOd-OgjxMs)
- [LetsDefend: Memory Dumper](https://beginninghacking.net/2022/08/08/letsdefend-memory-dumper/)
- [LetsDefend challenge Memory Analysis writeup](https://mahim-firoj.medium.com/letsdefend-challenge-memory-analysis-writeup-9d6958ea3dac)

### Questions

1 - What was the date and time when Memory from the compromised endpoint was acquired?

> **Answer:** 2022-07-26 18:16:32

2 - What was the suspicious process running on the system? (Format : name.extension)

> **Answer:** lsass.exe

3 - Analyze and find the  malicious tool  running on the system by the attacker (Format name.extension)

> **Answer:**  winPEAS.exe 

4 - Which User Account was compromised? Format (DomainName/USERNAME)

> **Answer:** MSEDGEWIN10/CyberJunkie

5 - What is the compromised user password?

> **Answer:** password123