# Notepad

Todo lo que tengo pendiente por revisar  maquina Tally


```ruby

# Nmap 7.94 scan initiated Tue Jan 16 22:11:14 2024 as: nmap -sCV -p21,80,135,139,445,808,15567,32843,32844,32846,47001,49664,49665,49666,49667,49668,49669,49670 -vvv -oN Scan 10.129.1.183
Nmap scan report for 10.129.1.183
Host is up, received echo-reply ttl 127 (0.31s latency).
Scanned at 2024-01-16 22:11:15 EST for 73s

PORT      STATE SERVICE              REASON          VERSION
21/tcp    open  ftp                  syn-ack ttl 127 Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp    open  http                 syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-favicon: Unknown favicon MD5: 50996DA127314E31E0B14D57B9847C9F
|_http-generator: Microsoft SharePoint
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
| http-title: Home
|_Requested resource was http://10.129.1.183/_layouts/15/start.aspx#/default.aspx
|_http-server-header: Microsoft-IIS/10.0
135/tcp   open  msrpc                syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn          syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds         syn-ack ttl 127 Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
808/tcp   open  ccproxy-http?        syn-ack ttl 127
15567/tcp open  http                 syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: Site doesn't have a title.
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|   Negotiate
|_  NTLM
| http-ntlm-info: 
|   Target_Name: TALLY
|   NetBIOS_Domain_Name: TALLY
|   NetBIOS_Computer_Name: TALLY
|   DNS_Domain_Name: TALLY
|   DNS_Computer_Name: TALLY
|_  Product_Version: 10.0.14393
|_http-server-header: Microsoft-IIS/10.0
32843/tcp open  http                 syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Service Unavailable
32844/tcp open  ssl/http             syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
| ssl-cert: Subject: commonName=SharePoint Services/organizationName=Microsoft/countryName=US/organizationalUnitName=SharePoint
| Subject Alternative Name: DNS:localhost, DNS:tally
| Issuer: commonName=SharePoint Root Authority/organizationName=Microsoft/countryName=US/organizationalUnitName=SharePoint
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha1WithRSAEncryption
| Not valid before: 2017-09-17T22:51:16
| Not valid after:  9999-01-01T00:00:00
| MD5:   965f:55d6:a0b1:fed5:4ce5:3887:2938:0d53
| SHA-1: 0f6a:3c08:bee8:b7ad:237e:9759:e91c:f683:8f0b:149f
| -----BEGIN CERTIFICATE-----
| MIIEWTCCAkGgAwIBAgIQyV6dVL5Kk6BEr58pxdsV6TANBgkqhkiG9w0BAQUFADBa
| MQswCQYDVQQGEwJVUzESMBAGA1UEChMJTWljcm9zb2Z0MRMwEQYDVQQLEwpTaGFy
| ZVBvaW50MSIwIAYDVQQDExlTaGFyZVBvaW50IFJvb3QgQXV0aG9yaXR5MCAXDTE3
| MDkxNzIyNTExNloYDzk5OTkwMTAxMDAwMDAwWjBUMQswCQYDVQQGEwJVUzESMBAG
| A1UEChMJTWljcm9zb2Z0MRMwEQYDVQQLEwpTaGFyZVBvaW50MRwwGgYDVQQDExNT
| aGFyZVBvaW50IFNlcnZpY2VzMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
| AQEApN4ZSEX3h7SYbASpHe0GGBydQQR3fhCyDV9qhj/Vx5ciK4ncVZTahAbVenN8
| 9xNPloxMcqadhp3WwOhr77MZ6X/P8SnbpFoKVFCUVxXIBhVZQ3sAqZ2oI5+6VOYn
| UqkzYE5UFYnlA8tSfNgpCeZ4gNhr3VNmxXx+5SaUufm2qLKJn93RGvnRYF0abTBz
| 5wbjjjELmq6+2eRjNbk24mzMWiVI/yW5Ea7BturA6YqumRvhqXgqgSjiD/OfDPXI
| J0kimJuHre6MGFPBDmYFa47W+NLZxW6j4POQasady+98CHvM88456TCp9WvWH6R6
| DxKdmWrA+A6qJkr7rTP5n5oJCQIDAQABox8wHTAbBgNVHREEFDASgglsb2NhbGhv
| c3SCBXRhbGx5MA0GCSqGSIb3DQEBBQUAA4ICAQBGkHAoLvIgw3mH6EyflnMyWREG
| yEZ02iUx/I0yJDUp6gnEgHNeNh0dnqNOjvyQktFG1+e+VFgt5kSI4sUlGSkFasDf
| fcnFUcM6iq6bRZzWNgYyhrYBaPgr50oaZZs4qEJufObrmeD6rL37URiO7tFE/UOM
| 77AipPQ8j7BVGwCG++XEYQPpYt1fo/N/aCrdY4akz2rKQ+GmoO6V429ovTJtO+z0
| qJID3JUhYjA2ZiL6Are4+L6eZAlnxFR45W2p1XS2by+J4AxSGj1aZGVE83ngrdi9
| F/WB6IIInpFsDiCYgDdyqIR/7xR+iiIdwqsHBZ6OU0YV5UBkWAOjUHIoJkp6rJ9L
| RtcQBlyRSEEiFVn1tU4GK7Sb5E+HsSBpvFA8K1vKZDP+N4J83ii1p6esaZ6g0oy3
| tMY9E+v6xQkzXjCb1ZW2jBSqZK7Bzb/SKcjOnzDvDeKZwJY8RUEHpVVEhwj752ml
| Xr95eiWQsuzJyB2cJ5jwiL+uBWcswrjFLQk+zpY/jx0WXnBS8aEGnyohmbQ1POcg
| ETpi4jhYGmFG4EJyHv25c2k3JvvrY4HufeUQg5qWljLG+UCSgnZrpDgIv4/pTSZ1
| ICd9gsCOZZ44qx9OwP25yxb165VU+kDt218w2WSrBwxuk6D59jjQw9z3+/kCZug9
| ox1fB7OQe5ABVPlttQ==
|_-----END CERTIFICATE-----
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: 2024-01-17T03:12:27+00:00; +1s from scanner time.
|_http-title: Service Unavailable
32846/tcp open  msexchange-logcopier syn-ack ttl 127 Microsoft Exchange 2010 log copier
47001/tcp open  http                 syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc                syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc                syn-ack ttl 127 Microsoft Windows RPC
49666/tcp open  msrpc                syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc                syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc                syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc                syn-ack ttl 127 Microsoft Windows RPC
49670/tcp open  msrpc                syn-ack ttl 127 Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2024-01-17T03:12:20
|_  start_date: 2024-01-17T03:02:39
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 17035/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 22406/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 64933/udp): CLEAN (Failed to receive data)
|   Check 4 (port 10847/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Tue Jan 16 22:12:28 2024 -- 1 IP address (1 host up) scanned in 73.54 seconds


```

```ruby

PORT      STATE SERVICE
21/tcp    open  ftp
80/tcp    open  http
| http-frontpage-login: 
|   VULNERABLE:
|   Frontpage extension anonymous login
|     State: VULNERABLE
|       Default installations of older versions of frontpage extensions allow anonymous logins which can lead to server compromise.
|       
|     References:
|_      http://insecure.org/sploits/Microsoft.frontpage.insecurities.html
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
445/tcp   open  microsoft-ds
808/tcp   open  ccproxy-http
15567/tcp open  unknown
32843/tcp open  unknown
32844/tcp open  unknown
32846/tcp open  unknown
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49668/tcp open  unknown
49669/tcp open  unknown
49670/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 163.91 seconds


```

Whatweb 

```
http://10.129.1.183 [302 Found] Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.129.1.183], Microsoft-IIS[10.0], Microsoft-Sharepoint[15.0.0.4420], RedirectLocation[http://10.129.1.183/default.aspx], Title[Document Moved], UncommonHeaders[x-sharepointhealthscore,sprequestguid,request-id,sprequestduration,spiislatency,microsoftsharepointteamservices,x-content-type-options,x-ms-invokeapp], X-Frame-Options[SAMEORIGIN], X-Powered-By[ASP.NET]
http://10.129.1.183/default.aspx [200 OK] ASP_NET[4.0.30319], Country[RESERVED][ZZ], HTTPServer[Microsoft-IIS/10.0], IP[10.129.1.183], MetaGenerator[Microsoft SharePoint], Microsoft-IIS[10.0], Microsoft-Sharepoint[15.0.0.4420], Script[text/javascript], Title[Home - Home][Title element contains newline(s)!], UncommonHeaders[x-sharepointhealthscore,sprequestguid,request-id,sprequestduration,spiislatency,microsoftsharepointteamservices,x-content-type-options,x-ms-invokeapp], X-Frame-Options[SAMEORIGIN], X-Powered-By[ASP.NET], X-UA-Compatible[IE=10]

```


Los links que deberias de leer

```bash

#BoF

https://sniferl4bs.com/2019/03/exploiting-101-que-son-los-badchars-generando-badchars-desde-python-y-mona/

https://infosecwriteups.com/brainstrom-tryhackme-523b916661ff

https://github.com/Tib3rius/Pentest-Cheatsheets/blob/master/exploits/buffer-overflows.rst

https://tryhackme.com/room/bufferoverflowprep


## EMAPT y ECCPT

https://ishsome.medium.com/i-passed-ecpptv2-august-2023-8507d4afee66

https://brcyrr.medium.com/recommendations-review-of-emapt-819e72a27f06


## S4vitar machines.IO

https://infosecmachines.io/

# Maquina Tally

https://github.com/zcgonvh/CVE-2020-17144

https://github.com/zcgonvh/CVE-2020-17144

https://github.com/tijldeneut/Security/blob/master/CVE-2020-0688.py


"Microsoft Exchange 2010 github exploit"

https://swarm.ptsecurity.com/attacking-ms-exchange-web-interfaces/

https://github.com/0xdevalias/sparty

https://github.com/H0j3n/EzpzSharepoint

https://gist.github.com/testanull/dac6029d306147e6cc8dce9424d09868

Microsoft-Sharepoint 15.0.0.4420 github exploit

https://hackmag.com/security/sharepoint-serving-the-hacker/

https://github.com/frizb/Hydra-Cheatsheet


```

Output Dir buster


```bash


Starting OWASP DirBuster 1.0-RC1
Starting dir/file list based brute forcing
Dir found: / - 302
Dir found: /_app_bin/ - 403
Dir found: /_controltemplates/ - 403
Dir found: /_layouts/ - 403
Dir found: /_layouts/1033/ - 403
File found: /_layouts/1033.aspx - 200
Dir found: /_catalogs/masterpage/forms/allitems.aspx/ - 200
Jan 16, 2024 10:29:24 PM au.id.jericho.lib.html.LoggerProviderJava$JavaLogger info
INFO: StartTag a at (r419,c7378,p40608) has missing whitespace after quoted attribute value at position (r419,c7975,p41205)
Jan 16, 2024 10:29:25 PM au.id.jericho.lib.html.LoggerProviderJava$JavaLogger info
INFO: StartTag a at (r419,c7378,p40608) contains attribute name with invalid first character at position (r419,c7975,p41205)
Jan 16, 2024 10:29:25 PM au.id.jericho.lib.html.LoggerProviderJava$JavaLogger info
INFO: StartTag a at (r419,c7378,p40608) has missing whitespace after quoted attribute value at position (r419,c7977,p41207)
Jan 16, 2024 10:29:25 PM au.id.jericho.lib.html.LoggerProviderJava$JavaLogger info
INFO: StartTag a at (r419,c8661,p41891) has missing whitespace after quoted attribute value at position (r419,c9281,p42511)
Jan 16, 2024 10:29:25 PM au.id.jericho.lib.html.LoggerProviderJava$JavaLogger info
INFO: StartTag a at (r419,c8661,p41891) contains attribute name with invalid first character at position (r419,c9281,p42511)
Jan 16, 2024 10:29:25 PM au.id.jericho.lib.html.LoggerProviderJava$JavaLogger info
INFO: StartTag a at (r419,c8661,p41891) has missing whitespace after quoted attribute value at position (r419,c9283,p42513)
Dir found: /_catalogs/wp/forms/allitems.aspx/ - 200
File found: /default.aspx - 200
Dir found: /_catalogs/lt/forms/allitems.aspx/ - 200
File found: /_app_bin/_layouts/1033.aspx - 200
File found: /_app_bin/_layouts/1033/accessdeniedpage.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/aclinv.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/aclver.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/addgrp1.aspx.aspx - 200
Dir found: /_app_bin/_layouts/ - 403
Dir found: /_app_bin/_layouts/1033/ - 403
File found: /_app_bin/_layouts/1033/addgrp2.aspx.aspx - 200
Dir found: /_layouts/_admin/operations.aspx/ - 200
File found: /_app_bin/_layouts/1033/addrole.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/advsetng.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/accessdeniedpage.aspx/ - 200
Dir found: /_layouts/_catalogs/masterpage/forms/allitems.aspx/ - 200
Dir found: /_controltemplates/_layouts/ - 403
File found: /_app_bin/_layouts/1033/alertdirectory.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/aclinv.aspx/ - 200
Dir found: /_layouts/_catalogs/wp/forms/allitems.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/ - 403
File found: /_app_bin/_layouts/1033/alertserror.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/alertsadmin.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/aclver.aspx/ - 200
Dir found: /_layouts/_catalogs/wt/forms/common.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/addgrp1.aspx/ - 200
File found: /_app_bin/_layouts/1033/allgrps.aspx.aspx - 200
Exception in thread "Timer-1" java.lang.ArrayIndexOutOfBoundsException: No such child: 120
        at java.desktop/java.awt.Container.getComponent(Container.java:354)
        at com.sittinglittleduck.DirBuster.monitorThreads.ProcessChecker.run(ProcessChecker.java:183)
        at java.base/java.util.TimerThread.mainLoop(Timer.java:566)
        at java.base/java.util.TimerThread.run(Timer.java:516)
Dir found: /_controltemplates/_layouts/1033/accessdeniedpage.aspx/ - 200
File found: /_app_bin/_layouts/1033/applyregionalsettings.aspx.aspx - 200
Dir found: /_layouts/_catalogs/lt/forms/allitems.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/addgrp2.aspx/ - 200
File found: /_app_bin/_layouts/1033/associateportal.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/addrole.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/aclinv.aspx/ - 200
File found: /_app_bin/_layouts/1033/audience_chooser.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/aclver.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/advsetng.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/addgrp1.aspx/ - 200
File found: /_app_bin/_layouts/1033/audience_chooser2.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/alertdirectory.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/alertserror.aspx/ - 200
File found: /_app_bin/_layouts/1033/audience_defruleedit.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/addgrp2.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/alertsadmin.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/addrole.aspx/ - 200
Dir found: /_layouts/_layouts/1033/accessdeniedpage.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/allgrps.aspx/ - 200
Dir found: /_layouts/_layouts/1033/aclinv.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/advsetng.aspx/ - 200
File found: /_app_bin/_layouts/1033/audience_edit.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/audience_list.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/alertserror.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/alertdirectory.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/applyregionalsettings.aspx/ - 200
File found: /_app_bin/_layouts/1033/audience_main.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/allgrps.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/audience_chooser.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/applyregionalsettings.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/alertsadmin.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/associateportal.aspx/ - 200
Dir found: /_layouts/_layouts/1033/aclver.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/audience_chooser2.aspx/ - 200
File found: /_app_bin/_layouts/1033/audience_memberlist.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/associateportal.aspx/ - 200
File found: /_controltemplates/_layouts/1033.aspx - 200
Dir found: /_layouts/_layouts/1033/addgrp1.aspx/ - 200
File found: /_app_bin/_layouts/1033/audience_sched.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/audience_chooser.aspx/ - 200
File found: /_controltemplates/_layouts/1033/accessdeniedpage.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/addgrp2.aspx/ - 200
File found: /_app_bin/_layouts/1033/audience_view.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/audience_defruleedit.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/audience_chooser2.aspx/ - 200
File found: /_controltemplates/_layouts/1033/aclinv.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/addrole.aspx/ - 200
File found: /_app_bin/_layouts/1033/autocat.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/audience_defruleedit.aspx/ - 200
File found: /_controltemplates/_layouts/1033/aclver.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/advsetng.aspx/ - 200
File found: /_app_bin/_layouts/1033/avreport.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/audience_edit.aspx/ - 200
File found: /_controltemplates/_layouts/1033/addgrp1.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/audience_edit.aspx/ - 200
Dir found: /_layouts/_layouts/1033/alertdirectory.aspx/ - 200
File found: /_app_bin/_layouts/1033/avreport.htm.aspx - 200
Dir found: /_app_bin/_layouts/1033/audience_list.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/audience_list.aspx/ - 200
File found: /_controltemplates/_layouts/1033/addgrp2.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/audience_main.aspx/ - 200
Dir found: /_layouts/_layouts/1033/alertsadmin.aspx/ - 200
File found: /_app_bin/_layouts/1033/bin.aspx - 200
Dir found: /_layouts/_layouts/1033/alertserror.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/audience_main.aspx/ - 200
File found: /_app_bin/_layouts/1033/bpcf.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/audience_memberlist.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/audience_memberlist.aspx/ - 200
File found: /_controltemplates/_layouts/1033/addrole.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/allgrps.aspx/ - 200
File found: /_controltemplates/_layouts/1033/advsetng.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/categorypickerpopup.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/audience_sched.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/audience_sched.aspx/ - 200
Dir found: /_layouts/_layouts/1033/applyregionalsettings.aspx/ - 200
File found: /_app_bin/_layouts/1033/catpp1.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/audience_view.aspx/ - 200
File found: /_app_bin/_layouts/1033/catman.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/audience_view.aspx/ - 200
File found: /_controltemplates/_layouts/1033/alertdirectory.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/associateportal.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/autocat.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/autocat.aspx/ - 200
File found: /_app_bin/_layouts/1033/centraldatabaselock.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/alertsadmin.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/audience_chooser.aspx/ - 200
File found: /_app_bin/_layouts/1033/checkin.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/avreport.aspx/ - 200
File found: /_controltemplates/_layouts/1033/alertserror.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/avreport.aspx/ - 200
Dir found: /_layouts/_layouts/1033/audience_chooser2.aspx/ - 200
Dir found: /_layouts/_layouts/1033/audience_defruleedit.aspx/ - 200
File found: /_controltemplates/_layouts/1033/allgrps.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/choosecs.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/audience_edit.aspx/ - 200
File found: /_app_bin/_layouts/1033/confirmadvancedmode.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/applyregionalsettings.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/audience_list.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/bpcf.aspx/ - 200
File found: /_app_bin/_layouts/1033/confirmalert.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/bpcf.aspx/ - 200
File found: /_controltemplates/_layouts/1033/associateportal.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/audience_main.aspx/ - 200
File found: /_app_bin/_layouts/1033/confirmation.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/categorypickerpopup.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/categorypickerpopup.aspx/ - 200
File found: /_controltemplates/_layouts/1033/audience_chooser.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/audience_memberlist.aspx/ - 200
File found: /_app_bin/_layouts/1033/conngps.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/catman.aspx/ - 200
File found: /_controltemplates/_layouts/1033/audience_chooser2.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/copyrole.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/audience_sched.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/catman.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/catpp1.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/catpp1.aspx/ - 200
File found: /_controltemplates/_layouts/1033/audience_defruleedit.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/centraldatabaselock.aspx/ - 200
Dir found: /_layouts/_layouts/1033/audience_view.aspx/ - 200
File found: /_app_bin/_layouts/1033/create.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/audience_edit.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/centraldatabaselock.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/checkin.aspx/ - 200
Dir found: /_layouts/_layouts/1033/autocat.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/checkin.aspx/ - 200
File found: /_app_bin/_layouts/1033/createmysite.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/audience_list.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/choosecs.aspx/ - 200
Dir found: /_layouts/_layouts/1033/avreport.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/choosecs.aspx/ - 200
File found: /_controltemplates/_layouts/1033/audience_main.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/confirmadvancedmode.aspx/ - 200
File found: /_app_bin/_layouts/1033/createws.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/cspp1.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/audience_memberlist.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/confirmalert.aspx/ - 200
File found: /_controltemplates/_layouts/1033/audience_sched.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/confirmadvancedmode.aspx/ - 200
File found: /_app_bin/_layouts/1033/cspp2.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/confirmation.aspx/ - 200
File found: /_app_bin/_layouts/1033/default.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/confirmalert.aspx/ - 200
File found: /_controltemplates/_layouts/1033/audience_view.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/conngps.aspx/ - 200
Dir found: /_layouts/_layouts/1033/bpcf.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/confirmation.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/copyrole.aspx/ - 200
File found: /_controltemplates/_layouts/1033/autocat.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/categorypickerpopup.aspx/ - 200
File found: /_controltemplates/_layouts/1033/avreport.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/conngps.aspx/ - 200
File found: /_app_bin/_layouts/1033/deletemu.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/create.aspx/ - 200
Dir found: /_layouts/_layouts/1033/catman.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/copyrole.aspx/ - 200
File found: /_app_bin/_layouts/1033/deleteweb.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/avreport.htm.aspx - 200
Dir found: /_app_bin/_layouts/1033/createmysite.aspx/ - 200
Dir found: /_layouts/_layouts/1033/catpp1.aspx/ - 200
File found: /_app_bin/_layouts/1033/discbar.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/create.aspx/ - 200
File found: /_controltemplates/_layouts/1033/bin.aspx - 200
Dir found: /_app_bin/_layouts/1033/createws.aspx/ - 200
Dir found: /_layouts/_layouts/1033/centraldatabaselock.aspx/ - 200
File found: /_app_bin/_layouts/1033/displaymappings.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/bpcf.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/createmysite.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/cspp1.aspx/ - 200
Dir found: /_layouts/_layouts/1033/checkin.aspx/ - 200
File found: /_app_bin/_layouts/1033/dladvopt.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/categorypickerpopup.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/cspp2.aspx/ - 200
Dir found: /_layouts/_layouts/1033/choosecs.aspx/ - 200
File found: /_app_bin/_layouts/1033/dmworkspacemgmt.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/createws.aspx/ - 200
File found: /_controltemplates/_layouts/1033/catman.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/default.aspx/ - 200
Dir found: /_layouts/_layouts/1033/confirmadvancedmode.aspx/ - 200
File found: /_app_bin/_layouts/1033/download.aspx.aspx - 200
Dir found: /_layouts/15/ - 403
Dir found: /_catalogs/masterpage/ - 302
Dir found: /_catalogs/wp/ - 302
File found: /_controltemplates/_layouts/1033/catpp1.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/cspp1.aspx/ - 200
Dir found: /_layouts/_layouts/1033/confirmalert.aspx/ - 200
File found: /_app_bin/_layouts/1033/dws.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/default.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/cspp2.aspx/ - 200
File found: /_controltemplates/_layouts/1033/centraldatabaselock.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/deletemu.aspx/ - 200
Dir found: /_layouts/_layouts/1033/confirmation.aspx/ - 200
File found: /_app_bin/_layouts/1033/editalert.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/checkin.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/deleteweb.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/displaymappings.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/discbar.aspx/ - 200
Dir found: /_layouts/_layouts/1033/conngps.aspx/ - 200
File found: /_app_bin/_layouts/1033/editdisplaymapping.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/deletemu.aspx/ - 200
File found: /_controltemplates/_layouts/1033/choosecs.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/dladvopt.aspx/ - 200
Dir found: /_layouts/_layouts/1033/copyrole.aspx/ - 200
File found: /_app_bin/_layouts/1033/editdsserver.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/deleteweb.aspx/ - 200
File found: /_controltemplates/_layouts/1033/confirmadvancedmode.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/confirmalert.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/dmworkspacemgmt.aspx/ - 200
Dir found: /_layouts/_layouts/1033/create.aspx/ - 200
File found: /_app_bin/_layouts/1033/editgrp.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/discbar.aspx/ - 200
File found: /_controltemplates/_layouts/1033/confirmation.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/download.aspx/ - 200
Dir found: /_layouts/_layouts/1033/createmysite.aspx/ - 200
File found: /_app_bin/_layouts/1033/editprms.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/displaymappings.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/dws.aspx/ - 200
Dir found: /_layouts/_layouts/1033/createws.aspx/ - 200
File found: /_app_bin/_layouts/1033/editprofile.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/dladvopt.aspx/ - 200
File found: /_controltemplates/_layouts/1033/conngps.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/editalert.aspx/ - 200
File found: /_app_bin/_layouts/1033/editproperty.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/cspp1.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/dmworkspacemgmt.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/download.aspx/ - 200
File found: /_controltemplates/_layouts/1033/copyrole.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/editdisplaymapping.aspx/ - 200
Dir found: /_layouts/_layouts/1033/cspp2.aspx/ - 200
File found: /_app_bin/_layouts/1033/editrole.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/dws.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/editdsserver.aspx/ - 200
Dir found: /_layouts/_layouts/1033/default.aspx/ - 200
File found: /_app_bin/_layouts/1033/editsearchschedule.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/editalert.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/editgrp.aspx/ - 200
File found: /_app_bin/_layouts/1033/editsearchsettings.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/create.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/editdisplaymapping.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/editprms.aspx/ - 200
File found: /_app_bin/_layouts/1033/editsection.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/editdsserver.aspx/ - 200
File found: /_controltemplates/_layouts/1033/createmysite.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/editprofile.aspx/ - 200
Dir found: /_layouts/_layouts/1033/deletemu.aspx/ - 200
Dir found: /_layouts/_layouts/1033/deleteweb.aspx/ - 200
File found: /_app_bin/_layouts/1033/error.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/editgrp.aspx/ - 200
File found: /_controltemplates/_layouts/1033/createws.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/editproperty.aspx/ - 200
Dir found: /_layouts/_layouts/1033/discbar.aspx/ - 200
Dir found: /_layouts/_layouts/1033/displaymappings.aspx/ - 200
File found: /_app_bin/_layouts/1033/error.htm.aspx - 200
Dir found: /_controltemplates/_layouts/1033/editprms.aspx/ - 200
File found: /_controltemplates/_layouts/1033/cspp1.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/editrole.aspx/ - 200
Dir found: /_layouts/_layouts/1033/dladvopt.aspx/ - 200
File found: /_app_bin/_layouts/1033/filedlg.htm.aspx - 200
Dir found: /_controltemplates/_layouts/1033/editprofile.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/editsearchschedule.aspx/ - 200
File found: /_controltemplates/_layouts/1033/cspp2.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/dmworkspacemgmt.aspx/ - 200
File found: /_app_bin/_layouts/1033/filetypes.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/editproperty.aspx/ - 200
File found: /_controltemplates/_layouts/1033/default.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/fldedit.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/editsearchsettings.aspx/ - 200
Dir found: /_layouts/_layouts/1033/download.aspx/ - 200
File found: /_app_bin/_layouts/1033/fldnew.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/deletemu.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/editsection.aspx/ - 200
Dir found: /_layouts/_layouts/1033/dws.aspx/ - 200
Dir found: /_layouts/_layouts/1033/editalert.aspx/ - 200
File found: /_app_bin/_layouts/1033/folders.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/error.aspx/ - 200
File found: /_controltemplates/_layouts/1033/deleteweb.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/editdisplaymapping.aspx/ - 200
File found: /_app_bin/_layouts/1033/fontdlg.htm.aspx - 200
Dir found: /_controltemplates/_layouts/1033/editrole.aspx/ - 200
Dir found: /_layouts/1033/images/ - 403
File found: /_controltemplates/_layouts/1033/discbar.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/editdsserver.aspx/ - 200
File found: /_app_bin/_layouts/1033/formedt.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/editsearchschedule.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/editsearchsettings.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/editsection.aspx/ - 200
File found: /_controltemplates/_layouts/1033/displaymappings.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/editgrp.aspx/ - 200
File found: /_app_bin/_layouts/1033/global.asax.aspx - 200
Dir found: /_controltemplates/_layouts/1033/error.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/filetypes.aspx/ - 200
File found: /_controltemplates/_layouts/1033/dladvopt.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/editprms.aspx/ - 200
File found: /_app_bin/_layouts/1033/grpman.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/fldedit.aspx/ - 200
File found: /_controltemplates/_layouts/1033/dmworkspacemgmt.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/editprofile.aspx/ - 200
File found: /_app_bin/_layouts/1033/grpmbrs.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/download.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/fldnew.aspx/ - 200
Dir found: /_layouts/_layouts/1033/editproperty.aspx/ - 200
File found: /_app_bin/_layouts/1033/grpsel.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/filetypes.aspx/ - 200
File found: /_controltemplates/_layouts/1033/dws.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/folders.aspx/ - 200
Dir found: /_layouts/_layouts/1033/editrole.aspx/ - 200
File found: /_app_bin/_layouts/1033/help.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/fldnew.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/fldedit.aspx/ - 200
File found: /_controltemplates/_layouts/1033/editalert.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/editsearchschedule.aspx/ - 200
File found: /_app_bin/_layouts/1033/htmledit.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/hierarchyman.ascx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/formedt.aspx/ - 200
File found: /_controltemplates/_layouts/1033/editdisplaymapping.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/folders.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/formedt.aspx/ - 200
Dir found: /_layouts/_layouts/1033/editsearchsettings.aspx/ - 200
File found: /_app_bin/_layouts/1033/htmltranslate.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/editdsserver.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/editsection.aspx/ - 200
File found: /_app_bin/_layouts/1033/htmltrredir.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/grpman.aspx/ - 200
File found: /_controltemplates/_layouts/1033/editgrp.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/grpman.aspx/ - 200
Dir found: /_layouts/_layouts/1033/error.aspx/ - 200
File found: /_app_bin/_layouts/1033/htmltrverify.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/grpmbrs.aspx/ - 200
File found: /_controltemplates/_layouts/1033/editprms.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/grpmbrs.aspx/ - 200
File found: /_app_bin/_layouts/1033/iframe.htm.aspx - 200
File found: /_app_bin/_layouts/1033/iframe.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/grpsel.aspx/ - 200
File found: /_controltemplates/_layouts/1033/editprofile.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/grpsel.aspx/ - 200
File found: /_app_bin/_layouts/1033/images.aspx - 200
Dir found: /_controltemplates/_layouts/1033/help.aspx/ - 200
File found: /_controltemplates/_layouts/1033/editproperty.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/help.aspx/ - 200
File found: /_app_bin/_layouts/1033/importdata.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/editrole.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/filetypes.aspx/ - 200
File found: /_app_bin/_layouts/1033/infopage.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/htmledit.aspx/ - 200
File found: /_controltemplates/_layouts/1033/editsearchschedule.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/htmledit.aspx/ - 200
Dir found: /_layouts/_layouts/1033/fldedit.aspx/ - 200
File found: /_app_bin/_layouts/1033/instable.htm.aspx - 200
File found: /_controltemplates/_layouts/1033/editsearchsettings.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/htmltranslate.aspx/ - 200
Dir found: /_layouts/_layouts/1033/fldnew.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/htmltranslate.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/htmltrredir.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/htmltrverify.aspx/ - 200
File found: /_controltemplates/_layouts/1033/editsection.aspx.aspx - 200
java.net.SocketException: Connection reset
        at java.base/sun.nio.ch.NioSocketImpl.implRead(NioSocketImpl.java:328)
        at java.base/sun.nio.ch.NioSocketImpl.read(NioSocketImpl.java:355)
        at java.base/sun.nio.ch.NioSocketImpl$1.read(NioSocketImpl.java:808)
        at java.base/java.net.Socket$SocketInputStream.read(Socket.java:966)
        at java.base/java.io.BufferedInputStream.fill(BufferedInputStream.java:244)
        at java.base/java.io.BufferedInputStream.read(BufferedInputStream.java:263)
        at org.apache.commons.httpclient.HttpParser.readRawLine(HttpParser.java:78)
        at org.apache.commons.httpclient.HttpParser.readLine(HttpParser.java:106)
        at org.apache.commons.httpclient.HttpConnection.readLine(HttpConnection.java:1116)
        at org.apache.commons.httpclient.MultiThreadedHttpConnectionManager$HttpConnectionAdapter.readLine(MultiThreadedHttpConnectionManager.java:1413)
        at org.apache.commons.httpclient.HttpMethodBase.readStatusLine(HttpMethodBase.java:1973)
        at org.apache.commons.httpclient.HttpMethodBase.readResponse(HttpMethodBase.java:1735)
        at org.apache.commons.httpclient.HttpMethodBase.execute(HttpMethodBase.java:1098)
        at org.apache.commons.httpclient.HttpMethodDirector.executeWithRetry(HttpMethodDirector.java:398)
        at org.apache.commons.httpclient.HttpMethodDirector.executeMethod(HttpMethodDirector.java:171)
        at org.apache.commons.httpclient.HttpClient.executeMethod(HttpClient.java:397)
        at org.apache.commons.httpclient.HttpClient.executeMethod(HttpClient.java:323)
        at com.sittinglittleduck.DirBuster.utils.HeadRequestCheck.test(HeadRequestCheck.java:62)
        at com.sittinglittleduck.DirBuster.workGenerators.WorkerGeneratorMultiThreaded.run(WorkerGeneratorMultiThreaded.java:131)
        at java.base/java.lang.Thread.run(Thread.java:833)
java.net.SocketException: Connection reset
        at java.base/sun.nio.ch.NioSocketImpl.implRead(NioSocketImpl.java:328)
        at java.base/sun.nio.ch.NioSocketImpl.read(NioSocketImpl.java:355)
        at java.base/sun.nio.ch.NioSocketImpl$1.read(NioSocketImpl.java:808)
        at java.base/java.net.Socket$SocketInputStream.read(Socket.java:966)
        at java.base/java.io.BufferedInputStream.fill(BufferedInputStream.java:244)
        at java.base/java.io.BufferedInputStream.read(BufferedInputStream.java:263)
        at org.apache.commons.httpclient.HttpParser.readRawLine(HttpParser.java:78)
        at org.apache.commons.httpclient.HttpParser.readLine(HttpParser.java:106)
        at org.apache.commons.httpclient.HttpConnection.readLine(HttpConnection.java:1116)
        at org.apache.commons.httpclient.MultiThreadedHttpConnectionManager$HttpConnectionAdapter.readLine(MultiThreadedHttpConnectionManager.java:1413)
        at org.apache.commons.httpclient.HttpMethodBase.readStatusLine(HttpMethodBase.java:1973)
        at org.apache.commons.httpclient.HttpMethodBase.readResponse(HttpMethodBase.java:1735)
        at org.apache.commons.httpclient.HttpMethodBase.execute(HttpMethodBase.java:1098)
        at org.apache.commons.httpclient.HttpMethodDirector.executeWithRetry(HttpMethodDirector.java:398)
        at org.apache.commons.httpclient.HttpMethodDirector.executeMethod(HttpMethodDirector.java:171)
        at org.apache.commons.httpclient.HttpClient.executeMethod(HttpClient.java:397)
        at org.apache.commons.httpclient.HttpClient.executeMethod(HttpClient.java:323)
        at com.sittinglittleduck.DirBuster.utils.HeadRequestCheck.test(HeadRequestCheck.java:62)
        at com.sittinglittleduck.DirBuster.workGenerators.WorkerGeneratorMultiThreaded.run(WorkerGeneratorMultiThreaded.java:131)
        at java.base/java.lang.Thread.run(Thread.java:833)
Dir found: /_app_bin/_layouts/1033/htmltrredir.aspx/ - 200
ERROR: http://10.129.1.183:80/_app_bin/_layouts/1033/conngps.aspx/_admin/operations.aspx.txt - IOException Connection reset
Dir found: /_layouts/_layouts/1033/folders.aspx/ - 200
File found: /_app_bin/_layouts/1033/keywordbbman.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/error.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/iframe.aspx/ - 200
File found: /_app_bin/_layouts/1033/listcontentsources.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/htmltrverify.aspx/ - 200
File found: /_controltemplates/_layouts/1033/error.htm.aspx - 200
Dir found: /_layouts/_layouts/1033/formedt.aspx/ - 200
File found: /_app_bin/_layouts/1033/listedit.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/images/ - 403
Dir found: /_app_bin/_layouts/1033/infopage.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/importdata.aspx/ - 200
File found: /_app_bin/_layouts/1033/listindexes.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/iframe.aspx/ - 200
File found: /_controltemplates/_layouts/1033/filedlg.htm.aspx - 200
Dir found: /_layouts/_layouts/1033/grpman.aspx/ - 200
Dir found: /_layouts/_layouts/1033/grpmbrs.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/images/ - 403
File found: /_controltemplates/_layouts/1033/filetypes.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/keywordbbman.aspx/ - 200
Dir found: /_layouts/_layouts/1033/help.aspx/ - 200
Dir found: /_layouts/_layouts/1033/grpsel.aspx/ - 200
File found: /_app_bin/_layouts/1033/listsearchschedules.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/importdata.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/listcontentsources.aspx/ - 200
File found: /_controltemplates/_layouts/1033/fldedit.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/listsearchscopes.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/infopage.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/listedit.aspx/ - 200
File found: /_app_bin/_layouts/1033/logsummary.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/folders.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/fldnew.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/fontdlg.htm.aspx - 200
Dir found: /_layouts/_layouts/1033/htmledit.aspx/ - 200
File found: /_app_bin/_layouts/1033/logviewer.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/listindexes.aspx/ - 200
Dir found: /_layouts/_layouts/1033/htmltranslate.aspx/ - 200
File found: /_app_bin/_layouts/1033/lroperationstatus.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/keywordbbman.aspx/ - 200
File found: /_controltemplates/_layouts/1033/formedt.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/listsearchschedules.aspx/ - 200
Dir found: /_layouts/_layouts/1033/htmltrredir.aspx/ - 200
File found: /_app_bin/_layouts/1033/lstman.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/listsearchscopes.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/logsummary.aspx/ - 200
Dir found: /_layouts/_layouts/1033/htmltrverify.aspx/ - 200
File found: /_app_bin/_layouts/1033/lstman2.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/global.asax.aspx - 200
Dir found: /_layouts/_layouts/1033/iframe.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/listedit.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/listcontentsources.aspx/ - 200
File found: /_controltemplates/_layouts/1033/grpman.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/grpmbrs.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/logviewer.aspx/ - 200
ERROR: http://10.129.1.183:80/_controltemplates/_layouts/1033/confirmalert.aspx/_layouts/1033.aspx - IOException Connection reset
File found: /_app_bin/_layouts/1033/lstsetng.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/listindexes.aspx/ - 200
File found: /_controltemplates/_layouts/1033/grpsel.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/lroperationstatus.aspx/ - 200
File found: /_app_bin/_layouts/1033/mapproperty.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/listsearchschedules.aspx/ - 200
File found: /_controltemplates/_layouts/1033/help.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/lstman.aspx/ - 200
Dir found: /_layouts/_layouts/1033/importdata.aspx/ - 200
Dir found: /_layouts/_layouts/1033/infopage.aspx/ - 200
File found: /_app_bin/_layouts/1033/mcontent.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/listsearchscopes.aspx/ - 200
File found: /_app_bin/_layouts/1033/menu.htc.aspx - 200
Dir found: /_controltemplates/_layouts/1033/logsummary.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/lstsetng.aspx/ - 200
File found: /_controltemplates/_layouts/1033/hierarchyman.ascx.aspx - 200
Dir found: /_app_bin/_layouts/1033/lstman2.aspx/ - 200
Dir found: /_layouts/_layouts/1033/keywordbbman.aspx/ - 200
File found: /_app_bin/_layouts/1033/menubar.htc.aspx - 200
Dir found: /_controltemplates/_layouts/1033/logviewer.aspx/ - 200
File found: /_controltemplates/_layouts/1033/htmledit.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/mapproperty.aspx/ - 200
Dir found: /_layouts/_layouts/1033/listcontentsources.aspx/ - 200
File found: /_app_bin/_layouts/1033/mgrdsserver.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/lroperationstatus.aspx/ - 200
File found: /_controltemplates/_layouts/1033/htmltranslate.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/mcontent.aspx/ - 200
File found: /_app_bin/_layouts/1033/mgrproperty.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/lstman.aspx/ - 200
File found: /_controltemplates/_layouts/1033/htmltrredir.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/listedit.aspx/ - 200
File found: /_app_bin/_layouts/1033/mngdisc.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/lstman2.aspx/ - 200
File found: /_controltemplates/_layouts/1033/htmltrverify.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/iframe.htm.aspx - 200
File found: /_controltemplates/_layouts/1033/iframe.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/listindexes.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/lstsetng.aspx/ - 200
File found: /_controltemplates/_layouts/1033/images.aspx - 200
File found: /_app_bin/_layouts/1033/mngsubwebs.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/mapproperty.aspx/ - 200
File found: /_controltemplates/_layouts/1033/importdata.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/listsearchschedules.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/mcontent.aspx/ - 200
Dir found: /_layouts/_layouts/1033/listsearchscopes.aspx/ - 200
File found: /_app_bin/_layouts/1033/myalerts.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/mtgredir.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/myalerts.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/mngdisc.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/mtgredir.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/mgrproperty.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/mngsubwebs.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/mgrdsserver.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/mgrdsserver.aspx/ - 200
Dir found: /_layouts/_layouts/1033/logsummary.aspx/ - 200
File found: /_app_bin/_layouts/1033/mygrps.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/infopage.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/mgrproperty.aspx/ - 200
Dir found: /_layouts/_layouts/1033/logviewer.aspx/ - 200
File found: /_app_bin/_layouts/1033/myquicklinks.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/mygrps.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/mngsubwebs.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/mngdisc.aspx/ - 200
File found: /_controltemplates/_layouts/1033/instable.htm.aspx - 200
Dir found: /_layouts/_layouts/1033/lroperationstatus.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/myquicklinks.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/mtgredir.aspx/ - 200
Dir found: /_layouts/_layouts/1033/lstman.aspx/ - 200
File found: /_app_bin/_layouts/1033/mysiteheader.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/new.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/mysubs.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/mysiteheader.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/mygrps.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/myalerts.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/myquicklinks.aspx/ - 200
File found: /_app_bin/_layouts/1033/newalert.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/new.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/mysubs.aspx/ - 200
File found: /_controltemplates/_layouts/1033/keywordbbman.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/mysiteheader.aspx/ - 200
Dir found: /_layouts/_layouts/1033/lstman2.aspx/ - 200
File found: /_app_bin/_layouts/1033/newcatalog.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/newalertfromsts.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/listcontentsources.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/mysubs.aspx/ - 200
Dir found: /_layouts/_layouts/1033/lstsetng.aspx/ - 200
File found: /_app_bin/_layouts/1033/newdisplaymapping.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/listedit.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/new.aspx/ - 200
Dir found: /_layouts/_layouts/1033/mapproperty.aspx/ - 200
File found: /_app_bin/_layouts/1033/newdwp.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/listsearchschedules.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/listindexes.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/newfiletype.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/newgrp.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/newalert.aspx/ - 200
File found: /_controltemplates/_layouts/1033/listsearchscopes.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/mcontent.aspx/ - 200
File found: /_app_bin/_layouts/1033/newmws.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/newalertfromsts.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/newcatalog.aspx/ - 200
ERROR: http://10.129.1.183:80/_layouts/_layouts/1033/allgrps.aspx/50.php - IOException Connection reset
ERROR: http://10.129.1.183:80/_layouts/_layouts/1033/applyregionalsettings.aspx/60/ - IOException Connection reset
ERROR: http://10.129.1.183:80/_controltemplates/_layouts/1033/centraldatabaselock.aspx/_layouts/1033/alertdirectory.aspx.aspx - IOException Connection reset
ERROR: http://10.129.1.183:80/_controltemplates/_layouts/1033/audience_memberlist.aspx/3082.html - IOException Connection reset
ERROR: http://10.129.1.183:80/_controltemplates/_layouts/1033/centraldatabaselock.aspx/_layouts/1033/advsetng.aspx.aspx - IOException Connection reset
ERROR: http://10.129.1.183:80/_controltemplates/_layouts/1033/audience_memberlist.aspx/1033.html - IOException Connection reset
File found: /_controltemplates/_layouts/1033/logviewer.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/logsummary.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/newalertfromsts.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/newalert.aspx/ - 200
File found: /_app_bin/_layouts/1033/newsbweb.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/newdisplaymapping.aspx/ - 200
File found: /_app_bin/_layouts/1033/notesedit.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/newsiterule.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/newdwp.aspx/ - 200
File found: /_controltemplates/_layouts/1033/lroperationstatus.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/newcatalog.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/newfiletype.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/newgrp.aspx/ - 200
File found: /_controltemplates/_layouts/1033/lstman.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/newdisplaymapping.aspx/ - 200
Dir found: /_layouts/_layouts/1033/mgrdsserver.aspx/ - 200
File found: /_app_bin/_layouts/1033/noteswizard1.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/lstman2.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/newdwp.aspx/ - 200
File found: /_app_bin/_layouts/1033/noteswizard2.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/newmws.aspx/ - 200
File found: /_controltemplates/_layouts/1033/mapproperty.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/lstsetng.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/newfiletype.aspx/ - 200
File found: /_app_bin/_layouts/1033/noteswizard3.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/noteswizard4.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/password.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/newsbweb.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/newsiterule.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/notesedit.aspx/ - 200
ERROR: http://10.129.1.183:80/_layouts/_layouts/1033/catpp1.aspx/_layouts/1033/editproperty.aspx.php - IOException Connection reset
ERROR: http://10.129.1.183:80/_app_bin/_layouts/1033/confirmadvancedmode.aspx/_layouts/1033/autocat.aspx.html - IOException Connection reset
ERROR: http://10.129.1.183:80/_layouts/_layouts/1033/audience_main.aspx/_layouts/1033/aclinv.aspx.aspx - IOException Connection reset
ERROR: http://10.129.1.183:80/_app_bin/_layouts/1033/createmysite.aspx/_layouts/1033/cspp1.aspx.txt - IOException Connection reset
ERROR: http://10.129.1.183:80/_controltemplates/_layouts/1033/create.aspx/_layouts/1033/editgrp.aspx.aspx - IOException Connection reset
ERROR: http://10.129.1.183:80/_layouts/_layouts/1033/categorypickerpopup.aspx/_layouts/1033/createws.aspx.html - IOException Connection reset
File found: /_controltemplates/_layouts/1033/mcontent.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/mgrproperty.aspx/ - 200
File found: /_app_bin/_layouts/1033/personalsites.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/noteswizard2.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/noteswizard1.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/noteswizard3.aspx/ - 200
File found: /_controltemplates/_layouts/1033/menu.htc.aspx - 200
Dir found: /_app_bin/_layouts/1033/newgrp.aspx/ - 200
Dir found: /_layouts/_layouts/1033/mngsubwebs.aspx/ - 200
Dir found: /_layouts/_layouts/1033/myalerts.aspx/ - 200
Dir found: /_layouts/_layouts/1033/mtgredir.aspx/ - 200
Dir found: /_layouts/_layouts/1033/mngdisc.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/password.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/noteswizard4.aspx/ - 200
File found: /_controltemplates/_layouts/1033/menubar.htc.aspx - 200
Dir found: /_layouts/_layouts/1033/mygrps.aspx/ - 200
File found: /_app_bin/_layouts/1033/portal.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/pickercontainer.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/newmws.aspx/ - 200
Dir found: /_layouts/_layouts/1033/mysubs.aspx/ - 200
Dir found: /_layouts/_layouts/1033/mysiteheader.aspx/ - 200
Dir found: /_layouts/_layouts/1033/myquicklinks.aspx/ - 200
File found: /_app_bin/_layouts/1033/portalproperties.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/portalsettings.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/portalheader.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/personalsites.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/pickercontainer.aspx/ - 200
File found: /_controltemplates/_layouts/1033/mgrdsserver.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/newsbweb.aspx/ - 200
File found: /_app_bin/_layouts/1033/portalview.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/portal.aspx/ - 200
Dir found: /_layouts/_layouts/1033/new.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/portalheader.aspx/ - 200
File found: /_controltemplates/_layouts/1033/mgrproperty.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/newsiterule.aspx/ - 200
Dir found: /_layouts/_layouts/1033/newalert.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/portalproperties.aspx/ - 200
File found: /_controltemplates/_layouts/1033/mngdisc.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/notesedit.aspx/ - 200
Dir found: /_layouts/_layouts/1033/newalertfromsts.aspx/ - 200
File found: /_app_bin/_layouts/1033/profadminedit.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/portalsettings.aspx/ - 200
File found: /_controltemplates/_layouts/1033/mngsubwebs.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/noteswizard1.aspx/ - 200
Dir found: /_layouts/_layouts/1033/newdisplaymapping.aspx/ - 200
Dir found: /_layouts/_layouts/1033/newcatalog.aspx/ - 200
ERROR: http://10.129.1.183:80/_layouts/_layouts/1033/addrole.aspx/_layouts/1033/accessdeniedpage.aspx.txt - IOException Connection reset
ERROR: http://10.129.1.183:80/_app_bin/_layouts/1033/createws.aspx/_layouts/1033/editsearchschedule.aspx.txt - IOException Connection reset
ERROR: http://10.129.1.183:80/_layouts/_layouts/1033/addrole.aspx/_layouts/1033.txt - IOException Connection reset
ERROR: http://10.129.1.183:80/_catalogs/wp/forms/allitems.aspx/_layouts/1033/images.aspx - IOException Connection reset
ERROR: http://10.129.1.183:80/_controltemplates/_layouts/1033/audience_view.aspx/_layouts/1033/addgrp1.aspx.asp - IOException Connection reset
ERROR: http://10.129.1.183:80/_layouts/_layouts/1033/addrole.aspx/_layouts.txt - IOException Connection reset
File found: /_app_bin/_layouts/1033/profmain.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/profadminedit.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/portalview.aspx/ - 200
File found: /_controltemplates/_layouts/1033/myalerts.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/mtgredir.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/noteswizard2.aspx/ - 200
Dir found: /_layouts/_layouts/1033/newdwp.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/profmain.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/noteswizard3.aspx/ - 200
Dir found: /_layouts/_layouts/1033/newfiletype.aspx/ - 200
File found: /_app_bin/_layouts/1033/profmngr.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/profmngr.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/profnew.aspx/ - 200
File found: /_controltemplates/_layouts/1033/mygrps.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/noteswizard4.aspx/ - 200
Dir found: /_layouts/_layouts/1033/newgrp.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/progresspage.aspx/ - 200
File found: /_controltemplates/_layouts/1033/myquicklinks.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/personalsites.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/password.aspx/ - 200
Dir found: /_layouts/_layouts/1033/newmws.aspx/ - 200
File found: /_app_bin/_layouts/1033/profnew.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/properties.aspx/ - 200
File found: /_controltemplates/_layouts/1033/mysiteheader.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/newsbweb.aspx/ - 200
File found: /_app_bin/_layouts/1033/progresspage.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/propertyproperties.aspx/ - 200
File found: /_controltemplates/_layouts/1033/mysubs.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/proxy.aspx/ - 200
File found: /_controltemplates/_layouts/1033/new.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/pickercontainer.aspx/ - 200
Dir found: /_layouts/_layouts/1033/newsiterule.aspx/ - 200
File found: /_app_bin/_layouts/1033/properties.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/publishback.aspx/ - 200
File found: /_controltemplates/_layouts/1033/newalert.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/notesedit.aspx/ - 200
File found: /_app_bin/_layouts/1033/proxy.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/propertyproperties.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/qstedit.aspx/ - 200
Dir found: /_layouts/_layouts/1033/noteswizard1.aspx/ - 200
File found: /_app_bin/_layouts/1033/publishback.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/qstnew.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/portal.aspx/ - 200
File found: /_app_bin/_layouts/1033/qstedit.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/quicklinks.aspx/ - 200
File found: /_controltemplates/_layouts/1033/newalertfromsts.aspx.aspx - 200
Dir found: /_layouts/_layouts/1033/noteswizard2.aspx/ - 200
Dir found: /_layouts/_layouts/1033/noteswizard3.aspx/ - 200
File found: /_app_bin/_layouts/1033/qstnew.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/quicklinks.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/newcatalog.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/newdisplaymapping.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/portalheader.aspx/ - 200
File found: /_app_bin/_layouts/1033/rcxform.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_admin/operations.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/rcxform.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/portalproperties.aspx/ - 200
Dir found: /_layouts/_layouts/1033/noteswizard4.aspx/ - 200
File found: /_app_bin/_layouts/1033/redirect.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/regionalsetng.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/redirect.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_admin/operations.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/portalsettings.aspx/ - 200
Dir found: /_layouts/_layouts/1033/password.aspx/ - 200
File found: /_app_bin/_layouts/1033/regionalsetng.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/newdwp.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/portalview.aspx/ - 200
Dir found: /_layouts/_layouts/1033/personalsites.aspx/ - 200
File found: /_app_bin/_layouts/1033/reorder.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_catalogs/masterpage/forms/allitems.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/reorder.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/report.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_catalogs/masterpage/forms/allitems.aspx/ - 200
File found: /_controltemplates/_layouts/1033/newfiletype.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/profadminedit.aspx/ - 200
Dir found: /_controltemplates/_layouts/_admin/operations.aspx/ - 200
Dir found: /_layouts/_layouts/1033/pickercontainer.aspx/ - 200
File found: /_app_bin/_layouts/1033/report.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_catalogs/wt/forms/common.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/_catalogs/wp/forms/allitems.aspx/ - 200
Dir found: /_app_bin/_layouts/_admin/operations.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/reporthome.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/profmain.aspx/ - 200
Dir found: /_controltemplates/_layouts/_catalogs/masterpage/forms/allitems.aspx/ - 200
File found: /_app_bin/_layouts/1033/reporthome.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/reqacc.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_catalogs/wp/forms/allitems.aspx/ - 200
File found: /_controltemplates/_layouts/1033/newgrp.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/newmws.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/profmngr.aspx/ - 200
Dir found: /_controltemplates/_layouts/_catalogs/wp/forms/allitems.aspx/ - 200
Dir found: /_layouts/_layouts/1033/portal.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/_catalogs/lt/forms/allitems.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/rfcxform.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_catalogs/wt/forms/common.aspx/ - 200
File found: /_controltemplates/_layouts/1033/newsbweb.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/profnew.aspx/ - 200
Dir found: /_controltemplates/_layouts/_catalogs/wt/forms/common.aspx/ - 200
Dir found: /_layouts/_layouts/1033/portalheader.aspx/ - 200
File found: /_app_bin/_layouts/1033/reqacc.aspx.aspx - 200
Dir found: /_app_bin/_layouts/_catalogs/masterpage/forms/allitems.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/rfpxform.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_catalogs/lt/forms/allitems.aspx/ - 200
File found: /_controltemplates/_layouts/1033/newsiterule.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/progresspage.aspx/ - 200
Dir found: /_controltemplates/_layouts/_catalogs/lt/forms/allitems.aspx/ - 200
Dir found: /_layouts/_layouts/1033/portalproperties.aspx/ - 200
File found: /_app_bin/_layouts/1033/rfcxform.aspx.aspx - 200
Dir found: /_app_bin/_layouts/_catalogs/wp/forms/allitems.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/role.aspx/ - 200
File found: /_controltemplates/_layouts/1033/notesedit.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/properties.aspx/ - 200
Dir found: /_layouts/_layouts/1033/portalsettings.aspx/ - 200
File found: /_app_bin/_layouts/1033/rfpxform.aspx.aspx - 200
Dir found: /_app_bin/_layouts/_catalogs/wt/forms/common.aspx/ - 200
File found: /_controltemplates/_layouts/1033/noteswizard1.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/propertyproperties.aspx/ - 200
Dir found: /_layouts/_layouts/1033/portalview.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/accessdeniedpage.aspx/ - 200
Dir found: /_app_bin/_layouts/_catalogs/lt/forms/allitems.aspx/ - 200
File found: /_controltemplates/_layouts/1033/noteswizard2.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/noteswizard3.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/proxy.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/publishback.aspx/ - 200
Dir found: /_layouts/_layouts/1033/profadminedit.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/aclinv.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/savetmpl.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/accessdeniedpage.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/qstedit.aspx/ - 200
Dir found: /_layouts/_layouts/1033/profmain.aspx/ - 200
File found: /_app_bin/_layouts/1033/role.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/savetmpl.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/scsignup.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/aclver.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/scsignup.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/aclinv.aspx/ - 200
File found: /_controltemplates/_layouts/1033/noteswizard4.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/qstnew.aspx/ - 200
Dir found: /_layouts/_layouts/1033/profmngr.aspx/ - 200
File found: /_app_bin/_layouts/1033/searchresults.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/addgrp1.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/searchresults.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/aclver.aspx/ - 200
java.net.SocketException: Connection reset
        at java.base/sun.nio.ch.NioSocketImpl.implRead(NioSocketImpl.java:328)
        at java.base/sun.nio.ch.NioSocketImpl.read(NioSocketImpl.java:355)
        at java.base/sun.nio.ch.NioSocketImpl$1.read(NioSocketImpl.java:808)
        at java.base/java.net.Socket$SocketInputStream.read(Socket.java:966)
        at java.base/java.io.BufferedInputStream.fill(BufferedInputStream.java:244)
        at java.base/java.io.BufferedInputStream.read(BufferedInputStream.java:263)
        at org.apache.commons.httpclient.HttpParser.readRawLine(HttpParser.java:78)
        at org.apache.commons.httpclient.HttpParser.readLine(HttpParser.java:106)
        at org.apache.commons.httpclient.HttpConnection.readLine(HttpConnection.java:1116)
        at org.apache.commons.httpclient.MultiThreadedHttpConnectionManager$HttpConnectionAdapter.readLine(MultiThreadedHttpConnectionManager.java:1413)
        at org.apache.commons.httpclient.HttpMethodBase.readStatusLine(HttpMethodBase.java:1973)
        at org.apache.commons.httpclient.HttpMethodBase.readResponse(HttpMethodBase.java:1735)
        at org.apache.commons.httpclient.HttpMethodBase.execute(HttpMethodBase.java:1098)
        at org.apache.commons.httpclient.HttpMethodDirector.executeWithRetry(HttpMethodDirector.java:398)
        at org.apache.commons.httpclient.HttpMethodDirector.executeMethod(HttpMethodDirector.java:171)
        at org.apache.commons.httpclient.HttpClient.executeMethod(HttpClient.java:397)
        at org.apache.commons.httpclient.HttpClient.executeMethod(HttpClient.java:323)
        at com.sittinglittleduck.DirBuster.utils.HeadRequestCheck.test(HeadRequestCheck.java:62)
        at com.sittinglittleduck.DirBuster.workGenerators.WorkerGeneratorMultiThreaded.run(WorkerGeneratorMultiThreaded.java:131)
        at java.base/java.lang.Thread.run(Thread.java:833)
ERROR: http://10.129.1.183:80/_controltemplates/_layouts/1033/create.aspx/_layouts/1033/listsearchscopes.aspx.aspx - IOException Connection reset
ERROR: http://10.129.1.183:80/_app_bin/_layouts/1033/catman.aspx/_layouts/1033/dmworkspacemgmt.aspx.txt - IOException Connection reset
ERROR: http://10.129.1.183:80/_controltemplates/_layouts/1033/profmain.aspx/_catalogs/wt/forms/common.aspx.php - IOException Connection reset
ERROR: http://10.129.1.183:80/_controltemplates/_layouts/1033/audience_memberlist.aspx/_layouts/1033/copyrole.aspx.html - IOException Connection reset
java.net.SocketException: Connection reset
        at java.base/sun.nio.ch.NioSocketImpl.implRead(NioSocketImpl.java:328)
        at java.base/sun.nio.ch.NioSocketImpl.read(NioSocketImpl.java:355)
        at java.base/sun.nio.ch.NioSocketImpl$1.read(NioSocketImpl.java:808)
        at java.base/java.net.Socket$SocketInputStream.read(Socket.java:966)
        at java.base/java.io.BufferedInputStream.fill(BufferedInputStream.java:244)
        at java.base/java.io.BufferedInputStream.read(BufferedInputStream.java:263)
        at org.apache.commons.httpclient.HttpParser.readRawLine(HttpParser.java:78)
        at org.apache.commons.httpclient.HttpParser.readLine(HttpParser.java:106)
        at org.apache.commons.httpclient.HttpConnection.readLine(HttpConnection.java:1116)
        at org.apache.commons.httpclient.MultiThreadedHttpConnectionManager$HttpConnectionAdapter.readLine(MultiThreadedHttpConnectionManager.java:1413)
        at org.apache.commons.httpclient.HttpMethodBase.readStatusLine(HttpMethodBase.java:1973)
        at org.apache.commons.httpclient.HttpMethodBase.readResponse(HttpMethodBase.java:1735)
        at org.apache.commons.httpclient.HttpMethodBase.execute(HttpMethodBase.java:1098)
        at org.apache.commons.httpclient.HttpMethodDirector.executeWithRetry(HttpMethodDirector.java:398)
        at org.apache.commons.httpclient.HttpMethodDirector.executeMethod(HttpMethodDirector.java:171)
        at org.apache.commons.httpclient.HttpClient.executeMethod(HttpClient.java:397)
        at org.apache.commons.httpclient.HttpClient.executeMethod(HttpClient.java:323)
        at com.sittinglittleduck.DirBuster.utils.HeadRequestCheck.test(HeadRequestCheck.java:62)
        at com.sittinglittleduck.DirBuster.workGenerators.WorkerGeneratorMultiThreaded.run(WorkerGeneratorMultiThreaded.java:131)
        at java.base/java.lang.Thread.run(Thread.java:833)
File found: /_controltemplates/_layouts/1033/password.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/quicklinks.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/accessdeniedpage.aspx/ - 200
Dir found: /_layouts/_layouts/1033/profnew.aspx/ - 200
File found: /_app_bin/_layouts/1033/searchscope.aspx.aspx - 200
Dir found: /_app_bin/_layouts/_layouts/1033/accessdeniedpage.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/searchscope.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/addgrp1.aspx/ - 200
File found: /_controltemplates/_layouts/1033/personalsites.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/aclinv.aspx/ - 200
Dir found: /_layouts/_layouts/1033/progresspage.aspx/ - 200
File found: /_app_bin/_layouts/1033/searchsettings.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/addgrp2.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/aclinv.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/searchsettings.aspx/ - 200
File found: /_controltemplates/_layouts/1033/pickercontainer.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/rcxform.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/aclver.aspx/ - 200
Dir found: /_layouts/_layouts/1033/properties.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/addrole.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/aclver.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/addgrp2.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/regionalsetng.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/redirect.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/addgrp1.aspx/ - 200
Dir found: /_layouts/_layouts/1033/propertyproperties.aspx/ - 200
File found: /_app_bin/_layouts/1033/selcolor.htm.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/advsetng.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/addgrp1.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/addrole.aspx/ - 200
File found: /_controltemplates/_layouts/1033/portal.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/reorder.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/report.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/addgrp2.aspx/ - 200
Dir found: /_layouts/_layouts/1033/proxy.aspx/ - 200
File found: /_app_bin/_layouts/1033/setimport.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/selectuser.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/setanon.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/alertdirectory.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/addgrp2.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/selectuser.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/advsetng.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/reporthome.aspx/ - 200
Dir found: /_layouts/_layouts/1033/publishback.aspx/ - 200
File found: /_app_bin/_layouts/1033/setrqacc.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/alertserror.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/alertsadmin.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/setanon.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/alertdirectory.aspx/ - 200
File found: /_controltemplates/_layouts/1033/portalheader.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/reqacc.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/addrole.aspx/ - 200
Dir found: /_layouts/_layouts/1033/qstedit.aspx/ - 200
File found: /_app_bin/_layouts/1033/settings.aspx.aspx - 200
Dir found: /_app_bin/_layouts/_layouts/1033/addrole.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/setimport.aspx/ - 200
File found: /_controltemplates/_layouts/1033/portalproperties.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/portalsettings.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/rfcxform.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/advsetng.aspx/ - 200
Dir found: /_layouts/_layouts/1033/qstnew.aspx/ - 200
File found: /_app_bin/_layouts/1033/shropt.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/allgrps.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/alertdirectory.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/advsetng.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/setrqacc.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/alertsadmin.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/rfpxform.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/alertdirectory.aspx/ - 200
Dir found: /_layouts/_layouts/1033/quicklinks.aspx/ - 200
File found: /_app_bin/_layouts/1033/sitelist.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/applyregionalsettings.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/alertsadmin.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/settings.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/alertserror.aspx/ - 200
File found: /_controltemplates/_layouts/1033/portalview.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/role.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/savetmpl.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/scsignup.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/alertsadmin.aspx/ - 200
Dir found: /_layouts/_layouts/1033/rcxform.aspx/ - 200
File found: /_app_bin/_layouts/1033/siteoperationrefuse.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/associateportal.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/alertserror.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/sitelist.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/shropt.aspx/ - 200
File found: /_controltemplates/_layouts/1033/profmain.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/profadminedit.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/searchresults.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/alertserror.aspx/ - 200
Dir found: /_layouts/_layouts/1033/redirect.aspx/ - 200
File found: /_app_bin/_layouts/1033/sitepp1.aspx.aspx - 200
Dir found: /_app_bin/_layouts/_layouts/1033/allgrps.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/siteoperationrefuse.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/allgrps.aspx/ - 200
File found: /_controltemplates/_layouts/1033/profmngr.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/searchscope.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/allgrps.aspx/ - 200
Dir found: /_layouts/_layouts/1033/regionalsetng.aspx/ - 200
File found: /_app_bin/_layouts/1033/sitesubs.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/audience_chooser.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/audience_chooser2.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/applyregionalsettings.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/associateportal.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/sitepp1.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/applyregionalsettings.aspx/ - 200
File found: /_controltemplates/_layouts/1033/profnew.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/applyregionalsettings.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/associateportal.aspx/ - 200
Dir found: /_layouts/_layouts/1033/reorder.aspx/ - 200
File found: /_app_bin/_layouts/1033/siteusrs.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/audience_defruleedit.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/audience_chooser.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/sitesubs.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/audience_chooser2.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/associateportal.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/audience_chooser.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/searchsettings.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/audience_chooser.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/audience_edit.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/audience_chooser2.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/siteusrs.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/audience_defruleedit.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/audience_chooser2.aspx/ - 200
Dir found: /_layouts/_layouts/1033/report.aspx/ - 200
File found: /_app_bin/_layouts/1033/spanon.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/spaddrole.aspx.aspx - 200
Dir found: /_app_bin/_layouts/_layouts/1033/audience_defruleedit.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/audience_edit.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/spaddrole.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/spanon.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/audience_edit.aspx/ - 200
File found: /_controltemplates/_layouts/1033/progresspage.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/selectuser.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/audience_defruleedit.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/audience_edit.aspx/ - 200
File found: /_app_bin/_layouts/1033/spcataddperm.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/audience_list.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/audience_list.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/spcataddperm.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/audience_list.aspx/ - 200
File found: /_controltemplates/_layouts/1033/properties.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/setanon.aspx/ - 200
Dir found: /_layouts/_layouts/1033/reporthome.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/audience_main.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/audience_main.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/spcateditperm.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/audience_main.aspx/ - 200
File found: /_controltemplates/_layouts/1033/propertyproperties.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/setimport.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/audience_list.aspx/ - 200
Dir found: /_layouts/_layouts/1033/reqacc.aspx/ - 200
File found: /_app_bin/_layouts/1033/spcateditperm.aspx.aspx - 200
File found: /_app_bin/_layouts/1033/spcatsec.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/audience_memberlist.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/audience_memberlist.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/spcatsec.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/audience_memberlist.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/audience_sched.aspx/ - 200
File found: /_controltemplates/_layouts/1033/publishback.aspx.aspx - 200
File found: /_controltemplates/_layouts/1033/proxy.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/setrqacc.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/images/_admin/operations.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/audience_main.aspx/ - 200
Dir found: /_layouts/_layouts/1033/rfcxform.aspx/ - 200
File found: /_app_bin/_layouts/1033/spcf.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/audience_sched.aspx/ - 200
Dir found: /_app_bin/_layouts/_layouts/1033/audience_sched.aspx/ - 200
Dir found: /_controltemplates/_layouts/1033/spcf.aspx/ - 200
Dir found: /_app_bin/_layouts/1033/_layouts/1033/audience_view.aspx/ - 200
File found: /_controltemplates/_layouts/1033/qstedit.aspx.aspx - 200
Dir found: /_app_bin/_layouts/1033/settings.aspx/ - 200
Dir found: /_controltemplates/_layouts/_layouts/1033/audience_memberlist.aspx/ - 200
Dir found: /_layouts/_layouts/1033/rfpxform.aspx/ - 200
File found: /_app_bin/_layouts/1033/spcontnt.aspx.aspx - 200
Dir found: /_controltemplates/_layouts/1033/_layouts/1033/audience_view.aspx/ - 200


```
