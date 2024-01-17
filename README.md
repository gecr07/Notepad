# Notepad

Todo lo que tengo pendiente por revisar


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
