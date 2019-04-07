**Vulnerability Summary**<br>
An ASUSTOR NAS or network attached storage is “a computer appliance built from the ground up for storing and serving files. It attaches directly to a network, allowing those on the network to access and share files from a central location”. In the following advisory we will discuss a vulnerability found inside ASUSTOR NAS which lets anonymous attackers bypass authentication requirement of the product.

**Credit**<br>
An independent security researcher, Ahmed Y. Elmogy, has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
ASUSTOR NAS devices running ADM version 3.0.5.RDU1 and prior

**Vulnerability Details**<br>
The vulnerability lies in the web interface of ASUSTOR NAS, in the file located in /initial/index.cgi, which responsible for initializing the device with your ASUSTOR ID. The problem is that this file is always available even after the first initialization, and it doesn’t require any authentication at all.
So by abusing /initial/index.cgi?act=register, you’ll be logged in with the administrator privileges without any kind of authentication.

**How to Exploit**<br>
Visit:<br>
`http://<IP_ADDR>:<NAS_PORT>/initial/index.cgi?act=register`<br>
(Port will probably be 8800)<br>
Check “Register later”, click on next, and press the “Start” button. You’ll be redirected to /portal/index.cgi with a sid parameter, bypassing the authentication, and accessing the web interface with admin privileges.
