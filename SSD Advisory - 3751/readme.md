**Vulnerability Summary**<br>
Android 8.1 has introduced the new feature of a default printing service. This service, based on the very similar, freely available Mopria Alliance Print Service on the Google Play Store, suffers from a lack of validation which can lead to both man in the middle attacks and subsequent interception of print jobs, as well as an issue that results in potentially unsafe printing devices to be used without any sort of warning or confirmation.

**Credit**<br>
An independent security researcher, Matt Parnell, has reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
Android 8.1 Default Printing Service
Vendor Response
“The Android Security Team has conducted an initial severity assessment on this report. Based on our published severity assessment matrix (1) it was rated as not being a security vulnerability that would meet the severity bar for inclusion in an Android security bulletin. If you have additional information that you believe we should use to reassess this report, please let us know.
The Resolution Notes label has been set to NSBC (Not Security Bulletin Class) to reflect this assessment.”

**Vulnerability Details**<br>
Lets look at the New Android 8.1 Default Printing Service:<br>

<img src="https://blogs.securiteam.com/wp-content/uploads/2018/08/android-print-service.png">
When a user uses the “add manual printer” feature, such as with an IPP printer, they may assume that the system is context aware. This is however not the case, and so should the device connect to a malicious network, or to a man in the middle network, such as a Pineapple, all that operator has to do is either:<br>
1. Spoof a hostname that is known to be the printer used by the target and provide an IPP compatible service in it’s place
2. Provide an IPP service at the device’s expected IP address

<img src="https://blogs.securiteam.com/wp-content/uploads/2018/09/Adding-a-printer-by-ip-or-host.png"><br>

<img src="https://blogs.securiteam.com/wp-content/uploads/2018/09/printing-to-a-spoofed-ipp-printer.png"><br>

Both of these options will work on ANY connected network, and as such, as long as they have been configured, an attacker can simply be on the same network providing the proper hostname or IP, and intercept print jobs. Of course, in such situations, penetrating the target’s usual network for printing, or using a pineapple in between the target and the network would be the most successful method. That said, Android by default will preselect the last used printer, even if it is not detected/connected, or connected to the network the printer was added or used on, and as such, careless users are likely to simply select print without even looking. In the test above, we printed using the IPP service here. The only modification was to change it to use the default IPP port 631: https://github.com/watson/ipp-printer
Any printer will do – As a secondary attack vector, the new print service is nice enough to aggregate a list of available printers using mDNS, which can be poisoned, or an attacker can simply provide one or more realistic virtual printers using the Common Unix Printing System (CUPS). Using names that sound like real printers, or by using devices named such as “Hotel Business Center Printer,” an attacker is sure to show up in the selectable list of printers when a user goes to print on their Android 8.1 device. No validation is performed whatsoever, and the user does not have to confirm the use or addition of a given printer before they can print. Fire and forget!
Below: our fake, autodetected CUPS printers in action.<br>
<img src="https://blogs.securiteam.com/wp-content/uploads/2018/09/cups-mitm.png"><br>
<img src="https://blogs.securiteam.com/wp-content/uploads/2018/09/cups-mitm2.png"><br>

In either case, once the fake devices are active, an attacker may either capture the print jobs and leave, or to add an extra level of stealth, actually print the jobs once intercepted so that the target is none the wiser. Imagine the possibilities!
