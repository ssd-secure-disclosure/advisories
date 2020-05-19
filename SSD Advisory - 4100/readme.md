 **Vulnerability Summary**

The update functionality of the Cisco AnyConnect Secure Mobility Client for Windows is affected by a path traversal vulnerability that allows local attackers to create/overwrite files in arbitrary locations. Successful exploitation of this vulnerability allows the attacker to gain `SYSTEM` privileges.

**Credit**

An independent Security Researcher has reported this vulnerability to SSD Secure Disclosure program.

**Affected Systems**

Cisco AnyConnect Secure Mobility Client for Windows, Version 4.8.01090.

**Vendor Response**

Placeholder

**Vulnerability Details**

Cisco AnyConnect Secure Mobility Client contains functionality to auto-update itself. Auto-update also works for low-privileged users, which is possible because the update is initiated from a service called `Cisco AnyConnect Secure Mobility Agent` and is running with `SYSTEM` privileges. This service exposes TCP port 62522 on the loopback device to which clients can connect and send commands to be handled by this service. One of these command is to launch the `vpndownloader` application and update AnyConnect.

A path traversal vulnerability exists in the `vpndownloader` application for Windows that allows a local user to create and run files outside of the temporary installer folder. Successful exploitation of this vulnerability allows a local attacker to gain `SYSTEM` privileges.

The AnyConnect auto-update functionality has been affected by a number of vulnerabilities in the past that can be abused by local users to gain SYSTEM privileges (eg. [Kostya Kortchinsky](https://expertmiami.blogspot.nl/2015/06/cisco-anyconnect-secure-mobility-client.html), [Securify](https://www.securify.nl/advisory/SFY20150601/cisco-anyconnect-elevation-of-privileges-via-dll-side-loading.html), [Project Zero](https://bugs.chromium.org/p/project-zero/issues/detail?id=460), [SerializingMe](https://www.serializing.me/2016/12/14/anyconnect-elevation-of-privileges-part-1/)). Cisco has made a number of changes to mitigate these attacks, amongst these changes are:

- Executables need to have a valid Authenticode signature from `Cisco Systems, Inc`.
- (New) versions of `vpndownloader.exe` are copied to `%ProgramData%\Cisco\Cisco AnyConnect Secure Mobility Client\Temp\Downloader`.
- Proper NTFS Permissions are (now) set on the `%ProgramData%\Cisco\Cisco AnyConnect Secure Mobility Client\` folder.
- the `vpndownloader.exe` executable must have `vpndownloader.exe` configured as the original filename in its version information.
- When `vpndownloader.exe` launches additional installation files, these files also need to have a valid Authenticode signature from `Cisco Systems, Inc.`.
- Installation files are copied in a separate temporary folder under `%ProgramData%\Cisco\Cisco AnyConnect Secure Mobility Client\Temp\Installer` before they are executed.

In a nutshell, the auto-update mechanism works by send a message to the AnyConnect Agent to launch `vpndownloader.exe` and instruct it to perform a certain action (as command line argument). This action is either moving/copying a profile (XML) file to a profile folder or launch a Cisco signed installer file. Technically, this doesn’t need to be an installer file, any Cisco signed executable will do. When `vpndownloader.exe` is instructed to run an installer file, the file is first copied to a temporary folder under `%ProgramData%\Cisco\Cisco AnyConnect Secure Mobility Client\Temp\Installer`. After the file has been copied, the digital signature is checked including the signer of the file. If all checks out, the file is launched from the temporary folder and the folder is deleted after execution has completed.

Because the executable is copied to a new temporary folder, and the folder has proper NTFS permissions, it is not possible to perform a file/DLL planting attack to run arbitrary code. In addition, the file must be signed by Cisco and the signature must be valid, preventing the execution of arbitrary executables.

A path traversal vulnerability exists in the step where the (user-supplied) executable is copied into the temporary folder. `vpndownloader.exe` will extract the target file name from the source file name. Essentially it does this by searching for the last occurrence of the backslash (\) character in the source path, the right part after the backslash is treated as the filename and is used as the target file name. AnyConnect does not take into account that the Windows API also accepts the forward slash (/) as directory separator character. Because of this it is possible to cause `vpndownloader.exe` to create files outside its temporary folder.

Since the signature verification is done after the file is copied, it is possible for an attacker to copy any file to any location residing on the same volume as `%ProgramData%` (generally C:\). Copying of the file is done with `SYSTEM` privileges - when `vpndownloader.exe` is launched through the AnyConnect Agent. If the target file exists and `SYSTEM` has write access to this file, it will be overwritten with the attacker-supplied file. This alone is enough for a local user to gain elevated privileges.

Another attack scenario is to hijack a DLL that is loaded by a Cisco signed executable. Most Cisco executables are affected by DLL hijacking, a common DLL that is used by Cisco applications is the `dbghelp.dll` file. The attack consists of two steps:

1. Create an attacker-controlled `dbghelp.dll` file outside of the temporary folder to prevent removal, traversing one folder up is enough.
2. Launch a Cisco signed executable which is vulnerable to DLL hijacking from the same folder, again using the path traversal vulnerability.

When the Cisco signed executable is launched through the AnyConnect Agent, it will also run with `SYSTEM` privileges. The code in the attacker-controlled DLL will also run with these privileges. The application itself is opened within `Session 0`. Windows 10 1803 has [removed](https://docs.microsoft.com/en-us/windows/deployment/planning/windows-10-removed-features) the `Interactive Services Detection Service`, which makes it impossible for users to interact with any GUI displayed in `Session 0`. This of course does nothing to stop an attacker from gaining `SYSTEM` privileges, but it does require an additional step for the attacker to launch a GUI application with elevated privileges.

**Exploit**

The POC is a PowerShell module which has the function Invoke-ExploitAnyConnectPathTraversal. This function has two modes.

**Without arguments:**

This mode tries to hijack `%ProgramFiles%\Common Files\microsoft shared\ink\HID.dll`, which is used by the on-screen keyboard. Run the following commands in a PowerShell prompt:

1. Import-Module .-ExploitAnyConnectPathTraversal.psm1
2. Invoke-ExploitAnyConnectPathTraversal
3. Lock the Windows session or sign out
4. Open accessibility tools in the login screen and launch the on-screen keyboard

A PowerShell prompt should open (behind the keyboard) running as `SYSTEM`. (Note that the on-screen keyboard of Windows 7 isn’t affected by this DLL hijack).

**With arguments:**

Running the function with arguments will create three files within `%ProgramData%\Cisco\Cisco AnyConnect Secure Mobility Client\Temp\Installer`:

- payload.bat
- dbghelp.dll
- cstub.exe

`cstub.exe` is a Cisco signed executable, which will be launched by `vpndownloader`. `dbghelp.dll` is hijacked to run `payload.bat`. The provided argument(s) are written to `payload.bat` and thus will run as `SYSTEM`.

1. Import-Module .-ExploitAnyConnectPathTraversal.psm1
2. Invoke-ExploitAnyConnectPathTraversal

You can find the exploit in: [POC Folder](\POC)