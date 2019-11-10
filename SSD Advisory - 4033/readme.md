# SSD Advisory - OpenSSH Pre-Auth XMSS Integer Overflow

**Vulnerability Summary**  
The following advisory describes a Pre-Auth Integer Overflow in the XMSS Key Parsing Algorithm in OpenSSH.

**CVE**  
CVE-2019-16905

**Credit**  
An independent Security Researcher, Adam "pi3" Zabrocki, has reported this vulnerability to SSD Secure Disclosure program.

**Affected Systems**  
OpenSSH version 7.7 up to the latest one (8.0) supporting XMSS keys (compiled with a defined WITH_XMSS macro).  
Nevertheless, the bug is only there when OpenSSH is compiled via a compiler with data model ILP64, LLP64 or ILP32 (e.g. any 32 bits systems).

**Vendor Response**  
[The vulnerability was fixed in OpenSSH version 8.1](https://www.openssh.com/releasenotes.html)

**Vulnerability Details**

**OpenSSH**

OpenSSH is a free version of the SSH connectivity tools which technical users of the Internet rely on. Users of telnet, rlogin, and ftp may not realize that their password is transmitted across the Internet unencrypted, but in fact it is.  
OpenSSH encrypts all traffic (including passwords) to effectively eliminate eavesdropping, connection hijacking, and other attacks. Additionally, OpenSSH provides secure tunneling capabilities and several authentication methods, and supports all SSH protocol versions.

OpenSSH supports several signing algorithms (for authentication keys) which can be divided in two groups depending on the mathematical properties they exploit:

*   DSA and RSA, which rely on the practical difficulty of factoring the product of two large prime numbers
*   ECDSA and Ed25519, which rely on the elliptic curve discrete logarithm problem

Elliptic curve cryptography (ECC) algorithms are a more recent addition to public key cryptosystems. One of their main advantages is their ability to provide the same level of security with smaller keys, which makes for less computationally intensive operations (i.e. faster key creation, encryption and decryption) and reduced storage and transmission requirements.

OpenSSH 7.7 add experimental support for PQC (Post Quantum Cryptography) XMSS keys (Extended Hash-Based Signatures) is designed to work in Post Quantum area. The code is not compiled in by default at this time.

**XMSS**

The eXtended Merkle Signature Scheme (XMSS) is the latest stateful hash-based signature scheme. It has the smallest signatures out of such schemes and comes with a multi-tree variant that solves the problem of slow key generation.  
Moreover, it can be shown that XMSS is secure, making only mild assumptions on the underlying hash function. Especially, it is not required that the cryptographic hash function is collision-resistant for the security of XMSS.

In contrast to traditional signature schemes, the signature schemes used in XMSS are stateful, meaning the secret key changes over time. If a secret key state is used twice, no cryptographic security guarantees remain. In consequence, it becomes feasible to forge a signature on a new message.

**The Vulnerability**

Integer Overflow vulnerability causing a memory corruption bug was found during process of parsing XMSS private key. This process requires taking into account previously saved "state", if available. A function responsible for handling XMSS saved "states" is prone to a memory corruption via integer overflow vulnerability:

``` c
int
sshkey_xmss_decrypt_state(const struct sshkey *k, struct sshbuf *encoded,
   struct sshbuf **retp)
{
...
    struct sshbuf *copy = NULL, *decrypted = NULL;
...
    size_t keylen, ivlen, authlen, aadlen;
    u_int blocksize, encrypted_len, index;
...
    blocksize = cipher_blocksize(cipher);
    keylen = cipher_keylen(cipher);
    ivlen = cipher_ivlen(cipher);
    authlen = cipher_authlen(cipher);
...

    if ((copy = sshbuf_fromb(encoded)) == NULL ||
        (decrypted = sshbuf_new()) == NULL ||
        (iv = malloc(ivlen)) == NULL) {
        r = SSH_ERR_ALLOC_FAIL;
        goto out;
    }
...
    if (sshbuf_len(encoded) < sizeof(XMSS_MAGIC) ||
...
    if ((r = sshbuf_consume(encoded, sizeof(XMSS_MAGIC))) != 0 ||
        (r = sshbuf_get_u32(encoded, &index)) != 0 ||
        (r = sshbuf_get_u32(encoded, &encrypted_len)) != 0)
        goto out;

...
    /* check size of encrypted key blob */
    if (encrypted_len < blocksize || (encrypted_len % blocksize) != 0) {
        r = SSH_ERR_INVALID_FORMAT;
        goto out;
    }
    /* check that an appropriate amount of auth data is present */
[1] if (sshbuf_len(encoded) < encrypted_len + authlen) {
        r = SSH_ERR_INVALID_FORMAT;
        goto out;
    }

    aadlen = sshbuf_len(copy) - sshbuf_len(encoded);
...
    /* decrypt private state of key */
[2] if ((r = sshbuf_reserve(decrypted, aadlen + encrypted_len, &dp)) != 0 ||
        (r = cipher_init(&ciphercontext, cipher, key, keylen,
        iv, ivlen, 0)) != 0 ||
[3]     (r = cipher_crypt(ciphercontext, 0, dp, sshbuf_ptr(copy),
        encrypted_len, aadlen, authlen)) != 0)
        goto out;

    /* there should be no trailing data */
    if ((r = sshbuf_consume(encoded, encrypted_len + authlen)) != 0)
        goto out;
    if (sshbuf_len(encoded) != 0) {
        r = SSH_ERR_INVALID_FORMAT;
        goto out;
    }

    /* remove AAD */
    if ((r = sshbuf_consume(decrypted, aadlen)) != 0)
        goto out;
...
}
```

If an attacker generates a state where `aadlen + encrypted_len` is bigger than INT_MAX, then it is possible to successfully pass verification at [1].  
Additionally, if `authlen + encrypted_len` is also bigger than INT_MAX, then an integer overflow at [2] results in allocating a smaller buffer than desired.

Immediate overflow can happen at [3] where cipher_crypt() is called. This function operates as follows:

*   Copy `aadlen` bytes (without en/decryption) from `src` to `dest`.
*   Theses bytes are treated as additional authenticated data for authenticated encryption modes.
*   En/Decrypt `len` bytes at offset `aadlen` from `src` to `dest`.
*   Use `authlen` bytes at offset `len + aadlen` as the authentication tag.
*   This tag is written on encryption and verified on decryption.

Because of the nature of `cipher_crypt()` function, it is possible to overflow a lot of useful data before a crash, because `copy` is not being done in a 1 single shot but chunk-by-chunk during crypto operation. Nevertheless, it is not a trivial task.

**Vectors of Attack**

Any OpenSSH functionality which can parse private XMSS key is vulnerable. E.g. If sshd daemon is configured to use an XMSS host key that is malformed, it will crash upon any attempt to connect to this server:

``` shell
root@ubuntu:~/orig/openssh-8.0p1# gdb -q /root/orig/openssh-8.0p1/sshd
Reading symbols from /root/orig/openssh-8.0p1/sshd...done.
(gdb) r -d
Starting program: /root/orig/openssh-8.0p1/sshd -d
debug1: sshd version OpenSSH_8.0, OpenSSL 1.0.2g  1 Mar 2016
debug1: private host key #0: ssh-xmss@openssh.com SHA256:vVBn0NvOCLKdVFT3CtEFxNHiEgJ1xXBhHdr/YXq5tGc
debug1: rexec_argv[0]='/root/orig/openssh-8.0p1/sshd'
debug1: rexec_argv[1]='-d'
debug1: Set /proc/self/oom_score_adj from 0 to -1000
debug1: Bind to port 65535 on 0.0.0.0.
Server listening on 0.0.0.0 port 65535.
debug1: Bind to port 65535 on ::.
Server listening on :: port 65535.

<Someone connects>

debug1: Server will not fork when running in debugging mode.
debug1: rexec start in 5 out 5 newsock 5 pipe -1 sock 8
process 8844 is executing new program: /root/orig/openssh-8.0p1/sshd

debug1: inetd sockets after dupping: 3, 3
Connection from 127.0.0.1 port 39378 on 127.0.0.1 port 65535
debug1: Local version string SSH-2.0-OpenSSH_8.0
debug1: Remote protocol version 2.0, remote software version OpenSSH_8.0
debug1: match: OpenSSH_8.0 pat OpenSSH* compat 0x04000000
debug1: permanently_set_uid: 108/65534 [preauth]
debug1: list_hostkey_types: ssh-xmss@openssh.com [preauth]
debug1: SSH2_MSG_KEXINIT sent [preauth]
debug1: SSH2_MSG_KEXINIT received [preauth]
debug1: kex: algorithm: curve25519-sha256 [preauth]
debug1: kex: host key algorithm: ssh-xmss@openssh.com [preauth]
debug1: kex: client->server cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none [preauth]
debug1: kex: server->client cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none [preauth]
debug1: expecting SSH2_MSG_KEX_ECDH_INIT [preauth]

Program received signal SIGSEGV, Segmentation fault.
0xb7e40723 in ?? () from /lib/i386-linux-gnu/libcrypto.so.1.0.0
(gdb) bt
#0  0xb7e40723 in ?? () from /lib/i386-linux-gnu/libcrypto.so.1.0.0
#1  0x0e66e054 in ?? ()
#2  0xa2a4b21b in ?? ()
...
#195 0xca2d8e00 in ?? ()
#196 0xa442f816 in ?? ()
#197 0x0000d868 in ?? ()
#198 0x00000000 in ?? ()
(gdb) i r
eax            0xba	186
ecx            0xb0afbbd0	-1330660400
edx            0x4fa0c440	1335936064
ebx            0xb0ae4770	-1330755728
esp            0xbfffebcc	0xbfffebcc
ebp            0x4f0b80	0x4f0b80
esi            0x4f1e46	5185094
edi            0x4f0e96	5181078
eip            0xb7e40723	0xb7(gdb) e40723
eflags         0x210282	[ SF IF RF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
(gdb) x/i $eip
=> 0xb7e40723:	movups -0x10(%edx,%ecx,1),%xmm0
(gdb) 
```

If someone configures `authorized_key` to use XMSS public key and keep private key to be able to connect to the server, ssh client will crash:

``` shell
pi3@ubuntu:~/orig/openssh-8.0p1$ ./ssh -i ~/.ssh/id_xmss 127.0.0.1 -p 65535 -oHostKeyAlgorithms="ssh-xmss@openssh.com" -oPubkeyAcceptedKeyTypes="ssh-xmss@openssh.com" -l test
verify:: idx = 20
Segmentation fault
pi3@ubuntu:~/orig/openssh-8.0p1$ 
```

If someone tries to add this key to `ssh-agent`, it will crash too:

``` shell
pi3@ubuntu:~/orig/openssh-8.0p1$ rm -rf ~/.ssh/*
pi3@ubuntu:~/orig/openssh-8.0p1$ ./ssh-agent 
SSH_AUTH_SOCK=/tmp/ssh-VEgZcFmzWZ2o/agent.8927; export SSH_AUTH_SOCK;
SSH_AGENT_PID=8928; export SSH_AGENT_PID;
echo Agent pid 8928;
pi3@ubuntu:~/orig/openssh-8.0p1$ SSH_AUTH_SOCK=/tmp/ssh-VEgZcFmzWZ2o/agent.8927; export SSH_AUTH_SOCK;
pi3@ubuntu:~/orig/openssh-8.0p1$ SSH_AGENT_PID=8928; export SSH_AGENT_PID;
pi3@ubuntu:~/orig/openssh-8.0p1$ ./ssh-add -M 2
pi3@ubuntu:~/orig/openssh-8.0p1$ cp ~/p_key_bug/* ~/.ssh/
pi3@ubuntu:~/orig/openssh-8.0p1$ ./ssh-add -M 2
Segmentation fault
pi3@ubuntu:~/orig/openssh-8.0p1$ 
```

From the real world cases, many hosting services allow the user to upload user's own pair of private/public keys for the authentication. Then it can be automatically consumed when creating new VMs. They need to parse it so an attacker can upload a malicious key and cause vulnerability during parsing process. Examples include Azure Key Vault, Amazon Key Management Service (KMS) or Cloud Key Management Service by Google Cloud. Any Key management service might be a vector of the attack.