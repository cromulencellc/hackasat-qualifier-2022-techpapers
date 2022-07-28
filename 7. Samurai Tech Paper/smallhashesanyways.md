# smallhashesanyways

We were presented with a binary:
```
$ file small_hashes_anyways-quebec577292delta3/small_hashes_anyways 
small_hashes_anyways-quebec577292delta3/small_hashes_anyways: ELF 32-bit MSB executable, Xilinx MicroBlaze 32-bit RISC, version 1 (SYSV), dynamically linked, interpreter /lib/ld.so.1, for GNU/Linux 3.2.0, stripped
```
Knowing nothing about microblaze and given that ghidra couldn't open it, we proceeded dynamically. The binary appeared to run fine under qemu if the root for the loader and the library path were set:

```
$ qemu-microblaze -L ./microblaze-linux -E LD_LIBRARY_PATH=./microblaze-linux/lib ./small_hashes_anyways-quebec577292delta3/small_hashes_anyways
small hashes anyways:
```

Giving some input:
```
small hashes anyways: 
flag
wrong length wanted 112 got 4
```
told us the length it was expecting. So we can give it what it expects:
```
$ python -c "print('\x00'*112)" | qemu-microblaze -L ./microblaze-linux -E LD_LIBRARY_PATH=./microblaze-linux/lib ./small_hashes_anyways-quebec577292delta3/small_hashes_anyways 
small hashes anyways: 
mismatch 1 wanted 1993550816 got 3523407757
```
**s**mall**h**ashes**a**nyways might refer to SHA so perhaps we're looking at a hashing algorithm. Googling the constant that the binary 'got' gives lots of results for CRC32 and we know the flag format starts with `flag{` and:
```python
In [1]: from zlib import crc32

In [2]: crc32(b'f')
Out[2]: 1993550816
```
confirms that the 'mismatch at 1' indeed wanted the CRC32 for `'f'`. A quick check for byte by byte:
```
$ python -c "print('f'*112)" | qemu-microblaze -L ./microblaze-linux -E LD_LIBRARY_PATH=./microblaze-linux/lib ./small_hashes_anyways-quebec577292delta3/small_hashes_anyways
small hashes anyways: 
mismatch 2 wanted 914027437 got 3601799859
```
gives the mismatch at 2 as the CRC32 of `'fl'` and not simply `'l'` so the binary appears to be telling us at what index the progressive CRC of our input mismatches. All that's left is to script it up into a loop which computes the progressive CRC for the currently discovered flag prefix with all possible next bytes and feed it to the binary until we have an input length 112:

```python
from pwn import *
from re import findall

lu = {}

flag = b''
p = log.progress('brute')

while len(flag)<112:
    for x in range(0x20,0x80):
        lu[crc.crc_32(flag+bytes([x]))] = bytes([x])

    with context.quiet:
        io = process('qemu-microblaze -L ./microblaze-linux -E LD_LIBRARY_PATH=./microblaze-linux/lib small_hashes_anyways-quebec577292delta3/small_hashes_anyways'.split(' '))

    io.recvline()
    io.sendline(flag.ljust(112,b'\x00'))
    flag+=lu[int(findall(b'wanted (.*?) ',io.recvline())[0])]
    p.status(flag.decode())
    
    with context.quiet:
        io.close()
p.success(flag.decode())
```