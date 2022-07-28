# Black Hole
The service starts by giving you a random 256-byte encoded secret upon connection, and a prompt. If you send a message to the service between size 0-256, you get back a 256-byte encoding of your input.

By sending placeholder messages of size 1 .. 256 to the service, and xoring the result with the encoded secret, you can discover the length of the secret. Most messages only have a few matching bytes, but when you submit a message with the same length as the secret, the padding will match, resulting in 00 bytes anywhere there is padding.

From there, you can construct an xor mask by submitting 0x1, 0x2, and 0x3 of the appropriate length, and xoring their encoded messages back together. This mask can be used to decode messages, but not determine the position of scrambled bytes.

From here, build a lookup table by submitting a known unique sequence (e.g. a-z), xoring the result with your mask, and checking where each input character appears in the output.

Now xor the secret against your mask and use the lookup table to unscramble the bytes. Submit the decoded secret to the service and you get a flag.

```python
from collections import Counter
from mp import *
import string

def xor(a, b):
    return bytes([a1 ^ b1 for a1, b1 in zip(a, b)])

def b_and(a, b):
    return bytes([a1 & b1 for a1, b1 in zip(a, b)])

flag_prefix = b'flag{oscar36549kilo3:'

ticket = 'ticket{oscar36549kilo3:GH6Z16zzdxSJyX1GbxD2gQ1qvVUApew5kxkL-IXFqdbfWk5gi9_CjKi-OfVVKNHpjw}'
p = remote('black_hole.satellitesabove.me', 5300)
p >> 'Ticket please:' << ticket << '\n'
p >> 'Encoded msg is: ' >> '\n'
encoded = bytes.fromhex(p.data.decode())

def cmd(msg):
    p >> 'Msg:' << msg << '\n'
    p >> '\n'
    return bytes.fromhex(p.data.decode().strip())

def xor_match(enc):
    count = xor(encoded, enc).count(0)
    return count

def xor_match_mask(enc, mask):
    return bytes([c for i, c in enumerate(xor(encoded, enc)) if mask[i]]).count(0)

for i in reversed(range(146, 200)):
    b01 = cmd('01' * i)
    count = xor_match(b01)
    if count >= (256 - i):
        break
else:
    raise ValueError

length = i

b02 = cmd('02' * length)
b03 = cmd('03' * length)

mask = bytes([0x00 if (a == b == 0xff) else 0xff for a, b in zip(xor(xor(b01, encoded), bytes([0xff])*256), xor(xor(b02, encoded), bytes([0xff])*256))])
x1 = b_and(xor(xor(b01, b02), b03), mask)

LUT = {}

for i in range(0, length, len(string.ascii_lowercase)):
    buf = bytearray([1] * length)
    buf[i:i+len(string.ascii_lowercase)] = string.ascii_lowercase.encode()
    buf = buf[:length]
    resp = cmd(buf.hex())
    dec = b_and(xor(resp, x1), mask)
    for i, c in enumerate(buf):
        if c != 1 and c in dec:
            LUT[i] = dec.index(c)

decoded = b_and(xor(x1, encoded), mask)
data = bytes([decoded[LUT[i]] for i in range(length)])
p << data.hex() << '\n'
```