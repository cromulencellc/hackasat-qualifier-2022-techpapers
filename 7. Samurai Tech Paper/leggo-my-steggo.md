# Leggo My Steggo! Writeup
## Challenge Description
```
We've been running this satellite that has the same command mnemonic as an old Hack-a-Sat 2020 satellite - but now its infected with something.

In our last communication it dumped out all these files.

Re-gain authority over the satellite

The satellite seems to still respond to the commands mnemonics we used before but replies in a strange way.

https://github.com/cromulencellc/hackasat-final-2020/tree/master/solvers/c4/solver_ruby_scripts
```

We can connect with
```
nc leggo.satellitesabove.me 5300
```

And our ticket was
```
ticket{uniform495584kilo3:GIZxDd1tLKankSA_Ry6AJ3lqMc_Ha54yGsuqTXTItEgLHBu8KWdbMmYoKJFROQgnDg}
```

We're also given a .zip of satellite images of 10 different cities.

## Stegsolve?
Since this is a stego challenge, we decided to see if there was any data hidden within the images, using stegsolve, steghide, etc.

Using https://futureboy.us/stegano/decinput.html online, each image was uploaded and checked for hidden content.

Here were the findings for each image:
```
Boston -> 4aada52c9abb92d32c57007091f35bc8
Chicago -> a6ec1dcd107fc4b5373003db4ed901f3
LA -> ae7a2a6b7b583aa9cee67bd13edb211e
Miami -> 1312798c840210cd7d18cf7d1ff64a40
NYC -> e115d6633cdecdad8c5c84ee8d784a55
Oahu -> Use the command mnemonic that outputs moon.png
Portland -> 20b7542ea7e35bf58e9c2091e370a77d
SF -> f24b6a952d3f0a8f724e3c70de2e250c
SLC -> 09e829c63aff7b72cb849a92bf7e7b48
Las Vegas -> 7cef397dfa73de3dfedb7e537ed8bf03
```

The other hashes look like md5sums. If we use CrackStation (or another similar website), we can see that each of these values map to a cracked password:
```
Boston -> 4aada52c9abb92d32c57007091f35bc8 -> beanpot
Chicago -> a6ec1dcd107fc4b5373003db4ed901f3 -> deepdish
LA -> ae7a2a6b7b583aa9cee67bd13edb211e -> cityofangels
Miami -> 1312798c840210cd7d18cf7d1ff64a40 -> springbreak
NYC -> e115d6633cdecdad8c5c84ee8d784a55 -> fuhgeddaboudit
Portland -> 20b7542ea7e35bf58e9c2091e370a77d -> stayweird
SF -> f24b6a952d3f0a8f724e3c70de2e250c -> housingmarket
SLC -> 09e829c63aff7b72cb849a92bf7e7b48 -> skiparadise
Las Vegas -> 7cef397dfa73de3dfedb7e537ed8bf03 -> letsgolasvegas
```

## Oahu Message
The Oahu message shown earlier tells us "Use the command mnemonic that outputs moon.png"

The challenge description tells us to use https://github.com/cromulencellc/hackasat-final-2020/tree/master/solvers/c4/solver_ruby_scripts

There are a handful of scripts in this file, but the last line of https://github.com/cromulencellc/hackasat-final-2020/blob/master/solvers/c4/solver_ruby_scripts/test_image.rb#L8 is
```
cmd("CF PLAYBACK_FILE with CCSDS_STREAMID 6323, CCSDS_SEQUENCE 49152, CCSDS_LENGTH 149, CCSDS_FUNCCODE 2, CCSDS_CHECKSUM 0, CLASS 1, CHANNEL 0, PRIORITY 0, PRESERVE 1, PEER_ID '0.21', SRC_FILENAME '/cf/img.png', DEST_FILENAME '/home/op1/c4/moon.png'")
```

This line references moon.png. It looks us a while to figure out the correct syntax, since every script command as-is returned an "invalid" message.

As it turns out, we just had to send `PLAYBACK_FILE`.

## SHA256 Questions
Once we connect to the server with `nc leggo.satellitesabove.me 5300` and our ticket, then provide `PLAYBACK_FILE` as our command input, the server asks us a question:
```
CMD>PLAYBACK_FILE
d6bc6fbee628c3278ef534fd22700ea4017914c2214aa86447805f858d9b8ad4?
```

The question is a long hash and nothing else. After some experimentation, we got the idea to SHA256 each image.

Here is the mapping of images to hashes:
```
boston d6bc6fbee628c3278ef534fd22700ea4017914c2214aa86447805f858d9b8ad4
chicago 04ca7d835e92ae1e4b6abc44fa2f78f6490e0058427fcb0580dbdcf7b15bbb55
LA 242f693263d0bcc3dd3d710409c22673e5b6a58c1a1d16ed2e278a8d844d7b0b
miami 2aa0736e657a05244e0f8a1c10c4492dde39907c032dba9f3527b49873f1d534
nyc 983b1cc802ff33ab1ceae992591f55244538a509cd58f59ceee4f73b6a17b182
portland b4447c4b264b52674e9e1c8113e5f29b5adf3ee4024ccae134c2d12e1b158737
sf f37e36824f6154287818e6fde8a4e3ca56c6fea26133aba28198fe4a5b67e1a1
slc 088f26f7c0df055b6d1ce736f6d5ffc98242b752bcc72f98a1a20ef3645d05c1
vegas 3b20a3b5b327c524674ca5a8310beb2d9efc5c257e60c4a9b0709d41e63584a3
```

Putting this all together, the server will ask us a bunch of questions (SHA256 hashes) and we need to answer back with the cracked password corresponding to each provided image file.

For example, if it asks "d6bc6fbee628c3278ef534fd22700ea4017914c2214aa86447805f858d9b8ad4?" we answer back with Boston's cracked password value of "beanpot".

## Solution script
Using this script:
```
#!/usr/bin/env python
from pwn import *

host = 'leggo.satellitesabove.me'
port = 5300
ticket = 'ticket{uniform495584kilo3:GIZxDd1tLKankSA_Ry6AJ3lqMc_Ha54yGsuqTXTItEgLHBu8KWdbMmYoKJFROQgnDg}'

hash_dictionary = {
    b'd6bc6fbee628c3278ef534fd22700ea4017914c2214aa86447805f858d9b8ad4': 'beanpot',        # boston
    b'04ca7d835e92ae1e4b6abc44fa2f78f6490e0058427fcb0580dbdcf7b15bbb55': 'deepdish',       # chicago
    b'242f693263d0bcc3dd3d710409c22673e5b6a58c1a1d16ed2e278a8d844d7b0b': 'cityofangels',   # los angeles
    b'2aa0736e657a05244e0f8a1c10c4492dde39907c032dba9f3527b49873f1d534': 'springbreak',    # miami
    b'983b1cc802ff33ab1ceae992591f55244538a509cd58f59ceee4f73b6a17b182': 'fuhgeddaboudit', # nyc
    b'b4447c4b264b52674e9e1c8113e5f29b5adf3ee4024ccae134c2d12e1b158737': 'stayweird',      # portland
    b'f37e36824f6154287818e6fde8a4e3ca56c6fea26133aba28198fe4a5b67e1a1': 'housingmarket',  # sf
    b'088f26f7c0df055b6d1ce736f6d5ffc98242b752bcc72f98a1a20ef3645d05c1': 'skiparadise',    # slc
    b'3b20a3b5b327c524674ca5a8310beb2d9efc5c257e60c4a9b0709d41e63584a3': 'letsgolasvegas', # las vegas
}

def connect():
    r = remote(host, port)
    output = r.recvuntil('Ticket please:\n')
    print(output)
    r.sendline(ticket)
    return r

r = connect()
r.recvuntil('CMD>')

r.send("PLAYBACK_FILE\n")

for i in range(5):
    sha = r.recvuntil("?")
    # print(sha[:-1])

    sha = sha[:-1]

    r.recvuntil(">>")

    passwd = hash_dictionary[sha]
    r.sendline(passwd)

    r.recvuntil('Thank you\n')

output = r.recvuntil('OK you can have the satellite back\n')
flag = r.recvuntil('}')

print("FLAG is", flag)
```

If we run the script:
```
$ python leggo.py
[+] Opening connection to leggo.satellitesabove.me on port 5300: Done
b'Ticket please:\n'
[*] Switching to interactive mode
$
d6bc6fbee628c3278ef534fd22700ea4017914c2214aa86447805f858d9b8ad4?
>>$ beanpot
Thank you
088f26f7c0df055b6d1ce736f6d5ffc98242b752bcc72f98a1a20ef3645d05c1?
>>$ skiparadise
Thank you
983b1cc802ff33ab1ceae992591f55244538a509cd58f59ceee4f73b6a17b182?
>>$ fuhgeddaboudit
Thank you
2aa0736e657a05244e0f8a1c10c4492dde39907c032dba9f3527b49873f1d534?
>>$ springbreak
Thank you
b4447c4b264b52674e9e1c8113e5f29b5adf3ee4024ccae134c2d12e1b158737?
>>$ stayweird
Thank you
OK you can have the satellite back
flag{uniform495584kilo3:GBW34mhaL58VW6EmkNTv4qX5mSC6Ck0kBHhqGS4-bMvZP0RxHyLt0khKFTQYpIdmHLCkrVwXz0iZqQIOo6SZglM}
[*] Got EOF while reading in interactive
```

We get the flag: `flag{uniform495584kilo3:GBW34mhaL58VW6EmkNTv4qX5mSC6Ck0kBHhqGS4-bMvZP0RxHyLt0khKFTQYpIdmHLCkrVwXz0iZqQIOo6SZglM}`
