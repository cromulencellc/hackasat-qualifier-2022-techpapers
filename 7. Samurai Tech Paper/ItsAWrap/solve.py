import numpy as np

phrase = 'HACKASAT3'

print('Flattened Phrase:')
print(','.join(map(str, map(ord, phrase))))

# convert to 3x3 matrix
phrase = np.array(list(map(ord, phrase)))
phrase = phrase.reshape(3,3)

# provided
encryptionMatrix = np.matrix([[-3,-3,-4],[0,1,1],[4,3,4]])
print('Encryption Matrix:')
print(encryptionMatrix)

print('Phrase Matrix:')
print(phrase)

# calculate encryption via matrix multiplication
#  - matrices transposed in make_F_array
result = phrase.T * encryptionMatrix.T

print('Result Matrix:')
print(result)

print('Flattened:')
print(','.join(map(str, np.asarray(result).flatten())))

# Script Output
'''
Flattened Phrase:
72,65,67,75,65,83,65,84,51
Encryption Matrix:
[[-3 -3 -4]
 [ 0  1  1]
 [ 4  3  4]]
Phrase Matrix:
[[72 65 67]
 [75 65 83]
 [65 84 51]]
Result Matrix:
[[-701  140  773]
 [-726  149  791]
 [-654  134  721]]
Flattened:
-701,140,773,-726,149,791,-654,134,721
'''

# Service Output
'''
Ticket please:
ticket{oscar497485tango3:GALk2c1U3W3iUQ-skWv8TdWQXvU92SSzB3_-6IKV-QgPO_Iv8HS0ZfGkAiQW4GMg6w}
You have inherited a simple encryption dll from previous project
that you must use.  It used to work but now it seems it does not.
Given the encryption matrix:
| -3 -3 -4 |
|  0  1  1 |
|  4  3  4 |
...and the phrase 'HACKASAT3'.

 Enter the phrase in standard decimal ASCII
 and the resulting encrypted list
    Example: 'XYZ': 88,89,90
             Encrypted list: 1,2,3,4,5,6,7,8,9
 Enter phrase> 72,65,67,75,65,83,65,84,51
 Enter encrypted phrase> -701,140,773,-726,149,791,-654,134,721
 Entered phrase:  72,65,67,75,65,83,65,84,51
 Encrypted phrase:  -701,140,773,-726,149,791,-654,134,721

Computing encrypted phrase...

----------------------------------
Congradulations you got it right!!

Here is your flag:  flag{oscar497485tango3:GGpcA0zn-lXNghnKK0ZMuEuUdhM-5ilObnd1Z6HONyge6cFrRQOsgHQpLMPkjeQmdmMSntUX_VH8zfgeiLXeWIg}
----------------------------------
'''