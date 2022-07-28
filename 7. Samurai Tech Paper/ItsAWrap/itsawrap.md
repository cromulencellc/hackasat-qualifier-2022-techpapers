# Hack-a-Sat Qualifier 2022: It's A Wrap

**Category:** The Only Good Bug is a Dead Bug

**Description:** Do you like inception?

## Write-up
The challenge is provided as an archive containing two files: a compiled 
python binary named encrypt.pyc and a x86-64 shared object, along with a 
network address and port to interact with the service. Connecting to the 
service results in the following text after providing the team ticket:

```
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
 Enter phrase> 
 Enter encrypted phrase> 
```

The first prompt: "Enter phrase> ", is demonstrated with the sample of 'XYZ'. 
The phrase 'HACKASAT3' must simply be converted into the decimal values for 
each character in the phrase, separated by commas. A quick line of python 
provides the answer: print(','.join(map(str, map(ord, 'HACKASAT3'))))

=> 72,65,67,75,65,83,65,84,51

To determine the encrypted phrase, we will need to look into the provided 
binaries. Since pyc files can usually be decompiled reasonably well, we'll 
assume the important bits are in the shared object. Opening it up in IDA, we 
see that the binary has a handful of exported functions with names relating to
encryption along with EncodeMatrix and DecodeMatrix data objects. The 
encrypt_it function sounds like just what we're looking for. From an initial 
look, the function says allocates a "result array" of 0x48 bytes, calls the 
C_encode_decode function, copies data from the EncodeMatrix exported object 
onto the stack, then calls make_F_array on the copied data from EncodeMatrix 
and the input argument to the function, along with pointers to some 
uninitialized data on the stack. The next function mat_mult_ takes these 
presumably now-initialized data pointers from the stack as well as the 
allocated result array. The name suggests that the encryption is perhaps 
just matrix multiplication of the input phrase with the EncodeMatrix, but we 
will want to understand the data format of the matrix first to verify that.

In order to understand the data format, the print_array function sounds like 
it should be helpful. It iterates through the array printing int64 values for 
each element in a row, with the first argument being the number of rows and 
the second being the number of columns. Although these are passed in, the 
iteration through the array is hardcoded to move ahead 24 bytes, or 3 elements, 
for each row. So, the array is stored as a flat list of numbers in memory, 
with 3 values per row, and we know there are 3 rows per matrix from what is 
printed when we connect to the service. This print_array function includes the 
string "C: " in front of the array, and given the make_C_array and make_F_array 
functions, it seems like there may be multiple different datatypes in the task. 
The encrypt_it function calls C_encode_decode on the input argument, so we 
assume the input to the function is of the format of the print_array function. 
There is a second print_array_ function that calls into a bunch of gfortran_*
functions. So, the make_F_array must convert the C-style array we just looked 
at into a gfortran array. Based on the print_array function, we'll define the 
C-style matrix with the following structures:

```
struct matrix_column
{
  int64_t values[3];
};

struct matrix
{
  matrix_column rows[3];
};
```

Looking at the make_F_array function, it appears to just copy the data into a 
new structure of the same size and type. To verify this, we will declare the 
input and output matrices with the new type and check the decompilation:

```
__int64 __fastcall make_F_array(matrix *src, matrix *dst)
{
  __int64 result; // rax
  int i; // [rsp+18h] [rbp-8h]
  int j; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i <= 2; ++i )
  {
    for ( j = 0; j <= 2; ++j )
    {
      result = i;
      dst->rows[j].values[i] = src->rows[i].values[j];
    }
  }
  return result;
}
```

The data structures seem okay, however there is one important difference: the 
i and j iterators through the rows and indices are swapped between the src and 
dst matrices. So, gfortran may store the matrix in a transposed format as 
compared to the C format. However, the function that performs the actual 
matrix multiplication (mat_mult_) is not calling into gfortran, but instead 
implements the matrix multiplication directly. Applying the matrix type to the 
function, the output is still somewhat awkward to read:

```
_BOOL8 __fastcall mat_mult_(matrix *m1, matrix *m2, matrix *res)
{
  _BOOL8 result; // rax
  int i; // [rsp+1Ch] [rbp-Ch]
  int out_row; // [rsp+20h] [rbp-8h]
  int out_column; // [rsp+24h] [rbp-4h]

  for ( out_column = 1; ; ++out_column )
  {
    result = out_column > 3;
    if ( out_column > 3 )
      break;
    for ( out_row = 1; out_row <= 3; ++out_row )
    {
      *((_QWORD *)&res->rows[out_row - 1] + out_column - 1) = 0LL;
      for ( i = 1; i <= 3; ++i )
        *((_QWORD *)&res->rows[out_row - 1] + out_column - 1) += *((_QWORD *)&m2->rows[out_row - 1] + i - 1)
                                                               * *((_QWORD *)&m1->rows[i - 1] + out_column - 1);
    }
  }
  return result;
}
```

Matrix multiplication is implemented as the dot product of a row from the the 
first matrix with the column of the second matrix. In the above function, with 
the C-style matrix definition, we can see normal matrix multiplication of 
m2 x m1, as m2 is iterated across the row (stepping through columns) and m1 is 
iterated across the column (stepping through rows). So, the order of arguments 
is not what one might expect, but otherwise it is normal matrix multiplication 
given the C-style matrix defintion. Returning to encrypt_it, the function is 
called with the following arguments: mat_mult_(&encodeF, &inputF, result);
Since the F-style matrices are used, they are transposed representations as 
compared to the C-style matrices. So encryption ends up being:
transpose(input) * transpose(EncodeMatrix). This can be calculated using 
numpy matrices with simply: input.T * EncodeMatrix.T. The output must be 
flattened then and turned into comma-separated elements to submit to the 
service. The flattened result is input as:

-701,140,773,-726,149,791,-654,134,721

which is accepted to give us the flag.
