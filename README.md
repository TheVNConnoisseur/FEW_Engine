# FEW Engine
Tool that allows the modification of script files offered in ANIM and CROWD powered visual novels (created by [SIS Planning](http://www.hs-crowd.co.jp/)).

### Notes on its usage
1. When extracting a script file, a `(originalname)_sce_metadata.dat` file will be generated. Said file contains the header of the original file (minus the 4 bytes magic signature and the 16 bytes key) intact. This is because that part is still yet to be understood and is mandatory for recreating the script file.
2. The tool has only been tested (and will NOT be tested with other games) with [Zetsuboushi](https://vndb.org/v3315). Still, pull requests will be accepted and tested to see if they work correctly.
3. The program will decrypt any *_define.dat file, but it will not convert it to a human readable format, as it may vary a bit between games, and not something I intend on tackling myself.

### How are *_sce.dat and *_define.dat files structured?
While the code also documents how these files are structured, here it is also the same information on a more accessible manner.

All these files are encrypted the same way, by using a simple XOR encryption process that starts after the header portion of the file. Something to note off, is that the key used gets updated after **16 bytes** (the initial one is the one used at the header of the file).

A script file is divided into 3 parts:
  * **Header**: Magic signature (4 bytes) + Key (16 bytes)
    * Magic signature: like with any format, these bytes represent the beginning of a specific file format.
    * Key: the key used to encrypt the file.
  * **Script's logic**: Unknown (4 bytes) + Offset of script (4 bytes) + Unknown (Unknown bytes)
    * Offset of script: it specifies at what byte (after the header) the script starts.
  * **Script**: it includes each instruction of the script file, separated by a null byte between each of them. If the file does not end with a multiple of 4, it introduces the null bytes after the last instruction to comply with that restriction.
