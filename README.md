# FEW Engine
Tool that allows the modification of script files offered in ANIM and CROWD powered visual novels (created by [SIS Planning](http://www.hs-crowd.co.jp/)).

### Notes on its usage
The tool has only been tested (and will NOT be tested with other games) with [Zetsuboushi](https://vndb.org/v3315). So, considering that this tool does a full recompilation of the script file, incompatibilities across the entire library of CROWD and ANIM games.

### How are *_sce.dat files created?
While the code also documents how these files are structured, here it is also the same information on a more accessible manner.

This engine has an interesting quirk: the script files get compiled directly by the **game's main executable**. The developer is expected to run some debug files and some other stuff in order to compile the script from .txt to .dat, and it will inform to the developer if the process was successful or not, alongside a pretty robust (albeit rigid) structure.

The compiler works this way, it first leaves 12 bytes for 3 offsets, the first is for the label section, the following one for the strings section, and finally a jump label section.
The first step is to compile all of the instructions given to a binary array, and storing away all of the strings, labels and jump labels in their respective (temporary arrays). Once all of the instructions have been done successfully, the compiler will fill in the blanks of all of the placeholder bytes left by all of the instructions that used any label.
Then, **it writes a byte (0x01)** as padding, and then it writes the label section. Honestly, said part of the script doesn't seem to do anything at all, and it is not clear what's supposed to do, considering that the jumps are already defined through the instructions themselves. It could perfectly be a remnant of an older version of the TakanoScript engine (this name is the only reference to any game's engine, and even then said name is only expected to be used if the developer intended to use a limited set of instructions, so who knows).

After that, it writes the current offset to the first 4 bytes of the byte array (it tells us the offset for the label list). Once that's done, it goes back to the end of the array and it writes the strings section and puts a zero byte padding in between each string and another extra one once said list is completed. The same process gets repeated for the jump label section (the offset for the strings section is put in bytes 4-7), although this cannot be confirmed since the analyzed game simply does not even write anything, just the padding byte (in fact, the offset for the jump label section is not even written, almost as if it was expected to never have any jump label at all).

All of this is what constitutes the actual script file, but we are missing an important key: the encryption key and the magic header. The game takes the entire array and inserts 4 bytes (the magic header) and a hardcoded key (16 bytes) at the beginning of the byte array, and then proceeds to encrypt it by using a simple XOR encryption process that starts after those 20 bytes. Something to note off, is that the key used gets updated after **16 bytes** (the initial one is the one used at the header of the file). Said functionality is also hardcoded into the game's executable.

So, all in all, a script file is divided into 3 parts:
  * **Header**: Magic signature (4 bytes) + Key (16 bytes)
    * Magic signature: like with any format, these bytes represent the beginning of a specific file format.
    * Key: the key used to encrypt the file.
  * **Offsets for all sections**: Offset to label (4 bytes) + Offset of strings (4 bytes) + Offset of jump labels (4 bytes)
  * **Bytecode section**: it includes each instruction of the script file.
  * **Label section**: its actual functionality is unknown, but in the analyzed game is never created.
  * **String section**: a list of all of the strings used in the game that are user-defined.
  * **Jump label section**: probably a list similar to the label section.

### How are *_define.dat files created?
While the code also documents how these files are structured, here it is also the same information on a more accessible manner.

These files are way simpler than the script ones, they simply contain all of the bytecode for the instructions that have been written into it, nothing more. If it has any kind of structure, it is not know, but there does not seem to be any in particular, so it is fair to assume that the game expects a set of instructions in a specific order, hardcoded into the main executable most probably.
In fact, most of the instructions don't seem to be utilized at all, just the one that defines the descriptions for each of the events present in the recollection room in-game.
    
### Can you confirm to me that your decompilation process works flawlessly?
Honestly, no. The process of compilation destroys a lot of information, like for example where to know if the developer is using the _TakanoScript_ format or not, or even worse, if at any point in time is using instructions like "if" and "else", which basically requires you to track the same set of instructions as before but with the addition that you have to know at what level of if you are currently at, which is not possible to know.

### Hey! This program does not seem to work with my game? What gives?
Quite a lot of progress has been made on understanding the game format. Since this project is mostly focused on the game mentioned earlier and just in case something may vary between games, the following files have been included in order help users understanding the engine's inner workings:
- **Decompilation**: the engine opcodes are defined in the game executable. In this case, a .i64 file generated with IDA Pro 9.1 with a lot of the game's functions understood, and for the opcodes the function to look for has been called **CompileScript**, and **CompileDefine**. The cracked game executable has been included (a full retail copy is still needed to debug the game, but no to open the pseudocode decompilation) since the original executable is packed with a DRM called [Alpha-DVD](https://www.discpartner.de/media/service/kopierschutz%20settec/Alpha_rom.PDF), so using the cracked executable makes the job possible. The initial investigation was done by [Crsky](https://github.com/crskycode/).
- **Script**: the game's zet_sce.dat is the decrypted version of the original file.

Something worthy mentioning regarding the analyzed game, the game offers two things that can help a tiny bit when debugging and understanding the game. If you launch the main program while adding as a parameter a specific number, you'll get the game running plus a debug window too:
- **1:** you'll get a window that tracks all of the flags and the sound files loaded for each BGM and SE available track.
- **2:** it closes the game immediately (I'm not even sure if you need a file called modebug.bin or something, I can't confirm that part).
- **5:** it opens a window which said purpose is still unknown.
- **6:** it combines the effects of parameters 1 and 5.

Sadly, CROWD and ANIM have made a lot of changes in the engine (either in the past and in the future if we take our analyzed game as a point of reference), so there's no other option that to decompile your game's main executable of choice and try to find what instructions it is expecting and how each of them are structured.
Thankfully, most of the structure seems to be mostly the same, so a lot of the work done here can be taken forward to make more games compatible with this tool.
### ℹ️ Regardless of that, if you happen to want to edit the string list (and ONLY said list), just download [version 1](https://github.com/TheVNConnoisseur/FEW_Engine/releases/tag/1.0) of this tool, it works flawlessly for those purposes, albeit with the limitations imposed by the script's file format.
