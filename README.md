# PCode-Dump
This repo contains a simple Ghidra P-Code dumping script. 

# Usage

Place the script file in Ghidra's user script folder. Open a binary, then run the script using the script manager. You will find the script in the PCode cathegory. The output will be a file containing all the decompiled functions, each function starting with its name, followed by a series of addresses of the basic blocks, each followed by a series of instructions. Each element will be printed on a single line.

# Features to be added in the future

- Printing registers using their name instead of internal P-Code numbers
- Dumping data
