# PCode-Dump
This repo contains a simple Ghidra P-Code dumping script. 

# Usage

Place the script file in Ghidra's user script folder. Open a binary, then run the script using the script manager. You will find the script in the PCode cathegory. The output will be a file containing all the decompiled functions, each function starting with its name, followed by a series of addresses of the basic blocks, each followed by a series of instructions. Each element will be printed on a single line.
Data from the RAM address range will be dumped after that, preceded by a keyword "MEMORY".
