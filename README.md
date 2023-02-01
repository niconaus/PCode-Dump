# PCode-Dump
This repo contains a simple Ghidra P-Code dumping script. 

# Usage

Place the script file in Ghidra's user script folder. Open a binary, then run the script using the script manager. You will find the script in the PCode cathegory. The output will be a file containing all the decompiled functions, each function starting with its name, followed by a series of addresses of the basic blocks, each followed by a series of instructions. Each element will be printed on a single line.
Data from the RAM address range will be dumped after that, preceded by a keyword "MEMORY".

#### Acknowledgements:

This material is based upon work supported by the Defense Advanced Research Projects Agency (DARPA) and Naval Information Warfare Center Pacific (NIWC Pacific) under contract N6600121C4028 and Agreement No. HR.00112090028, and the US Office of Naval Research (ONR) under grant N00014-17-1-2297.

Any opinions, findings and conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of DARPA or NIWC Pacific, or ONR. 

Special thanks to [KevOrr](https://github.com/KevOrr "KevOrr") for his feedback
