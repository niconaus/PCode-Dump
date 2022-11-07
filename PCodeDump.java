//Dumps the pcode into a txt file.
//@category PCode

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Scanner;
import java.io.InputStream;
import ghidra.util.Msg;
import java.util.ArrayList;
import java.lang.Byte;
import ghidra.program.model.address.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.lang.Register;
import ghidra.program.model.mem.*;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Function;

public class PCodeDump extends GhidraScript {

	// P-Code Dump Settings
	// Print Registers using string identifiers
	boolean registersAsString = false;
	boolean normalizeDecompilation = false;
	boolean fixCBranch = true;

	private Function func;
	protected HighFunction high;

	@Override
	protected void run() throws Exception {
		PluginTool tool = state.getTool();
		if (tool == null) {
			println("Script is not running in GUI");
		}
		File f = askFile("Enter file name, including extension for P-Code dump", "OK");
		try {
			println("going to dump into file " + f);
			if(f.createNewFile()){ println("File created!");} else {println("File exists already, contents will be overwritten.");}
			FileWriter file = new FileWriter(f,false);

			DecompileOptions options = new DecompileOptions();
			DecompInterface ifc = new DecompInterface();
			ifc.setOptions(options);

			func = getFirstFunction();

			while(true){

				if (monitor.isCancelled()) { break;}
				if (func == null) {break;}

				if (!ifc.openProgram(this.currentProgram)) {
	    		throw new DecompileException("Decompiler", "Unable to initialize: " + ifc.getLastMessage());
				}
				if (normalizeDecompilation) {ifc.setSimplificationStyle("normalize");}
				DecompileResults res = ifc.decompileFunction(func, 30, null);
				high = res.getHighFunction();

				// In some cases, Ghidra is unable to perform disassembly or decompilation, and high will be null
				// In those cases, we skip this function and move on to the next
				if (high == null) {func = getFunctionAfter(func); continue;}

				// test if function is external
				boolean ext = func.isThunk();
				if (ext) {
					// If so, add "EXT_" to function name
					file.write("EXT_");
				}

				// Print function header information
				file.write(func.getName() + "\n");

				//iterate over the basic blocks in the function
				ArrayList<PcodeBlockBasic> blocks = high.getBasicBlocks();

				// test if function is external
				if (ext) {
					file.write(blocks.get(0).getStart().toString() + "\n");
					file.write(" ---  EXTCALL " + func.getName()+ "\n");
				}
				else{

				for (int i = 0; i < blocks.size();	i++) {
					Address blockAddr = blocks.get(i).getStart();
					Iterator<PcodeOp> block = blocks.get(i).getIterator();
					if(block.hasNext()){file.write(blockAddr.toString() + "\n");}

					while(block.hasNext()){
						PcodeOp op = block.next();

						// Printing instruction
						// Determine if it is an assignment
						if (op.isAssignment()){
								// if so, print output varnode
								file.write(printVarnode(op.getOutput()));
						}
						else {
							// if not, print " --- "
							file.write(" --- ");
						}

						// Then, print opcode
						int opcode = op.getOpcode();
						file.write(" " + op.getMnemonic() + " ");

						// Then, print all inputs, if any
						Varnode[] inputs = op.getInputs();
						// begin loop
						for (int j = 0; j < inputs.length; j++) {
							// print varnode
							//check if we are dealing with a conditional branch
							if (opcode == 5 && j==0 && fixCBranch) {
								// if so, we actually need the false out address
									file.write(printAddressAsVarnode(blocks.get(i).getTrueOut().getStart())+" , ");//"(ram, 0x" + blocks.get(i).getTrueOut().getStart().toString() + ", 1) , ");
									file.write(printAddressAsVarnode(blocks.get(i).getFalseOut().getStart()));
								}
  						else if (opcode == 60) {
								// we are dealing with a multiequal. Try to get all addresses that point to this block
								int incoming = blocks.get(i).getInSize(); // don't think we need this line
								file.write(printVarnode(op.getInput(j)) + " , " + blocks.get(i).getIn(j).getStart().toString());

							}
							else {file.write(printVarnode(op.getInput(j)));}
							// if next, print " , "
							if (inputs.length > (j+1)) {file.write(" , ");}
						}

						file.write("\n");
						// Done!
					}
			 // At this point, we wanna check if fall though is consistent.
			 // First, we determine if we will perform fall though (last instruction is not CBRANCH, BRANCH or BRANCHIND)
			 Iterator<PcodeOp> instrs = blocks.get(i).getIterator();
			 	int lastInstr = -1;
				while (instrs.hasNext()) lastInstr = instrs.next().getOpcode();
			 	if (lastInstr != 4 && lastInstr != 6 && lastInstr != 5) {
					// This includes safety checks: does a next block exist? Is there a known exit path? Is there only one?
					if (i+1 < blocks.size() && blocks.get(i).getOutSize() == 1) {
			 			// If so, what address does the Ghidra API think we will jump to?
			 			Address apiNext = blocks.get(i).getOut(0).getStart();
			 			// And what is the address of the next block?
						Address fallNext = blocks.get(i+1).getStart();
			 			// Compare these two. If inconsistent, we need to insert a BRANCH to the address indicated by the API.
						if (apiNext != fallNext) {
							file.write(" ---  BRANCH* (ram, 0x" + apiNext + ", 1)\n");
			 				// We also send a notification to the terminal, to mark that this has happened.
							println("Fall through inconsistent." + apiNext.toString() + " " + fallNext.toString());
		 }
		 }
		 }
		 }
		 }
				func = getFunctionAfter(func);
			}

			// keyword indicating that memory section starts
			file.write("MEMORY\n");

			Iterator<AddressRange> mem1 = currentProgram.getMemory().getAllInitializedAddressSet().iterator();
			while(mem1.hasNext()){
				Iterator<Address> range = mem1.next().iterator();
				while (range.hasNext()){
					Address a = range.next();
					if(a.getAddressSpace().getName().equals("ram")){
					file.write(a.toString() + " ");
					byte b = currentProgram.getMemory().getByte(a);
					file.write(Byte.toUnsignedInt(b) + "\n");
				}
				}
				}


			file.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	protected String printVarnode(Varnode vn) {
		String result = "";

		if(vn.isRegister() && registersAsString){
			result += "(register, ";
			Register reg = func.getProgram().getRegister(vn.getAddress(), vn.getSize());
			 	if (reg != null) { // do we need this condition?
			 			result += reg.getName();
						result += ", ";
						result += vn.getSize();
						result += ")";
			 	}
		} else {result += vn.toString();}

		return result;
	}

	protected String printAddressAsVarnode(Address a) {
		String result = "(";

		String pA = a.toString();
		//checks to see if we are dealing with HARVARD architecture binary
		if((pA.length() > 4) && (pA.substring(0,4).equals("CODE"))){
			result += "CODE, 0x";
			result += pA.substring(5,pA.length());
		} else { result += "ram, 0x" + pA;}

		result += ", 1)";
		return result;

		}
}
