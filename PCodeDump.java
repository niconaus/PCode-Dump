//Dumps the pcode into a txt file.
//@category PCode

//my imports
import java.io.File;
import java.io.FileWriter;   // Import the FileWriter class
import java.io.IOException;
import ghidra.util.Msg;
import java.util.ArrayList;
import ghidra.program.model.address.*;

//old imports
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
import ghidra.program.model.address.Address;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.GenericCallingConvention;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.Union;
import ghidra.program.model.listing.Function;
import ghidra.program.model.pcode.FunctionPrototype;
import ghidra.program.model.pcode.HighConstant;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.HighGlobal;
import ghidra.program.model.pcode.HighLocal;
import ghidra.program.model.pcode.HighOther;
import ghidra.program.model.pcode.HighParam;
import ghidra.program.model.pcode.HighSymbol;
import ghidra.program.model.pcode.HighVariable;
import ghidra.program.model.pcode.PcodeBlock;
import ghidra.program.model.pcode.PcodeBlockBasic;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.SequenceNumber;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.pcode.VarnodeAST;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class PCodeDump extends GhidraScript {

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
			if(f.createNewFile()){ println("File created!");} else {println("File exists already."); return;}
			FileWriter file = new FileWriter(f);

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
				ifc.setSimplificationStyle("normalize");
				DecompileResults res = ifc.decompileFunction(func, 30, null);
				high = res.getHighFunction();

				// Print function header information
				file.write(func.getName() + "\n");

				//iterate over the basic blocks in the function
				ArrayList<PcodeBlockBasic> blocks = high.getBasicBlocks();

				for (int i = 0; i < blocks.size();	i++) {
					Address blockAddr = blocks.get(i).getStart();
					Iterator<PcodeOp> block = blocks.get(i).getIterator();
					if(block.hasNext()){file.write(blockAddr.toString() + "\n");}

					while(block.hasNext()){
						PcodeOp op = block.next();
						file.write(op.toString() + "\n");
					}
				}

				func = getFunctionAfter(func);
			}
			
			file.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
