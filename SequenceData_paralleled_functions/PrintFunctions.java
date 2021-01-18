import java.util.ArrayList;

import java.util.List;
import java.util.Iterator;
import java.util.HashMap;
import java.util.*;


import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.StackFrame;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.*;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.decompiler.ClangTokenGroup;
import ghidra.app.decompiler.ClangNode;
import ghidra.app.decompiler.*;
import ghidra.util.task.ConsoleTaskMonitor;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.pcode.*;
import java.util.HashMap;
import ghidra.program.model.address.*;
import java.util.Map;
import java.awt.Color;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import ghidra.program.model.lang.Register;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.util.DefinedDataIterator;


public class PrintFunctions extends GhidraScript {

	private DecompInterface decompInterface;

	// Prepares decompiler
	private DecompInterface setUpDecompiler(Program program) {
		DecompInterface decompInterface = new DecompInterface();

		// call it to get results
		if (!decompInterface.openProgram(currentProgram)) {
			println("Decompile Error: " + decompInterface.getLastMessage());
			return null;
		}

		DecompileOptions options;
		options = new DecompileOptions();
		decompInterface.setOptions(options);

		decompInterface.toggleCCode(true);
		decompInterface.toggleSyntaxTree(true);
		decompInterface.setSimplificationStyle("decompile");

		return decompInterface;
	}

	// Prints C code
	private void decompileFunction(Function function) {
		DecompileResults results = decompInterface.decompileFunction(function, decompInterface.getOptions().getDefaultTimeout(), ConsoleTaskMonitor.DUMMY);
		
		if (results.failedToStart()) {
			println("Failed to start decompilation");
		} 	
		
		if (!results.decompileCompleted()) {
			System.out.println(results.getErrorMessage());
		}
		else {
			//println(results.getCCodeMarkup().toString());	
			println(results.getDecompiledFunction().getC());
			try{
				String path = "./data/GhidraCFull/" 
				+ currentProgram.getName().substring(0,currentProgram.getName().length()-4);
				File dir = new File(path);
				dir.mkdir();
				String filename = path + "/" + function.getName() + ".txt";
				FileWriter fw = new FileWriter(filename);
				fw.write(results.getDecompiledFunction().getC());
				fw.close();
			}catch(Exception e){
				;
			}
			
		}
	}

	@Override
	public void run() throws Exception {
		try {
			decompInterface = setUpDecompiler(currentProgram);
			FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
			
			// Uncomment this code for automating the entire program.
			while (iter.hasNext()) {
				Function function = iter.next();
				println("Function = " + function.getName());

				decompileFunction(function);
				//decompileRawPcode(function);
				//decompileCCodeMarkup(function);
			}

		}
		finally {
			decompInterface.dispose();
		}
	}
	
}