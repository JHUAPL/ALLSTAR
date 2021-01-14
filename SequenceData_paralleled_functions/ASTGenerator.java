//AST Generator
//@author Arquimedes Canedo
//@category MINDSIGHT

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


// PCode Description: https://ghidra.re/courses/languages/html/pcoderef.html4


public class ASTGenerator extends GhidraScript {
	
	String acfgOutputDir = "";
	String dotOutputDir = "";
	FileWriter gfw;
	
	private DecompInterface decompInterface;
	
	// Other interesting links and doc
	// https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/src/main/help/help/topics/DecompilePlugin/Decompiler.htm
	// Pcode Trees: https://ghidra.re/courses/languages/html/sleigh_constructors.html#idm140310874886224
	// Scripts that dump Pcode data: https://github.com/d-millar/ghidra_pcode_scripts
	
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
	
	// https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighFunction.html
	// https://github.com/cetfor/GhidraSnippets#dumping-refined-pcode
	private void decompileHighFunction(Function function) {
		DecompileResults results = decompInterface.decompileFunction(function, decompInterface.getOptions().getDefaultTimeout(), ConsoleTaskMonitor.DUMMY);
		
		if (results.failedToStart()) {
			println("Failed to start decompilation");
		} 	
		
		if (!results.decompileCompleted()) {
			System.out.println(results.getErrorMessage());
		}
		else {
			Address fstart = results.getHighFunction().getFunction().getEntryPoint();
			int fsize = (int) results.getHighFunction().getFunction().getBody().getNumAddresses();
    		println(results.getHighFunction().buildFunctionXML(fstart, fsize));	
		}		
	}
	
	
	private String printBasicBlockFeatures(Map<String, Number>features, Boolean dotFormat) {
		String myString = " ";
				
		if (dotFormat == true) {
			myString += "\"[";
		}
		myString += features.get("totalInstructions");
		myString += ", ";
		myString += features.get("arithmeticInstructions");
		myString += ", ";
		myString += features.get("logicInstructions");
		myString += ", ";
		myString += features.get("transferInstructions");
		myString += ", ";
		myString += features.get("callInstructions");
		myString += ", ";
		myString += features.get("dataTransferInstructions");
		myString += ", ";
		myString += features.get("ssaInstructions");
		myString += ", ";
		myString += features.get("compareInstructions");
		myString += ", ";
		myString += features.get("pointerInstructions");
		myString += ", ";
		myString += features.get("otherInstructions");
		myString += ", ";
		myString += features.get("totalConstants");
		myString += ", ";
		myString += features.get("totalStrings");
		
		if (dotFormat == true) {
			myString += "]\"";
		}

		return myString;
	}
	
	// Get features for a basic block instructions
	private Map<String, Number> getBasicBlockFeatures(PcodeBlockBasic bb, Map<Long, String> programStrings) {
		Iterator<PcodeOp> insns = bb.getIterator();
		Map<String, Number> features = new HashMap<>();
		
		// Features: https://github.com/qian-feng/Gencoding/blob/master/raw-feature-extractor/graph_analysis_ida.py
		int totalInstructions = 0;
		int arithmeticInstructions = 0;
		int logicInstructions = 0;
		int transferInstructions = 0;
		int callInstructions = 0;
		int otherInstructions = 0;
		int dataTransferInstructions = 0;
		int ssaInstructions = 0;
		int pointerInstructions = 0;
		int compareInstructions = 0;
		
		int totalConstants = 0;
		int totalStrings = 0;
		
		while(insns.hasNext()) { 
			PcodeOp node = insns.next();
		
			String mnemonic = node.getMnemonic();
			switch(mnemonic) {
				case "INT_ADD":
				case "INT_SUB":
				case "INT_MULT":
				case "INT_DIV":
				case "INT_REM":
				case "INT_SDIV":
				case "INT_SREM":
				case "INT_LEFT":
				case "INT_RIGHT":
				case "INT_SRIGHT":
				case "FLOAT_ADD":
				case "FLOAT_SUB":
				case "FLOAT_MULT":
				case "FLOAT_DIV":
				case "FLOAT_ABS":
				case "FLOAT_SQRT":
				case "FLOAT_CEIL":
				case "FLOAT_FLOOR":
				// Not sure about these belong here
				case "INT_ZEXT":
				case "INT_SEXT":
					arithmeticInstructions += 1;
					break;
					
				case "BOOL_NEGATE":
				case "BOOL_AND":
				case "BOOL_XOR":
				case "BOOL_OR":
				// Not sure about these belong here
				case "INT_OR":
				case "INT_AND":
				case "INT_XOR":
					logicInstructions += 1;
					break;
					
				case "BRANCH":
				case "CBRANCH":
				case "BRANCHIND":
				case "RETURN":
					transferInstructions += 1;
					break;
					
				case "CALL":
				case "CALLIND":
					callInstructions += 1;
					break;
					
				case "COPY":
				case "LOAD":
				case "STORE":
				// Not sure about these belong here
				case "PIECE":
				case "SUBPIECE":
				case "CAST":
					dataTransferInstructions += 1;
					break;
					
				case "MULTIEQUAL":
				case "INDIRECT":
					ssaInstructions += 1;
					break;
					
				case "INT_EQUAL":
				case "INT_NOTEQUAL":
				case "INT_LESS":
				case "INT_SLESS":
				case "INT_LESSEQUAL":
				case "INT_SLESSEQUAL":
				case "FLOAT_EQUAL":
				case "FLOAT_NOTEQUAL":
				case "FLOAT_LESS":
				case "FLOAT_LESSEQUAL":
					compareInstructions += 1;
					break;
					
				case "PTRSUB":
				case "PTRADD":
					pointerInstructions += 1;
					break;
					
				default:
					println(mnemonic);
					otherInstructions += 1;
					break;
			}
			
			
			for (int i=0; i<node.getNumInputs(); i++) {
				Varnode operand = node.getInput(i);
				if (operand.isConstant()) {
					totalConstants += 1;
				}
				if (operand.toString() != null) {
					Address myAddr = operand.getAddress();
					if (programStrings.containsKey(myAddr.getOffset())) {
						totalStrings += 1;
					}
				}
				
			}
			
			
			totalInstructions += 1;
		}
		
		features.put("totalInstructions", totalInstructions);
		features.put("arithmeticInstructions", arithmeticInstructions);
		features.put("logicInstructions", logicInstructions);
		features.put("transferInstructions", transferInstructions);
		features.put("callInstructions", callInstructions);
		features.put("dataTransferInstructions", dataTransferInstructions);
		features.put("ssaInstructions", ssaInstructions);
		features.put("compareInstructions", compareInstructions);
		features.put("pointerInstructions", pointerInstructions);
		features.put("otherInstructions", otherInstructions);
		features.put("totalConstants", totalConstants);
		features.put("totalStrings", totalStrings);

		
		//println(printBasicBlockFeatures(features));
		
		return features;
	}
	
	// Get all the strings in the program
	// XXX: the Address from definedStrings and varnode do not match. One gives the address 0x1111 the other gives (ram)0x1111 and the match finds.
	// XXX: keeping it as Long
	private Map<Long, String> getProgramStrings() {		
		Map<Long, String> programStrings = new HashMap<>();
	    for (Data data : DefinedDataIterator.definedStrings(currentProgram)) {
	        StringDataInstance str = StringDataInstance.getStringDataInstance(data);
	        if (StringDataInstance.NULL_INSTANCE == str) {
	        	continue;
	        }
	        programStrings.put(str.getAddress().getOffset(), str.getStringValue());
	    }
	    return programStrings;
	}
	
	// https://reverseengineering.stackexchange.com/questions/20905/ghidra-control-flow-graph
	private BasicBlockMetadata decompileBasicBlocks(Function function) {
		DecompileResults results = decompInterface.decompileFunction(function, decompInterface.getOptions().getDefaultTimeout(), ConsoleTaskMonitor.DUMMY);
		ArrayList basicBlocks = new ArrayList();
		ArrayList edges = new ArrayList();
		ArrayList<String> attributes = new ArrayList();
		ArrayList<String> boundaries = new ArrayList();
		BasicBlockMetadata bbInfo = null;
		
		if (results.failedToStart()) {
			println("Failed to start decompilation");
		} 	
		
		if (!results.decompileCompleted()) {
			System.out.println(results.getErrorMessage());
		}
		else {
			DotWriter myDot = new DotWriter(this.dotOutputDir + function.toString() + ".dot");
			
			myDot.write("Digraph G {\n");
			
			HighFunction hf = results.getHighFunction();
			ArrayList<PcodeBlockBasic> bbs = hf.getBasicBlocks();
			println("Function " + hf.toString() + " has " + bbs.size() + " basic blocks");
			println("BB varnodes = " + hf.getNumVarnodes());
			
			Map<Long, String> programStrings = getProgramStrings();
			
			// https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/PcodeBlockBasic.html
			for (PcodeBlockBasic bb : bbs) {
				Map<String, Number> bbFeatures = getBasicBlockFeatures(bb, programStrings);
				basicBlocks.add(bb);
				attributes.add(bb.toString() + "," + printBasicBlockFeatures(bbFeatures, false));
				
				//myDot.writeln("\"" + bb.toString() + "\"" + " [label=" + printBasicBlockFeatures(bbFeatures, true) + "]");
				myDot.writeln("\"" + bb.toString() + "\"");
				
				// Process Input BBs
				for (int i=0; i<bb.getInSize(); i++) {
					String src = bb.getIn(i).toString();
					String dst = bb.toString();
					myDot.writeln("\"" + src + "\" -> \"" + dst + "\"");
					edges.add(new Tuple(src, dst));
				}
				
				boundaries.add(bb.getStart().toString() + ", " + bb.getStop().toString());
			}
			
			myDot.write("}");
			myDot.close();

		}		
		
		bbInfo = new BasicBlockMetadata(basicBlocks, edges, attributes, boundaries);
		return bbInfo;
	}
	
	
	private String getVarnodeKey(VarnodeAST vn) {
		PcodeOp op = vn.getDef();
		String id;
		if (op != null) {
			// v is for varnode vertex
			id = op.getSeqnum().getTarget().toString(true) + " v " +
				Integer.toString(vn.getUniqueId());
		}
		else {
			// i v is a memory address poiting to the function body of the call that follows
			id = "i v " + Integer.toString(vn.getUniqueId());
		}
		return id;
	}
	
	// https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/ghidra_scripts/GraphAST.java
	private void decompileAST(Function function) {
		DecompileResults results = decompInterface.decompileFunction(function, decompInterface.getOptions().getDefaultTimeout(), ConsoleTaskMonitor.DUMMY);
		
		if (results.failedToStart()) {
			println("Failed to start decompilation");
		} 	
		
		if (!results.decompileCompleted()) {
			System.out.println(results.getErrorMessage());
		}
		else {
			HighFunction hf = results.getHighFunction();
			ArrayList<PcodeBlockBasic> bbs = hf.getBasicBlocks();
			
			Iterator<PcodeOpAST> iter = hf.getPcodeOps();
			while(iter.hasNext()) {
				PcodeOpAST node = iter.next();
				//println(node.toString());
			}
			
			buildGraph(function, hf);
		}		
	}
	
	
	
	
	// Pretty prints ClangNode
	private String ppClangNode(ClangNode node) {
		if (node instanceof ClangOpToken) {
			return "OP " + ((ClangOpToken) node).getText();
		}
		if (node instanceof ClangTypeToken) {
			return "TYPE " + node.toString();
		}
		if (node instanceof ClangStatement) {
			return "STMT";
		}
		if (node instanceof ClangVariableToken) {
			String clean = node.toString().replace("\"", "");
			return "VAR " + clean;
		}
		if (node instanceof ClangVariableDecl) {
			return "VAR_DECL";
		}
		if (node instanceof ClangFuncProto) {
			return "FUNC_PROTO";
		}
		if (node instanceof ClangReturnType) {
			return "RETURN_TYPE";
		}
		if (node instanceof ClangFuncNameToken) {
			return "FUNC_NAME " + node.toString();
		}
		if (node instanceof ClangTokenGroup) {
			return "TOKEN_GROUP";
		}
		
		
		return "node";
	}
	
	// Traverse all levels of the Clang expressions
	// https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/ghidra_scripts/ShowConstantUse.java
	int ClangNumNodes = 0;
	HashMap<ClangNode, Integer> ClangMap;
	
	private void traverseClangChildren(ClangNode node, int depth, DotWriter myDot) {
		int i;
	
		// Add node to the ClangMap to get a unique ID
		if (!ClangMap.containsKey(node)) {
			ClangNumNodes += 1;
			ClangMap.put(node, ClangNumNodes);
		}
		
		println("(" + depth + "):" +  node.getClass().getName() + " " + node.toString());
		
		for (i=0; i<node.numChildren(); i++) {
			ClangNode child = node.Child(i);
			if (child instanceof ClangBreak 
					|| child instanceof ClangSyntaxToken
					|| child instanceof ClangBreak) {
				continue;
			}
			
			traverseClangChildren(node.Child(i), depth+1, myDot);
		
			if (ClangMap.containsKey(child) && ClangMap.containsKey(node)) {
				int childID = ClangMap.get(child);
				int myID = ClangMap.get(node);
				myDot.write("\"" + myID + " " + ppClangNode(node) + "\"" + " -> " + "\"" + childID + " " + ppClangNode(child) + "\"" + "\n");
			}
		}
	}
	
	
	
	// ******************
	private String getOpKey(PcodeOpAST op) {
		SequenceNumber sq = op.getSeqnum();
		// o is for Op (Pcode) vertex
		String id =
			sq.getTarget().toString(true) + " o " + Integer.toString(op.getSeqnum().getTime());
		return id;
	}
	
	protected AttributedVertex createOpVertex(Function func, HighFunction hf, PcodeOpAST op) {
		String name = op.getMnemonic();
		String id = getOpKey(op);
		int opcode = op.getOpcode();
		if ((opcode == PcodeOp.LOAD) || (opcode == PcodeOp.STORE)) {
			Varnode vn = op.getInput(0);
			AddressSpace addrspace =
				func.getProgram().getAddressFactory().getAddressSpace((int) vn.getOffset());
			name += ' ' + addrspace.getName();
		}
		else if (opcode == PcodeOp.INDIRECT) {
			Varnode vn = op.getInput(1);
			if (vn != null) {
				PcodeOp indOp = hf.getOpRef((int) vn.getOffset());
				if (indOp != null) {
					name += " (" + indOp.getMnemonic() + ')';
				}
			}
		}
		//AttributedVertex vert = graph.addVertex(id, name);
		//vert.setAttribute(ICON_ATTRIBUTE, "Square");
		AttributedVertex vert = new AttributedVertex(id, name);
		//println("Adding vertex to graph... id=" + id.toString() + ", name=" + name);
		return vert;
	}
	
	protected Iterator<PcodeOpAST> getPcodeOpIterator(HighFunction hf) {
		Iterator<PcodeOpAST> opiter = hf.getPcodeOps();
		return opiter;
	}
	
	protected AttributedVertex createVarnodeVertex(VarnodeAST vn) {
		String name = vn.getAddress().toString(true);
		String id = getVarnodeKey(vn);
		AttributedVertex vert = new AttributedVertex(id, name);
		return vert;
	}
	
	protected AttributedVertex getVarnodeVertex(Map<Integer, AttributedVertex> vertices, VarnodeAST vn) {
		AttributedVertex res;
		res = vertices.get(vn.getUniqueId());
		if (res == null) {
			res = createVarnodeVertex(vn);
			vertices.put(vn.getUniqueId(), res);
		}
		return res;
	}
	
	
	protected void getHighFunctionSymbols(HighFunction hf) {
		// Other interesting HF methods
		// 	containsVariableWithName​
		// mysymbol.getPCAddress
		// mysymbol.getHighVariable().getRepresentative() gets the Varnode associated to the high variable.
		
		println("High Function Symbols:");
		LocalSymbolMap variable_map = hf.getLocalSymbolMap();
		Iterator<HighSymbol> symboliter = variable_map.getSymbols();

		while(symboliter.hasNext()) {
			HighSymbol mysymbol = symboliter.next();
			println("SymbolMap: ");
			println("  Name: " + mysymbol.getName());
			println("  DataType: " + mysymbol.getDataType().toString());
			HighVariable myhv = mysymbol.getHighVariable();
			Varnode [] myhv_instances = myhv.getInstances();
			for (int i=0; i<myhv_instances.length; i++) {
				println("    Instance: " + myhv_instances[i].toString());
				Iterator<PcodeOp> descendants = myhv_instances[i].getDescendants();
				while(descendants.hasNext()) {
					PcodeOp descendant = descendants.next();
					println("        Descendant: " + descendant.toString());
				}
			}
		}
	}
	
	// https://ghidra.re/ghidra_docs/api/ghidra/program/model/listing/StackFrame.html
	// https://reverseengineering.stackexchange.com/questions/21071/get-stack-references-in-ghidra-of-a-function-from-the-java-api
	protected void getStackVariables(Function f) {
		StackFrame sf = f.getStackFrame();
		Variable [] localVars = sf.getLocals();
		for (int i=0; i<localVars.length; i++) {
			println("Stack variable: " + localVars[i].getName() + " " + localVars[i].getFirstStorageVarnode().toString() + " " + localVars[i].getLastStorageVarnode().toString());
		}
	}
	
	
	protected void getHighFunctionInfo(HighFunction hf) {
		// Other interesting methods
		// getJumpTables
		getHighFunctionSymbols(hf);
	}
	
	// Prints the Pcode in the form of complete statements OUTPUT = OPCODE(INPUT_1, INPUT_2, ..., INPUT_N)
	protected void getOpInfo(PcodeOpAST op) {
		String pcode_info = "";
		
		// Output
		VarnodeAST output = (VarnodeAST) op.getOutput();
		if (output != null) {
			pcode_info += output.toString();
		}
			
		pcode_info += " = ";
		
		// Inputs
		pcode_info += op.getMnemonic() + "(";
		for (int i = 0; i < op.getNumInputs(); ++i) {
			VarnodeAST input = (VarnodeAST) op.getInput(i);
			
			if (input != null) {
				pcode_info += input.toString();
			}
			
			if (i < op.getNumInputs()-1) {
				pcode_info += ", ";
			}
		}
		pcode_info += ")";
		println(pcode_info);
	}
	
	// Adapted from buildGraph
	// https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Decompiler/ghidra_scripts/GraphAST.java
	protected void buildGraph(Function function, HighFunction hf) {

		HashMap<Integer, AttributedVertex> vertices = new HashMap<>();

		getHighFunctionInfo(hf);
		getStackVariables(function);

		
		DotWriter myDot = new DotWriter("/tmp/function.dot");
		myDot.write("Digraph G {\n");

		Iterator<PcodeOpAST> opiter = getPcodeOpIterator(hf);
		while (opiter.hasNext()) {
			PcodeOpAST op = opiter.next();
			AttributedVertex o = createOpVertex(function, hf, op);
			
			getOpInfo(op);

			
			for (int i = 0; i < op.getNumInputs(); ++i) {
				int opcode = op.getOpcode();
				if ((i == 0) && ((opcode == PcodeOp.LOAD) || (opcode == PcodeOp.STORE))) {
					println("+++++++ LOAD/STORE " + op.getMnemonic());
					continue;
				}
				if ((i == 1) && (opcode == PcodeOp.INDIRECT)) {
					println("+++++++ INDIRECT " + op.getMnemonic());
					continue;
				}
				
				VarnodeAST vn = (VarnodeAST) op.getInput(i);
				
				HighVariable hv = vn.getHigh();
				if (hv != null) {
					//println("********* VARIABLE input(" + i + ") " +  hv.getRepresentative().toString());
					
					// Interesting methods
					// hv.getInstances; A variable can reside in different locations at various times. Get all the instances of the variable.
					// hv.getDataType; get the data type attached to the variable
					// hv.getSize; get the size of the variable

				}
				
				
				if (vn != null) {
					AttributedVertex v = getVarnodeVertex(vertices, vn);
					//println("Edge = " + v.toString() + "->" + o.toString());
					//createEdge(v, o); 
					myDot.write("\t" + v.toString() + " -> " + o.toString() + "\n");
				}
			}
			
			VarnodeAST outvn = (VarnodeAST) op.getOutput();
			if (outvn != null) {
				AttributedVertex outv = getVarnodeVertex(vertices, outvn);
				if (outv != null) {
					//createEdge(o, outv);
					//println("Edge = " + o.toString() + "->" + outv.toString());
					myDot.write("\t" + o.toString() + " -> " + outv.toString() + "\n");
				}
			}
			
		}
		
		myDot.write("}");
		myDot.close();

	}
	
	
	
	// There are two forms of Pcode: raw and refined. 
	// Adapted from https://github.com/cetfor/GhidraSnippets
	private void decompileRawPcode(Function function) {
		AddressSetView func_body = function.getBody();
		Listing listing = currentProgram.getListing();
		InstructionIterator opiter = listing.getInstructions(func_body, true);
		while (opiter.hasNext()) {
			Instruction insn = opiter.next();
			PcodeOp [] raw_pcode = insn.getPcode();
			for (int i=0; i<raw_pcode.length; i++) {
				println(raw_pcode[i].toString());
			}
		}
	}

	
	// https://github.com/NationalSecurityAgency/ghidra/issues/574
	private void decompileCCodeMarkup(Function function) {
		DecompileResults results = decompInterface.decompileFunction(function, decompInterface.getOptions().getDefaultTimeout(), ConsoleTaskMonitor.DUMMY);
		
		DotWriter myDot = new DotWriter("/tmp/clang.dot");
		myDot.write("Digraph G {\n");
		
		if (results.failedToStart()) {
			println("Failed to start decompilation");
		} 	
		
		if (!results.decompileCompleted()) {
			System.out.println(results.getErrorMessage());
		}
		else {
    		ClangTokenGroup group = results.getCCodeMarkup();
    		ClangMap = new HashMap<>();
    		traverseClangChildren(group, 0, myDot);
		}	
		
		myDot.write("}\n");
		myDot.close();
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
    			gfw.write(results.getDecompiledFunction().getC());
    			gfw.write("\n");
    		}catch(Exception e){
    			;
    		}
    		
		}
	}
	
	// Is this the best way to get global variable names?
	// The hv.getName() does not provide a name. It is always null (?)
	// https://github.com/NationalSecurityAgency/ghidra/issues/1561
	public HashMap<Address, Symbol> getGlobalSymbols() {
		HashMap<Address, Symbol> GlobalSymbols = new HashMap<>();
		// Note: this may need to be adjusted to not only initialized symbols
    	AddressSetView initialized = currentProgram.getMemory().getLoadedAndInitializedAddressSet();
    	AddressIterator addrIter = initialized.getAddresses(true);
    	while (addrIter.hasNext() && !monitor.isCancelled()) {
    		Address addr = addrIter.next();
    		Symbol sym = getSymbolAt(addr);
    		
    		if (sym != null) {
    			printf("Symbol at 0x%x", addr.getOffset());
    			printf(" = %s\n", sym.getName());
    			GlobalSymbols.put(addr, sym);
    		} 
    	}
    	return GlobalSymbols;
	}
	
	private void decompileGlobalAccesses(Function function) {
		DecompileResults results = decompInterface.decompileFunction(function, decompInterface.getOptions().getDefaultTimeout(), ConsoleTaskMonitor.DUMMY);
		
		if (results.failedToStart()) {
			println("Failed to start decompilation");
		} 	
		
		if (!results.decompileCompleted()) {
			System.out.println(results.getErrorMessage());
		}
		else {
			
		}
		
		HighFunction hf = results.getHighFunction();			
		Iterator<PcodeOpAST> iter = hf.getPcodeOps();
		HashMap<Address, Symbol> GlobalSymbols = getGlobalSymbols();
		while(iter.hasNext()) {				
			PcodeOpAST op = iter.next();
			for (int i = 0; i < op.getNumInputs(); ++i) {					
				VarnodeAST vn = (VarnodeAST) op.getInput(i);
				HighVariable hv = vn.getHigh();
				// If hv is HighGlobal
				if (hv instanceof HighGlobal) {
					printf("Global access found %s, %s\n", op.toString(), hv.toString());
					if (GlobalSymbols.containsKey(hv.getRepresentative().getAddress())) {
						printf("\tname = %s\n", GlobalSymbols.get(hv.getRepresentative().getAddress()));
					}
				}
			}

		}		
	}
	
	private void createDir(String dirName) {
		File directory = new File(dirName);
		if (!directory.exists()) {
			directory.mkdir();
		}
	}
	
	private void ACFG() {
		FileWriter programWriter = null;
		FileWriter edgeWriter = null;
		FileWriter attributeWriter = null;
		FileWriter boundaryWriter = null;
		try {
			this.acfgOutputDir = "/tmp/" + currentProgram.getName() + "-acfg/";
			this.dotOutputDir = this.acfgOutputDir + "/dot/";
			
			createDir(this.acfgOutputDir);
			createDir(this.dotOutputDir);
			
	        programWriter = new FileWriter(this.acfgOutputDir + "program.csv");
	        edgeWriter = new FileWriter(this.acfgOutputDir + "edges.csv");
	        attributeWriter = new FileWriter(this.acfgOutputDir + "attributes.csv");
	        boundaryWriter = new FileWriter(this.acfgOutputDir + "block_boundaries.csv");
	        
	    	FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
	    	while (iter.hasNext()) {
	    		Function function = iter.next();
	            programWriter.write(function.getName() + ", ");
	            
	            BasicBlockMetadata bbMetadata = decompileBasicBlocks(function);
	            
	            // Print Program (function-basic blocks)
	            for (int i=0; i<bbMetadata.basicBlocks.size(); i++) {
	            	PcodeBlockBasic bb = (PcodeBlockBasic) bbMetadata.basicBlocks.get(i);
	            	if (i != bbMetadata.basicBlocks.size()-1) {
		            	programWriter.write(bb.toString() + ",");	            		
	            	}
	            	else {
	            		programWriter.write(bb.toString() + "\n");
	            	}
	            	
	            	// Print block boundaries
	            	String boundaries = (String) bbMetadata.boundaries.get(i);
	            	boundaryWriter.write(bb.toString() + ", " + boundaries + "\n");
	            }
	            
	            // Print Edges (bb-bb)
	            for (int i=0; i<bbMetadata.edges.size(); i++) {
	            	Tuple edge = (Tuple) bbMetadata.edges.get(i);
	            	edgeWriter.write(edge.x + ", " + edge.y + "\n");
	            }
	            
	            // Print attributes
	            for (int i=0; i<bbMetadata.attributes.size(); i++) {
	            	String attributes = (String) bbMetadata.attributes.get(i);
	            	attributeWriter.write(attributes + "\n");
	            }

	    	}

	        programWriter.flush();
	        programWriter.close();
	        
	        edgeWriter.flush();
	        edgeWriter.close();
	        
	        attributeWriter.flush();
	        attributeWriter.close();
	        
	        boundaryWriter.flush();
	        boundaryWriter.close();
	        
	        
		
		} catch (Exception e) {
            e.printStackTrace();
        }
		
		println("Finished analyzing control flow graph " + currentProgram.getName());
	}
	
	
	private void ACallGraph() {
		FileWriter callGraphWriter = null;
    	FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
    	
    	try {
    		this.acfgOutputDir = "/tmp/" + currentProgram.getName() + "-acfg/";
			createDir(this.acfgOutputDir);
			callGraphWriter = new FileWriter(this.acfgOutputDir + "callgraph.csv");
    		
        	while (iter.hasNext()) {
        		Function function = iter.next();
        		Set<Function> incoming = function.getCallingFunctions(ghidra.util.task.TaskMonitor.DUMMY);
        		Set<Function> outgoing = function.getCalledFunctions(ghidra.util.task.TaskMonitor.DUMMY);
        		callGraphWriter.write(function.getName() +  ", " + incoming.size() + ", " + outgoing.size() + "\n");
        	}
        	callGraphWriter.flush();
        	callGraphWriter.close();
	
		} catch (Exception e) {
	        e.printStackTrace();
	    }
		println("Finished analyzing callgraph for " + currentProgram.getName());

	}
	
	
    @Override
    public void run() throws Exception {
    	try {
    		decompInterface = setUpDecompiler(currentProgram);
        	FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        	
        	// Uncomment this code for automating the entire program.
        	
        	gfw = new FileWriter("output.txt");

        	while (iter.hasNext()) {
        		Function function = iter.next();
        		println("Function = " + function.getName());

        		//gfw.write(function.getName()+"\n");

        		
        		decompileFunction(function);
        		//decompileRawPcode(function);
        		//decompileCCodeMarkup(function);
        	}
        	gfw.close();
        	
        	//decompileCCodeMarkup(getFunctionContaining(currentAddress));
        	//decompileHighFunction(getFunctionContaining(currentAddress));
        	//decompileBasicBlocks(getFunctionContaining(currentAddress));
        	//decompileAST(getFunctionContaining(currentAddress));
        	//decompileRawPcode(getFunctionContaining(currentAddress));
        	//decompileGlobalAccesses(getFunctionContaining(currentAddress));
        	
        	
        	//ACFG();
        	
        	ACallGraph();

    	}
    	finally {
    		decompInterface.dispose();
    	}
    }
    
}
