//Function renaming for DIRE corpus generation
//@author Arquimedes Canedo
//@category MINDSIGHT

import java.util.ArrayList;
import java.util.List;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.symbol.SourceType;

public class FunctionRename extends GhidraScript {

	
    @Override
    public void run() throws Exception {

        Address start = currentProgram.getMinAddress();
        Address end = currentProgram.getMaxAddress();
    	FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
    	while (iter.hasNext()) {
    		Function function = iter.next();
    		println("Function = " + function.getName());
    		function.setName("MINDSIGHT_" + function.getName(), SourceType.USER_DEFINED);
    		println("Function = " + function.getName());
    	}
    }
    
}