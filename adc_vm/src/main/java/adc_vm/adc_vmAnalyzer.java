package adc_vm;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class adc_vmAnalyzer extends AbstractAnalyzer {

	public adc_vmAnalyzer() {
		super("ADCVM Strings Analyzer", "Applies string enums to all opcodes", AnalyzerType.INSTRUCTION_ANALYZER);
		
		setSupportsOneTimeAnalysis();
	}
	
	private static boolean isAdcVmLoader(Program program) {
		return program.getExecutableFormat().equalsIgnoreCase(adc_vmLoader.ADCVM_LOADER_NAME);
	}
	
	@Override
	public boolean getDefaultEnablement(Program program) {
		return adc_vmAnalyzer.isAdcVmLoader(program);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return adc_vmAnalyzer.isAdcVmLoader(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		var listing = program.getListing();
		var refsMgr = program.getReferenceManager();
		var ram = program.getAddressFactory().getDefaultAddressSpace();
		var mem = program.getMemory();
		var refsBase = ram.getAddress(adc_vmLoader.REFS_BASE);
		var refsBlock = mem.getBlock(refsBase);
		var symbols = program.getSymbolTable();
		
		var it = set.getAddresses(true);
		
		while (it.hasNext()) {
			var addr = it.next();
			var inst = listing.getInstructionAt(addr);
			
			if (inst == null) {
				continue;
			}
			
			var opc = inst.getMnemonicString();
			
			switch (opc) {
			case "IF":
			case "WHILE":
			{
				var scalar = inst.getScalar(0);
				
				if (scalar == null) {
					continue;
				}
				
				refsMgr.addMemoryReference(addr, ram.getAddress(scalar.getUnsignedValue()), RefType.DATA, SourceType.ANALYSIS, 0);
			} break;
			case "EVDEF":
			{
				var ref = inst.getOperandReferences(0);
				
				if (ref.length == 0) {
					continue;
				}
				
				var refVal = ref[0].getToAddress();
				
				try {
					if (refsBlock != null && (refVal.compareTo(refsBlock.getStart()) < 0 || refVal.compareTo(refsBlock.getEnd()) > 0)) {
						continue;
					}
					
					DataUtilities.createData(program, refVal, Pointer32DataType.dataType, -1, true, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
					
					var dest = mem.getInt(refVal);
					
					var evFunc = ram.getAddress(dest);
					DisassembleCommand cmd = new DisassembleCommand(evFunc, null, false);
					cmd.applyTo(program, monitor);
					
					var evFuncSyms = symbols.getSymbols(evFunc);
					var noName = true;
					
					for (var sym : evFuncSyms) {
						if (sym.getSource() == SourceType.USER_DEFINED) {
							noName = false;
							break;
						}
					}
					
					if (noName) {
						var objs = inst.getOpObjects(1);
						
						if (objs == null || objs.length == 0) {
							continue;
						}
						
						if (!(objs[0] instanceof Scalar)) {
							continue;
						}
						
						var evtIndex = ((Scalar)objs[0]).getUnsignedValue();
						
						var label = String.format("evt_%d_func_%06X", (int)evtIndex, (int)evFunc.getOffset());
						
						CreateFunctionCmd cmd2 = new CreateFunctionCmd(label, evFunc, null, SourceType.ANALYSIS);
						cmd2.applyTo(program, monitor);
					}
				} catch (MemoryAccessException | CodeUnitInsertionException e) {
					e.printStackTrace();
					log.appendException(e);
					continue;
				}
			} break;
			case "JMP":
			{
				var scalar = inst.getScalar(0);
				
				if (scalar == null) {
					continue;
				}
				
				var val = scalar.getUnsignedValue();
				
				if (val >= 0xF000) {
					continue;
				}
				
				try {
					var dest = ram.getAddress(mem.getInt(refsBase.add(val * 4)) & 0xFFFFFFFF);
					
					refsMgr.addMemoryReference(addr, dest, RefType.UNCONDITIONAL_JUMP, SourceType.ANALYSIS, 0);
					
					DisassembleCommand cmd = new DisassembleCommand(dest, null, true);
					cmd.applyTo(program, monitor);
					
					CreateFunctionCmd cmd2 = new CreateFunctionCmd(null, dest, null, SourceType.ANALYSIS);
					cmd2.applyTo(program, monitor);
				} catch (MemoryAccessException | AddressOutOfBoundsException e) {
					e.printStackTrace();
					log.appendException(e);
				}
				
				DisassembleCommand cmd = new DisassembleCommand(addr.add(4), null, false);
				cmd.applyTo(program, monitor);
			} break;
			case "CALL":
			{
				var scalar = inst.getScalar(0);
				
				if (scalar == null) {
					continue;
				}
				
				var val = scalar.getUnsignedValue();
				
				if (val >= 0xF000) {
					continue;
				}
				
				try {
					var dest = ram.getAddress(mem.getInt(refsBase.add(val * 4)) & 0xFFFFFFFF);
					
					refsMgr.addMemoryReference(addr, dest, RefType.UNCONDITIONAL_CALL, SourceType.ANALYSIS, 0);
					
					DisassembleCommand cmd = new DisassembleCommand(dest, null, true);
					cmd.applyTo(program, monitor);
					
					CreateFunctionCmd cmd2 = new CreateFunctionCmd(null, dest, null, SourceType.ANALYSIS);
					cmd2.applyTo(program, monitor);
				} catch (MemoryAccessException | AddressOutOfBoundsException e) {
					e.printStackTrace();
					log.appendException(e);
				}
			} break;
			case "ENDWHILE":
			{
				DisassembleCommand cmd = new DisassembleCommand(addr.add(4), null, false);
				cmd.applyTo(program, monitor);
			} break;
			case "BGLOAD":
			case "PALLOAD":
			case "BGMREQ":
			case "SEREQ":
			case "SEPAN":
			case "SEVOL":
			{
				var scalar = inst.getScalar(1);
				
				if (scalar == null) {
					continue;
				}
				
				refsMgr.addMemoryReference(addr, ram.getAddress(scalar.getUnsignedValue()), RefType.DATA, SourceType.ANALYSIS, 1);
			} break;
			case "MAPLOAD":
			{
				var scalar1 = inst.getScalar(1);
				var scalar2 = inst.getScalar(2);
				
				if (scalar1 == null || scalar2 == null) {
					continue;
				}
				
				refsMgr.addMemoryReference(addr, ram.getAddress(scalar1.getUnsignedValue()), RefType.DATA, SourceType.ANALYSIS, 1);
				refsMgr.addMemoryReference(addr, ram.getAddress(scalar2.getUnsignedValue()), RefType.DATA, SourceType.ANALYSIS, 2);
			} break;
			case "MAPWRT":
			{
				var scalar = inst.getScalar(2);
				
				if (scalar == null) {
					continue;
				}
				
				refsMgr.addMemoryReference(addr, ram.getAddress(scalar.getUnsignedValue()), RefType.DATA, SourceType.ANALYSIS, 2);
			} break;
			case "SESTOP":
			{
				var scalar = inst.getScalar(0);
				
				if (scalar == null) {
					continue;
				}
				
				refsMgr.addMemoryReference(addr, ram.getAddress(scalar.getUnsignedValue()), RefType.DATA, SourceType.ANALYSIS, 0);
			} break;
			case "SEREQPV":
			case "SEREQSPR":
			{
				var scalar = inst.getScalar(3);
				
				if (scalar == null) {
					continue;
				}
				
				refsMgr.addMemoryReference(addr, ram.getAddress(scalar.getUnsignedValue()), RefType.DATA, SourceType.ANALYSIS, 1);
			} break;
			case "AVIPLAY":
			{
				var scalar = inst.getScalar(5);
				
				if (scalar == null) {
					continue;
				}
				
				refsMgr.addMemoryReference(addr, ram.getAddress(scalar.getUnsignedValue()), RefType.DATA, SourceType.ANALYSIS, 5);
			} break;
			case "MSGOUT":
			{
				var scalar = inst.getScalar(2);
				
				if (scalar == null) {
					continue;
				}
				
				refsMgr.addMemoryReference(addr, ram.getAddress(scalar.getUnsignedValue()), RefType.DATA, SourceType.ANALYSIS, 2);
			} break;
			}
		}
		
		return true;
	}

}
