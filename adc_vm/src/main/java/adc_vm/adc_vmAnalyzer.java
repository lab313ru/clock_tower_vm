package adc_vm;

import ghidra.app.plugin.core.equate.CreateEnumEquateCommand;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.Enum;
import ghidra.program.model.listing.Program;
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
		
		var dtManager = program.getDataTypeManager();
		
		final var strDt = dtManager.getDataType(dtManager.getRootCategory().getCategoryPath(), "strings");
		
		if (strDt == null) {
			return false;
		}
		
		CreateEnumEquateCommand cmd = new CreateEnumEquateCommand(program, set, (Enum) strDt, true);
		cmd.applyTo(program, monitor);
		
		final var sjisDt = dtManager.getDataType(dtManager.getRootCategory().getCategoryPath(), "sjis");
		
		if (sjisDt == null) {
			return false;
		}
		
		cmd = new CreateEnumEquateCommand(program, set, (Enum) sjisDt, true);
		cmd.applyTo(program, monitor);
		
		return true;
	}

}
