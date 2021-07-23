package adc_vm;

import java.io.IOException;

import ghidra.app.plugin.processors.sleigh.SleighLanguage;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.lang.PcodeInjectLibrary;
import ghidra.program.model.listing.Program;

public class adc_vmPcodeInjectLibrary extends PcodeInjectLibrary {

	public adc_vmPcodeInjectLibrary(SleighLanguage l) {
		super(l);
	}
	
	public adc_vmPcodeInjectLibrary(adc_vmPcodeInjectLibrary op2) {
		super(op2);
	}

	@Override
	public PcodeInjectLibrary clone() {
		return new adc_vmPcodeInjectLibrary(this);
	}

	@Override
	public ConstantPool getConstantPool(Program program) throws IOException {
		return new adc_vmConstantPool(program);
	}
}
