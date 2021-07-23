package adc_vm;

import ghidra.program.model.data.Pointer32DataType;
import ghidra.program.model.data.StringDataInstance;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.ConstantPool;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;

public final class adc_vmConstantPool extends ConstantPool {
	
	private Program program;
	private Listing listing;
	
	public adc_vmConstantPool(Program program) {
		this.program = program;
		listing = program.getListing();
	}

	@Override
	public Record getRecord(long[] ref) {
		Record res = new Record();
		
		long address = ref[0];
		int type = (int)ref[1];
		
		switch (type) {
		case 0:
		case 1:
		{
			res.tag = ConstantPool.STRING_LITERAL;
			
			var strAddr = program.getAddressFactory().getDefaultAddressSpace().getAddress(address);
			var dt = listing.getDataAt(strAddr);
			
			res.byteData = StringDataInstance.getStringDataInstance(dt).getStringValue().getBytes();
			
			if (type == 1) {
				res.type = new Pointer32DataType(TerminatedStringDataType.dataType);
			} else {
				res.type = new Pointer32DataType(SjisTerminatedStringDataType.dataType);
			}
		} break;
		case 2:
		{
			if (address >= 0xF000) {
				res.tag = ConstantPool.PRIMITIVE;
				res.token = "int";
				res.value = address;
				res.type = UnsignedIntegerDataType.dataType;
				break;
			}
			
			var r = program.getAddressFactory().getDefaultAddressSpace().getAddress(adc_vmLoader.REFS_BASE + address * 4);

			try {
				int val = program.getMemory().getInt(r) & 0xFFFFFFFF;
				res.tag = ConstantPool.PRIMITIVE;
				res.token = "void*";
				res.value = val;
				res.type = new Pointer32DataType(VoidDataType.dataType);
			} catch (MemoryAccessException e) {
				e.printStackTrace();
			}
		} break;
		}
		
		return res;
	}

}
