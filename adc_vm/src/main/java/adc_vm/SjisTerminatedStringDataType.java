package adc_vm;

import ghidra.program.model.data.AbstractStringDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.StringLayoutEnum;

public final class SjisTerminatedStringDataType extends AbstractStringDataType {

	public static final SjisTerminatedStringDataType dataType = new SjisTerminatedStringDataType();

	public SjisTerminatedStringDataType() {
		this(null);
	}
	
	public SjisTerminatedStringDataType(DataTypeManager dtm) {
		super("TerminatedSjisString", // data type name
				"ds", // mnemonic
				"SJIS", // default label
				"SJ", // default label prefix
				"sj", // default abbrev label prefix
				"Sjis (Null Terminated)", // description
				"Shift_JIS", // charset
				CharDataType.dataType, // replacement data type
				StringLayoutEnum.NULL_TERMINATED_UNBOUNDED, // StringLayoutEnum
				null // data type manager
				);
	}

	@Override
	public DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new SjisTerminatedStringDataType(dtm);
	}

}
