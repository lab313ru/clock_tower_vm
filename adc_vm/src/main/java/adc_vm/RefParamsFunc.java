package adc_vm;

public final class RefParamsFunc {
	// 0xFF39, 1), new Pair<>("BGLOAD", 1)
	private final int opcode;
	private final int argsCount;
	private final int[] refOps;
	private final String name;
	
	public RefParamsFunc(int opcode, int argsCount, final int[] refOps, final String name) {
		this.opcode = opcode;
		this.argsCount = argsCount;
		this.refOps = refOps;
		this.name = name;
	}
	
	public int getOpcode() { return opcode; }
	
	public int getArgsCount() { return argsCount; }
	
	public int[] getRefOperands() { return refOps; }
	
	public String getName() { return name; }
}
