/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package adc_vm;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.RefType;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

public class adc_vmAnalyzer extends AbstractAnalyzer {

	private static boolean isAdcVmLoader(Program program) {
		return program.getExecutableFormat().equalsIgnoreCase(adc_vmLoader.ADCVM_LOADER_NAME);
	}
	
	public adc_vmAnalyzer() {
		super("ADCVM Calls & Jumps Analyzer", "Fixed calls and jumps references", AnalyzerType.INSTRUCTION_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {
		return isAdcVmLoader(program);
	}

	@Override
	public boolean canAnalyze(Program program) {
		return isAdcVmLoader(program);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		Memory mem = program.getMemory();
		AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
		
		Address vmBase = ram.getAddress(0L);
		Address refs = ram.getAddress(adc_vmLoader.REFS_BASE);
		
		MemoryBlock refsBlock = mem.getBlock("refs");
		
		if (refsBlock == null) {
			return false;
		}
		
		long refsLen = refsBlock.getSize();
		
		var listing = program.getListing();
		var it = set.iterator();
		
		while (it.hasNext()) {
			if (monitor.isCancelled()) {
				break;
			}
			
			var it2 = it.next().iterator();
			
			while (it2.hasNext()) {
				if (monitor.isCancelled()) {
					break;
				}
				
				var instr = listing.getInstructionAt(it2.next());
				
				if (instr == null) {
					continue;
				}
				
				var opcode = instr.getMnemonicString();
				boolean isCall = opcode.equals("CALL");
				boolean isJump = opcode.equals("JMP");
				
				var refType = isCall ? RefType.UNCONDITIONAL_CALL : (isJump ? RefType.UNCONDITIONAL_JUMP : null);
				
				if (refType != null) {
					var objs = instr.getOpObjects(0);
//					final var index = instr.getScalar(0).getUnsignedValue();
//					
//					boolean isAbsolute = index <= refsLen;
//					
//					try {
//						if (isAbsolute) {
//							final var refsAddr = refs.add(index * 4);
//							
//							var dest = mem.getInt(refsAddr) & 0xFFFFFFFFL;
//							dest = (((dest >> 16L) & 0xFFFF) * 0x8000L) | (dest & 0xFFFF);
//							dest += 2;
//							var refAddr = vmBase.add(dest);
//							instr.addOperandReference(0, refAddr, RefType.UNCONDITIONAL_CALL, null);
//							
//							DisassembleCommand cmd = new DisassembleCommand(refAddr, null, true);
//							cmd.applyTo(program, monitor);
//							
//							CreateFunctionCmd cmd2 = new CreateFunctionCmd(null, refAddr, null, SourceType.ANALYSIS);
//							cmd2.applyTo(program, monitor);
//						} else {
//							refType = isCall ? RefType.COMPUTED_CALL : (isJump ? RefType.COMPUTED_JUMP : null);
//							
//							var varType = (int)(index >> 12);
//							var varIndex = (index & 0x3FF) * 2;
//							
//							Address varsc = ram.getAddress(adc_vmLoader.VARSC_BASE);
//							Address varsd = ram.getAddress(adc_vmLoader.VARSD_BASE);
//							Address varse = ram.getAddress(adc_vmLoader.VARSE_BASE);
//							Address varsf = ram.getAddress(adc_vmLoader.VARSF_BASE);
//							
//							Address varRef = varsd.add(varIndex);
//							
//							switch (varType) {
//							case 0xC: {
//								varRef = varsc.add(varIndex);
//							} break;
//							case 0xE: {
//								varRef = varse.add(varIndex);
//							} break;
//							case 0xF: {
//								varRef = varsf.add(varIndex);
//							} break;
//							}
//							
//							program.getReferenceManager().addMemoryReference(instr.getAddress(), varRef, refType, SourceType.ANALYSIS, 0);
//						}
//					} catch (MemoryAccessException e) {
//						e.printStackTrace();
//						log.appendException(e);
//						return false;
//					}
				}
			}
		}
		
		return false;
	}
}
