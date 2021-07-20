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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.plugin.core.equate.CreateEnumEquateCommand;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.EnumDataType;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.TerminatedStringDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.LanguageCompilerSpecPair;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.mem.MemoryConflictException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class adc_vmLoader extends AbstractLibrarySupportLoader {

	public static final String ADCVM_LOADER_NAME = "ADC Object File";
	private static final String ADCVM_TAG = "ADC Object File";
	public static final long IMAGE_BASE    = 0x100L;
	public static final long VARSC_BASE    = 0x0100C000L;
	public static final long VARSD_BASE    = 0x0100D000L;
	public static final long VARSE_BASE    = 0x0100E000L;
	public static final long VARSF_BASE    = 0x0100F000L;
	public static final long REFS_BASE     = 0x02000000L;
	public static final long STRINGS_BASE  = 0x03000000L;
	
	@Override
	public String getName() {
		return ADCVM_LOADER_NAME;
	}

	@Override
	public Collection<LoadSpec> findSupportedLoadSpecs(ByteProvider provider) throws IOException {
		List<LoadSpec> loadSpecs = new ArrayList<>();
		
		BinaryReader reader = new BinaryReader(provider, true);
		reader.setPointerIndex(0L);
		
		final var tag = reader.readNextAsciiString();
		
		if (tag != null && tag.equals(ADCVM_TAG) && provider.getInputStream(ADCVM_TAG.length()).available() > 0xF0) {
			loadSpecs.add(new LoadSpec(this, IMAGE_BASE, new LanguageCompilerSpecPair("adcvm:LE:32:default", "default"), true));
		}

		return loadSpecs;
	}

	@Override
	protected void load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			Program program, TaskMonitor monitor, MessageLog log)
			throws CancelledException, IOException {
		
		String adtPath = program.getExecutablePath();
		adtPath = adtPath.substring(0, adtPath.length()-1) + "T";
		File adtFile = new File(adtPath);
		
		if (!adtFile.exists()) {
			log.appendException(new IOException("Cannot find corresponding ADT file!"));
			return;
		}

		Memory mem = program.getMemory();
		AddressSpace ram = program.getAddressFactory().getDefaultAddressSpace();
		
		InputStream stream = provider.getInputStream(IMAGE_BASE);
		final var vmData = stream.readAllBytes();
		stream.close();
		
		Address vmBase  = ram.getAddress(IMAGE_BASE);
		Address varsc = ram.getAddress(VARSC_BASE);
		Address varsd = ram.getAddress(VARSD_BASE);
		Address varse = ram.getAddress(VARSE_BASE);
		Address varsf = ram.getAddress(VARSF_BASE);
		Address refs  = ram.getAddress(REFS_BASE);

		try {
			MemoryBlock block = mem.createInitializedBlock("vm", vmBase, new ByteArrayInputStream(vmData), vmData.length, monitor, false);
			
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(true);
		} catch (LockException | MemoryConflictException | AddressOverflowException | CancelledException | IllegalArgumentException e) {
			e.printStackTrace();
			log.appendException(e);
			return;
		}
		
		var st = program.getSymbolTable();
		st.addExternalEntryPoint(vmBase);
		
		try {
			st.createLabel(vmBase, "start", SourceType.IMPORTED);
		} catch (InvalidInputException e) {
			e.printStackTrace();
			log.appendException(e);
			return;
		}
		
		if (!createVarsSegment(program, mem, "varsc", varsc, monitor, log)) {
			return;
		}
		
		if (!createVarsSegment(program, mem, "varsd", varsd, monitor, log)) {
			return;
		}
		
		if (!createVarsSegment(program, mem, "varse", varse, monitor, log)) {
			return;
		}
		
		if (!createVarsSegment(program, mem, "varsf", varsf, monitor, log)) {
			return;
		}
		
		FileInputStream fs = new FileInputStream(adtFile);
		var refsData = fs.readAllBytes();
		fs.close();
		
		try {
			BinaryReader reader = new BinaryReader(new ByteArrayProvider(refsData), true);
			
			MemoryBlock block = mem.createInitializedBlock("refs", refs, refsData.length, (byte) 0x00, monitor, false);
			
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(false);
			
			for (var i = 0; i < refsData.length; i += 4) {
				final var offset = reader.readNextUnsignedShort();
				final var index = reader.readNextUnsignedShort();
				final var ref = (index * 0x8000) | offset;
				mem.setInt(refs.add(i), ref + 2);
			}
		} catch (LockException | MemoryConflictException | AddressOverflowException | CancelledException | IllegalArgumentException | IOException | AddressOutOfBoundsException | MemoryAccessException e) {
			e.printStackTrace();
			log.appendException(e);
		}
		
		try {
			preprocessIfWhile(vmData, vmBase, mem); // this call must be the first
			preprocessStrings(vmData, vmBase, mem, ram, monitor);
		} catch (LockException | IllegalArgumentException | MemoryConflictException | AddressOverflowException
				| CancelledException | AddressOutOfBoundsException | MemoryAccessException | CodeUnitInsertionException
				| IOException e) {
			e.printStackTrace();
			log.appendException(e);
		}
	}
	
	private static boolean createVarsSegment(Program program, Memory mem, final String name, final Address start, TaskMonitor monitor, MessageLog log) {
		try {
			MemoryBlock block = mem.createInitializedBlock(name, start, 0x800, (byte) 0x00, monitor, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
			
			for (var i = 0; i < block.getSize(); i += 2) {
				DataUtilities.createData(program, start.add(i), WordDataType.dataType, WordDataType.dataType.getLength(), false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			}
		} catch (LockException | MemoryConflictException | AddressOverflowException | CancelledException | IllegalArgumentException | CodeUnitInsertionException e) {
			e.printStackTrace();
			log.appendException(e);
			return false;
		}
		
		return true;
	}
	
	private static void preprocessStrings(final byte[] vmData, final Address vmBase, Memory mem, AddressSpace ram, TaskMonitor monitor) throws IOException, LockException, IllegalArgumentException, MemoryConflictException, AddressOverflowException, CancelledException, AddressOutOfBoundsException, MemoryAccessException, CodeUnitInsertionException {
		final long size = vmData.length;

		var vmReader = new BinaryReader(new ByteArrayProvider(vmData), true);
		
		var stringsAddrs = new HashMap<String, Address>();
		final var stringsBase = ram.getAddress(STRINGS_BASE);
		var stringsCurr = stringsBase;
		
		var patchOffsets = new HashMap<Address, String>();
		var instrOffsets = new ArrayList<Address>();
		
		while (vmReader.getPointerIndex() < size) {
			Address currAddr = vmBase.add(vmReader.getPointerIndex());
			int opcode = vmReader.readNextUnsignedShort();
			
			switch (opcode) {
			case 0xFF39: // BGLOAD
			case 0xFF3A: // PALLOAD
			case 0xFF3B: // BGMREQ
			case 0xFF67: // SEREQ
			case 0xFF7B: // SEPAN
			case 0xFF7C: // SEVOL
			{
				instrOffsets.add(currAddr);
				
				vmReader.readNextUnsignedShort();
				
				var patchAddr = vmBase.add(vmReader.getPointerIndex());
				var str1 = readVmString(vmReader, size);
				patchOffsets.put(patchAddr, str1);
				
				if (!stringsAddrs.containsKey(str1)) {
					stringsAddrs.put(str1, stringsCurr);
					stringsCurr = stringsCurr.add(str1.length() + 1);
				}
			} break;
			case 0xFF53: // MAPLOAD
			{
				instrOffsets.add(currAddr);
				
				vmReader.readNextUnsignedShort();
				
				var patchAddr = vmBase.add(vmReader.getPointerIndex());
				var str1 = readVmString(vmReader, size);
				patchOffsets.put(patchAddr, str1);
				
				if (!stringsAddrs.containsKey(str1)) {
					stringsAddrs.put(str1, stringsCurr);
					stringsCurr = stringsCurr.add(str1.length() + 1);
				}
				
				patchAddr = vmBase.add(vmReader.getPointerIndex());
				var str2 = readVmString(vmReader, size);
				patchOffsets.put(patchAddr, str2);
				
				if (!stringsAddrs.containsKey(str2)) {
					stringsAddrs.put(str2, stringsCurr);
					stringsCurr = stringsCurr.add(str2.length() + 1);
				}
			} break;
			case 0xFF65: // MAPWRT
			{
				instrOffsets.add(currAddr);
				
				vmReader.readNextUnsignedShort();
				vmReader.readNextUnsignedShort();
				
				var patchAddr = vmBase.add(vmReader.getPointerIndex());
				var str1 = readVmString(vmReader, size);
				patchOffsets.put(patchAddr, str1);
				
				if (!stringsAddrs.containsKey(str1)) {
					stringsAddrs.put(str1, stringsCurr);
					stringsCurr = stringsCurr.add(str1.length() + 1);
				}
			} break;
			case 0xFF69: // SESTOP
			{
				instrOffsets.add(currAddr);
				
				var patchAddr = vmBase.add(vmReader.getPointerIndex());
				var str1 = readVmString(vmReader, size);
				patchOffsets.put(patchAddr, str1);
				
				if (!stringsAddrs.containsKey(str1)) {
					stringsAddrs.put(str1, stringsCurr);
					stringsCurr = stringsCurr.add(str1.length() + 1);
				}
			} break;
			case 0xFF71: // SEREQPV
			case 0xFF72: // SEREQSPR
			{
				instrOffsets.add(vmBase.add(vmReader.getPointerIndex()));
				
				vmReader.readNextUnsignedShort();
				vmReader.readNextUnsignedShort();
				vmReader.readNextUnsignedShort();
				
				var patchAddr = vmBase.add(vmReader.getPointerIndex());
				var str1 = readVmString(vmReader, size);
				patchOffsets.put(patchAddr, str1);
				
				if (!stringsAddrs.containsKey(str1)) {
					stringsAddrs.put(str1, stringsCurr);
					stringsCurr = stringsCurr.add(str1.length() + 1);
				}
			} break;
			case 0xFF87: // AVIPLAY
			{
				instrOffsets.add(currAddr);
				
				vmReader.readNextUnsignedShort();
				vmReader.readNextUnsignedShort();
				vmReader.readNextUnsignedShort();
				vmReader.readNextUnsignedShort();
				vmReader.readNextUnsignedShort();
				
				var patchAddr = vmBase.add(vmReader.getPointerIndex());
				var str1 = readVmString(vmReader, size);
				patchOffsets.put(patchAddr, str1);
				
				if (!stringsAddrs.containsKey(str1)) {
					stringsAddrs.put(str1, stringsCurr);
					stringsCurr = stringsCurr.add(str1.length() + 1);
				}
			} break;
			}
		}

		MemoryBlock block = mem.createInitializedBlock("strings", stringsBase, stringsCurr.subtract(stringsBase), (byte) 0x00, monitor, false);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(false);
		
		for (final var str : stringsAddrs.keySet()) {
			final var strAddr = stringsAddrs.get(str);
			mem.setBytes(strAddr, str.getBytes());
			DataUtilities.createData(mem.getProgram(), strAddr, TerminatedStringDataType.dataType, -1, false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
		}
		
		for (final var patchAddr : patchOffsets.keySet()) {
			final var str = patchOffsets.get(patchAddr);
			final var strAddr = stringsAddrs.get(str);
			
			mem.setInt(patchAddr, (int)strAddr.getOffset());
			
			var strLen = str.length() + 2;
			strLen -= 4;
			int delta = 0;
			
			while (strLen > 0) {
				final var fill = new byte[] {(byte) 0x90, (byte) 0xFF}; // custom STR00 opcode
				mem.setBytes(patchAddr.add(4).add(delta), fill);
				
				delta += 2;
				strLen -= 2;
			}
		}
		
		for (final var instrOff : instrOffsets)  {
			DisassembleCommand cmd = new DisassembleCommand(instrOff, null, false);
			cmd.applyTo(mem.getProgram(), monitor);
		}
		
		EnumDataType dt = new EnumDataType("strings", 4);
		
		for (final var str : stringsAddrs.keySet()) {
			final var strAddr = stringsAddrs.get(str);
			dt.add(str, strAddr.getOffset());
		}
		
		var set = new AddressSet(vmBase, vmBase.add(vmData.length));
		
		CreateEnumEquateCommand cmd = new CreateEnumEquateCommand(mem.getProgram(), set, dt, true);
		cmd.applyTo(mem.getProgram(), monitor);
	}
	
	private static String readVmString(BinaryReader reader, long size) throws IOException {
		String result = "";
		
		while (reader.getPointerIndex() < size) {
			var word = reader.readNextByteArray(2);
			
			if (word[0] == 0x00 && word[1] == 0x00) {
				break;
			}
			
			if (word[0] != 0x00) {
				result += (char)word[0];
			}
			
			if (word[1] != 0x00) {
				result += (char)word[1];
			}
		}
		
		return result;
	}
	
	private static void preprocessIfWhile(final byte[] vmData, final Address vmBase, Memory mem) throws IOException, MemoryAccessException {
		final long size = vmData.length;

		var vmReader = new BinaryReader(new ByteArrayProvider(vmData), true);
		
		while (vmReader.getPointerIndex() < size) {
			int opcode = vmReader.readNextUnsignedShort();
			Address patchAddr = vmBase.add(vmReader.getPointerIndex());
			long delta = 0L;
			
			switch (opcode) {
			case 0xFF29: // IF
			{
				int id = vmReader.readNextUnsignedShort();
				delta = findIfWhileEndDelta(vmReader, id, vmBase, patchAddr, 0xFF2D);
			} break;
			case 0xFF2A: // WHILE
			{
				int id = vmReader.readNextUnsignedShort();
				delta = findIfWhileEndDelta(vmReader, id, vmBase, patchAddr, 0xFF2E);
			} break;
			}
			
			if (delta != 0L) {
				if (delta <= 0xFFFF) {
					mem.setShort(patchAddr, (short)(delta & 0xFFFF));
				} else {
					throw new IOException(String.format("Cannot patch reference at 0x%06X", patchAddr.subtract(2)));
				}
			}
		}
	}
	
	private static long findIfWhileEndDelta(BinaryReader vmReader, int id, final Address base, final Address patchAddr, int endOpcode) throws IOException {
		Address while_end = null;
		
		while (true) {
			int word = vmReader.readNextUnsignedShort();
			
			if (word == endOpcode) {
				int end_id = vmReader.readNextUnsignedShort();
				
				if (id != end_id) {
					continue;
				}
				
				while_end = base.add(vmReader.getPointerIndex()).subtract(4);
				break;
			}
		}
		
		return while_end.subtract(patchAddr);
	}
}
