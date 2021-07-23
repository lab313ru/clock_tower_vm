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
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.*;

import generic.stl.Pair;
import ghidra.app.plugin.core.reloc.InstructionStasher;
import ghidra.app.util.Option;
import ghidra.app.util.bin.BinaryReader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.AbstractLibrarySupportLoader;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.framework.options.Options;
import ghidra.framework.store.LockException;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
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
		
		Options aOpts = program.getOptions(Program.ANALYSIS_PROPERTIES);
		aOpts.setBoolean("Decompiler Switch Analysis", false);
		aOpts.setBoolean("ASCII Strings", false);
		aOpts.setBoolean("Create Address Tables", false);
		aOpts.setBoolean("Data Reference", false);
		aOpts.setBoolean("Apply Data Archives", false);
		aOpts.setBoolean("Embedded Media", false);
		//aOpts.setBoolean("Non-Returning Functions - Discovered", false);
		aOpts.setBoolean("Scalar Operand References", false);
		
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
		var vmData = stream.readAllBytes();
		stream.close();
		
		Address vmBase  = ram.getAddress(IMAGE_BASE);
		Address varsc = ram.getAddress(VARSC_BASE);
		Address varsd = ram.getAddress(VARSD_BASE);
		Address varse = ram.getAddress(VARSE_BASE);
		Address varsf = ram.getAddress(VARSF_BASE);
		Address refs  = ram.getAddress(REFS_BASE);
		
		if (!createVarsSegment(program, mem, "varsc", varsc, log)) {
			return;
		}
		
		if (!createVarsSegment(program, mem, "varsd", varsd, log)) {
			return;
		}
		
		if (!createVarsSegment(program, mem, "varse", varse, log)) {
			return;
		}
		
		if (!createVarsSegment(program, mem, "varsf", varsf, log)) {
			return;
		}
		
		FileInputStream fs = new FileInputStream(adtFile);
		var refsData = fs.readAllBytes();
		fs.close();
		
		BinaryReader reader = new BinaryReader(new ByteArrayProvider(refsData), true);
		
		var refsInts = new long[refsData.length / 4]; 
		
		for (var i = 0; i < refsInts.length; ++i) {
			final var offset = reader.readNextUnsignedShort();
			final var index = reader.readNextUnsignedShort();
			final var ref = (index * 0x8000) | offset;
			refsInts[i] = ref + 2;
		}
		
		try {
			var patchOffsets = preprocessStrings(vmData, vmBase, refsInts, mem, ram, monitor);
			vmData = shrinkVmData(vmData, patchOffsets, refsInts);
		} catch (LockException | IllegalArgumentException | MemoryConflictException | AddressOverflowException
				| CancelledException | AddressOutOfBoundsException | MemoryAccessException | CodeUnitInsertionException
				| IOException e) {
			e.printStackTrace();
			log.appendException(e);
		}
		
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
		
		try {
			preprocessIfWhile(vmData, vmBase, mem);
		} catch (MemoryAccessException | IOException e) {
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
		
		try {
			MemoryBlock block = mem.createInitializedBlock("refs", refs, refsInts.length * 4, (byte) 0x00, monitor, false);
			
			block.setRead(true);
			block.setWrite(false);
			block.setExecute(false);
			
			for (var i = 0; i < refsInts.length; ++i) {
				mem.setInt(refs.add(i * 4), (int)refsInts[i]);
			}
		} catch (LockException | MemoryConflictException | AddressOverflowException | CancelledException | IllegalArgumentException | AddressOutOfBoundsException | MemoryAccessException e) {
			e.printStackTrace();
			log.appendException(e);
		}
	}
	
	private static byte[] shrinkVmData(byte[] vmData, final TreeMap<Long, Pair<String, Integer>> patchOffsets, long[] refs) {
		int delta = 0;
		
		for (final var patch : patchOffsets.entrySet()) {
			final var patchAddr = patch.getKey() + 4 - delta;
			var strLen = patch.getValue().second;
			
			updateRefs(refs, IMAGE_BASE + patchAddr - 4, strLen);
			delta += strLen;
			
			byte[] part1 = Arrays.copyOfRange(vmData, 0, (int)patchAddr);
			byte[] part2 = Arrays.copyOfRange(vmData, (int)(patchAddr + strLen), vmData.length);
			vmData = new byte[part1.length + part2.length];
			System.arraycopy(part1, 0, vmData, 0, part1.length);
			System.arraycopy(part2, 0, vmData, part1.length, part2.length);
		}
		
		return vmData;
	}
	
	private static boolean createVarsSegment(Program program, Memory mem, final String name, final Address start, MessageLog log) {
		try {
			MemoryBlock block = mem.createUninitializedBlock(name, start, 0x800, false);
			block.setRead(true);
			block.setWrite(true);
			block.setExecute(false);
			block.setVolatile(true);
			
			for (var i = 0; i < block.getSize(); i += 2) {
				DataUtilities.createData(program, start.add(i), WordDataType.dataType, WordDataType.dataType.getLength(), false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			}
		} catch (LockException | MemoryConflictException | AddressOverflowException | IllegalArgumentException | CodeUnitInsertionException e) {
			e.printStackTrace();
			log.appendException(e);
			return false;
		}
		
		return true;
	}
	
	private static TreeMap<Long, Pair<String, Integer>> preprocessStrings(byte[] vmData, final Address vmBase, long[] refs, Memory mem, AddressSpace ram, TaskMonitor monitor) throws IOException, LockException, IllegalArgumentException, MemoryConflictException, AddressOverflowException, CancelledException, AddressOutOfBoundsException, MemoryAccessException, CodeUnitInsertionException {
		final long size = vmData.length;

		var vmReader = new BinaryReader(new ByteArrayProvider(vmData), true);
		
		var stringsAddrs = new TreeMap<String, Pair<Address, Boolean>>();
		final var stringsBase = ram.getAddress(STRINGS_BASE);
		var stringsCurr = stringsBase;
		
		var patchOffsets = new TreeMap<Long, Pair<String, Integer>>();
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
				
				var patchAddr = vmReader.getPointerIndex();
				var str1 = readVmString(vmReader, size);
				var zeroed = removeZeros(str1);
				var putStr = new String(zeroed);
				
				var resLen = str1.length - 2;
				
				if ((resLen & 1) != 0) {
					resLen += 1;
				}
				
				patchOffsets.put(patchAddr, new Pair<>(putStr, resLen));
				
				if (!stringsAddrs.containsKey(putStr)) {
					stringsAddrs.put(putStr, new Pair<>(stringsCurr, false));
					stringsCurr = stringsCurr.add(zeroed.length + 1);
				}
			} break;
			case 0xFF53: // MAPLOAD
			{
				instrOffsets.add(currAddr);
				
				vmReader.readNextUnsignedShort();
				
				var patchAddr = vmReader.getPointerIndex();
				var str1 = readVmString(vmReader, size);
				var zeroed1 = removeZeros(str1);
				var putStr1 = new String(zeroed1);
				
				patchOffsets.put(patchAddr, new Pair<>(putStr1, 0));
				
				if (!stringsAddrs.containsKey(putStr1)) {
					stringsAddrs.put(putStr1, new Pair<>(stringsCurr, false));
					stringsCurr = stringsCurr.add(zeroed1.length + 1);
				}
				
				var str2 = readVmString(vmReader, size);
				var zeroed2 = removeZeros(str2);
				var putStr2 = new String(zeroed2);
				
				var resLen = str1.length + str2.length - 4;
				
				if ((resLen & 1) != 0) {
					resLen += 1;
				}
				
				patchOffsets.put(patchAddr + 4, new Pair<>(putStr2, resLen));
				
				if (!stringsAddrs.containsKey(putStr2)) {
					stringsAddrs.put(putStr2, new Pair<>(stringsCurr, false));
					stringsCurr = stringsCurr.add(zeroed2.length + 1);
				}
			} break;
			case 0xFF65: // MAPWRT
			{
				instrOffsets.add(currAddr);
				
				vmReader.readNextUnsignedShort();
				vmReader.readNextUnsignedShort();
				
				var patchAddr = vmReader.getPointerIndex();
				var str1 = readVmString(vmReader, size);
				var zeroed = removeZeros(str1);
				var putStr = new String(zeroed);
				
				var resLen = str1.length - 2;
				
				if ((resLen & 1) != 0) {
					resLen += 1;
				}
				
				patchOffsets.put(patchAddr, new Pair<>(putStr, resLen));
				
				if (!stringsAddrs.containsKey(putStr)) {
					stringsAddrs.put(putStr, new Pair<>(stringsCurr, false));
					stringsCurr = stringsCurr.add(zeroed.length + 1);
				}
			} break;
			case 0xFF69: // SESTOP
			{
				instrOffsets.add(currAddr);
				
				var patchAddr = vmReader.getPointerIndex();
				var str1 = readVmString(vmReader, size);
				var zeroed = removeZeros(str1);
				var putStr = new String(zeroed);
				
				var resLen = str1.length - 2;
				
				if ((resLen & 1) != 0) {
					resLen += 1;
				}
				
				patchOffsets.put(patchAddr, new Pair<>(putStr, resLen));
				
				if (!stringsAddrs.containsKey(putStr)) {
					stringsAddrs.put(putStr, new Pair<>(stringsCurr, false));
					stringsCurr = stringsCurr.add(zeroed.length + 1);
				}
			} break;
			case 0xFF71: // SEREQPV
			case 0xFF72: // SEREQSPR
			{
				instrOffsets.add(vmBase.add(vmReader.getPointerIndex()));
				
				vmReader.readNextUnsignedShort();
				vmReader.readNextUnsignedShort();
				vmReader.readNextUnsignedShort();

				var patchAddr = vmReader.getPointerIndex();
				var str1 = readVmString(vmReader, size);
				var zeroed = removeZeros(str1);
				var putStr = new String(zeroed);
				
				var resLen = str1.length - 2;
				
				if ((resLen & 1) != 0) {
					resLen += 1;
				}
				
				patchOffsets.put(patchAddr, new Pair<>(putStr, resLen));
				
				if (!stringsAddrs.containsKey(putStr)) {
					stringsAddrs.put(putStr, new Pair<>(stringsCurr, false));
					stringsCurr = stringsCurr.add(zeroed.length + 1);
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
				
				var patchAddr = vmReader.getPointerIndex();
				var str1 = readVmString(vmReader, size);
				var zeroed = removeZeros(str1);
				var putStr = new String(zeroed);
				
				var resLen = str1.length - 2;
				
				if ((resLen & 1) != 0) {
					resLen += 1;
				}
				
				patchOffsets.put(patchAddr, new Pair<>(putStr, resLen));
				
				if (!stringsAddrs.containsKey(putStr)) {
					stringsAddrs.put(putStr, new Pair<>(stringsCurr, false));
					stringsCurr = stringsCurr.add(zeroed.length + 1);
				}
			} break;
			case 0xFF33: // MSGOUT
			{
				instrOffsets.add(currAddr);
				
				vmReader.readNextUnsignedShort();
				vmReader.readNextUnsignedShort();
				
				var patchAddr = vmReader.getPointerIndex();
				var str1 = readVmSjisString(vmReader, size);
				var zeroed = removeZeros(str1);
				var putStr = prepareForEnum(zeroed);
				
				var resLen = str1.length - 2;
				
				if ((resLen & 1) != 0) {
					resLen += 1;
				}
				
				patchOffsets.put(patchAddr, new Pair<>(putStr, resLen));
				
				if (!stringsAddrs.containsKey(putStr)) {
					stringsAddrs.put(putStr, new Pair<>(stringsCurr, true));
					stringsCurr = stringsCurr.add(zeroed.length + 1);
				}
			} break;
			}
		}
		
		var len = stringsCurr.subtract(stringsBase);
		
		if (len == 0) {
			return patchOffsets;
		}

		MemoryBlock block = mem.createInitializedBlock("strings", stringsBase, len, (byte) 0x00, monitor, false);
		block.setRead(true);
		block.setWrite(false);
		block.setExecute(false);
		
		for (final var str : stringsAddrs.keySet()) {
			final var strAddr = stringsAddrs.get(str);
			
			InstructionStasher stasher = new InstructionStasher(mem.getProgram(), strAddr.first);
			
			DataType dt = TerminatedStringDataType.dataType;

			if (!strAddr.second) {
				mem.setBytes(strAddr.first, str.replaceAll("\u0000", "").getBytes());
			} else {
				mem.setBytes(strAddr.first, str.getBytes("shift-jis"));
				
				dt = SjisTerminatedStringDataType.dataType;
			}
			
			DataUtilities.createData(mem.getProgram(), strAddr.first, dt, -1, false, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			
			stasher.restore();
		}
		
		for (final var patchAddr : patchOffsets.keySet()) {
			final var str = patchOffsets.get(patchAddr);
			final var strAddr = stringsAddrs.get(str.first).first.getOffset();
			
			var intBytes = new byte[] {(byte)(strAddr >>> 0), (byte)(strAddr >>> 8), (byte)(strAddr >>> 16), (byte)(strAddr >> 24) };
			System.arraycopy(intBytes, 0, vmData, (int)(long)patchAddr, 4);
		}
		
		return patchOffsets;
	}
	
	private static void updateRefs(long[] refs, long startAddress, int delta) {
		for (int i = 0; i < refs.length; ++i) {
			final var ref = refs[i];
			
			if (startAddress > ref) {
				continue;
			}

			refs[i] = ref - delta;
		}
	}
	
	private static String prepareForEnum(final byte[] bytes) throws UnsupportedEncodingException {
		return new String(bytes, "shift-jis");
	}
	
	private static byte[] removeZeros(final byte[] array) {
		byte[] dest = array.clone();
		int targetIndex = 0;
		for( int sourceIndex = 0;  sourceIndex < array.length;  sourceIndex++ )
		{
		    if( dest[sourceIndex] != 0 )
		    	dest[targetIndex++] = dest[sourceIndex];
		}
		byte[] newArray = new byte[targetIndex];
		System.arraycopy( dest, 0, newArray, 0, targetIndex );
		
		return newArray;
	}
	
	private static byte[] readVmString(BinaryReader reader, long size) throws IOException {
		ByteArrayOutputStream result = new ByteArrayOutputStream();
		
		while (reader.getPointerIndex() < size) {
			var word = reader.readNextByteArray(2);
			
			if (word[0] == 0x00 && word[1] == 0x00) {
				break;
			}
			
			result.write(word);
		}
		
		return result.toByteArray();
	}
	
	private static byte[] readVmSjisString(BinaryReader reader, long size) throws IOException {
		ByteArrayOutputStream result = new ByteArrayOutputStream();
		
		while (reader.getPointerIndex() < size) {
			var word = reader.readNextByteArray(2);
			
			if (word[1] == (byte)0xFF && (word[0] == 0x20 || word[0] == 0x28 || word[0] == 0x36)) { // ALLEND, END, MSGWAIT
				break;
			}
			
			result.write(word);
		}
		
		return result.toByteArray();
	}
	
	private static void preprocessIfWhile(final byte[] vmData, final Address vmBase, Memory mem) throws IOException, MemoryAccessException {
		final long size = vmData.length;

		var vmReader = new BinaryReader(new ByteArrayProvider(vmData), true);
		
		Map<Integer, Address> whileStarts = new TreeMap<>();
		
		while (vmReader.getPointerIndex() + 2 < size) {
			int opcode = vmReader.readNextUnsignedShort();
			Address patchAddr = vmBase.add(vmReader.getPointerIndex());
			long delta = 0L;
			
			switch (opcode) {
			case 0xFF29: // IF
			{
				int id = vmReader.readNextUnsignedShort();
				delta = findIfWhileEndDelta(vmReader, size, id, vmBase, patchAddr, List.of(0xFF2D, 0xFF2F)); // ENDIF, ELSE
			} break;
			case 0xFF2A: // WHILE
			{
				int id = vmReader.readNextUnsignedShort();
				delta = findIfWhileEndDelta(vmReader, size, id, vmBase, patchAddr, List.of(0xFF2E)); // ENDWHILE
				
				whileStarts.put(id, patchAddr.subtract(4));
			} break;
			case 0xFF2F: // ELSE
			{
				int id = vmReader.readNextUnsignedShort();
				delta = findIfWhileEndDelta(vmReader, size, id, vmBase, patchAddr, List.of(0xFF2D)); // ENDIF
				delta -= 2;
			} break;
			case 0xFF2E: // ENDWHILE
			{
				int id = vmReader.readNextUnsignedShort();
				var whileStart = whileStarts.get(id);
				delta = patchAddr.subtract(whileStart);
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
	
	private static long findIfWhileEndDelta(BinaryReader vmReader, long size, int id, final Address base, final Address patchAddr, final List<Integer> endOpcodes) throws IOException {
		Address while_end = null;
		long pos = vmReader.getPointerIndex();
		
		while (vmReader.getPointerIndex() + 2 < size) {
			int word = vmReader.readNextUnsignedShort();
			
			if (endOpcodes.contains(word)) {
				int end_id = vmReader.readNextUnsignedShort();
				
				if (id != end_id) {
					continue;
				}
				
				while_end = base.add(vmReader.getPointerIndex()).subtract(4);
				break;
			}
		}
		
		vmReader.setPointerIndex(pos);
		return while_end != null ? while_end.subtract(patchAddr) : 0;
	}
}
