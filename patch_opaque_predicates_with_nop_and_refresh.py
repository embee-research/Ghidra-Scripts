"""
Patch Opaque Predicates in StealC Sample

Hash: 1e09d04c793205661d88d6993cb3e0ef5e5a37a8660f504c1d36b0d8562e63a2

1. Locate Opaque Predicates Via hardcoded pattern
2. Patch with NOP BytesWarning
3. Clear Code Bytes For each patched function
4. Re-analyze all functions to restore disassembly


"""

#Import relevant modules
from ghidra.util.NumericUtilities import convertStringToBytes
from ghidra.program.model.listing import Function
from ghidra.program.flatapi import FlatProgramAPI


memory = currentProgram.getMemory()

old_bytes = b'\x74\x03\x75\x01\xb8'
new_bytes = [0x90,0x90,0x90,0x90,0x90]

matches = findBytes(toAddr("0x00400000"), old_bytes, 1000)

#Print locations where opaque pattern was found
print(matches)

#dis = ghidra.program.disassemble.Disassembler

for patch_addr in matches:
	transaction_id = currentProgram.startTransaction("something")
	try:
        #Clear code units and patch with NOP bytes (\x90)
		print("Patch Address {}".format(patch_addr))
		currentProgram.getListing().clearCodeUnits(patch_addr, patch_addr.add(4), False)
		for offset,byte in enumerate(new_bytes):
			memory.setByte(patch_addr.add(offset),byte)
			print("Patched instructions at {}".format(patch_addr))

	except Exception as e:
		print("Failed to patch bytes at {} reason {}".format(patch_addr,e))
	finally:
		currentProgram.endTransaction(transaction_id, True)

for patch_addr in matches:
    #Clear code bytes for entire function
	parent_function = getFunctionContaining(patch_addr)
	if parent_function:
		try:
			parent_function = getFunctionContaining(patch_addr)
			print("Parent Function {}".format(parent_function))
			if parent_function:
				parent_size = parent_function.getBody().getNumAddresses()
				parent_start = parent_function.getEntryPoint()
				currentProgram.getListing().clearCodeUnits(parent_start, parent_start.add(parent_size), False)
			
		except Exception as e:
			print(e)

#Re-analyze program to restore disassembly
analyzeAll(currentProgram)
