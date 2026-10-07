package com.themixednuts.resources;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.themixednuts.utils.JsonMapperHolder;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SymbolTable;
import org.junit.jupiter.api.Test;

class ProgramInfoIdentityTest {
  @Test
  void resourceKeepsExistingFieldsAndSharesIdentityIncludingMissingMetadata() throws Exception {
    Program program = mock(Program.class);
    Memory memory = mock(Memory.class);
    FunctionManager functions = mock(FunctionManager.class);
    SymbolTable symbols = mock(SymbolTable.class);
    when(program.getMemory()).thenReturn(memory);
    when(memory.getBlocks()).thenReturn(new MemoryBlock[0]);
    when(program.getFunctionManager()).thenReturn(functions);
    when(functions.getFunctionCount()).thenReturn(3);
    when(program.getSymbolTable()).thenReturn(symbols);
    when(program.getExecutableSHA256()).thenReturn("A".repeat(64));
    ProgramInfoResource resource = spy(new ProgramInfoResource());
    doReturn(program).when(resource).getProgramByName("client.dll");

    var result =
        JsonMapperHolder.getMapper()
            .readTree(resource.read(null, "ghidra://program/client.dll/info", null).block());

    assertEquals("client.dll", result.get("programName").asText());
    assertEquals(3, result.get("functionCount").asInt());
    assertEquals("unknown", result.get("executablePath").asText());
    assertTrue(result.has("language"));
    assertTrue(result.get("imageBase").isNull());
    assertEquals("a".repeat(64), result.get("binaryIdentity").get("sha256").asText());
    assertTrue(result.get("binaryIdentity").get("language_id").isNull());
    verify(program).release(resource);
  }
}
