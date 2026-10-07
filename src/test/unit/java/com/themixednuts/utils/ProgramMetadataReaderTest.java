package com.themixednuts.utils;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import com.themixednuts.models.BinaryIdentity.HashStatus;
import ghidra.framework.model.DomainFile;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFactory;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.lang.CompilerSpec;
import ghidra.program.model.lang.CompilerSpecID;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.lang.Processor;
import ghidra.program.model.listing.Program;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class ProgramMetadataReaderTest {
  @TempDir Path temp;

  @Test
  void recordedHashMatchesKnownFileButDoesNotFollowSourceFileChanges() throws Exception {
    byte[] original = {1, 2, 3, 4};
    Path source = Files.write(temp.resolve("input.bin"), original);
    String importedHash =
        HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(original));
    Program program = mock(Program.class);
    when(program.getExecutableSHA256()).thenReturn(importedHash.toUpperCase(java.util.Locale.ROOT));
    when(program.getExecutablePath()).thenReturn(source.toString());
    Files.write(source, new byte[] {5});

    var identity = ProgramMetadataReader.readIdentity(program);

    assertEquals(importedHash, identity.sha256());
    assertEquals(HashStatus.AVAILABLE, identity.sha256Status());
    assertFalse(identity.originalFileVerified());
    assertEquals("program_database_import_metadata", identity.hashSource());
    var json = JsonMapperHolder.getMapper().valueToTree(identity);
    assertEquals("available", json.get("sha256_status").asText());
    assertTrue(json.get("language_id").isNull());
    assertTrue(json.has("missing_fields"));
  }

  @Test
  void missingAndMalformedHashRemainDistinct() {
    Program program = mock(Program.class);
    when(program.getExecutableSHA256()).thenReturn(" ", "not-a-sha256");
    var missing = ProgramMetadataReader.readIdentity(program);
    var invalid = ProgramMetadataReader.readIdentity(program);
    assertNull(missing.sha256());
    assertEquals(HashStatus.MISSING, missing.sha256Status());
    assertTrue(missing.missingFields().contains("sha256"));
    assertEquals(HashStatus.INVALID, invalid.sha256Status());
    assertEquals("not-a-sha256", invalid.sha256());
    assertFalse(invalid.missingFields().contains("sha256"));
  }

  @Test
  void architectureAndCurrentRebasedImagebaseAreMappedWithoutMemoryAccess() {
    Program program = mock(Program.class);
    Language language = mock(Language.class);
    CompilerSpec compiler = mock(CompilerSpec.class);
    AddressFactory addresses = mock(AddressFactory.class);
    AddressSpace space = mock(AddressSpace.class);
    Address base = mock(Address.class);
    DomainFile file = mock(DomainFile.class);
    when(program.getDomainFile()).thenReturn(file);
    when(file.getPathname()).thenReturn("/build2/client.dll");
    when(program.getName()).thenReturn("client.dll");
    when(program.getLanguage()).thenReturn(language);
    when(program.getLanguageID()).thenReturn(new LanguageID("x86:LE:64:default"));
    when(language.getProcessor()).thenReturn(Processor.findOrPossiblyCreateProcessor("x86"));
    when(program.getCompilerSpec()).thenReturn(compiler);
    when(compiler.getCompilerSpecID()).thenReturn(new CompilerSpecID("windows"));
    when(program.getAddressFactory()).thenReturn(addresses);
    when(addresses.getDefaultAddressSpace()).thenReturn(space);
    when(space.getSize()).thenReturn(64);
    when(program.getImageBase()).thenReturn(base);
    when(base.toString()).thenReturn("180000000");

    var identity = ProgramMetadataReader.readIdentity(program);

    assertEquals("/build2/client.dll", identity.projectPath());
    assertEquals("x86:LE:64:default", identity.languageId());
    assertEquals("windows", identity.compilerSpecId());
    assertEquals("little", identity.endian());
    assertEquals(64, identity.addressSizeBits());
    assertEquals("180000000", identity.imageBase());
    verify(program, never()).getMemory();
  }
}
