package com.themixednuts.utils;

import com.themixednuts.models.BinaryIdentity;
import com.themixednuts.models.BinaryIdentity.HashStatus;
import ghidra.program.model.listing.Program;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Locale;
import java.util.Objects;

/** Shared metadata mapping for the identity tool and the existing program-info resource. */
public final class ProgramMetadataReader {
  private ProgramMetadataReader() {}

  public static BinaryIdentity readIdentity(Program program) {
    Objects.requireNonNull(program, "program");
    var file = program.getDomainFile();
    var language = program.getLanguage();
    var languageId = program.getLanguageID();
    var compiler = program.getCompilerSpec();
    var compilerId = compiler == null ? null : compiler.getCompilerSpecID();
    var factory = program.getAddressFactory();
    var space = factory == null ? null : factory.getDefaultAddressSpace();
    var base = program.getImageBase();
    String sha256 = nonBlank(program.getExecutableSHA256());
    HashStatus hashStatus =
        sha256 == null
            ? HashStatus.MISSING
            : sha256.matches("(?i)[0-9a-f]{64}") ? HashStatus.AVAILABLE : HashStatus.INVALID;
    if (hashStatus == HashStatus.AVAILABLE) {
      sha256 = sha256.toLowerCase(Locale.ROOT);
    }
    String path = nonBlank(program.getExecutablePath());
    String format = nonBlank(program.getExecutableFormat());
    String langId = languageId == null ? null : nonBlank(languageId.getIdAsString());
    String compId = compilerId == null ? null : nonBlank(compilerId.getIdAsString());
    String processor =
        language == null || language.getProcessor() == null
            ? null
            : nonBlank(language.getProcessor().toString());
    String endian = language == null ? null : language.isBigEndian() ? "big" : "little";
    Integer addressBits = space == null ? null : space.getSize();
    String imageBase = base == null ? null : base.toString();
    var missing = new ArrayList<String>();
    if (hashStatus == HashStatus.MISSING) missing.add("sha256");
    if (path == null) missing.add("executable_path");
    if (format == null) missing.add("executable_format");
    if (langId == null) missing.add("language_id");
    if (compId == null) missing.add("compiler_spec_id");
    if (processor == null) missing.add("processor");
    if (endian == null) missing.add("endian");
    if (addressBits == null) missing.add("address_size_bits");
    if (imageBase == null) missing.add("image_base");
    if (file == null) missing.add("project_path");
    return new BinaryIdentity(
        1,
        Instant.now().toString(),
        program.getName(),
        file == null ? null : file.getPathname(),
        sha256,
        hashStatus,
        "program_database_import_metadata",
        false,
        path,
        format,
        langId,
        compId,
        processor,
        endian,
        addressBits,
        imageBase,
        missing);
  }

  private static String nonBlank(String value) {
    return value == null || value.isBlank() ? null : value;
  }
}
