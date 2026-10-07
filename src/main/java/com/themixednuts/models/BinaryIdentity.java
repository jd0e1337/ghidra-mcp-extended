package com.themixednuts.models;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.List;
import java.util.Locale;

/** Recorded import identity plus current program configuration; never a hash of patched memory. */
public record BinaryIdentity(
    @JsonProperty("schema_version") int schemaVersion,
    @JsonProperty("observed_at") String observedAt,
    @JsonProperty("file_name") String fileName,
    @JsonProperty("project_path") String projectPath,
    @JsonProperty("sha256") String sha256,
    @JsonProperty("sha256_status") HashStatus sha256Status,
    @JsonProperty("hash_source") String hashSource,
    @JsonProperty("original_file_verified") boolean originalFileVerified,
    @JsonProperty("executable_path") String executablePath,
    @JsonProperty("executable_format") String executableFormat,
    @JsonProperty("language_id") String languageId,
    @JsonProperty("compiler_spec_id") String compilerSpecId,
    @JsonProperty("processor") String processor,
    @JsonProperty("endian") String endian,
    @JsonProperty("address_size_bits") Integer addressSizeBits,
    @JsonProperty("image_base") String imageBase,
    @JsonProperty("missing_fields") List<String> missingFields) {
  public BinaryIdentity {
    missingFields = List.copyOf(missingFields);
  }

  public enum HashStatus {
    AVAILABLE,
    MISSING,
    INVALID;

    @JsonValue
    public String value() {
      return name().toLowerCase(Locale.ROOT);
    }
  }
}
