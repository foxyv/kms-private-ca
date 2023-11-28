package dev.wobbegong.kmsca.entities.asn1;

import java.util.Arrays;

/**
 * The BER identifier octets encode the ASN.1 tags. The list of Universal Class tags can be found at Rec. ITU-T X.680,
 * clause 8, table 1.[2] The following tags are native to ASN.1:
 */
public enum ASN1TagType {
    EndOfContent(0x00, "P", "EOC"),
    BOOLEAN(0x01, "P", "BOOLEAN"),
    INTEGER(0x02, "P", "INTEGER"),
    BIT_STRING(0x03, "PC", "BIT STRING"),
    OCTET_STRING(0x04, "PC", "OCTET STRING"),
    NULL(0x05, "P", "NULL"),
    OBJECT_IDENTIFIER(0x06, "P", "OBJECT IDENTIFIER"),
    OBJECT_DESCRIPTOR(0x07, "PC", "OBJECT DESCRIPTION"),
    EXTERNAL(0x08, "C", "EXTERNAL"),
    REAL(0x09, "P", "REAL"),
    ENUMERATED(0x0A, "P", "ENUMERATED"),
    EMBEDDED_PDV(0x0B, "C", "EMBEDDED PDV"),
    UTF8_STRING(0x0C, "PC", "UTF8String"),
    RELATIVE_OID(0x0D, "P", "RELATIVE-OID"),
    TIME(0x0E, "P", "TIME"),
    RESERVED(0x0F, "", ""),
    SEQUENCE(0x10, "C", "SEQUENCE"),
    SET(0x11, "C", "SET"),
    NUMERIC_STRING(0x12, "PC", "NumericString"),
    PRINTABLE_STRING(0x13, "PC", "PrintableString"),
    T61_STRING(0x14, "PC", "T61String"),
    VideotexString(0x15, "PC", "VideotexString"),
    IA5String(0x16, "PC", "IA5String"),
    UTCTime(0x17, "PC", "UTCTime"),
    GeneralizedTime(0x18, "PC", "GeneralizedTime"),
    GraphicString(0x19, "PC", "GraphicString"),
    VisibleString(0x1A, "PC", "VisibleString"),
    GeneralString(0x1B, "PC", "GeneralString"),
    UniversalString(0x1C, "PC", "UniversalString"),
    CHARACTER_STRING(0x1D, "C", "CHARACTER STRING"),
    BMPString(0x1E, "PC", "BMPString"),
    DATE(0x1F, "P", "DATE"),
    TIME_OF_DAY(0x20, "P", "TIME-OF-DAY"),
    DATE_TIME(0x21, "P", "DATE-TIME"),
    DURATION(0x22, "P", "DURATION"),
    OID_IRI(0x23, "P", "OID-IRI"),
    RELATIVE_OID_IRI(0x24, "P", "RELATIVE-OID-IRI");

    public final int ordinal;
    public final boolean allowPrimitive;
    public final boolean allowConstructed;
    public final String ASN1Name;

    ASN1TagType(int ordinal, String pc, String asn1Name) {
        this.ordinal = ordinal;
        ASN1Name = asn1Name;
        switch (pc) {
            case "P" -> {
                allowPrimitive = true;
                allowConstructed = false;
            }
            case "C" -> {
                allowConstructed = true;
                allowPrimitive = false;
            }
            case "PC" -> {
                allowPrimitive = true;
                allowConstructed = true;
            }
            default -> {
                allowPrimitive = false;
                allowConstructed = false;
            }
        }
    }

    public static ASN1TagType fromOrdinal(int ordinal) {
        return Arrays.stream(ASN1TagType.values())
                .filter(type -> type.ordinal == ordinal)
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Cannot find tag type for: " + ordinal));
    }
}
