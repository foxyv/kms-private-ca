package dev.wobbegong.kmsca.utils;

import dev.wobbegong.kmsca.entities.BitString;
import dev.wobbegong.kmsca.entities.asn1.ASN1TagType;
import dev.wobbegong.kmsca.entities.asn1.charsets.PrintableStringCharset;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Item;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Sequence;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Set;
import dev.wobbegong.kmsca.entities.oid.KnownOids;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

/**
 * Abstract Syntax Notation One (ASN.1) is a standard interface description language (IDL) for defining data
 * structures that can be serialized and deserialized in a cross-platform way. It is broadly used in
 * telecommunications and computer networking, and especially in cryptography.
 *
 * @see <a href="https://en.wikipedia.org/wiki/ASN.1">Wikipedia: ASN.1</a>
 */
public class ASN1Utils {
    public static String toString(ASN1Item item) {
        return toString(item, 0);
    }

    private static String toString(ASN1Item item, int indentLevel) {
        StringBuilder sb = new StringBuilder();
        sb.append("\t".repeat(Math.max(0, indentLevel)));
        sb.append(item.type().ordinal).append(" ").append(item.type().name()).append("\n");

        if (item instanceof ASN1Sequence sequence) {
            sequence.asn1ItemList.forEach(i -> sb.append(toString(i, indentLevel + 1)));
            return sb.toString();
        }

        if (item instanceof ASN1Set set) {
            set.asn1ItemList.forEach(i -> sb.append(toString(i, indentLevel + 1)));
            return sb.toString();
        }

        switch (item.type()) {
            case OBJECT_IDENTIFIER -> {
                sb.append("\t".repeat(Math.max(0, indentLevel + 1)));

                String oid = DERDecodingUtils.decodeOID(item);
                Optional<String> knownOID = KnownOids.forOID(oid).map(Enum::name);

                String value;
                if(knownOID.isEmpty()) {
                    value = oid;
                } else {
                    value = knownOID.orElse(oid);
                }
                sb.append(value).append("\n");
            }
            case INTEGER -> {
                sb.append("\t".repeat(Math.max(0, indentLevel + 1)));
                sb.append(DERDecodingUtils.decodeInteger(item)).append("\n");
            }
            case UTCTime -> {
                sb.append("\t".repeat(Math.max(0, indentLevel + 1)));
                sb.append(DERDecodingUtils.decodeUTCTime(item)).append("\n");
            }
            case NULL -> {
                sb.append("\t".repeat(Math.max(0, indentLevel + 1)));
                sb.append(item.contents().length).append("\n");
            }
            case PRINTABLE_STRING -> {

                sb.append("\t".repeat(Math.max(0, indentLevel + 1)));
                sb.append(new String(item.contents(), PrintableStringCharset.singleton())).append("\n");
            }
            case UTF8_STRING -> {
                sb.append("\t".repeat(Math.max(0, indentLevel + 1)));
                sb.append(new String(item.contents(), StandardCharsets.UTF_8)).append("\n");
            }
            case BIT_STRING -> {
                BitString bitString = DERDecodingUtils.decodeBitString(item);
                sb.append("\t".repeat(Math.max(0, indentLevel + 1)));
                sb.append(bitString.unusedBits()).append(" : ").append(Hex.toHexString(bitString.data())).append("\n");
            }
            case IA5String -> {
                sb.append("\t".repeat(Math.max(0, indentLevel + 1)));
                sb.append(DERDecodingUtils.decodeIA5(item)).append("\n");
            }
            default -> {
                sb.append("\t".repeat(Math.max(0, indentLevel + 1)));
                sb.append(Hex.toHexString(item.contents())).append("\n");
            }
        }

        return sb.toString();
    }

    public ASN1Item nullItem() {
        return new ASN1Item(0, ASN1TagType.NULL, new byte[0]);
    }

    public ASN1Item oidItem(String oid) {
        byte[] encodedOID = DEREncodingUtils.encodeOID(oid);
        return new ASN1Item(0, ASN1TagType.OBJECT_IDENTIFIER, encodedOID);
    }

}
