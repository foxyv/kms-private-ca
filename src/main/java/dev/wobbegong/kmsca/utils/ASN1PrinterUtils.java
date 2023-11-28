package dev.wobbegong.kmsca.utils;

import dev.wobbegong.kmsca.entities.BitString;
import dev.wobbegong.kmsca.entities.asn1.ASN1TagType;
import dev.wobbegong.kmsca.entities.asn1.charsets.PrintableStringCharset;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Item;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Sequence;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Set;
import dev.wobbegong.kmsca.entities.oid.KnownOids;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.io.StringWriter;
import java.io.Writer;
import java.nio.ByteBuffer;

public class ASN1PrinterUtils {
    public static void printASN1(ASN1Item item, Writer toMe) throws IOException {
        printASN1(item, toMe, 0);
    }

    private static void printASN1(ASN1Item item, Writer toMe, int depth) throws IOException {
        String depthDots = ". ".repeat(depth);
        if (item.type() == ASN1TagType.SEQUENCE && item instanceof ASN1Sequence sequence) {
            toMe.write(hexLocation(sequence.start) + " " + hexOrdinal(sequence.type().ordinal) + " " + hexLength(sequence.length) + " " + paddedLength(sequence.length) + ": " + depthDots + "SEQUENCE\n");

            for (ASN1Item itemInSequence : sequence.asn1ItemList) {
                printASN1(itemInSequence, toMe, depth + 1);
            }
        } else if (item.type() == ASN1TagType.SET && item instanceof ASN1Set set) {
            toMe.write(hexLocation(set.start) + " " + hexOrdinal(set.type().ordinal) + " " + hexLength(set.length) + " " + paddedLength(set.length) + ": " + depthDots + "SET\n");

            for (ASN1Item itemInSequence : set.asn1ItemList) {
                printASN1(itemInSequence, toMe, depth + 1);
            }
        } else {
            final String value = itemToString(item);
            toMe.write(hexLocation(item.start) + " " + hexOrdinal(item.type().ordinal) + " " + hexLength(item.length) + " " + paddedLength(item.length) + ": " + depthDots + item.type().ASN1Name + " " + value + "\n");
        }
    }

    private static String itemToString(ASN1Item item) {
        return switch (item.type()) {
            case OBJECT_IDENTIFIER -> {
                String oidString = DERDecodingUtils.decodeOID(item);
                yield oidString + ":" + KnownOids.forOID(oidString).map(oid -> oid.desc).orElse("Unknown");
            }
            case PRINTABLE_STRING -> "'" + new String(item.contents(), PrintableStringCharset.singleton()) + "'";
            case BIT_STRING -> {
                BitString bitString = DERDecodingUtils.decodeBitString(item);
                String unusedBitsHex = paddedHex(new byte[]{(byte) bitString.unusedBits()}, 2, 1);

                StringBuilder sb = new StringBuilder().append("\n")
                        .append(" ".repeat(25)).append(": ").append(unusedBitsHex);
                ByteBuffer buffer = ByteBuffer.wrap(item.contents());
                byte[] bytes = new byte[16];
                while(buffer.hasRemaining()) {
                    int length = Math.min(16, buffer.remaining());
                    buffer.get(bytes, 0, length);
                    // 30 68 02 61 00 be aa 8b 77 54 a3 af ca 77 9f 2f
                    sb.append("\n").append(" ".repeat(25)).append(": ").append(paddedHex(bytes, 47, length));
                }

                yield sb.toString();
            }
            default -> "";
        };
    }

    private static String paddedLength(int length) {
        String lengthString = Integer.toString(length);
        int padding = Math.max(0, 4 - lengthString.length());
        return " ".repeat(padding) + lengthString;
    }

    public static String printToString(ASN1Item item) {
        try (StringWriter sw = new StringWriter()) {
            printASN1(item, sw);
            return sw.toString();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }


    private static String hexLength(int length) {
        // Get the first octet of the length value
        byte[] data = DEREncodingUtils.lengthFor(length);
        return paddedHex(data, 8, data.length);
    }

    private static String paddedHex(byte[] data, int paddedLength, int byteLength) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < byteLength; i++) {
            byte nextByte = data[i];
            sb.append(Hex.toHexString(new byte[]{nextByte}));
            if (i != byteLength - 1) {
                sb.append(" ");
            }
        }
        while (sb.length() < paddedLength) {
            sb.append(" ");
        }

        return sb.toString();

    }

    private static String hexLocation(int location) {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
        buffer.putInt(location);
        return Hex.toHexString(buffer.array());
    }

    private static String hexOrdinal(int ordinal) {
        byte value = (byte) ordinal;
        return Hex.toHexString(new byte[]{value});
    }
}
