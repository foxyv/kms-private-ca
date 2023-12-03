package dev.wobbegong.kmsca.utils;

import dev.wobbegong.kmsca.entities.BitString;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Item;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Sequence;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Set;
import org.bouncycastle.util.Arrays;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.List;

public class DEREncodingUtils {
    public static byte[] lengthFor(int length) {
        if (length <= 127) {
            return new byte[]{(byte) length};
        } else {
            BigInteger lengthBigInt = BigInteger.valueOf(length);
            byte[] value = lengthBigInt.toByteArray();
            byte valueBytes = (byte) (0b1000_0000 | value.length);

            return Arrays.concatenate(new byte[]{valueBytes}, value);
        }

    }

    public static byte[] encodeItem(ASN1Item item) {
        // Re-encode sequences and sets using their contents
        if (item instanceof ASN1Sequence asn1Sequence) {
            return encodeSequence(asn1Sequence);
        }

        if (item instanceof ASN1Set asn1Set) {
            return encodeSet(asn1Set);
        }

        // All other items follow the same pattern
        byte[] length = lengthFor(item.length);
        ByteBuffer buffer = ByteBuffer.allocate(item.length + length.length + 1);
        buffer.put((byte) item.type().ordinal);
        buffer.put(length);
        buffer.put(item.contents());
        throw new RuntimeException("Not Yet Implemented");
    }

    private static byte[] encodeSet(ASN1Set asn1Set) {

        // Encode underlying items
        List<byte[]> items = asn1Set.asn1ItemList.stream().map(DEREncodingUtils::encodeItem).toList();

        // Calculate the total length of the contents
        int contentsLength = items.stream().mapToInt(b -> b.length).sum();
        byte type = (byte) asn1Set.type().ordinal;
        byte[] length = lengthFor(contentsLength);
        int totalDEREncodedLength = contentsLength + length.length + 1;

        // Load every item into a buffer.
        ByteBuffer bb = ByteBuffer.allocate(totalDEREncodedLength);
        bb.put(type);
        bb.put(length);
        items.forEach(bb::put);

        return bb.array();
    }

    private static byte[] encodeSequence(ASN1Sequence sequence) {


        // Calculate the total length of the contents
        byte type = (byte) sequence.type().ordinal;
        byte[] contents = encodeSequenceContents(sequence.asn1ItemList);
        int contentsLength = contents.length;
        byte[] length = lengthFor(contentsLength);
        int totalDEREncodedLength = contentsLength + length.length + 1;

        // Load every item into a buffer.
        ByteBuffer bb = ByteBuffer.allocate(totalDEREncodedLength);
        bb.put(type);
        bb.put(length);
        bb.put(contents);
        return bb.array();
    }

    public static byte[] encodeSequenceContents(List<ASN1Item> asn1ItemList) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        asn1ItemList.forEach(item -> {
            try {
                baos.write(encodeItem(item));
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        });
        return baos.toByteArray();
    }

    public static byte[] encodeBitString(BitString bitString) {
        byte length = (byte) bitString.unusedBits();
        ByteBuffer buffer = ByteBuffer.allocate(bitString.data().length + 1);
        buffer.put(length);
        buffer.put(bitString.data());
        return buffer.array();
    }

    public static byte[] encodeInteger(BigInteger integer) {
        byte[] value = integer.toByteArray();
        if (value[0] == 0) {
            value = Arrays.copyOfRange(value, 1, value.length);
        }
        return value;
    }

    public static byte[] encodeOID(String oid) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        // Split the OID into its arc values
        List<Long> values = java.util.Arrays.stream(oid.split("\\.")).map(Long::parseLong).toList();

        // First two values are encoded together as a single byte. 2 bit first value, 6 bit second value.
        long arc1 = values.get(0);
        long arc2 = values.get(1);

        // Encode the first two values as the first byte
        byte firstByte = (byte) (arc1 * 40 + arc2);
        baos.write(firstByte);

        // Starting at the third item, encode each value
        for (int i = 2; i < values.size(); i++) {
            long arc = values.get(i);
            byte[] encodedArc = encodeOIDArc(arc);
            try {
                baos.write(encodedArc);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        // Return the encoded OID
        return baos.toByteArray();

    }

    /**
     * Encode an OID arc value as a byte array. The first bit of each byte is set to 1 except for the last byte.
     * @param arc The arc value to encode
     * @return The encoded arc value
     */
    public static byte[] encodeOIDArc(long arc) {
        if(arc < 128) {
            return new byte[]{(byte) arc};
        }

        // Extract 7 digit values from the arc into an InputBuffer from right to left
        int inOffset = 0;
        byte[] buffer = new byte[6];
        long value = arc;
        while(value != 0) {
            // Encode the lowest 7 bits of the value
            byte byteValue = (byte) (value & 0b0111_1111);

            // Shift the value right by 7 bits
            value = value >> 7;

            if(inOffset != 0) {
                // Set the more bit for all but the first byte
                byteValue = (byte) (byteValue | 0b1000_0000);
            }

            // Write the byte to the buffer
            buffer[inOffset] = byteValue;
            inOffset++;
        }

        // Decrement the offset to account for the last increment
        inOffset--;

        // Put the 7 digit values into a byte array in reverse order (FILO)
        int length = inOffset + 1;
        int outOffset = 0;
        byte[] result = new byte[length];
        while(outOffset < length) {
            result[outOffset] = buffer[inOffset];
            outOffset++;
            inOffset--;
        }

        return result;
    }
}
