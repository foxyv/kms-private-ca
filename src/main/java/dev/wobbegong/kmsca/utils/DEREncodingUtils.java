package dev.wobbegong.kmsca.utils;

import dev.wobbegong.kmsca.entities.BitString;
import org.bouncycastle.util.Arrays;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class DEREncodingUtils {
    public static byte[] lengthFor(int length) {
        if(length <= 127) {
            return new byte[]{(byte) length};
        } else {
            BigInteger lengthBigInt = BigInteger.valueOf(length);
            byte[] value = lengthBigInt.toByteArray();
            byte valueBytes = (byte) (0b1000_0000 | value.length);

            return Arrays.concatenate(new byte[]{valueBytes}, value);
        }

    }

    public static byte[] encodeBitString(BitString bitString) {
        byte length = (byte) bitString.unusedBits();
        ByteBuffer buffer = ByteBuffer.allocate(bitString.data().length + 1);
        buffer.put(length);
        buffer.put(bitString.data());
        return buffer.array();
    }
}
