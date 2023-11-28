package test;

import dev.wobbegong.kmsca.entities.asn1.ASN1LengthOctet;
import dev.wobbegong.kmsca.utils.DERDecodingUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

public class TestASN1 {
    @Test
    public void test() {
        for (int i = 0; i <= 0xFF; i++) {
            testUsing(i, i & 0x7f, (i >> 7) == 1);
        }

        testUsing(0b1000_0000, 0, true);
        testUsing(0b1010_0100, 0b10_0100, true);
        testUsing(0b0010_0100, 0b10_0100, false);
        testUsing(0b0000_0000, 0b00_0000, false);

    }

    private static void testUsing(int value, int expectedOctetLength, boolean expectedLongForm) {
        ByteBuffer buffer = ByteBuffer.allocate(1);
        buffer.put((byte) value);
        buffer.flip();
        ASN1LengthOctet length = DERDecodingUtils.readLengthOctet(buffer);

        if(expectedLongForm) {
            Assertions.assertTrue(length.longForm());
        } else {
            Assertions.assertFalse(length.longForm());
        }

        Assertions.assertEquals(expectedOctetLength, length.lengthOctets());
    }
}
