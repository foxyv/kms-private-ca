package test;

import dev.wobbegong.kmsca.utils.DERDecodingUtils;
import dev.wobbegong.kmsca.utils.DEREncodingUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class TestDEREncodingUtils {
    @Test
    public void testLengths() {
        // Test encoding and decoding length values
        for (int size = 0; size < 1_000_000; size++) {
            byte[] length = DEREncodingUtils.lengthFor(size);
            ByteBuffer lengthBuffer = ByteBuffer.wrap(length);
            BigInteger contentsLength = DERDecodingUtils.parseNextLength(lengthBuffer);
            Assertions.assertEquals(size, contentsLength.intValueExact());
        }

        System.out.println(DERDecodingUtils.parseNextLength(ByteBuffer.wrap(Hex.decode("820240"))));
    }
}
