package test;

import dev.wobbegong.kmsca.entities.asn1.ASN1TagType;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Item;
import dev.wobbegong.kmsca.entities.oid.KnownOids;
import dev.wobbegong.kmsca.utils.DERDecodingUtils;
import dev.wobbegong.kmsca.utils.DEREncodingUtils;
import dev.wobbegong.kmsca.utils.DERNumberUtils;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class TestDEREncodingUtils {

    Map<String, String> oidMap = new HashMap<>();

    public TestDEREncodingUtils() {
        oidMap.put("1.2.840.113549.1.1.11", "KoZIhvcNAQEL");
        oidMap.put("1.2.840.113549.1.1.5", "KoZIhvcNAQEF");
        oidMap.put("1.2.840.10045.4.3.3", "KoZIzj0EAwM=");
        oidMap.put("1.2.840.113549.1.1.12", "KoZIhvcNAQEM");
    }

    @Test
    public void testEncodingOIDArcs() {
        for (long expected = 1; expected < 20_000; expected++) {
            testUsingLong(expected);
        }
    }

    private static void testUsingLong(long expected) {
        final byte[] encoded;
        final BigInteger decoded;
        try {
            encoded = DEREncodingUtils.encodeOIDArc(expected);
            decoded = DERNumberUtils.oidNumberForBytes(encoded, 0, encoded.length);
        } catch (Exception e) {
            System.out.println("Failed to encode " + expected);
            throw e;
        }

        Assertions.assertEquals(expected, decoded.longValueExact(), Hex.toHexString(encoded));
    }

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

    @Test
    public void testOIDEncoding() {
        oidMap.forEach((key, value) -> testOIDEncoding(value, key));

        Arrays.stream(KnownOids.values())
                .map(k -> k.oid)
                .forEach(this::testOIDEncoding);
    }

    private void testOIDEncoding(String expectedBase64, String oid) {
        byte[] encoded = DEREncodingUtils.encodeOID(oid);
        byte[] expected = Base64.getDecoder().decode(expectedBase64);
        Assertions.assertEquals(Hex.toHexString(expected), Hex.toHexString(encoded));
    }

    private void testOIDEncoding(String knownOids) {
        byte[] encoded = DEREncodingUtils.encodeOID(knownOids);
        ASN1Item oidItem = new ASN1Item(encoded.length, 0, ASN1TagType.OBJECT_IDENTIFIER, encoded);
        String decoded = DERDecodingUtils.decodeOID(oidItem);
        Assertions.assertEquals(knownOids, decoded);
    }
}
