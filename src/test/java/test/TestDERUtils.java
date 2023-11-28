package test;

import dev.wobbegong.kmsca.entities.asn1.ASN1TagType;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Item;
import dev.wobbegong.kmsca.utils.CryptoUtils;
import dev.wobbegong.kmsca.utils.DERDecodingUtils;
import dev.wobbegong.kmsca.utils.DERNumberUtils;
import org.bouncycastle.util.encoders.Hex;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.Oid;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class TestDERUtils {

    @Test
    public void testNumber() throws GSSException {

        byte[] test1 = Hex.decode("c27b");
        Assertions.assertEquals(8571, DERNumberUtils.oidNumberForBytes(test1, 0, test1.length).longValueExact());
        testUsing(0xc27b);

        testUsing(16384);
        testUsing(4_294_967_295L);

        for (long i = 0; i < 100_000; i++) {
            testUsing(CryptoUtils.SRAND.nextLong(4_294_967_295L + 1));
        }
    }

    private static void testUsing(long i) throws GSSException {
        String testOID = "1.0." + i;
        byte[] contents = new Oid(testOID).getDER();
        ASN1Item item = DERDecodingUtils.parseNextASN1(ByteBuffer.wrap(contents));
        long actual = DERNumberUtils.oidNumberForBytes(item.contents(), 1, item.contents().length - 1).longValueExact();
        Assertions.assertEquals(i, actual, "For OID: " + testOID);
    }

    @Test
    public void testMoreBit() {
        for (int i = 0; i < 128; i++) {
            Assertions.assertFalse(DERNumberUtils.moreBit((byte) i));
        }

        for (int i = 128; i < 256; i++) {
            Assertions.assertTrue(DERNumberUtils.moreBit((byte) i));
        }
    }

    @Test
    public void testTwoDigitYearSlidingWindow() {
        // Check around 2000
        Assertions.assertEquals(1999, DERDecodingUtils.nearestYearFor(99, 2000));
        Assertions.assertEquals(2013, DERDecodingUtils.nearestYearFor(13, 2000));
        Assertions.assertEquals(2013, DERDecodingUtils.nearestYearFor(13, 2000));
        Assertions.assertEquals(2025, DERDecodingUtils.nearestYearFor(25, 2000));
        Assertions.assertEquals(2013, DERDecodingUtils.nearestYearFor(13, 2013));
        Assertions.assertEquals(2014, DERDecodingUtils.nearestYearFor(14, 2013));
        Assertions.assertEquals(2000, DERDecodingUtils.nearestYearFor(0, 2013));
        Assertions.assertEquals(1985, DERDecodingUtils.nearestYearFor(85, 2013));

        // Check around +-50 years
        Assertions.assertEquals(2063, DERDecodingUtils.nearestYearFor(13 + 50, 2013));
        Assertions.assertEquals(1964, DERDecodingUtils.nearestYearFor(13 + 51, 2013));
        Assertions.assertEquals(2015, DERDecodingUtils.nearestYearFor(65 - 50, 2065));
        Assertions.assertEquals(2114, DERDecodingUtils.nearestYearFor(65 - 51, 2065));

        for (int i = 0; i < 100; i++) {
            for (int j = 0; j < 100; j++) {
                int oneThousandYear = 1000 + i;

                int currentYear = 2000 + j;
                int nearestYear = DERDecodingUtils.nearestYearFor(i, currentYear);
                Assertions.assertTrue(Math.abs(currentYear - nearestYear) <= 50);
                Assertions.assertEquals(("" + oneThousandYear).substring(2, 4), ("" + nearestYear).substring(2, 4));
            }
        }
    }

    @Test
    public void test() throws GSSException {
        testIntegerUsing("48", 72);
        testIntegerUsing("7F", 127);
        testIntegerUsing("80", -128);
        testIntegerUsing("0080", 128);
        testOIDUsing("1.0.8571.2");
    }

    private void testOIDUsing(String expected) throws GSSException {
        byte[] a = new Oid(expected).getDER();
        ASN1Item item = DERDecodingUtils.parseNextASN1(ByteBuffer.wrap(a));
        String oid = DERDecodingUtils.decodeOID(item);
        Assertions.assertEquals(expected, oid, "DER: " + Hex.toHexString(item.contents()));
    }

    private static void testIntegerUsing(String hex, int expected) {
        byte[] contents = Hex.decode(hex);
        BigInteger bigInteger = DERDecodingUtils.decodeInteger(new ASN1Item(contents.length, 0, ASN1TagType.INTEGER, contents));
        Assertions.assertEquals(expected, bigInteger.intValueExact());
    }
}
