package test;

import dev.wobbegong.kmsca.entities.asn1.types.ASN1Item;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Sequence;
import dev.wobbegong.kmsca.utils.ASN1Utils;
import dev.wobbegong.kmsca.utils.DERDecodingUtils;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class TestECPublicKey {

    /**
     * Bit Strings for EC public keys.
     */
    String[] ecPublicKeys = new String[]{
            "BCRcLaIq/RxLpl2XcycxrLKgaWLvZeimsPCsS5//HAtwD9OYL038DwCbN/B0BVcyly4F7ypDJaP7bjQnE/ZPfmnTAple6yRHksEkm+axIY/BJIH8aMwfabpY9Rki93TGFg==",
            "BM2b1Z+AgwrsCUrzFko+XM93rN5nBQ0dB7bcFvtaixTb4nFgxLpFlRGJjuoG3/cqFhykucXFMuAD4B6CGDiL10XYCmpu5gB3+wJRfSLYCm6aW3ff8PpB7DncdcpoBwwf6g==",
            "BAS+yq/V7JVhzt9plGkw0tkWmyoU9iGADolIk5Gu5IVoKfsP/loA/zdGsi/697AWcSgyTE5nBrkuSYccUzFsH4U=",
            "BCwUKCRzJcC5JjvBIvODChGsb5+XZhUF1YEGFjmHsnJPVCYm2c5Xo+jc26jl63XqmbSEawyNn34wpDE2p95qXMw=",
            "BJunlXZfs1yuGWRh83MmCsTHlG32AeYgj6Mumr7CDAXIvfgRek4iVHdmmBPNw3T8xh1x95b5eHkX0/AcyzkCV8M=",
            "BKOkA0YD30ZRVsvJOasizedsWZZ6k6D7uUAckDKINsYJdpxQ9VX3dl5oIJzuIu2DDBUwEEFEXjKskKHVqvLlQ7M=",
            "BMEbxppbmNmkKaDp1AS12+umsmxVwP/tmMZJLwYnUcu/cMEFesOxnYeJuq20ExfJqLSDyLiQ0cx0NTY8g3KwtdD3ImnI8YDEe0CPz2iHJlw5ifFNkU3aiYvkA8ND5b8vcw=="
    };
    @Test
    public void test() throws Exception {
        for (String ecPublicKey : ecPublicKeys) {
            testUsing(Base64.getDecoder().decode(ecPublicKey));
        }
    }

    private static void testUsing(byte[] encoded) throws Exception {

        //ASN1Item nullItem = ;
        //ASN1Sequence oidSequence = new ASN1Sequence(List.of(oid, nullItem));
        List<ASN1Item> items = new ArrayList<>();


        ASN1Sequence publicKeySequence = new ASN1Sequence(items);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        KeySpec keyspec = new X509EncodedKeySpec(encoded);
        PublicKey publicKey = keyFactory.generatePublic(keyspec);

        System.out.println(publicKey.getClass());
        var item = DERDecodingUtils.parseNextASN1(ByteBuffer.wrap(encoded));
        System.out.println(ASN1Utils.toString(item));
    }
}
