package dev.wobbegong.kmsca.utils;

import dev.wobbegong.kmsca.entities.asn1.ASN1TagType;
import dev.wobbegong.kmsca.entities.asn1.charsets.IA5Charset;
import dev.wobbegong.kmsca.entities.asn1.charsets.PrintableStringCharset;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Item;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Sequence;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Set;
import dev.wobbegong.kmsca.entities.pkcs12.X500Name;
import dev.wobbegong.kmsca.exceptions.X509CertException;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class X500NameUtils {
    public static X500Name fromASN1Item(ASN1Sequence asn1Sequence) throws X509CertException {
        Map<String, String> names = new HashMap<>();
        for (int i = 0; i < asn1Sequence.asn1ItemList.size(); i++) {
            ASN1Item item = asn1Sequence.asn1ItemList.get(i);
            if (!(item instanceof ASN1Set set)) {
                throw new X509CertException("Unexpected item in X500Name sequence. Instead found a: " + item.type().name());
            }

            for (var setItem : set.asn1ItemList) {
                if (!(setItem instanceof ASN1Sequence sequence2)) {
                    throw new X509CertException("Unexpected item in X500Name set. Instead found a: " + item.type().name());
                }

                ASN1Item oid = sequence2.asn1ItemList.get(0);
                ASN1Item value = sequence2.asn1ItemList.get(1);

                final String oidString;
                if (oid.type() != ASN1TagType.OBJECT_IDENTIFIER) {
                    throw new X509CertException("Expected OID as first element of X500Name sequence.");
                } else {
                    oidString = DERDecodingUtils.decodeOID(oid);
                }

                final String valueString;
                if (value.type() == ASN1TagType.IA5String) {
                    valueString = new String(value.contents(), IA5Charset.singleton());
                } else if (value.type() == ASN1TagType.UTF8_STRING) {
                    valueString = new String(value.contents(), StandardCharsets.UTF_8);
                } else if(value.type() == ASN1TagType.PRINTABLE_STRING) {
                    valueString = new String(value.contents(), PrintableStringCharset.singleton());
                } else {
                    throw new X509CertException("Unknown value type: " + value.type().name());
                }

                names.put(oidString, valueString);
            }
        }
        return new X500Name(names);
    }
}
