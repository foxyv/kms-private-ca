package dev.wobbegong.kmsca.utils;

import dev.wobbegong.kmsca.entities.BitString;
import dev.wobbegong.kmsca.entities.asn1.ASN1TagType;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Sequence;
import dev.wobbegong.kmsca.entities.oid.KnownOids;
import dev.wobbegong.kmsca.entities.pkcs1.DSAPublicKey;
import dev.wobbegong.kmsca.entities.pkcs1.RSAPublicKey;
import dev.wobbegong.kmsca.entities.pkcs12.X509PublicKey;
import dev.wobbegong.kmsca.exceptions.X509CertException;

import java.math.BigInteger;
import java.nio.ByteBuffer;

public class X509PublicKeyUtils {
    public static X509PublicKey<?> fromASN1Item(ASN1Sequence publicKeySequence) throws X509CertException {
        if (publicKeySequence.asn1ItemList.size() != 2) {
            throw new X509CertException("Public Key Sequence must have 2 items");
        }

        if (!(publicKeySequence.asn1ItemList.get(0) instanceof ASN1Sequence oidSequence)) {
            throw new X509CertException("Public Key Sequence must have OID Sequence as first item");
        }

        if (oidSequence.asn1ItemList.get(0).type() != ASN1TagType.OBJECT_IDENTIFIER) {
            throw new X509CertException("Public Key Sequence must have OID Sequence as first item");
        }

        String algorithmOID = DERDecodingUtils.decodeOID(oidSequence.asn1ItemList.get(0));
        BitString bitString = DERDecodingUtils.decodeBitString(publicKeySequence.asn1ItemList.get(1));

        return publicKeyFor(algorithmOID, bitString);
    }

    private static X509PublicKey<?> publicKeyFor(String publicKeyAlg, BitString bitString) throws X509CertException {
        KnownOids algorithm = KnownOids.forOID(publicKeyAlg)
                .orElseThrow(() -> new X509CertException("Unknown Algorithm OID: " + publicKeyAlg));
        return switch (algorithm) {
            case rsaEncryption -> rsaPublicKey(bitString);
            case ecPublicKey -> ecPublicKey(bitString);
            case dsa -> dsaPublicKey(bitString);
            default ->
                    throw new X509CertException("Unsupported Algorithm OID: " + algorithm.name() + " - " + algorithm.desc);
        };
    }

    private static X509PublicKey<?> dsaPublicKey(BitString bitString) throws X509CertException {
        var item = DERDecodingUtils.parseNextASN1(ByteBuffer.wrap(bitString.data()));
        if(item.type() != ASN1TagType.INTEGER) {
            throw new X509CertException("DSA Public Key must be an Integer");
        }
        return new X509PublicKey<>(KnownOids.dsa, new DSAPublicKey(DERDecodingUtils.decodeInteger(item)));
    }

    private static X509PublicKey<?> ecPublicKey(BitString bitString) {
        return null;
    }

    public static X509PublicKey<RSAPublicKey> rsaPublicKey(BitString bitString) {
        if (!(DERDecodingUtils.parseNextASN1(ByteBuffer.wrap(bitString.data())) instanceof ASN1Sequence sequence)) {
            throw new RuntimeException("Not Yet Implemented");
        }
        BigInteger modulus = DERDecodingUtils.decodeInteger(sequence.asn1ItemList.get(0));
        BigInteger publicExponent = DERDecodingUtils.decodeInteger(sequence.asn1ItemList.get(1));

        return new X509PublicKey<>(KnownOids.rsaEncryption, new RSAPublicKey(modulus, publicExponent));
    }
}
