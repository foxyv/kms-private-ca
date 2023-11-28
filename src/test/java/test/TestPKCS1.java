package test;

import dev.wobbegong.kmsca.entities.asn1.types.ASN1Item;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Sequence;
import dev.wobbegong.kmsca.exceptions.X509CertException;
import dev.wobbegong.kmsca.utils.DERDecodingUtils;
import dev.wobbegong.kmsca.utils.X509PublicKeyUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

public class TestPKCS1 {
    @Test
    public void testDSA() throws NoSuchAlgorithmException, InvalidKeySpecException, X509CertException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(2048);
        var keyPair = keyPairGenerator.generateKeyPair();
        var publicKey = keyPair.getPublic();
        byte[] encoded = publicKey.getEncoded();

        ASN1Item publicKeySequence = DERDecodingUtils.parseNextASN1(ByteBuffer.wrap(encoded));
        var x509PublicKey = X509PublicKeyUtils.fromASN1Item((ASN1Sequence) publicKeySequence);
        if (!(x509PublicKey.publicKey instanceof dev.wobbegong.kmsca.entities.pkcs1.DSAPublicKey dsaPublicKey)) {
            Assertions.fail("Expected DSA public key.");
        } else {
            Assertions.assertEquals(((DSAPublicKey) publicKey).getY(), dsaPublicKey.y());
        }
    }

    @Test
    public void testRSA() throws NoSuchAlgorithmException, InvalidKeySpecException, X509CertException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        var keyPair = keyPairGenerator.generateKeyPair();
        var publicKey = keyPair.getPublic();
        byte[] encoded = publicKey.getEncoded();

        ASN1Item publicKeySequence = DERDecodingUtils.parseNextASN1(ByteBuffer.wrap(encoded));
        var x509PublicKey = X509PublicKeyUtils.fromASN1Item((ASN1Sequence) publicKeySequence);
        if (!(x509PublicKey.publicKey instanceof dev.wobbegong.kmsca.entities.pkcs1.RSAPublicKey rsaPublicKey)) {
            Assertions.fail("Expected RSA public key.");
        } else {
            Assertions.assertEquals(((RSAPublicKey) publicKey).getPublicExponent(), rsaPublicKey.publicExponent());
            Assertions.assertEquals(((RSAPublicKey) publicKey).getModulus(), rsaPublicKey.modulus());
        }
    }
}
