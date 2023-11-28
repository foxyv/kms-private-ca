package test;

import dev.wobbegong.kmsca.entities.PEMObject;
import dev.wobbegong.kmsca.exceptions.PEMFormatException;
import dev.wobbegong.kmsca.utils.PEMUtils;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.StringWriter;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.Base64;
import java.util.List;
import java.util.regex.Matcher;

public class TestPEMUtils {

    @Test
    public void test() throws NoSuchAlgorithmException, PEMFormatException {
        var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        System.out.println(keyPairGenerator.getClass().getName());


        var keyPair = keyPairGenerator.generateKeyPair();

        // Use BouncyCastle to test PEM generation
        String expected = pemFor(keyPair.getPrivate());
        String actual = PEMUtils.pemFor("RSA PRIVATE KEY", keyPair.getPrivate().getEncoded());
        Assertions.assertEquals(expected, actual);

        String base64 = Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded());

        Matcher matcher = PEMUtils.PEM_PATTERN.matcher(expected);
        Assertions.assertTrue(matcher.matches());
        Assertions.assertEquals("RSA PRIVATE KEY", matcher.group(1));
        Assertions.assertEquals(base64, matcher.group(2).replaceAll(System.lineSeparator(), ""));
        Assertions.assertEquals("RSA PRIVATE KEY", matcher.group(3));

        List<PEMObject> pemFile = PEMUtils.parsePEMBytes(expected);
        Assertions.assertNotNull(pemFile);
        Assertions.assertEquals(1, pemFile.size());

        Assertions.assertEquals("RSA PRIVATE KEY", pemFile.get(0).type());
        Assertions.assertEquals(base64, Base64.getEncoder().encodeToString(pemFile.get(0).content()));
    }

    @Test
    public void testChain() {

    }


    public static String pemFor(PrivateKey privateKey) {
        var pemObject = new PemObject("RSA PRIVATE KEY", privateKey.getEncoded());

        try(StringWriter sw = new StringWriter(); PemWriter pemWriter = new PemWriter(sw)) {
            pemWriter.writeObject(pemObject);
            pemWriter.flush();
            return sw.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String generateRandomRSAKey() throws NoSuchAlgorithmException {
        var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);

        var keyPair = keyPairGenerator.generateKeyPair();

        System.out.println(keyPair.getPrivate().getClass().getName());
        var pemObject = new PemObject("RSA PRIVATE KEY", keyPair.getPrivate().getEncoded());

        try(StringWriter sw = new StringWriter(); PemWriter pemWriter = new PemWriter(sw)) {
            pemWriter.writeObject(pemObject);
            pemWriter.flush();
            return sw.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
