package test;

import dev.wobbegong.kmsca.entities.PEMObject;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Item;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Sequence;
import dev.wobbegong.kmsca.entities.pkcs12.SignedX509Certificate;
import dev.wobbegong.kmsca.exceptions.PEMFormatException;
import dev.wobbegong.kmsca.exceptions.X509CertException;
import dev.wobbegong.kmsca.utils.ASN1Utils;
import dev.wobbegong.kmsca.utils.DERDecodingUtils;
import dev.wobbegong.kmsca.utils.PEMUtils;
import dev.wobbegong.kmsca.utils.X509Utils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

/**
 * PKCS12 is the standard for Certificate files.
 */
public class TestPKCS12 {
    @Test
    public void test() throws CertificateException, PEMFormatException, X509CertException {
        testUsingCRT("certs/v3/oidref.com_443.pem");
        testUsingCRT("certs/v3/_.reddit.com.crt");
        testUsingCRT("certs/v3/DigiCert Global Root CA.crt");
        testUsingCRT("certs/v3/DigiCert TLS RSA SHA256 2020 CA1.crt");

        testUsingCRT("certs/v3/google-com-chain.pem");
        testUsingCRT("certs/v3/questionablecontent-net-chain.pem");

        testUsingCRT("certs/v3/www-homedepot-com-chain.pem");
        testUsingCRT("certs/v3/www-spacejam-com-chain.pem");
        testUsingCRT("certs/v3/yahoo-com-chain.pem");
        testUsingCRT("certs/v3/en.wikipedia.org_443.pem");
        testUsingCRT("certs/v3/github.com_443.pem");
        testUsingCRT("certs/v3/www.mozilla.org_443.pem");

        String v1Certs = """
                16k-dsa-example-cert.der
                16k-rsa-example-cert.pem
                512b-dsa-example-cert.der
                512b-rsa-example-cert.pem
                1024b-dsa-example-cert.der
                1024b-rsa-example-cert.pem
                2048b-dsa-example-cert.der
                2048b-rsa-example-cert.pem
                4096b-dsa-example-cert.der
                4096b-rsa-example-cert.pem
                8192b-dsa-example-cert.der
                8192b-rsa-example-cert.pem
                """;

        Arrays.stream(v1Certs.split("\n")).filter(name -> !name.trim().isEmpty())
                .map(name -> "certs/v1/" + name)
                .forEach(resource -> {
                    try {
                        testUsingCRT(resource);
                    } catch (CertificateException | PEMFormatException | X509CertException e) {
                        throw new RuntimeException("Failed for file: " + resource, e);
                    }
                });
    }

    private void testUsingCRT(String resource) throws CertificateException, PEMFormatException, X509CertException {
        List<PEMObject> certObjects;
        if(resource.endsWith(".der")) {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            try (InputStream is = this.getClass().getClassLoader().getResourceAsStream(resource)) {
                Assertions.assertNotNull(is);
                byte[] buffer = new byte[1024];
                int numRead;
                while ((numRead = is.read(buffer)) != -1) {
                    baos.write(buffer, 0, numRead);
                }
            } catch (IOException ex) {
                throw new RuntimeException(ex);
            }
            PEMObject der = new PEMObject("DER", baos.toByteArray());
            certObjects = Collections.singletonList(der);
        } else {
            try (InputStream is = this.getClass().getClassLoader().getResourceAsStream(resource)) {
                Assertions.assertNotNull(is, "Missing resource: " + resource);
                try (
                        InputStreamReader isr = new InputStreamReader(is, StandardCharsets.UTF_8);
                        BufferedReader br = new BufferedReader(isr)
                ) {
                    certObjects = PEMUtils.parsePEMs(br);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }

        for (PEMObject pem : certObjects) {
            // See: sun.security.x509.X509CertImpl.parse
            CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
            X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(pem.content()));
            System.out.println();

            System.out.println(resource);
            ASN1Item item = DERDecodingUtils.parseNextASN1(ByteBuffer.wrap(pem.content()));
            if (item instanceof ASN1Sequence sequence) {
                SignedX509Certificate signedX509Certificate = X509Utils.toCertificate(sequence);
                System.out.println("=== Certificate information ===");
                System.out.println("Public key: " + Base64.getEncoder().encodeToString(certificate.getPublicKey().getEncoded()));
                System.out.println(X509Utils.toHumanReadable(signedX509Certificate));
                System.out.println("============ASN.1==============\n");
                System.out.println(ASN1Utils.toString(item));
                System.out.println("===============================\n");
                Assertions.assertEquals(certificate.getVersion(), signedX509Certificate.tbsCertificate().version().versionNumber);
                Assertions.assertEquals(certificate.getSerialNumber(), signedX509Certificate.tbsCertificate().serialNumber());
            } else {
                throw new RuntimeException("Could not parse certificate: " + resource);
            }

        }

    }

    /**
     * Get the first PEM object in the byte data and return its contents.
     *
     * @param allBytes Byte data from the PEM object.
     * @return A ByteBuffer wrapping the contents of the first PEM object.
     */
    private ByteBuffer bufferFor(byte[] allBytes) {
        try {
            List<PEMObject> pem = PEMUtils.parsePEMBytes(new String(allBytes, StandardCharsets.UTF_8));
            Assertions.assertEquals(1, pem.size());
            return ByteBuffer.wrap(pem.get(0).content());
        } catch (Exception e) {
            return ByteBuffer.wrap(allBytes);
        }
    }
}
