package dev.wobbegong.kmsca.utils;

import dev.wobbegong.kmsca.entities.asn1.ASN1TagType;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Item;
import dev.wobbegong.kmsca.entities.asn1.types.ASN1Sequence;
import dev.wobbegong.kmsca.entities.oid.KnownOids;
import dev.wobbegong.kmsca.entities.pkcs12.*;
import dev.wobbegong.kmsca.exceptions.X509CertException;
import org.bouncycastle.util.encoders.Hex;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.CompletableFuture;

public class X509Utils {
    public static SignedX509Certificate toCertificate(ASN1Sequence root) throws X509CertException {

        final ToBeSignedCertificate tbsCertificate;
        if (root.asn1ItemList.get(0).type() == ASN1TagType.SEQUENCE && root.asn1ItemList.get(0) instanceof ASN1Sequence sequence1) {
            tbsCertificate = tbsCertificate(sequence1);
        } else {
            throw new X509CertException("First item in ASN1 structure of certificate is not a sequence as expected, but is instead a: " + root.asn1ItemList.get(0).type().name());
        }

        final X509SignatureAlgorithm signatureAlgorithm;
        if (root.asn1ItemList.get(1).type() == ASN1TagType.SEQUENCE && root.asn1ItemList.get(1) instanceof ASN1Sequence sequence2) {
            signatureAlgorithm = signatureAlgorithm(sequence2);
        } else {
            throw new X509CertException("Second item in ASN1 structure of certificate is not a sequence as expected, but is instead a: " + root.asn1ItemList.get(1).type().name());
        }

        final byte[] signature;
        if (root.asn1ItemList.get(2).type() == ASN1TagType.BIT_STRING) {
            signature = signatureFrom(root.asn1ItemList.get(2));
        } else {
            throw new X509CertException("Second item in ASN1 structure of certificate is not a sequence as expected, but is instead a: " + root.asn1ItemList.get(1).type().name());
        }

        return new SignedX509Certificate(tbsCertificate, signatureAlgorithm, signature);
    }

    private static byte[] signatureFrom(ASN1Item asn1Item) {
        return asn1Item.contents();
    }

    private static X509SignatureAlgorithm signatureAlgorithm(ASN1Sequence signatureAlgorithm) throws X509CertException {
        ASN1Item oidItem = signatureAlgorithm.asn1ItemList.get(0);
        if (oidItem.type() != ASN1TagType.OBJECT_IDENTIFIER) {
            throw new X509CertException("Expected OID as first element of signature algorithm sequence.");
        }

        // Decode the DER encoded OID
        String oidString = DERDecodingUtils.decodeOID(oidItem);
        KnownOids knownOID = KnownOids.forOID(oidString).orElseThrow(() -> new X509CertException("Unknown algorithm OID: " + oidString));

        // Return the signature algorithm specifier
        return new X509SignatureAlgorithm(knownOID);
    }

    private static ToBeSignedCertificate tbsCertificate(ASN1Sequence tbsCertificate) throws X509CertException {

        // Start iterating through the TBS Cert sequence
        Iterator<ASN1Item> certificateItems = tbsCertificate.asn1ItemList.iterator();

        // Check for EOC version
        // If there is an EOC at the beginning of the TBS that is the version item.

        final ASN1Item serialNumberItem;
        final X509Version version;
        {
            final ASN1Item firstItem = certificateItems.next();
            if (firstItem.type() == ASN1TagType.EndOfContent) {
                // The version is an Integer ASN1 item withing the contents of the EOC
                ASN1Item versionItem = DERDecodingUtils.parseNextASN1(ByteBuffer.wrap(firstItem.contents()));
                if (versionItem.type() == ASN1TagType.INTEGER) {
                    version = X509Version.fromASN1Number(DERDecodingUtils.decodeInteger(versionItem).intValueExact());
                } else {
                    version = X509Version.V1;
                }
                // Iterate to the next item before proceeding
                serialNumberItem = certificateItems.next();
            } else {
                // The first item is not the version, default to V1 in such cases
                version = X509Version.V1;

                // The first item should then be the serial number.
                serialNumberItem = firstItem;
            }
        }


        // Parse the serial number
        BigInteger serialNumber;
        if (serialNumberItem.type() == ASN1TagType.INTEGER) {
            serialNumber = DERDecodingUtils.decodeInteger(serialNumberItem);
        } else {
            throw new X509CertException("Missing serial number ASN.1 Integer. Instead found a: " + serialNumberItem.type().name());
        }

        // Parse the algorithm identifier
        final KnownOids algorithmOID = certificateOIDForASN1Item(certificateItems.next());

        // Parse the X500 section
        if (!(certificateItems.next() instanceof ASN1Sequence issuerSequence)) {
            throw new X509CertException("Missing X500Name ASN.1 Sequence. Instead found a: " + certificateItems.next().type().name());
        }
        final X500Name issuer = X500NameUtils.fromASN1Item(issuerSequence);

        if(!(certificateItems.next() instanceof ASN1Sequence datesSequence)) {
            throw new X509CertException("Missing validity/issued ASN.1 Sequence. Instead found a: " + certificateItems.next().type().name());
        }

        // Parse the issued and expiry dates
        if(datesSequence.asn1ItemList.size() != 2) {
            throw new X509CertException("Expected two items in validity/issued ASN.1 Sequence. Instead found: " + datesSequence.asn1ItemList.size());
        }

        if(datesSequence.asn1ItemList.get(0).type() != ASN1TagType.UTCTime) {
            throw new X509CertException("Expected UTCTime as first item in validity/issued ASN.1 Sequence. Instead found a: " + datesSequence.asn1ItemList.get(0).type().name());
        }

        if(datesSequence.asn1ItemList.get(1).type() != ASN1TagType.UTCTime) {
            throw new X509CertException("Expected UTCTime as second item in validity/issued ASN.1 Sequence. Instead found a: " + datesSequence.asn1ItemList.get(0).type().name());
        }

        // Parse the dates
        ZonedDateTime issued = DERDecodingUtils.decodeUTCTime(datesSequence.asn1ItemList.get(0)).atZone(ZoneId.of("UTC"));
        ZonedDateTime expires = DERDecodingUtils.decodeUTCTime(datesSequence.asn1ItemList.get(1)).atZone(ZoneId.of("UTC"));

        // Parse the subject X500
        if(!(certificateItems.next() instanceof ASN1Sequence subjectSequence)) {
            throw new X509CertException("Missing subject ASN.1 Sequence. Instead found a: " + certificateItems.next().type().name());
        }
        X500Name subject = X500NameUtils.fromASN1Item(subjectSequence);

        if(!(certificateItems.next() instanceof ASN1Sequence publicKeySequence)) {
            throw new X509CertException("Missing public key ASN.1 Sequence. Instead found a: " + certificateItems.next().type().name());
        }

        X509PublicKey publicKey = X509PublicKeyUtils.fromASN1Item(publicKeySequence);

        // TODO: Flesh out certificate information
        return new ToBeSignedCertificate(algorithmOID, new byte[0], version, serialNumber, issuer, issued, expires, subject);
    }

    private static KnownOids certificateOIDForASN1Item(ASN1Item certificateAlgorithm) throws X509CertException {
        if (certificateAlgorithm.type() == ASN1TagType.SEQUENCE) {
            if (certificateAlgorithm instanceof ASN1Sequence sequence) {
                if (sequence.asn1ItemList.size() == 0) {
                    throw new X509CertException("No items in ASN1Sequence for certificate algorithm identifier.");
                }

                if (sequence.asn1ItemList.size() > 2) {
                    throw new X509CertException("Too many items in ASN1Sequence for certificate algorithm identifier.");
                }

                if (sequence.asn1ItemList.size() == 2) {
                    ASN1Item item2 = sequence.asn1ItemList.get(1);
                    if (item2.type() != ASN1TagType.NULL) {
                        throw new X509CertException("Second item in ASN1Sequence for certificate algorithm identifier should be null.");
                    }
                }

                ASN1Item item1 = sequence.asn1ItemList.get(0);
                String oid = DERDecodingUtils.decodeOID(item1);
                return KnownOids.forOID(oid).orElseThrow(() -> new X509CertException("Unknown OID for algorithm: " + oid));
            } else {
                throw new RuntimeException("Sequence ASN.1 item was not of the type: " + ASN1Sequence.class.getCanonicalName());
            }
        } else {
            throw new X509CertException("Missing certificate algorithm ASN.1 Sequence. Instead found a: " + certificateAlgorithm.type().name());
        }
    }

    public static String toHumanReadable(SignedX509Certificate signedX509Certificate) {
        return "Signature Algorithm: " + signedX509Certificate.signatureAlgorithm().oid().desc + "\n" +
                "Signature: " + java.util.Base64.getEncoder().encodeToString(signedX509Certificate.signature()) + "\n" +
                toHumanReadable(signedX509Certificate.tbsCertificate());
    }

    private static String toHumanReadable(ToBeSignedCertificate tbsCertificate) {

        StringBuilder sb = new StringBuilder().append("Version: ").append(tbsCertificate.version()).append("\n");
        sb.append("Algorithm: ").append(tbsCertificate.algorithmOID().desc).append("\n");
        sb.append("Serial Number: ").append(hex(tbsCertificate.serialNumber())).append("\n");
        sb.append("Issuer:\n");
        for (var entry : tbsCertificate.issuer().oidValues().entrySet()) {
            String oidString = entry.getKey();
            String keyName = KnownOids.forOID(oidString).map(KnownOids::name).orElse(oidString);
            sb.append("\t").append(keyName).append(": ").append(entry.getValue()).append("\n");
        }

        sb.append("Issued: ").append(tbsCertificate.issued()).append("\n");
        sb.append("Expires: ").append(tbsCertificate.expires()).append("\n");

        sb.append("Subject:\n");
        for (var entry : tbsCertificate.subject().oidValues().entrySet()) {
            String oidString = entry.getKey();
            String keyName = KnownOids.forOID(oidString).map(KnownOids::name).orElse(oidString);
            sb.append("\t").append(keyName).append(": ").append(entry.getValue()).append("\n");
        }


        return sb.toString();
    }

    private static String hex(BigInteger serialNumber) {
        CharBuffer charBuffer = CharBuffer.wrap(Hex.toHexString(serialNumber.toByteArray()).toUpperCase());
        StringBuilder sb = new StringBuilder();
        char[] twoChars = new char[2];
        while (charBuffer.hasRemaining()) {
            charBuffer.get(twoChars);
            sb.append(twoChars);
            if (charBuffer.hasRemaining()) {
                sb.append(":");
            }
        }
        return sb.toString();
    }

    public static String toPEM(Certificate certificate) throws X509CertException {
        try {
            return PEMUtils.pemFor("CERTIFICATE", certificate.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new X509CertException("Could not extract DER bytes from certificate: " + certificate.getClass().getName(), e);
        }
    }

    /**
     * Download a certificate from a remote location.
     *
     * @param host The host to download the certificate from.
     * @param port The port to download the certificate from.
     * @return The certificate as a DER byte array.
     */
    public static List<Certificate> downloadCertificate(String host, int port) {
        // Connect to the location using an SSL socket
        try (SSLSocket socket = (SSLSocket) SSLSocketFactory.getDefault().createSocket(host, port)) {
            CompletableFuture<List<Certificate>> certificates = new CompletableFuture<>();
            socket.addHandshakeCompletedListener(completedEvent -> {
                try {
                    certificates.complete(List.of(completedEvent.getPeerCertificates()));
                } catch (SSLPeerUnverifiedException e) {
                    certificates.completeExceptionally(e);
                }
            });

            // Start the handshake
            socket.startHandshake();

            // Get the certificates from the result.
            return certificates.get();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
