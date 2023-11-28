package dev.wobbegong.kmsca.entities.pkcs12;

/**
 * An X509 certificate including a "To Be Signed" certificate followed by a signature.
 */
public record SignedX509Certificate(ToBeSignedCertificate tbsCertificate,
                                    X509SignatureAlgorithm signatureAlgorithm,
                                    byte[] signature) {

}
