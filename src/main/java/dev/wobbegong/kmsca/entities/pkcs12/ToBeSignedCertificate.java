package dev.wobbegong.kmsca.entities.pkcs12;

import dev.wobbegong.kmsca.entities.oid.KnownOids;

import java.math.BigInteger;
import java.time.ZonedDateTime;

public record ToBeSignedCertificate(KnownOids algorithmOID, byte[] publicKey, X509Version version, BigInteger serialNumber, X500Name issuer,
                                    ZonedDateTime issued, ZonedDateTime expires, X500Name subject) {
}
