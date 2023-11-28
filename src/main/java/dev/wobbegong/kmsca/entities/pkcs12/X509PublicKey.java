package dev.wobbegong.kmsca.entities.pkcs12;

import dev.wobbegong.kmsca.entities.oid.KnownOids;

public class X509PublicKey <T> {
    public final KnownOids algorithmOID;
    public final T publicKey;

    public X509PublicKey(KnownOids algorithmOID, T publicKey) {
        this.algorithmOID = algorithmOID;
        this.publicKey = publicKey;
    }
}
