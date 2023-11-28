package dev.wobbegong.kmsca.entities.asn1.types;

import dev.wobbegong.kmsca.entities.asn1.ASN1TagType;
import org.bouncycastle.util.encoders.Hex;

public class ASN1Item {
    public final int length;
    public final int start;
    private final ASN1TagType type;
    private final byte[] derContents;

    public ASN1Item(int start, ASN1TagType type, byte[] contents) {
        this.start = start;
        this.type = type;
        this.derContents = contents;
        this.length = contents.length;
    }

    public ASN1Item(int length, int start, ASN1TagType type, byte[] contents) {
        this.length = length;
        this.start = start;
        this.type = type;
        this.derContents = contents;
    }

    public ASN1TagType type() {
        return type;
    }

    public byte[] contents() {
        return derContents;
    }

    @Override
    public String toString() {
        return "{ type=\"" + type.name() + "\", contents=\"" + Hex.toHexString(derContents) + "\"}" ;
    }
}
