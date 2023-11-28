package dev.wobbegong.kmsca.entities.asn1.types;

import dev.wobbegong.kmsca.entities.asn1.ASN1TagType;

import java.util.Set;
import java.util.stream.Collectors;

public class ASN1Set extends ASN1Item {

    public final Set<ASN1Item> asn1ItemList;

    public ASN1Set(int length, int start, Set<ASN1Item> asn1ItemList, byte[] raw) {
        super(length, start, ASN1TagType.SET, raw);
        this.asn1ItemList = Set.copyOf(asn1ItemList);
    }

    @Override
    public String toString() {
        return "[" +
                asn1ItemList.stream().map(Object::toString).collect(Collectors.joining(", ")) +
                "]";

    }
}
