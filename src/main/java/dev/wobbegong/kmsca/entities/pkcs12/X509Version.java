package dev.wobbegong.kmsca.entities.pkcs12;

public enum X509Version {
    V1(1), V2(2), V3(3);

    public final int versionNumber;

    X509Version(int versionNumber) {
        this.versionNumber = versionNumber;
    }

    public static X509Version fromASN1Number(int number) {
        return switch (number) {
            case 0 -> V1;
            case 1 -> V2;
            case 2 -> V3;
            default -> throw new IllegalArgumentException("Unknown X509 version: " + number);
        };
    }
}
