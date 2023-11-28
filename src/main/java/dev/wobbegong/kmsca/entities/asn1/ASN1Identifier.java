package dev.wobbegong.kmsca.entities.asn1;

public record ASN1Identifier(TagClass tagClass, boolean isPrimitive, ASN1TagType tagType) {

    public enum TagClass {
        /**
         * The type is native to ASN.1
         */
        Universal(0),
        /**
         * The type is only valid for one specific application
         */
        Application(1),
        /**
         * Meaning of this type depends on the context (such as within a sequence, set or choice)
         */
        ContextSpecific(2),

        /**
         * Defined in private specifications
         */
        Private(3),

        EOF(255);

        public final int value;

        TagClass(int value) {
            this.value = value;
        }

        public static TagClass forValue(int value) {
            return switch (value) {
                case 0 -> Universal;
                case 1 -> Application;
                case 2 -> ContextSpecific;
                case 3 -> Private;
                default -> throw new IllegalArgumentException("2-bit Tag Class must be between 0 and 3. Actual: " + value);
            };
        }
    }

    @Override
    public String toString() {
        return "{tagClass=\"" + tagClass.name() + "\", isPrimitive=" + isPrimitive + ", tagType=\"" + tagType + "\"}";
    }
}
