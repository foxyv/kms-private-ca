package dev.wobbegong.kmsca.exceptions;

/**
 * An exception that is thrown when a PEM file cannot be parsed.
 */
public class PEMFormatException extends Exception {
    public PEMFormatException() {
    }

    public PEMFormatException(String message) {
        super(message);
    }

    public PEMFormatException(String message, Throwable cause) {
        super(message, cause);
    }

    public PEMFormatException(Throwable cause) {
        super(cause);
    }

    public PEMFormatException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
