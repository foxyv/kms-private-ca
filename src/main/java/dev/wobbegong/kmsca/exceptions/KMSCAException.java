package dev.wobbegong.kmsca.exceptions;

/**
 * A generic exception for any problems with KMSPrivateCA during runtime. Usually stuff like, the service is being
 * shut down or, we ran out of memory.
 */
@SuppressWarnings("unused")
public class KMSCAException extends RuntimeException {
    public KMSCAException() {
        super();
    }

    public KMSCAException(String message) {
        super(message);
    }

    public KMSCAException(String message, Throwable cause) {
        super(message, cause);
    }

    public KMSCAException(Throwable cause) {
        super(cause);
    }

    public KMSCAException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
