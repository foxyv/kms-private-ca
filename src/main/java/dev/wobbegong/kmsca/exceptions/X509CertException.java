package dev.wobbegong.kmsca.exceptions;


@SuppressWarnings("unused")
public class X509CertException extends Exception{
    public X509CertException() {
    }

    public X509CertException(String message) {
        super(message);
    }

    public X509CertException(String message, Throwable cause) {
        super(message, cause);
    }

    public X509CertException(Throwable cause) {
        super(cause);
    }

    public X509CertException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace) {
        super(message, cause, enableSuppression, writableStackTrace);
    }
}
