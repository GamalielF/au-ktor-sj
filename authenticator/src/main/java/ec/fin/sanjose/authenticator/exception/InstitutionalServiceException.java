package ec.fin.sanjose.authenticator.exception;

public class InstitutionalServiceException extends RuntimeException {

    public InstitutionalServiceException() {
        super("El IdP no está disponible");
    }

    public InstitutionalServiceException(String message) {
        super(message);
    }

    public InstitutionalServiceException(String message, Throwable cause) {
        super(message, cause);
    }
}
