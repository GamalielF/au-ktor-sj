package ec.fin.sanjose.authenticator.exception;

public class InvalidTotpException extends RuntimeException {

    public InvalidTotpException() {
        super("Código TOTP inválido o expirado");
    }

    public InvalidTotpException(String message) {
        super(message);
    }
}
