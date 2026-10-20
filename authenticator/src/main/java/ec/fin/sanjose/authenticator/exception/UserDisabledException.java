package ec.fin.sanjose.authenticator.exception;

public class UserDisabledException extends RuntimeException {

    public UserDisabledException() {
        super("El usuario se encuentra inhabilitado");
    }

    public UserDisabledException(String message) {
        super(message);
    }
}
