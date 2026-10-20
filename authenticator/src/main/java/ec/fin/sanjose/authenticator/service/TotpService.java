package ec.fin.sanjose.authenticator.service;

import com.warrenstrange.googleauth.GoogleAuthenticator;
import com.warrenstrange.googleauth.GoogleAuthenticatorConfig;
import com.warrenstrange.googleauth.GoogleAuthenticatorKey;
import ec.fin.sanjose.authenticator.exception.InvalidTotpException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

@Service
public class TotpService {

    private final GoogleAuthenticator gAuth = new GoogleAuthenticator(
            new GoogleAuthenticatorConfig
                    .GoogleAuthenticatorConfigBuilder()
                    .setWindowSize(1)
                    .build()
    );

    @Value("${spring.org.name}")
    private String appName;

    public String generateSecret() {
        GoogleAuthenticatorKey key = gAuth.createCredentials();
        return key.getKey();
    }

    public String generateOtpauthUrl(String secret, String username) {
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s", appName, username, secret, appName);
    }

    public void verifyCode(String secret, String code) {
        if (code == null || code.isBlank()) {
            throw new InvalidTotpException("El código TOTP es requerido");
        }
        try {
            int numericCode = Integer.parseInt(code.trim());
            if (!gAuth.authorize(secret, numericCode)) {
                throw new InvalidTotpException("Código TOTP inválido o expirado");
            }
        } catch (NumberFormatException e) {
            throw new InvalidTotpException("Formato de código TOTP inválido");
        }
    }
}
