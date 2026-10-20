package ec.fin.sanjose.authenticator.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class MfaVerifyRequestDTO {

    @NotBlank(message = "El access token temporal es requerido")
    private String accessToken;

    @NotBlank(message = "El código TOTP es requerido")
    @Pattern(regexp = "^\\d{6}$", message = "El código debe ser de 6 dígitos")
    private String totpCode;
}
