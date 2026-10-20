package ec.fin.sanjose.authenticator.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ResetTotpRequestDTO {

    @NotBlank(message = "Username is required")
    private String username;
}
