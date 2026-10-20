package ec.fin.sanjose.authenticator.controller;

import ec.fin.sanjose.authenticator.dto.*;
import ec.fin.sanjose.authenticator.service.AuthService;
import ec.fin.sanjose.authenticator.util.CookieUtil;
import ec.fin.sanjose.authenticator.util.JwtUtil;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final JwtUtil jwtUtil;

    @PostMapping("/login")
    public ResponseEntity<LoginResponseDTO> login(
            @Valid @RequestBody LoginRequestDTO request,
            HttpServletResponse response
    ) {
        LoginResponseDTO loginResponse = authService.authenticate(request);

        if (loginResponse.getTokenType() != null) {
            String refreshToken = authService.createRefreshToken(request.getUsername());
            CookieUtil.addRefreshToken(response, refreshToken);
        }

        return ResponseEntity.ok(loginResponse);
    }

    @PostMapping("/mfa/verify")
    public ResponseEntity<LoginResponseDTO> verifyMfa(
            @Valid @RequestBody MfaVerifyRequestDTO request,
            HttpServletResponse response
    ) {
        LoginResponseDTO loginResponse = authService.verifyMfa(request);

        if (loginResponse.getAccessToken() != null) {
            String username = jwtUtil.extractUsername(request.getAccessToken());
            String refreshToken = authService.createRefreshToken(username);
            CookieUtil.addRefreshToken(response, refreshToken);
        }

        return ResponseEntity.ok(loginResponse);
    }

    @PostMapping("/refresh")
    public ResponseEntity<LoginResponseDTO> refreshToken(
            @CookieValue(value = "refresh_token", required = false) String refreshToken,
            HttpServletResponse response
    ) {
        LoginResponseDTO loginResponse = authService.refreshAccessToken(refreshToken);
        String username = jwtUtil.extractUsername(loginResponse.getAccessToken());
        String newRefreshToken = authService.createRefreshToken(username);
        CookieUtil.addRefreshToken(response, newRefreshToken);
        return ResponseEntity.ok(loginResponse);
    }
    
    @Profile("dev")
    @PostMapping("/admin/reset-totp")
    public ResponseEntity<Map<String, String>> resetTotp(@Valid @RequestBody ResetTotpRequestDTO request) {
        authService.resetTotp(request.getUsername());
        return ResponseEntity.ok(Map.of(
                "username", request.getUsername(),
                "message", "TOTP reset successfully"
        ));
    }
}
