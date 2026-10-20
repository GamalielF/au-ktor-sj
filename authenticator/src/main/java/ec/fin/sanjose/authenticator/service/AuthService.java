package ec.fin.sanjose.authenticator.service;

import ec.fin.sanjose.authenticator.dto.AdAuthResponseDTO;
import ec.fin.sanjose.authenticator.dto.LoginRequestDTO;
import ec.fin.sanjose.authenticator.dto.LoginResponseDTO;
import ec.fin.sanjose.authenticator.dto.MfaVerifyRequestDTO;
import ec.fin.sanjose.authenticator.exception.InvalidCredentialsException;
import ec.fin.sanjose.authenticator.model.User;
import ec.fin.sanjose.authenticator.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final AdAuthService adAuthService;
    private final UserService userService;
    private final TotpService totpService;
    private final JwtUtil jwtUtil;

    @Transactional
    public LoginResponseDTO authenticate(LoginRequestDTO request) {
        AdAuthResponseDTO adResponse = adAuthService.authenticate(request.getUsername(), request.getPassword());
        boolean isAdEnabled = Boolean.TRUE.equals(adResponse.getUserInfo().getEnabled());

        String newSecret = totpService.generateSecret();
        User user = userService.syncAndGetUser(request.getUsername(), newSecret, isAdEnabled);

        String tempToken = jwtUtil.generateMfaToken(user.getId(), user.getUsername());

        if (Boolean.FALSE.equals(user.getMfaEnabled())) {
            return LoginResponseDTO.builder()
                    .accessToken(tempToken)
                    .otpauthUrl(totpService.generateOtpauthUrl(user.getSecret(), user.getUsername()))
                    .build();
        }

        return LoginResponseDTO.builder()
                .accessToken(tempToken)
                .build();
    }

    @Transactional
    public LoginResponseDTO verifyMfa(MfaVerifyRequestDTO request) {
        if (!jwtUtil.validateMfaToken(request.getAccessToken())) {
            throw new InvalidCredentialsException("Token inválido o expirado");
        }

        String username = jwtUtil.extractUsername(request.getAccessToken());
        User user = userService.getByUsername(username);

        totpService.verifyCode(user.getSecret(), request.getTotpCode());

        if (Boolean.FALSE.equals(user.getMfaEnabled())) {
            userService.activateMfa(user);
        }

        log.info("User authenticated successfully with 2FA: {}", user.getUsername());

        return LoginResponseDTO.builder()
                .accessToken(jwtUtil.generateToken(user.getId(), user.getUsername()))
                .tokenType("Bearer")
                .expiresIn(86400L)
                .build();
    }

    public String createRefreshToken(String username) {
        User user = userService.getByUsername(username);
        return jwtUtil.generateRefreshToken(user.getId(), user.getUsername());
    }

    public LoginResponseDTO refreshAccessToken(String refreshToken) {
        if (refreshToken == null || !jwtUtil.validateToken(refreshToken)) {
            throw new InvalidCredentialsException("Invalid refresh token");
        }

        String username = jwtUtil.extractUsername(refreshToken);
        User user = userService.getByUsername(username);

        return LoginResponseDTO.builder()
                .accessToken(jwtUtil.generateToken(user.getId(), user.getUsername()))
                .tokenType("Bearer")
                .expiresIn(86400L)
                .build();
    }

    @Transactional
    public void resetTotp(String username) {
        String newSecret = totpService.generateSecret();
        userService.resetMfa(username, newSecret);
        log.info("MFA reset for user: {}", username);
    }
}
