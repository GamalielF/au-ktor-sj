package ec.fin.sanjose.authenticator.service;

import ec.fin.sanjose.authenticator.exception.UserDisabledException;
import ec.fin.sanjose.authenticator.exception.UserNotFoundException;
import ec.fin.sanjose.authenticator.model.User;
import ec.fin.sanjose.authenticator.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    public User getByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new UserNotFoundException("Usuario '" + username + "' no encontrado"));

        if (Boolean.FALSE.equals(user.getEnabled())) {
            throw new UserDisabledException("El usuario se encuentra inhabilitado en el IdP");
        }

        return user;
    }

    @Transactional
    public User syncAndGetUser(String username, String initialTotpSecret, boolean isAdEnabled) {
        User user = userRepository.findByUsername(username).orElse(null);

        if (user == null) {
            if (!isAdEnabled) {
                log.warn("Attempt to login with disabled AD user: {}", username);
                throw new UserDisabledException("El usuario se encuentra inhabilitado en el IdP");
            }
            log.info("Provisioning new local user profile from AD for: {}", username);
            user = User.builder()
                    .username(username)
                    .secret(initialTotpSecret)
                    .mfaEnabled(false)
                    .enabled(true)
                    .build();
            return userRepository.save(user);
        }

        if (user.getEnabled() != isAdEnabled) {
            log.info("Updating user {} status from AD: enabled={}", username, isAdEnabled);
            user.setEnabled(isAdEnabled);
            user.setUpdatedAt(LocalDateTime.now());
            user = userRepository.save(user);
        }

        if (!isAdEnabled || Boolean.FALSE.equals(user.getEnabled())) {
            log.warn("Blocked login for disabled user: {}", username);
            throw new UserDisabledException("El usuario se encuentra inhabilitado en el IdP");
        }

        return user;
    }

    @Transactional
    public void activateMfa(User user) {
        if (Boolean.FALSE.equals(user.getMfaEnabled())) {
            user.setMfaEnabled(true);
            user.setUpdatedAt(LocalDateTime.now());
            userRepository.save(user);
            log.info("MFA activated for user: {}", user.getUsername());
        }
    }

    @Transactional
    public void resetMfa(String username, String newSecret) {
        User user = getByUsername(username);
        user.setSecret(newSecret);
        user.setMfaEnabled(false);
        user.setUpdatedAt(LocalDateTime.now());
        userRepository.save(user);
        log.info("MFA reset for user: {}", username);
    }
}
