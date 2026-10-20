package ec.fin.sanjose.authenticator.service;

import ec.fin.sanjose.authenticator.dto.AdAuthResponseDTO;
import ec.fin.sanjose.authenticator.dto.LoginRequestDTO;
import ec.fin.sanjose.authenticator.exception.InstitutionalServiceException;
import ec.fin.sanjose.authenticator.exception.InvalidCredentialsException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.time.Duration;

@Slf4j
@Service
public class AdAuthService {

    private final RestClient restClient;
    private final String authUrl;

    public AdAuthService(
            @Value("${IdP.auth.url}") String authUrl
    ) {
        this.authUrl = authUrl;

        SimpleClientHttpRequestFactory requestFactory = new SimpleClientHttpRequestFactory();
        requestFactory.setConnectTimeout(Duration.ofSeconds(10));
        requestFactory.setReadTimeout(Duration.ofSeconds(15));

        this.restClient = RestClient.builder()
                .requestFactory(requestFactory)
                .build();
    }

    public AdAuthResponseDTO authenticate(String username, String password) {
        try {
            log.info("Authenticating user '{}' with AD...", username);

            AdAuthResponseDTO response = restClient.post()
                    .uri(authUrl)
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(new LoginRequestDTO(username, password))
                    .retrieve()
                    .onStatus(HttpStatusCode::is4xxClientError, (req, resp) -> {
                        log.warn("AD authentication failed for user '{}' with status {}", username, resp.getStatusCode());
                        throw new InvalidCredentialsException("Usuario o contraseña incorrectos");
                    })
                    .onStatus(HttpStatusCode::is5xxServerError, (req, resp) -> {
                        log.error("AD authentication server error: status {}", resp.getStatusCode());
                        throw new InstitutionalServiceException("El IdP no está disponible");
                    })
                    .body(AdAuthResponseDTO.class);

            if (response == null) {
                throw new InstitutionalServiceException("Respuesta vacía del IdP");
            }

            return response;
        } catch (InvalidCredentialsException | InstitutionalServiceException e) {
            throw e;
        } catch (Exception e) {
            log.error("Communication error with AD service: {}", e.getMessage(), e);
            throw new InstitutionalServiceException("El IdP no está disponible", e);
        }
    }
}
