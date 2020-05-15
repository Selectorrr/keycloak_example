package io.selectorrr.kc.rest;

import io.selectorrr.kc.service.SecurityService;
import io.selectorrr.kc.service.dto.UserDto;
import lombok.RequiredArgsConstructor;
import org.keycloak.adapters.springboot.KeycloakSpringBootProperties;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AccountEndpoint {

    private final SecurityService securityService;

    private final KeycloakSpringBootProperties keycloakSpringBootProperties;

    @GetMapping("/api/me")
    @PreAuthorize("hasAuthority('USER')")
    public UserDto me() {
        return securityService.getUser();
    }

    @GetMapping("/keycloak.json")
    public KeycloakSpringBootProperties keycloakJson() {
        return keycloakSpringBootProperties;
    }

    @GetMapping("/api/logout")
    public void logout(@RequestParam(required = false) String redirectUrl) {
        securityService.logout(redirectUrl);
    }
}
