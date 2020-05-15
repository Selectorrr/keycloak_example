package io.selectorrr.kc;

import lombok.RequiredArgsConstructor;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.keycloak.representations.AccessToken;
import org.springframework.stereotype.Service;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
public class SecurityService {

    public static final String ANONYMOUS = "anonymous";
    private final HttpServletRequest request;
    private final HttpServletResponse response;

    private Optional<AccessToken> getAccessToken() {
        return Optional.ofNullable(request)
                .map(HttpServletRequest::getUserPrincipal)
                .map(KeycloakAuthenticationToken.class::cast)
                .map(KeycloakAuthenticationToken::getCredentials)
                .map(KeycloakSecurityContext.class::cast)
                .map(KeycloakSecurityContext::getToken);
    }

    public String getUsername() {
        return Optional.ofNullable(request)
                .map(HttpServletRequest::getUserPrincipal)
                .map(KeycloakAuthenticationToken.class::cast)
                .map(KeycloakAuthenticationToken::getName)
                .orElse(ANONYMOUS);
    }

    public void logout(String redirectUrl) {
        try {
            redirectUrl = Optional.ofNullable(redirectUrl).orElse(getHost());
            request.logout();
            response.sendRedirect(redirectUrl);
        } catch (ServletException | IOException e) {
            throw new RuntimeException(e);
        }
    }

    private String getHost() {
        StringBuffer url = request.getRequestURL();
        String uri = request.getRequestURI();
        int idx = (((uri != null) && (uri.length() > 0)) ? url.indexOf(uri) : url.length());
        return url.substring(0, idx);
    }

    public UserDto getUser() {
        String username = getUsername();
        Set<String> roles = getRoles();
        return new UserDto(username, roles);
    }

    private Set<String> getRoles() {
        return getAccessToken()
                .map(AccessToken::getRealmAccess)
                .map(AccessToken.Access::getRoles)
                .orElse(new HashSet<>());
    }
}
