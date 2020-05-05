package io.selectorrr.kc;

import lombok.RequiredArgsConstructor;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.KeycloakSecurityContext;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AddressClaimSet;
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
                .map(KeycloakPrincipal.class::cast)
                .map(KeycloakPrincipal::getKeycloakSecurityContext)
                .map(KeycloakSecurityContext.class::cast)
                .map(KeycloakSecurityContext::getToken);
    }

    public String getUsername() {
        return Optional.ofNullable(request)
                .map(HttpServletRequest::getUserPrincipal)
                .map(KeycloakPrincipal.class::cast)
                .map(KeycloakPrincipal::getName)
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
        UserDto.UserDtoBuilder builder = UserDto.builder()
                .username(getUsername())
                .roles(getRoles());

        Optional<AccessToken> accessToken = getAccessToken();
        if (accessToken.isPresent()) {
            AccessToken token = accessToken.get();
            builder
                    .name(token.getName())
                    .givenName(token.getGivenName())
                    .familyName(token.getFamilyName())
                    .middleName(token.getMiddleName())
                    .nickName(token.getNickName())
                    .preferredUsername(token.getPreferredUsername())
                    .profile(token.getProfile())
                    .picture(token.getPicture())
                    .website(token.getWebsite())
                    .email(token.getEmail())
                    .emailVerified(token.getEmailVerified())
                    .gender(token.getGender())
                    .birthdate(token.getBirthdate())
                    .zoneinfo(token.getZoneinfo())
                    .locale(token.getLocale())
                    .phoneNumber(token.getPhoneNumber())
                    .phoneNumberVerified(token.getPhoneNumberVerified())
                    .address(toAddress(token.getAddress()).orElse(null));

        }
        return builder.build();
    }

    private Optional<UserAddress> toAddress(AddressClaimSet address) {
        return Optional.ofNullable(address)
                .map(addressClaimSet -> UserAddress.builder()
                        .formattedAddress(addressClaimSet.getFormattedAddress())
                        .streetAddress(addressClaimSet.getStreetAddress())
                        .locality(addressClaimSet.getLocality())
                        .region(addressClaimSet.getRegion())
                        .postalCode(addressClaimSet.getPostalCode())
                        .country(addressClaimSet.getCountry())
                        .build());
    }

    private Set<String> getRoles() {
        return getAccessToken()
                .map(AccessToken::getRealmAccess)
                .map(AccessToken.Access::getRoles)
                .orElse(new HashSet<>());
    }
}
