/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.keycloak.adapters;

import org.jboss.logging.Logger;
import org.keycloak.KeycloakPrincipal;
import org.keycloak.TokenVerifier;
import org.keycloak.adapters.rotation.AdapterTokenVerifier;
import org.keycloak.adapters.spi.HttpFacade;
import org.keycloak.common.VerificationException;
import org.keycloak.common.util.KeycloakUriBuilder;
import org.keycloak.constants.AdapterConstants;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.JWSInputException;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.IDToken;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * @author <a href="mailto:mposolda@redhat.com">Marek Posolda</a>
 */
public class CookieTokenStore_ {

    private static final Logger log = Logger.getLogger(CookieTokenStore_.class);
    private static final String DELIM = "___";

    public static void setTokenCookie(KeycloakDeployment deployment, HttpFacade facade, RefreshableKeycloakSecurityContext session) {
        log.debugf("Set new %s cookie now", AdapterConstants.KEYCLOAK_ADAPTER_STATE_COOKIE);
        String accessToken = session.getTokenString();
        String idToken = session.getIdTokenString();
        String refreshToken = session.getRefreshToken();

        Map<String, String> cookies = new HashMap<>();
        cookies.put("accessToken", accessToken);
        cookies.put("idToken", idToken);
        cookies.put("refreshToken", refreshToken);

        String cookiePath = getCookiePath(deployment, facade);

        cookies.forEach((cookieName, cookieValue) -> {
            boolean required = deployment.getSslRequired().isRequired(facade.getRequest().getRemoteAddr());
            facade.getResponse().setCookie(cookieName, cookieValue, cookiePath, null, -1, required, true);
        });

    }

    public static KeycloakPrincipal<RefreshableKeycloakSecurityContext> getPrincipalFromCookie(KeycloakDeployment deployment, HttpFacade facade, AdapterTokenStore tokenStore) {
        OIDCHttpFacade.Cookie accessTokenCookie = facade.getRequest().getCookie("accessToken");
        OIDCHttpFacade.Cookie idTokenCookie = facade.getRequest().getCookie("idToken");
        OIDCHttpFacade.Cookie refreshTokenCookie = facade.getRequest().getCookie("refreshToken");

        List<String> cookies = Stream.of(accessTokenCookie, idTokenCookie, refreshTokenCookie)
                .filter(Objects::nonNull)
                .map(OIDCHttpFacade.Cookie::getValue)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());

        if (cookies.isEmpty()) {
            log.debug("Not found adapter state cookie in current request");
            return null;
        }

        if (cookies.size() != 3) {
            log.warnf("Invalid format of %s cookie. Count of tokens: %s, expected 3", AdapterConstants.KEYCLOAK_ADAPTER_STATE_COOKIE, cookies.size());
            return null;
        }

        String accessTokenString = cookies.get(0);
        String idTokenString = cookies.get(1);
        String refreshTokenString = cookies.get(2);

        try {
            // Skip check if token is active now. It's supposed to be done later by the caller
            TokenVerifier<AccessToken> tokenVerifier = AdapterTokenVerifier.createVerifier(accessTokenString, deployment, true, AccessToken.class)
                    .checkActive(false)
                    .verify();
            AccessToken accessToken = tokenVerifier.getToken();

            IDToken idToken;
            if (idTokenString != null && idTokenString.length() > 0) {
                try {
                    JWSInput input = new JWSInput(idTokenString);
                    idToken = input.readJsonContent(IDToken.class);
                } catch (JWSInputException e) {
                    throw new VerificationException(e);
                }
            } else {
                idToken = null;
            }

            log.debug("Token Verification succeeded!");
            RefreshableKeycloakSecurityContext secContext = new RefreshableKeycloakSecurityContext(deployment, tokenStore, accessTokenString, accessToken, idTokenString, idToken, refreshTokenString);
            return new KeycloakPrincipal<>(AdapterUtils.getPrincipalName(deployment, accessToken), secContext);
        } catch (VerificationException ve) {
            log.warn("Failed verify token", ve);
            return null;
        }
    }

    public static void removeCookie(KeycloakDeployment deployment, HttpFacade facade) {
        String cookiePath = getCookiePath(deployment, facade);
        facade.getResponse().resetCookie(AdapterConstants.KEYCLOAK_ADAPTER_STATE_COOKIE, cookiePath);
    }

    static String getCookiePath(KeycloakDeployment deployment, HttpFacade facade) {
        String path = deployment.getAdapterStateCookiePath() == null ? "" : deployment.getAdapterStateCookiePath().trim();
        if (path.startsWith("/")) {
            return path;
        }
        String contextPath = getContextPath(facade);
        StringBuilder cookiePath = new StringBuilder(contextPath);
        if (!contextPath.endsWith("/") && !path.isEmpty()) {
            cookiePath.append("/");
        }
        return cookiePath.append(path).toString();
    }

    static String getContextPath(HttpFacade facade) {
        String uri = facade.getRequest().getURI();
        String path = KeycloakUriBuilder.fromUri(uri).getPath();
        if (path == null || path.isEmpty()) {
            return "/";
        }
        int index = path.indexOf("/", 1);
        return index == -1 ? path : path.substring(0, index);
    }
}
