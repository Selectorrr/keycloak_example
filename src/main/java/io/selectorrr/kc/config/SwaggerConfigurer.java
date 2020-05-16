package io.selectorrr.kc.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.AuthorizationCodeGrantBuilder;
import springfox.documentation.builders.OAuthBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.service.*;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spi.service.contexts.SecurityContext;
import springfox.documentation.spring.web.plugins.Docket;
import springfox.documentation.swagger.web.SecurityConfiguration;
import springfox.documentation.swagger.web.SecurityConfigurationBuilder;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

import java.util.Arrays;
import java.util.Collections;

import static springfox.documentation.builders.PathSelectors.regex;


/*
 * Setting up Swagger for spring boot
 * https://www.baeldung.com/swagger-2-documentation-for-spring-rest-api
 */
@Configuration
@EnableSwagger2
public class SwaggerConfigurer {


    @Value("${keycloak.auth-server-url}")
    private String AUTH_SERVER;


    //    @Value("${keycloak.credentials.secret}")
    private String CLIENT_SECRET = null;


    @Value("${keycloak.resource}")
    private String CLIENT_ID;


    @Value("${keycloak.realm}")
    private String REALM;


    private static final String OAUTH_NAME = "spring_oauth";
    private static final String ALLOWED_PATHS = "/api/.*";
    private static final String GROUP_NAME = "pa";


    @Bean
    public Docket taskApi() {
        return new Docket(DocumentationType.SWAGGER_2)
                .useDefaultResponseMessages(true)
                .select()
                .paths(regex(ALLOWED_PATHS))
                .build()
                .securitySchemes(Arrays.asList(securityScheme()))
                .securityContexts(Arrays.asList(securityContext()));
    }


    @Bean
    public SecurityConfiguration security() {
        return SecurityConfigurationBuilder.builder()
                .realm(REALM)
                .clientId(CLIENT_ID)
                .clientSecret(CLIENT_SECRET)
//                .appName(GROUP_NAME)
                .scopeSeparator(" ")
                .build();
    }


    private SecurityScheme securityScheme() {
        GrantType grantType =
                new AuthorizationCodeGrantBuilder()
                        .tokenEndpoint(new TokenEndpoint(AUTH_SERVER + "/realms/" + REALM + "/protocol/openid-connect/token", CLIENT_ID))
                        .tokenRequestEndpoint(
                                new TokenRequestEndpoint(AUTH_SERVER + "/realms/" + REALM + "/protocol/openid-connect/auth", CLIENT_ID, CLIENT_SECRET))
                        .build();

        return new OAuthBuilder()
                .name(OAUTH_NAME)
                .grantTypes(Collections.singletonList(grantType))
                .scopes(Arrays.asList(scopes()))
                .build();
    }


    private AuthorizationScope[] scopes() {
        return new AuthorizationScope[]{
                new AuthorizationScope("openid", null)
        };
    }


    private SecurityContext securityContext() {
        return SecurityContext.builder()
                .securityReferences(Collections.singletonList(new SecurityReference(OAUTH_NAME, scopes())))
                .forPaths(PathSelectors.regex(ALLOWED_PATHS))
                .build();
    }
}
