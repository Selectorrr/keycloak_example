package io.selectorrr.kc;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class AccountEndpoint {

    private final SecurityService securityService;

    @GetMapping("/api/me")
    public UserDto me() {
        return securityService.getUser();
    }

    @GetMapping("/api/logout")
    public void logout(@RequestParam(required = false) String redirectUrl) {
        securityService.logout(redirectUrl);
    }
}
