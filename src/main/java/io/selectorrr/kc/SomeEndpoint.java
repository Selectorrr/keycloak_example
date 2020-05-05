package io.selectorrr.kc;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class SomeEndpoint {
    @GetMapping("/test")
    public String ping(Principal principal) {
        return principal.toString();
    }
}
