package io.selectorrr.kc;

import lombok.Value;

import java.util.Set;

@Value
public class UserDto {
    String username;
    Set<String> roles;
}
