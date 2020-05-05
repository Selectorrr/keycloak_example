package io.selectorrr.kc;

import lombok.Builder;
import lombok.Value;

@Value
@Builder
public class UserAddress {
    String formattedAddress;
    String streetAddress;
    String locality;
    String region;
    String postalCode;
    String country;
}
