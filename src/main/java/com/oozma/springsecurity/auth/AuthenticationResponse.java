package com.oozma.springsecurity.auth;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.oozma.springsecurity.model.Role;
import lombok.*;

@Data
@ToString
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class AuthenticationResponse {
//    @JsonProperty("access_token")
    private String accessToken;

//    @JsonProperty("refresh_token")
    private String refreshToken;

//    @JsonProperty("mfa_enabled")
    private boolean mfaEnabled;

//    @JsonProperty("secret_image_uri")
    private String secretImageUri;
    private Role role;

}
