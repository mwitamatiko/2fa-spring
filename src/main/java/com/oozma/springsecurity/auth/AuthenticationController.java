package com.oozma.springsecurity.auth;

import com.oozma.springsecurity.config.LogoutService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.log4j.Logger;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthenticationController {
    private final AuthenticationService service;
    private final LogoutService logoutService;
    private static final Logger log = Logger.getLogger(AuthenticationController.class);

    @PostMapping("/register")
    public ResponseEntity<?> register(
            @RequestBody RegisterRequest request
    ){
        var response = service.register(request);
        log.info("register request "+response);

        if(request.isMfaEnabled()){
            log.info("register request - 2fa enabled "+response);
            return ResponseEntity.ok(response);

        }

        return ResponseEntity.accepted().build();
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ){
        return ResponseEntity.ok(service.authenticate(request));
    }

    @PostMapping("/refresh-token")
    public void refresh(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        service.refreshToken(request,response);
    }

    @PostMapping("/verify")
    public ResponseEntity<?> verifyCode(
        @RequestBody VerificationRequest verificationRequest
    ){

        log.info("clicked verify endpoint");
        AuthenticationResponse response = null;
        try{
            response = service.verifyCode(verificationRequest);
            log.info("data for verification request "+response);

        }catch (Exception e){
            log.error("Exception: " + e.getLocalizedMessage());
            // Handle exception gracefully, e.g., return an error response
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
        return ResponseEntity.ok(response);
    }


//    @PostMapping("/logout")
//    public ResponseEntity<String> logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//        logoutService.logout(request, response, authentication);
//        return ResponseEntity.ok("Logout successful");
//    }

}
