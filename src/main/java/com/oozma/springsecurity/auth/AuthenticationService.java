package com.oozma.springsecurity.auth;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.oozma.springsecurity.config.JwtService;
import com.oozma.springsecurity.model.Role;
import com.oozma.springsecurity.model.Token;
import com.oozma.springsecurity.model.TokenType;
import com.oozma.springsecurity.model.User;
import com.oozma.springsecurity.repository.TokenRepository;
import com.oozma.springsecurity.repository.UserRepository;
import com.oozma.springsecurity.tfa.TwoFactorAuthenticationService;
import jakarta.persistence.EntityNotFoundException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.log4j.Logger;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final TwoFactorAuthenticationService tfaService;
    private static final Logger log = Logger.getLogger(AuthenticationService.class);


    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .mfaEnabled(request.isMfaEnabled())
                .build();

        log.info("user to be registered "+user);

        // if mfa enabled, generate secret
        if(request.isMfaEnabled()){
            user.setSecret(tfaService.generateNewSecret());
            log.info("user enabled mfa ");
        }

        var savedUser = repository.save(user);
        log.info("user saved"+savedUser);

        // return authentication response that contains token
        var jwtToken = jwtService.generateToken(user);
        //refresh token
        var refreshToken = jwtService.generateRefreshToken(user);

        //persist the generated token into db
        savedUserToken(savedUser, jwtToken);

        AuthenticationResponse response = AuthenticationResponse.builder()
                .secretImageUri(tfaService.generateQRCodeImageUri(user.getSecret()))
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .mfaEnabled(user.isMfaEnabled())
                .build();

        log.info("authentication response on registering user "+response);

        return response;

    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        //password and user are correct
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        var user = repository.findByEmail(request.getEmail())
                .orElseThrow();

        if(user.isMfaEnabled()){
            return AuthenticationResponse.builder()
                    .accessToken("")
                    .refreshToken("")
                    .mfaEnabled(true)
                    .role(user.getRole())
                    .build();
        }
        // return authentication response that contains token
        var jwtToken = jwtService.generateToken(user);

        // refresh token
        var refreshToken = jwtService.generateRefreshToken(user);

        //revoke all tokens
        revokeAllUserTokens(user);
        //persist the generated user token into db
        savedUserToken(user,jwtToken);

        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .mfaEnabled(false)
                .role(user.getRole())
                .build();
    }

    private void savedUserToken(User user, String jwtToken) {
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();

        tokenRepository.save(token);
    }

    //method to revoke all user tokens to have only one valid token
    // during authentication
    private void revokeAllUserTokens(User user){
       var validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());

       if(validUserTokens.isEmpty()){
           return;
       }
       validUserTokens.forEach(t ->{
           t.setExpired(true);
           t.setRevoked(true);
       });
       tokenRepository.saveAll(validUserTokens);
    }

    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {

        //extract auth header from our request
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;

        if(authHeader==null || !authHeader.startsWith("Bearer ")){
            //do not continue with the execution of the rest
            return;
        }

        //extract token from the auth header
        refreshToken = authHeader.substring(7);

        //extract user email from jwt token
        userEmail = jwtService.extractUsername(refreshToken);

        if(userEmail !=null){
            var user = this.repository.findByEmail(userEmail)
                    .orElseThrow();

            if(jwtService.isTokenValid(refreshToken,user) ){
               var accessToken = jwtService.generateToken(user);
                //revoke all tokens
                revokeAllUserTokens(user);
                //persist the generated user token into db
                savedUserToken(user,accessToken);

               var authResponse = AuthenticationResponse.builder()
                       .accessToken(accessToken)
                       .refreshToken(refreshToken)
                       .mfaEnabled(false)
                       .build();

               new ObjectMapper().writeValue(response.getOutputStream(),authResponse);
            }
        }


    }

    public AuthenticationResponse verifyCode(VerificationRequest verificationRequest) {
        User user = repository.findByEmail(verificationRequest.getEmail())
                .orElseThrow(() -> new EntityNotFoundException(
                        String.format("No user found with %s",verificationRequest.getEmail())
                ));
        log.info("user email found on verification request "+ user);

        if(tfaService.isOtpNotValid(user.getSecret(), verificationRequest.getCode())){
            throw new BadCredentialsException("Code is not correct");
        }

        var jwtToken = jwtService.generateToken(user);
        log.info("jwtToken generated on verification request "+jwtToken);

        AuthenticationResponse response =  AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .mfaEnabled(user.isMfaEnabled())
                .build();

        log.info("authentication response on verification request "+response);

        return response;
    }

}
