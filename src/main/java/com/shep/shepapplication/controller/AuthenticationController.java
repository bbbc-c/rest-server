package com.shep.shepapplication.controller;

import com.shep.shepapplication.dto.RegistrationDto;
import com.shep.shepapplication.exceptions.user.EmailIsBusyException;
import com.shep.shepapplication.exceptions.user.LoginIsBusyException;
import com.shep.shepapplication.security.jwt.JwtRequest;
import com.shep.shepapplication.security.jwt.JwtResponse;
import com.shep.shepapplication.security.jwt.RefreshJwtRequest;
import com.shep.shepapplication.service.AuthService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.security.auth.message.AuthException;
import javax.validation.Valid;

@RestController
@RequestMapping(value = "auth")
@Slf4j
public class AuthenticationController {
    private final AuthService authService;

    public AuthenticationController(AuthService authService) {
        this.authService = authService;
    }
    @PostMapping("login")
    public ResponseEntity<JwtResponse> login(@RequestBody JwtRequest authRequest) throws AuthException {
        final JwtResponse token = authService.login(authRequest);
        return ResponseEntity.ok(token);
    }
    @PostMapping("token")
    public ResponseEntity<JwtResponse> getNewAccessToken(@RequestBody RefreshJwtRequest request) throws AuthException {
        final JwtResponse token = authService.getAccessToken(request.getRefreshToken());
        return ResponseEntity.ok(token);
    }
    @PostMapping("refresh")
    public ResponseEntity<JwtResponse> getNewRefreshToken(@RequestBody RefreshJwtRequest request) throws AuthException {
        final JwtResponse token = authService.refresh(request.getRefreshToken());
        return ResponseEntity.ok(token);
    }
    @PostMapping("registration")
    public ResponseEntity<String> registration(@Valid @RequestBody RegistrationDto registrationDto) throws LoginIsBusyException, EmailIsBusyException {
        authService.register(registrationDto);
        return ResponseEntity.ok("User created");
    }
}
