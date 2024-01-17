package com.example.jwttest.controllers;

import com.example.jwttest.auth.AuthenticationRequest;
import com.example.jwttest.auth.AuthenticationResponse;
import com.example.jwttest.auth.RegisterRequest;
import com.example.jwttest.services.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest authenticationRequest
    ) {
        return ResponseEntity.ok(authService.register(authenticationRequest));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest authenticationRequest
    ) {
        return ResponseEntity.ok(authService.authenticate(authenticationRequest));
    }

}
