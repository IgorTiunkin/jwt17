package com.example.jwttest.services;

import com.example.jwttest.auth.AuthenticationRequest;
import com.example.jwttest.auth.AuthenticationResponse;
import com.example.jwttest.auth.RegisterRequest;
import com.example.jwttest.models.Role;
import com.example.jwttest.models.User;
import com.example.jwttest.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest authenticationRequest) {
        User user = User.builder()
                .firstName(authenticationRequest.getFirstName())
                .lastName(authenticationRequest.getLastName())
                .email(authenticationRequest.getEmail())
                .password(passwordEncoder.encode(authenticationRequest.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
        String token = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(token).build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
        //Delegate authentication to Manager - auto
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getEmail(),
                        authenticationRequest.getPassword()
                )
        );
        User user = userRepository.findByEmail(authenticationRequest.getEmail())
                .orElseThrow(()-> new UsernameNotFoundException("username not found"));

        String token = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(token).build();
    }
}
