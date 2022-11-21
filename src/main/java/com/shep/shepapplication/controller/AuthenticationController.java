package com.shep.shepapplication.controller;

import com.shep.shepapplication.dto.AuthenticationDto;
import com.shep.shepapplication.entity.UserEntity;
import com.shep.shepapplication.exceptions.user.EmailIsBusyException;
import com.shep.shepapplication.exceptions.user.LoginIsBusyException;
import com.shep.shepapplication.security.jwt.JwtTokenProvider;
import com.shep.shepapplication.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping(value = "/auth/")
@Slf4j
public class AuthenticationController {

    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserService userService;
    private final ModelMapper modelMapper;

    @Autowired
    public AuthenticationController(AuthenticationManager authenticationManager, JwtTokenProvider jwtTokenProvider, UserService userService, ModelMapper modelMapper) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenProvider = jwtTokenProvider;
        this.userService = userService;
        this.modelMapper = modelMapper;
    }
    @PostMapping("/login")
    public ResponseEntity login(@RequestBody AuthenticationDto authenticationDto) {
        try {
            String login = authenticationDto.getLogin();
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(login, authenticationDto.getPassword()));
            UserEntity userEntity = userService.findFirstByLogin(login);
            if (userEntity == null)
                throw new UsernameNotFoundException("Пользователь с логином: " + login + " не найден");
            String token = jwtTokenProvider.createToken(login, userEntity.getRoles());

            Map<Object, Object> response = new HashMap<>();
            response.put("login", login);
            response.put("token", token);
            return ResponseEntity.ok(response);
        } catch (AuthenticationException e) {
            throw new BadCredentialsException("Неправильный логин или пароль");
        }

    }
    @PostMapping("/registration")
    public ResponseEntity<AuthenticationDto> registration(@RequestBody AuthenticationDto user) throws LoginIsBusyException, EmailIsBusyException {
        return ResponseEntity.ok(modelMapper.map(
                userService.register(
                        modelMapper.map(user,UserEntity.class)
                ),
                AuthenticationDto.class));
    }
}
