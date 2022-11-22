package com.shep.shepapplication.controller;

import com.shep.shepapplication.dto.RegistrationDto;
import com.shep.shepapplication.entity.UserEntity;
import com.shep.shepapplication.security.jwt.JwtProvider;
import com.shep.shepapplication.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;


@RestController
@RequestMapping("/user")
@Slf4j
public class UserController {
    private final UserService userService;
    private final ModelMapper modelMapper;
    private final JwtProvider jwtProvider;

    public UserController(UserService userService, ModelMapper modelMapper, JwtProvider jwtProvider) {
        this.userService = userService;
        this.modelMapper = modelMapper;
        this.jwtProvider = jwtProvider;
    }

    @GetMapping("/{id}")
    public ResponseEntity<RegistrationDto> getOne(@PathVariable("id") Long id){
        Optional<UserEntity> userEntity = userService.findById(id);
        return ResponseEntity.ok(modelMapper.map(userEntity.get(), RegistrationDto.class));
    }



}
