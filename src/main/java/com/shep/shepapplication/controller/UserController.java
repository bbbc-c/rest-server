package com.shep.shepapplication.controller;

import com.shep.shepapplication.dto.AuthenticationDto;
import com.shep.shepapplication.entity.UserEntity;
import com.shep.shepapplication.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;


@RestController
@RequestMapping("/user")
@Slf4j
public class UserController {
    private final UserService userService;
    private final ModelMapper modelMapper;

    public UserController(UserService userService, ModelMapper modelMapper) {
        this.userService = userService;
        this.modelMapper = modelMapper;
    }

    @GetMapping("/{id}")
    public ResponseEntity<AuthenticationDto> getOne(@PathVariable("id") Long id){
        Optional<UserEntity> userEntity = userService.findById(id);
        return ResponseEntity.ok(modelMapper.map(userEntity.get(), AuthenticationDto.class));
    }



}
