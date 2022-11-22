package com.shep.shepapplication.service;

import com.shep.shepapplication.entity.*;
import com.shep.shepapplication.exceptions.user.EmailIsBusyException;
import com.shep.shepapplication.exceptions.user.LoginIsBusyException;
import com.shep.shepapplication.repository.RoleRepository;
import com.shep.shepapplication.repository.UserRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;


@Service
@Slf4j
public class UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    public UserService(UserRepository userRepository, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
    }
    public Optional<UserEntity> findById(Long id){
        return userRepository.findById(id);
    }
    public UserEntity findFirstByLogin(String login){
        return userRepository.findFirstByLogin(login);
    }
    public UserEntity findFirstByEmail(String email){
        return userRepository.findFirstByEmail(email);
    }
    public Optional<UserEntity> findByLogin(String login){
        return userRepository.findByLogin(login);
    }



}
