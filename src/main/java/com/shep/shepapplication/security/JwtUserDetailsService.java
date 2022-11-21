package com.shep.shepapplication.security;

import com.shep.shepapplication.entity.UserEntity;
import com.shep.shepapplication.security.jwt.JwtUser;
import com.shep.shepapplication.security.jwt.JwtUserFactory;
import com.shep.shepapplication.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class JwtUserDetailsService implements UserDetailsService {

    private final UserService userService;

    public JwtUserDetailsService(UserService userService) {
        this.userService = userService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        UserEntity user = userService.findFirstByLogin(username);

        if (user == null)
            throw new UsernameNotFoundException("Пользователь с логином:" + username + " не найден");

        JwtUser jwtUser = JwtUserFactory.create(user);
        log.info("IN loadUserByUsername - user c логином: {} успешно загружен",username);

        return jwtUser;
    }
}
