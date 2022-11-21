package com.shep.shepapplication.security.jwt;

import com.shep.shepapplication.entity.Role;
import com.shep.shepapplication.entity.UserEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.stream.Collectors;

public final class JwtUserFactory {
    public JwtUserFactory(){
    }

    public static JwtUser create(UserEntity userEntity){
        return new JwtUser(
                userEntity.getId(),
                userEntity.getLogin(),
                userEntity.getPassword(),
                mapToGrantedAuthority(userEntity.getRoles())
        );
    }

    private static List<GrantedAuthority> mapToGrantedAuthority(List<Role> userRoles){
        return userRoles.stream()
                .map(role ->
                        new SimpleGrantedAuthority(role.getName())
                ).collect(Collectors.toList());
    }
}
