package com.shep.shepapplication.service;

import com.shep.shepapplication.dto.RegistrationDto;
import com.shep.shepapplication.entity.Role;
import com.shep.shepapplication.entity.Status;
import com.shep.shepapplication.entity.UserEntity;
import com.shep.shepapplication.exceptions.user.EmailIsBusyException;
import com.shep.shepapplication.exceptions.user.LoginIsBusyException;
import com.shep.shepapplication.repository.RoleRepository;
import com.shep.shepapplication.repository.UserRepository;
import com.shep.shepapplication.security.jwt.JwtAuthentication;
import com.shep.shepapplication.security.jwt.JwtRequest;
import com.shep.shepapplication.security.jwt.JwtResponse;
import com.shep.shepapplication.security.jwt.JwtProvider;
import io.jsonwebtoken.Claims;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Service;

import javax.security.auth.message.AuthException;
import java.util.*;

@Service
@Slf4j
public class AuthService {
    private final UserService userService;
    // Todo убрать мапу (возможно на базуданных или redis)
    private final Map<String, String> refreshStorage = new HashMap<>();
    private final JwtProvider jwtProvider;
    private final RoleRepository roleRepository;
    private final UserRepository userRepository;
    private final ModelMapper modelMapper;

    public AuthService(UserService userService, JwtProvider jwtProvider, RoleRepository roleRepository, ModelMapper modelMapper, UserRepository userRepository) {
        this.userService = userService;
        this.jwtProvider = jwtProvider;
        this.roleRepository = roleRepository;
        this.modelMapper = modelMapper;
        this.userRepository = userRepository;
    }

    /**
     * Сначала мы находим пользователя по логину в базе данных.
     * Если пользователь найден, и присланный пароль совпадает с паролем пользователя, то передаем объект пользователя в JwtProvider и получаем от него токены.
     * Далее сохраняем выданный рефреш токен в мапу refreshStorage и возвращаем объект JwtResponse с токенами.
     * @param authRequest - JwtRequest
     * @return JwtResponse
     * @throws AuthException пользователь не найден или неправильный пароль
     */
    public JwtResponse login(JwtRequest authRequest) throws AuthException {
        final UserEntity user = userService.findByLogin(authRequest.getLogin())
                .orElseThrow(() -> new AuthException("Пользователь не найден"));
        if (user.getPassword().equals(authRequest.getPassword())) {
            final String accessToken = jwtProvider.createToken(user.getLogin(), user.getRoles());
            final String refreshToken = jwtProvider.createRefreshToken(user.getLogin());
            refreshStorage.put(user.getLogin(), refreshToken);
            return new JwtResponse(accessToken, refreshToken);
        } else {
            throw new AuthException("Неправильный пароль");
        }
    }

    /**
     * Создание пользователя и добавление его базу данных.
     * Роль по умолчанию ставится ROLE_USER.
     * Время ставиться текущие через класс Date().
     * Производится проверка не занят логин и почта.
     * @param registrationDto register Dto
     * @return вернет созданого пользователя
     * @throws LoginIsBusyException Логин уже занят
     * @throws EmailIsBusyException Почта уже занята
     */
    public UserEntity register(RegistrationDto registrationDto) throws LoginIsBusyException, EmailIsBusyException {
        if (userService.findFirstByLogin(registrationDto.getLogin()) != null) {
            throw new LoginIsBusyException();
        }
        if (userService.findFirstByEmail(registrationDto.getEmail()) != null)
            throw new EmailIsBusyException();
        UserEntity user = modelMapper.map(registrationDto,UserEntity.class);
        Role roleUser = roleRepository.findByName("ROLE_USER");
        List<Role> userRoles = new ArrayList<>();
        userRoles.add(roleUser);
        user.setRoles(userRoles);
        user.setStatus(Status.NOT_ACTIVE);
        user.setDateRegistration(new Date());
        UserEntity userEntity = userRepository.save(user);
        log.info("IN register - user: {} успешно зарегестрирован",userEntity);
        return userEntity;
    }
    /**
     * Принимает refresh токен, а возвращает новый access токен.
     * Сначала мы проверяем, что присланный rehresh токен валиден.
     * Если валиден, то получаем claims и оттуда получаем логин пользователя.
     * Далее по логину находим выданный пользователю refresh токен в мапе refreshStorage, и сверяем его с присланным пользователем.
     * Если токены одинаковые, то получаем объект User, который отправляем в JwtProvider и получаем новый access токен, без обновления refresh токена.
     * @param refreshToken refresh токен
     * @return JwtResponse
     * @throws AuthException пользователь не найден
     */
    public JwtResponse getAccessToken(String refreshToken) throws AuthException {
        if (jwtProvider.validateRefreshToken(refreshToken)) {
            final Claims claims = jwtProvider.getRefreshClaims(refreshToken);
            final String login = claims.getSubject();
            final String saveRefreshToken = refreshStorage.get(login);
            if (saveRefreshToken != null && saveRefreshToken.equals(refreshToken)) {
                final UserEntity user = userService.findByLogin(login)
                        .orElseThrow(() -> new AuthException("Пользователь не найден"));
                final String accessToken = jwtProvider.createToken(user.getLogin(),user.getRoles());
                return new JwtResponse(accessToken, null);
            }
        }
        return new JwtResponse(null, null);
    }

    /**
     * Обновление access и refresh token.
     * Допустимо только если был передан правильный accessToken.
     * @param refreshToken refresh token
     * @return новый access и refresh token
     * @throws AuthException Пльзователь не найден
     */
    public JwtResponse refresh(String refreshToken) throws AuthException {
        if (jwtProvider.validateRefreshToken(refreshToken)) {
            final Claims claims = jwtProvider.getRefreshClaims(refreshToken);
            final String login = claims.getSubject();
            final String saveRefreshToken = refreshStorage.get(login);
            if (saveRefreshToken != null && saveRefreshToken.equals(refreshToken)) {
                final UserEntity user = userService.findByLogin(login)
                        .orElseThrow(() -> new AuthException("Пользователь не найден"));
                final String accessToken = jwtProvider.createToken(user.getLogin(),user.getRoles());
                final String newRefreshToken = jwtProvider.createRefreshToken(user.getLogin());
                refreshStorage.put(user.getLogin(), newRefreshToken);
                return new JwtResponse(accessToken, newRefreshToken);
            }
        }
        throw new AuthException("Невалидный JWT токен");
    }

    /**
     * Все идентифицированые пользователи
     * @return все идентифицированые пользователи
     */
    public JwtAuthentication getAuthInfo() {
        return (JwtAuthentication) SecurityContextHolder.getContext().getAuthentication();
    }
}
