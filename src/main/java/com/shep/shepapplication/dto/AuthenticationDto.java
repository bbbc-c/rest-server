package com.shep.shepapplication.dto;

import lombok.Data;

@Data
public class AuthenticationDto {
    private String login;
    private String password;
    private String name;
    private String surname;
    private String patronymic;
    private String email;
    private String phoneNumber;
}
