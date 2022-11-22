package com.shep.shepapplication.dto;

import lombok.Data;

import javax.validation.constraints.Email;
import javax.validation.constraints.NotNull;

@Data
public class RegistrationDto {
    @NotNull
    private String login;
    @NotNull
    private String password;
    @NotNull
    private String name;
    @NotNull
    private String surname;
    @NotNull
    private String patronymic;
    @NotNull
    @Email
    private String email;
    @NotNull
    private String phoneNumber;
}
