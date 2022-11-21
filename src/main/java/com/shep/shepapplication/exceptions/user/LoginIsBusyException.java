package com.shep.shepapplication.exceptions.user;

/**
 * Exception что данный логин уже занят
 */
public class LoginIsBusyException extends Exception{

    private static final String msgError = "Логин уже занят";

    public LoginIsBusyException(){
        super(msgError);
    }
}
