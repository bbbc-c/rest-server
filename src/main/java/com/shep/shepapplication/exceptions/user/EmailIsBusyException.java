package com.shep.shepapplication.exceptions.user;

/**
 * Exception что данная почта уже занята
 */
public class EmailIsBusyException extends Exception {

    private static final String msgError = "Email уже занят";

    public EmailIsBusyException() {
        super(msgError);
    }
}
