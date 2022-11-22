package com.shep.shepapplication.dto;

import org.springframework.http.HttpStatus;

import java.util.HashMap;
import java.util.Map;

public class ErrorDto {
    private final HttpStatus httpStatus;
    private final String msg;

    public ErrorDto(HttpStatus httpStatus, String msg) {
        this.httpStatus = httpStatus;
        this.msg = msg;
    }


    public HttpStatus getHttpStatus() {
        return httpStatus;
    }

    public String getMsg() {
        return msg;
    }
}
