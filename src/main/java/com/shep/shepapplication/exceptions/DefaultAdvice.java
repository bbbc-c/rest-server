package com.shep.shepapplication.exceptions;

import com.shep.shepapplication.dto.ErrorDto;
import com.shep.shepapplication.exceptions.user.EmailIsBusyException;
import com.shep.shepapplication.exceptions.user.LoginIsBusyException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingPathVariableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import javax.security.auth.message.AuthException;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class DefaultAdvice extends ResponseEntityExceptionHandler {

    @ExceptionHandler(LoginIsBusyException.class)
    public ResponseEntity<ErrorDto> handleException(LoginIsBusyException e){
        ErrorDto error = new ErrorDto(HttpStatus.FORBIDDEN,e.getMessage());
        return new ResponseEntity<>(error,error.getHttpStatus());
    }
    @ExceptionHandler(EmailIsBusyException.class)
    public ResponseEntity<ErrorDto> handleException (EmailIsBusyException e){
        ErrorDto error = new ErrorDto(HttpStatus.FORBIDDEN,e.getMessage());
        return new ResponseEntity<>(error,error.getHttpStatus());
    }
    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ErrorDto> handleException (AuthException e){
        ErrorDto error = new ErrorDto(HttpStatus.FORBIDDEN,e.getMessage());
        return new ResponseEntity<>(error,error.getHttpStatus());
    }
    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(
            MethodArgumentNotValidException ex,
            HttpHeaders headers,
            HttpStatus status,
            WebRequest request) {

        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach((error) ->{
            String fieldName = ((FieldError) error).getField();
            String message = error.getDefaultMessage();
            errors.put(fieldName, message);
        });
        return new ResponseEntity<Object>(errors, HttpStatus.BAD_REQUEST);
    }
    @Override
    protected ResponseEntity<Object> handleMissingPathVariable(MissingPathVariableException ex, HttpHeaders headers,
                                                               HttpStatus status, WebRequest request) {
        ErrorDto error = new ErrorDto(HttpStatus.BAD_REQUEST,ex.getMessage());
        return new ResponseEntity<>(error,error.getHttpStatus());
    }
}
