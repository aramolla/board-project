package com.aramolla.jwt.global.response.success;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.http.HttpStatus;

@AllArgsConstructor
@Getter
public enum SuccessCode {

    // <=============== MEMBER ===============>
    CREATED_MEMBER(HttpStatus.CREATED.value(), SuccessMessage.CREATED_MEMBER.getMessage()),
    READ_MEMBER(HttpStatus.OK.value(), SuccessMessage.READ_MEMBER.getMessage()),
    UPDATE_MEMBER(HttpStatus.NO_CONTENT.value(), SuccessMessage.UPDATE_MEMBER.getMessage()),
    DELETE_MEMBER(HttpStatus.NO_CONTENT.value(), SuccessMessage.DELETE_MEMBER.getMessage()),

    // <=============== POST ===============>
    CREATED_POST(HttpStatus.CREATED.value(), SuccessMessage.CREATED_POST.getMessage()),
    READ_POST(HttpStatus.OK.value(), SuccessMessage.READ_POST.getMessage()),
    READ_POSTS(HttpStatus.OK.value(), SuccessMessage.READ_POSTS.getMessage()),
    UPDATE_POST(HttpStatus.NO_CONTENT.value(), SuccessMessage.UPDATE_POST.getMessage()),
    DELETE_POST(HttpStatus.NO_CONTENT.value(), SuccessMessage.DELETE_POST.getMessage()),


    // <=============== JWT ===============>
    REISSUE_SUCCESS(HttpStatus.OK.value(), SuccessMessage.REISSUE_SUCCESS.getMessage()),
    TOKEN_IS_VALID(HttpStatus.OK.value(), SuccessMessage.TOKEN_IS_VALID.getMessage()),
    ACCESS_TOKEN_SUCCESS(HttpStatus.OK.value(), SuccessMessage.ACCESS_TOKEN_SUCCESS.getMessage()),

    // <===============  Etc ===============>
    READ_IS_LOGIN(HttpStatus.OK.value(), SuccessMessage.READ_IS_LOGIN.getMessage()),
    LOGIN_SUCCESS(HttpStatus.OK.value(), SuccessMessage.LOGIN_SUCCESS.getMessage()),
    USERNAME_SUCCESS(HttpStatus.OK.value(), SuccessMessage.USERNAME_SUCCESS.getMessage()),
    NICKNAME_SUCCESS(HttpStatus.OK.value(), SuccessMessage.NICKNAME_SUCCESS.getMessage()),
    LOGOUT_SUCCESS(HttpStatus.OK.value(), SuccessMessage.LOGOUT_SUCCESS.getMessage()),
    UPDATE_PASSWORD(HttpStatus.NO_CONTENT.value(), SuccessMessage.UPDATE_PASSWORD.getMessage())
    ;

    private  int httpStatus;
    private String message;

}