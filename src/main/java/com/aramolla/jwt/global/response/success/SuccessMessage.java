package com.aramolla.jwt.global.response.success;

public enum SuccessMessage {

    CREATED_MEMBER("SUCCESS - 회원 가입 성공"),
    READ_MEMBER("SUCCESS - 회원 정보 조회 성공"),
    UPDATE_MEMBER("SUCCESS - 회원 정보 수정 성공"),
    DELETE_MEMBER("SUCCESS - 회원 탈퇴"),

    CREATED_POST("SUCCESS - 게시물 등록 성공"),
    READ_POST("SUCCESS - 게시물 조회 성공"),
    READ_POSTS("SUCCESS - 게시물 목록 조회 성공"),
    UPDATE_POST("SUCCESS - 게시물 수정 성공"),
    DELETE_POST("SUCCESS - 게시물 삭제"),

    LOGIN_SUCCESS("SUCCESS - 로그인 성공"),
    LOGOUT_SUCCESS("SUCCESS - 로그아웃 성공 및 user Refresh Token 삭제"),
    UPDATE_PASSWORD("SUCCESS - 비밀번호 수정 성공"),
    USERNAME_SUCCESS("SUCCESS - 사용 가능한 아이디입니다."),
    NICKNAME_SUCCESS("SUCCESS - 사용 가능한 닉네임입니다."),
    READ_IS_LOGIN("SUCCESS - 현재 로그인 여부 조회"),

    TOKEN_IS_VALID("VALID - 유효한 토큰"),
    REISSUE_SUCCESS("SUCCESS - JWT Access 토큰 재발급 성공"),
    ACCESS_TOKEN_SUCCESS("SUCCESS - GET JWT Access"),

    ;

    final private String message;

    SuccessMessage(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

}