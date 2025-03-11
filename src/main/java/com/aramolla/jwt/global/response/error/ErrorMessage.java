package com.aramolla.jwt.global.response.error;

public enum ErrorMessage {

    //  <((((((((((((((( MEMBER (((((((((((((((>
    NOT_FOUND_MEMBER("ERROR - 회원을 찾을 수 없습니다."),
    BAD_REQUEST_MEMBER("ERROR - 잘못된 회원 요청 에러"),
    BAD_REQUEST_PASSWORD("ERROR - 잘못된 비밀번호 요청 에러"),
    DUPLICATE_USERNAME("ERROR - 회원가입 ID 중복 에러"),
    //  <((((((((((((((( POST (((((((((((((((>
    DUPLICATE_NICKNAME("ERROR - 회원가입 닉네임 중복"),
    NOT_FOUND_POST("ERROR - 게시물을 찾을 수 없습니다."),
    BAD_REQUEST_POST("ERROR - 잘못된 게시물 요청"),
    //  <((((((((((((((( JWT (((((((((((((((>
    TOKEN_EXPIRED("ERROR - JWT 토큰 만료 에러"),
    TOKEN_ERROR("ERROR - 잘못된 JWT 토큰 에러"),
    BAD_REQUEST_TOKEN("ERROR - 잘못된 토큰 요청 에러"),
    TOKEN_IS_BLACKLIST("ERROR - 폐기된 토큰"),
    TOKEN_HASH_NOT_SUPPORTED("ERROR - 지원하지 않는 형식의 토큰"),
    WRONG_AUTH_HEADER("ERROR - [Bearer ]로 시작하는 토큰이 없습니다."),
    TOKEN_VALIDATION_TRY_FAILED("ERROR - 토큰 인증 실패"),
    TOKEN_NOT_EXPIRED("ERROR - 토큰 탈취 - 만료되지 않은 상태에서 재발급 요청으로 인해 토큰을 폐기합니다."),
    TOKEN_TAKE_OVER("ERROR - 토큰 탈취 - 토큰을 폐기합니다"),
    //  <((((((((((((((( ETC (((((((((((((((>
    UNAUTHORIZED("ERROR - Unauthorized 에러"), // 인증되지 않은 사용자
    FORBIDDEN("ERROR - Forbidden 에러"), // 권한 없을 때
    PREVENT_GET_ERROR("Status 204 - 리소스 및 리다이렉트 GET 호출 에러 방지"),
    INTERNAL_SERVER_ERROR("ERROR - 서버 내부"),

    ;

    final private String message;

    ErrorMessage(String message) {
        this.message = message;
    }

    public String getMessage() {
        return message;
    }

}