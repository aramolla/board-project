package com.aramolla.jwt.util;

import jakarta.servlet.http.Cookie;

public class CookieUtil {
    // static 메소드 밖에 없어서 생성자가 생길 수 있는 가능성을 배제하기 위해서 private 빈 생성자
    // TODO: 위 내용 찾아보기
    private CookieUtil() {
    }

    public static Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(60 * 60 * 60); // TODO: 쿠키 기간 refresh-token과 맞추기
//        cookie.setSecure(true);
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        return cookie;
    }

}