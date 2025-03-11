package com.aramolla.jwt.util;

import jakarta.servlet.http.HttpServletRequest;

public class HeaderUtil {

    private static final String HEADER_AUTHORIZATION = "Authorization";
    private static final String TOKEN_PREFIX = "Bearer ";
    private static final int START_TOKEN_INDEX = 7;

    // 요청 헤더에 Authorization 를 보면 접두사 Bearer가 포함되어있음. 제외하고 실제 Access 토큰을 가져오는 함수
    public static String resolveToken(HttpServletRequest request) {
        String accessToken = request.getHeader(HEADER_AUTHORIZATION);

        if (accessToken != null && accessToken.startsWith(TOKEN_PREFIX)) {
            return accessToken.substring(START_TOKEN_INDEX);  // 접두사 "Bearer "을 제외하고 실제 토큰 문자열을 반환.
        }
        // TODO: 개인적으로 null 을 넘기는 게 아니라 여기서 처리했으면 좋겠음.
        return null;
    }
}