package com.aramolla.jwt.auth.jwt.token;

import com.aramolla.jwt.global.response.ResponseData;
import com.aramolla.jwt.global.response.error.ErrorCode;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtParser {

    private static final String AUTHORITIES_KEY = "auth";
    private final JwtProperties jwtProperties;

    /*
    sub는 보통 사용자의 고유 식별자로 사용됩니다.
    로그인한 사용자나 특정 엔터티(Entity)를 나타내는 값이 들어갑니다.
    일반적으로 사용자의 ID 또는 이메일을 넣는 경우가 많습니다.
    * */
    public String getSubject(final String token) {
        return parseToken(token)
            .getPayload()
            .getSubject();
    }

    // 권한들고오는 함수
    public String getAuthority(final String token) {
        return parseToken(token)
            .getPayload()
            .get(AUTHORITIES_KEY, String.class);
    }

    public Jws<Claims> parseToken(String token) { // 해당
        try {
            return Jwts.parser().verifyWith(jwtProperties.getSecretKey()).build()
                .parseSignedClaims(token);
        } catch (ExpiredJwtException e) {
            throw new IllegalArgumentException(ErrorCode.TOKEN_EXPIRED.getMessage()); //토큰 기간 만료
        } catch (Exception e) {
            throw new IllegalArgumentException(ErrorCode.TOKEN_ERROR.getMessage());
        }
    }
}
