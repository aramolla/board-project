package com.aramolla.jwt.auth.jwt.token;

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
    sub는 보통 사용자의 고유 식별자로 사용 - 여기서는 member_id가 sub로 사용
    * */
    public String getSubject(final String token) {
        return parseToken(token)
            .getPayload()
            .getSubject();
    }

    // role 들고오는 함수
    public String getAuthority(final String token) {
        return parseToken(token)
            .getPayload()
            .get(AUTHORITIES_KEY, String.class);
    }

    public Jws<Claims> parseToken(String token) { // 해당
        try {
            return Jwts.parser().verifyWith(jwtProperties.getSecretKey()).build()
                .parseSignedClaims(token); // 토큰이 우리 서버에서 생성되었는지, 우리가 가지고 있는 키와 맞는지 확인
        } catch (ExpiredJwtException e) {
            throw new IllegalArgumentException(ErrorCode.TOKEN_EXPIRED.getMessage()); //토큰 기간 만료
        } catch (Exception e) {
            throw new IllegalArgumentException(ErrorCode.TOKEN_ERROR.getMessage());
        }
    }
}
