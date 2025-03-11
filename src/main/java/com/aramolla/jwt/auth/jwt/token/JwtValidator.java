package com.aramolla.jwt.auth.jwt.token;

import com.aramolla.jwt.auth.jwt.dto.TokenInfo;
import com.aramolla.jwt.auth.jwt.repository.RefreshTokenRepository;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtValidator {

    private final JwtParser jwtParser;
    private final JwtCleaner jwtCleaner;
    private final RefreshTokenRepository refreshTokenRepository;

    public void validateToken(String token) {
        jwtParser.parseToken(token);
    }

    // TODO: REDIS이용하여 AT, RT 유효성 검증 로직 구축

    // 토큰으로부터 Member 정보와  권한을 들고온다.
    public TokenInfo getMemberInfoFromToken(String token) {
        return new TokenInfo(getMemberIdFromToken(token),getRoleFromToken(token));
    }
    public Long getMemberIdFromToken(String token){
        return Long.parseLong(jwtParser.getSubject(token));
    }

    public String getRoleFromToken(String token) {
        return jwtParser.getAuthority(token);
    }


    private boolean isValidateTokens(String token) {
        try {
            jwtParser.parseToken(token);
            return true;
        } catch (ExpiredJwtException e) { // 만료 되었으면 통과 안되었으면 탈취 간주
            return false;
        } catch (Exception e) { // 다른 에러일 경우에도 폐기
            return false;
        }
    }

}
