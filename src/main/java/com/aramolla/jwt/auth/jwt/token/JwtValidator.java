package com.aramolla.jwt.auth.jwt.token;

import com.aramolla.jwt.auth.jwt.dto.TokenInfo;
import com.aramolla.jwt.auth.jwt.repository.RefreshTokenRepository;
import com.aramolla.jwt.global.response.error.ErrorCode;
import com.aramolla.jwt.member.domain.Role;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtValidator {

    private final JwtParser jwtParser;
    private final JwtCleaner jwtCleaner;
    private final RefreshTokenRepository refreshTokenRepository;

    public void validateToken(String token) {
        jwtParser.parseToken(token);
    }


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


    public boolean isValidateTokens(String token) {
        try {
            Claims claims = jwtParser.parseToken(token).getPayload(); // 토큰 기간 만료 확인, 클레임 정보 추츨
            return true;
        } catch (SecurityException | MalformedJwtException e) {
            log.error(ErrorCode.TOKEN_ERROR.getMessage() + token);
        } catch (ExpiredJwtException e) {
            log.error(ErrorCode.TOKEN_EXPIRED.getMessage() + token);
        } catch (UnsupportedJwtException e) {
            log.error(ErrorCode.TOKEN_HASH_NOT_SUPPORTED.getMessage() + token);
        } catch (IllegalArgumentException e) {
            log.error(ErrorCode.BAD_REQUEST_TOKEN.getMessage() + token);
        }
        return false;
    }



}
