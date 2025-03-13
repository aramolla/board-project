package com.aramolla.jwt.auth.jwt.token;

import io.jsonwebtoken.Jwts;
import java.nio.charset.StandardCharsets;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

/*
JWT - 시크릿 키, AT, RT 의 만료기간을 가져오는 클래스입니다.
* */
@Configuration
public class JwtProperties {

    // @RequiredArgsConstructor 와 @Value 는 같이 사용 못한다.  컴파일 타임에 Lombok 과 충돌이 생길 수 있다.
    @Value("${spring.jwt.secretKey}")
    private String secret;
    @Value("${spring.jwt.access.expiration}")
    Long accessTokenExpireTime;
    @Value("${spring.jwt.refresh.expiration}")
    Long refreshTokenExpireTime;

    public SecretKey getSecretKey() { // 시크릿 키를 객체 변수로 암호화
        return new SecretKeySpec(
            secret.getBytes(StandardCharsets.UTF_8),
            Jwts.SIG.HS256.key().build().getAlgorithm()
        );
    }

    public Long getAccessTokenExpireTime() {
        return accessTokenExpireTime;
    }

    public Long getRefreshTokenExpireTime() {
        return refreshTokenExpireTime;
    }

}