package com.aramolla.jwt.auth.jwt.token;

import com.aramolla.jwt.auth.jwt.domain.RefreshToken;
import com.aramolla.jwt.auth.jwt.repository.RefreshTokenRepository;
import com.aramolla.jwt.member.domain.Role;
import io.jsonwebtoken.Jwts;
import java.util.Date;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

/*
*  - @RequiredArgsConstructor 는 final 필드 또는 @NonNull 필드만 포함하는 생성자를 자동 생성해줌.
   - Spring 에서 의존성 주입(DI) 시 @Autowired 없이 생성자 주입 가능.
   - 불변성 유지 및 코드 간결화에 유용함.
*/
@RequiredArgsConstructor
@Component
public class JwtTokenFactory {

    private static final String CATEGORY_KEY = "category";
    private static final String AUTHORITIES_KEY = "auth";

    private final RefreshTokenRepository refreshTokenRepository;

    // 토큰 생성
    public String createToken(
        String email,
        SecretKey key,
        Role role,
        String category,
        Long expiredMs
    ) {
        Date date = new Date(); // 토큰 발행 시간
        Date validity = new Date(date.getTime() + expiredMs); // 만료 기간 설정

        return Jwts.builder() // 토큰 payload에 email, role이 포함되어 있음
            .subject(email)
            .claim(CATEGORY_KEY, category) // claim payload
            .claim(AUTHORITIES_KEY, role)
            .expiration(validity)
            .signWith(key) //시크릿키로 시그니처를 만들어 암호화
            .compact();
    }

    // RT 생성 후 DB 저장
    public void saveRefreshToken(
        String refreshToken,
        String email,
        Role role
    ) {
        RefreshToken newRefreshToken = RefreshToken.builder()
            .refreshToken(refreshToken)
            .email(email)
            .role(role)
            .build();

        refreshTokenRepository.save(newRefreshToken);
    }

}