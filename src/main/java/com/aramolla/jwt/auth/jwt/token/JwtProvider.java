package com.aramolla.jwt.auth.jwt.token;


import com.aramolla.jwt.auth.jwt.domain.RefreshToken;
import com.aramolla.jwt.auth.jwt.dto.MemberTokens;
import com.aramolla.jwt.auth.jwt.repository.RefreshTokenRepository;
import java.util.Collections;
import javax.crypto.SecretKey;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

@Component
public class JwtProvider {
    private static final String ACCESS = "access";
    private static final String REFRESH = "refresh";
    private final JwtParser jwtParser;
    private final JwtTokenFactory jwtTokenFactory;
    private final RefreshTokenRepository refreshTokenRepository;
    private final SecretKey secretKey;
    private final Long accessTokenExpireTime;
    private final Long refreshTokenExpireTime;

    // 스프링 Bean 으로 등록되어 있어 자동으로 의존성이 주입된다.jwtParser 와 jwtProperties는 Bean으로 등록되어있어야함.
    public JwtProvider(
        JwtParser jwtParser,
        JwtTokenFactory jwtTokenFactory,
        RefreshTokenRepository refreshTokenRepository,
        JwtProperties jwtProperties
    ) {
        this.jwtParser = jwtParser;
        this.jwtTokenFactory = jwtTokenFactory;
        this.refreshTokenRepository = refreshTokenRepository;
        this.secretKey = jwtProperties.getSecretKey();
        this.accessTokenExpireTime = jwtProperties.getAccessTokenExpireTime();
        this.refreshTokenExpireTime = jwtProperties.getRefreshTokenExpireTime();
    }

    public MemberTokens createTokensAndSaveRefreshToken(Long memberId, String roleType) {
        String accessToken = jwtTokenFactory.createToken(
            memberId,
            secretKey,
            roleType,
            ACCESS,
            accessTokenExpireTime
        );
        String refreshToken = jwtTokenFactory.createToken(
            memberId,
            secretKey,
            roleType,
            REFRESH,
            refreshTokenExpireTime
        );
        jwtTokenFactory.saveRefreshToken(refreshToken, memberId);
        return new MemberTokens(accessToken, refreshToken);
        // TODO: record 공부
    }


    // JWT 에서 토큰을 이용해 인증 정보를 추출 후 UsernamePasswordAuthenticationToken을 생성해 전달
    // Authentication 객체를 생성하고, 이를 SecurityContext에 설정하여 이후의 요청에서 인증 정보를 사용할 수 있도록 함.
    public Authentication getAuthentication(String token) {
        String memberId = jwtParser.getSubject(token);
        // 유저 권한은 하나밖에 없기에 singletonList로 진행함. 단 하나의 권한만 가질때 사용.
        GrantedAuthority authority = new SimpleGrantedAuthority(jwtParser.getAuthority(token));

        return new UsernamePasswordAuthenticationToken(memberId, null,
            Collections.singletonList(authority));
    }

    public RefreshToken getRefreshTokenInfo(Long id) {
        return refreshTokenRepository.findById(id)
            .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
        // TODO: 공부하세요. Optional && orElseThrow()
    }

}