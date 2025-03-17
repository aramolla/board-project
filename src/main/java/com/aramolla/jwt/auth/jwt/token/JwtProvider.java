package com.aramolla.jwt.auth.jwt.token;


import com.aramolla.jwt.auth.jwt.domain.RefreshToken;
import com.aramolla.jwt.auth.jwt.dto.MemberTokens;
import com.aramolla.jwt.auth.jwt.repository.RefreshTokenRepository;
import com.aramolla.jwt.global.response.error.ErrorCode;
import com.aramolla.jwt.member.domain.Role;
import io.jsonwebtoken.JwtException;
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
    private final JwtValidator jwtValidator;
    private final JwtCleaner jwtCleaner;

    // 스프링 Bean 으로 등록되어 있어 자동으로 의존성이 주입된다.jwtParser 와 jwtProperties는 Bean으로 등록되어있어야함.
    public JwtProvider(
        JwtParser jwtParser,
        JwtTokenFactory jwtTokenFactory,
        RefreshTokenRepository refreshTokenRepository,
        JwtProperties jwtProperties,
        JwtValidator jwtValidator,
        JwtCleaner jwtCleaner) {
        this.jwtParser = jwtParser;
        this.jwtTokenFactory = jwtTokenFactory;
        this.refreshTokenRepository = refreshTokenRepository;
        this.secretKey = jwtProperties.getSecretKey();
        this.accessTokenExpireTime = jwtProperties.getAccessTokenExpireTime();
        this.refreshTokenExpireTime = jwtProperties.getRefreshTokenExpireTime();
        this.jwtValidator = jwtValidator;
        this.jwtCleaner = jwtCleaner;
    }

    public MemberTokens createTokensAndSaveRefreshToken(Long memberId, Role roleType) {
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
        jwtTokenFactory.saveRefreshToken(refreshToken, memberId, roleType);
        return new MemberTokens(accessToken, refreshToken);
    }

    public MemberTokens reissueToken(String refreshToken) {
        if (!jwtValidator.isValidateTokens(refreshToken)) { // 리프레시 토큰 유효성 검증
            throw new JwtException(ErrorCode.TOKEN_ERROR.getMessage() + refreshToken);
        }
        RefreshToken storedToken = getRefreshTokenInfo(
            refreshToken); // 입력받은 리프레시 토큰과 일치하는 storedToken(저장된 refreshToken) 조회
        Long memberId = storedToken.getMemberId();
        jwtCleaner.deleteRefreshToken(memberId); // 기존 토큰 삭제

        if (!refreshToken.equals(storedToken.getRefreshToken())) { // 리프레시 토큰 일치 여부 확인
            throw new JwtException(ErrorCode.TOKEN_ERROR.getMessage() + refreshToken);
        }
        // 새로운 토큰 생성 및 저장
        Role role = storedToken.getRole();

        String newAccessToken = createTokensAndSaveRefreshToken(memberId, role).accessToken();
        String newRefreshToken = createTokensAndSaveRefreshToken(memberId, role).refreshToken();
        return new MemberTokens(newAccessToken, newRefreshToken);
    }


    // JWT 에서 토큰을 이용해 인증 정보를 추출 후 UsernamePasswordAuthenticationToken을 생성해 전달
    // Authentication 객체를 생성하고, 이를 SecurityContext에 설정하여 이후의 요청에서 인증 정보를 사용할 수 있도록 함.
    // UsernamePasswordAuthenticationToken 사용자가 입력한 이름과 비밀번호를 저장하여 인증 과정에서 사용자의 신원을 확인하는 데 사용됨
    public Authentication getAuthentication(String token) {
        String memberId = jwtParser.getSubject(token);
        // 유저 권한은 하나밖에 없기에 singletonList로 진행함. 단 하나의 권한만 가질때 사용.
        GrantedAuthority authority = new SimpleGrantedAuthority(jwtParser.getAuthority(token));

        return new UsernamePasswordAuthenticationToken(memberId, null,
            Collections.singletonList(authority));
    }

    public RefreshToken getRefreshTokenInfo(String refreshToken) {
        return refreshTokenRepository.findByRefreshToken(refreshToken) // 저장된 refreshToken 찾아서 반환
            .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 refresh token"));
        // TODO: 공부하세요. Optional && orElseThrow()
    }

}