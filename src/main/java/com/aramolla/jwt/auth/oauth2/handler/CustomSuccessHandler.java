package com.aramolla.jwt.auth.oauth2.handler;

import com.aramolla.jwt.auth.jwt.dto.MemberTokens;
import com.aramolla.jwt.auth.jwt.token.JwtProvider;
import com.aramolla.jwt.auth.jwt.token.JwtTokenFactory;
import com.aramolla.jwt.auth.oauth2.dto.CustomOAuth2User;
import com.aramolla.jwt.global.response.ResponseData;
import com.aramolla.jwt.global.response.success.SuccessCode;
import com.aramolla.jwt.member.domain.Role;
import com.aramolla.jwt.util.CookieUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

// OAuth2 로그인 성공하면 JWT발급해주는 코드
@Slf4j
@RequiredArgsConstructor
@Component
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;
    private final JwtTokenFactory jwtTokenFactory;
    private static final String REDIRECT_URL = "http://localhost:3000/";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
        Authentication authentication) throws IOException, ServletException {

        //OAuth2User
        CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();
        // username과 role값을 획득
        String email = oAuth2User.getUsername(); // username이 없어서 oAuth2User username에 email을 넣음
        Role role = oAuth2User.getrole();//getRoleFromAuthentication(oAuth2User.getAuthorities());
        // AT, RT 만들고 쿠키를 이용해 보내기
        MemberTokens tokens = jwtProvider.createTokensAndSaveRefreshToken(email, role);
        // MemberTokens에서 AT, RT 추출하여 문자열로 변환
        String accessToken = tokens.accessToken();
        log.info("발급된 Access Token : {}", accessToken);
        String refreshToken = tokens.refreshToken();
        log.info("발급된 Refresh Token : {}", refreshToken);

        response.addCookie(CookieUtil.createCookie("refresh_token", refreshToken));
        // RT 저장
        jwtTokenFactory.saveRefreshToken(refreshToken, email, role);

        log.info("리다이렉트 URL: {}", "http://localhost:3000/oauth/redirect?accessToken=" + accessToken);
        response.sendRedirect("http://localhost:3000/oauth/redirect?accessToken=" + accessToken);


    }

    // getAuthorities에서 Role객체로 꺼내기
    private Role getRoleFromAuthentication(Collection<? extends GrantedAuthority> authorities) {
        return authorities.stream()
            .findFirst()
            .map(GrantedAuthority::getAuthority)
            .map(roleCode -> {
                try {
                    return Role.valueOf(roleCode); // 권한 코드를 Role 객체로 변환
                } catch (IllegalArgumentException e) {
                    // 유효하지 않은 권한 코드 처리
                    throw new AccessDeniedException("Invalid role code: " + roleCode);
                }
            })
            .orElseThrow(() -> new AccessDeniedException("No authorities found"));
    }


}
