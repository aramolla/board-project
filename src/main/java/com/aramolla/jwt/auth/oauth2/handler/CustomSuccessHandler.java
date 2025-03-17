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
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

// OAuth2 로그인 성공하면 JWT발급해주는 코드
@Slf4j
@RequiredArgsConstructor
@Component
public class CustomSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtProvider jwtProvider;
    private final JwtTokenFactory jwtTokenFactory;
    private static final String REDIRECT_URL = "http://localhost:3000/";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        //OAuth2User
        CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();
        // username과 role값을 획득
        Long memberId = oAuth2User.getId();
        Role role = oAuth2User.getrole();//getRoleFromAuthentication(oAuth2User.getAuthorities());
        // AT, RT 만들고 쿠키를 이용해 보내기
        MemberTokens tokens = jwtProvider.createTokensAndSaveRefreshToken(memberId, role);
        // MemberTokens에서 AT, RT 추출하여 문자열로 변환
        String accessToken = tokens.accessToken();
        log.info("발급된 Access Token : {}", accessToken);
        String refreshToken = tokens.refreshToken();
        log.info("발급된 Refresh Token : {}", refreshToken);

        response.addCookie(CookieUtil.createCookie("refresh_token", refreshToken));
        // HTTP 응답 헤더에 AT을 전달
//        response.setHeader("access_token", accessToken);
        response.setHeader("Authorization", "Bearer " + accessToken);
        // RT 저장
        jwtTokenFactory.saveRefreshToken(refreshToken, memberId, role);

        // Access 토큰을 ResponseEntity를 사용하여 JSON으로 응답
        ResponseEntity<ResponseData<String>> responseEntity = ResponseData.success(
            SuccessCode.LOGIN_SUCCESS, // 적절한 SuccessCode를 사용
            accessToken
        );

        // ObjectMapper를 사용하여 ResponseEntity를 JSON 문자열로 변환
        ObjectMapper objectMapper = new ObjectMapper();
        String jsonResponse = objectMapper.writeValueAsString(responseEntity.getBody());

        // 응답 설정 (콘솔 출력을 위한 설정, 실제 응답은 redirect로 처리)
        log.info("Social Login Response: {}", jsonResponse);

        response.sendRedirect("http://localhost:3000/");



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
