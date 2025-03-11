package com.aramolla.jwt.auth.jwt.filter;

import com.aramolla.jwt.auth.jwt.response.JwtErrorResponder;
import com.aramolla.jwt.auth.jwt.token.JwtProvider;
import com.aramolla.jwt.auth.jwt.token.JwtValidator;
import com.aramolla.jwt.global.response.error.ErrorCode;
import com.aramolla.jwt.util.HeaderUtil;
import io.jsonwebtoken.ExpiredJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/*
=============== JWT Logic (DB 조회 생략)===================
-- 토큰 자체가 사용자의 인증 정보를 포함하고 있기 때문에 매번 DB 조회 없이 사용 가능.
1. 클라이언트가 JWT 토큰을 보내면 해당 필터가 요청을 가로챈다.
2. JWT 검증 후 UsernamePasswordAuthenticationToken 토큰(인증용 객체)을 생성
3. Authentication 객체를 SecurityContextHolder라는 곳에 저장
 */
@RequiredArgsConstructor
@Component
public class JwtFilter extends OncePerRequestFilter {

    private final JwtProvider jwtProvider;
    private final JwtValidator jwtValidator;
    private final JwtErrorResponder jwtErrorResponder;
    // 아래 요청은 filter 를 거치지 않음. - 경로가 추가 될 예정이라 1개여도 List 로 함.
    private static final List<String> EXCLUDE_PATHS = List.of("/auth/**");
    private static final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        String token = HeaderUtil.resolveToken(request);
        // 빈 문자열("")**이나 공백만 있는 문자열은 false
        if (!StringUtils.hasText(token)) {
            jwtErrorResponder.sendErrorResponse(response, ErrorCode.WRONG_AUTH_HEADER);
            return;
        }
        // JWT에서 토큰을 이용해 인증 정보를 추출 후 UsernamePasswordAuthenticationToken을 생성해 전달
        // Authentication 객체를 생성하고, 이를 SecurityContext에 설정하여 이후의 요청에서 인증 정보를 사용할 수 있도록 힘
        try {
            jwtValidator.validateToken(token);
            Authentication authentication = jwtProvider.getAuthentication(token);
            SecurityContextHolder.getContext().setAuthentication(authentication);
            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException e) {
            jwtErrorResponder.sendErrorResponse(response, ErrorCode.TOKEN_EXPIRED);
        } catch (Exception e) {
            jwtErrorResponder.sendErrorResponse(response, ErrorCode.TOKEN_ERROR);
        }
    }

    // 필터를 거치지 않아도 되는 요청
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        return EXCLUDE_PATHS.stream()
            .anyMatch(exclude -> pathMatcher.match(exclude, path));
    }

}