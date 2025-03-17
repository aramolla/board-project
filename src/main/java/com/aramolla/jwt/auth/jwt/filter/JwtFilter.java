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
=============== JWT Logic ===================
- UsernamePasswordAuthenticationFilter가 로그인 요청을 처리
- AuthenticationManager가 UserDetailsService를 호출하여 사용자 정보를 로드
- AuthenticationManager는 로드된 UserDetails와 사용자가 입력한 정보를 비교하여 인증을 수행
- 인증이 성공하면 Authentication 객체가 생성되고, Security Context에 저장
 successfulAuth에서 JWT를 만들어 사용자에게 응답을 해주면 됨

=============== 아래 코드 Logic ===================
UserDetailsService 대신 AuthService.login 메서드가 직접 사용자 인증 및 JWT 생성을 처리(UsernamePasswordAuthenticationFilter, AuthenticationManager 역할)
    -> 토큰 자체가 사용자의 인증 정보를 포함하고 있기 때문에 매번 DB 조회 없이 사용 가능하여 "/auth/**"는 필터가 무시되게 끔 해둠
    -> 이 필터는 로그인시 토큰을 발급받을때는 무시되고 그 후의 요청시 검증을 위해 사용됨
- 클라이언트가 JWT 토큰을 보내면 해당 필터가 요청을 가로챈다.
- JWT 검증 후 UsernamePasswordAuthenticationToken 토큰(인증용 객체)을 생성
- Authentication 객체를 SecurityContextHolder라는 곳에 저장
========= 프론트에서 JWTFilter가 필요한 이유 =========
프론트에서 API Client로 서버측에 요청을 보낼 때 권한이 필요한 경우 Access 토큰을 요청 헤더에 첨부한다. 이때 요청에 담긴 JWT를 검증하기 위한 JWT 필터를 만들어야
 */
@RequiredArgsConstructor
@Component
public class JwtFilter extends
    OncePerRequestFilter { //OncePerRequestFilter: 요청에 의해서 한번만 동작, override하여 doFilterInternal을 구현함

    private final JwtProvider jwtProvider;
    private final JwtValidator jwtValidator;
    private final JwtErrorResponder jwtErrorResponder;
    // 아래 요청은 filter 를 거치지 않음. - 경로가 추가 될 예정이라 1개여도 List 로 함.
    private static final List<String> EXCLUDE_PATHS = List.of("/auth/**"); //로그인, 회원가입에 필터에 걸리지 않음
    private static final AntPathMatcher pathMatcher = new AntPathMatcher();

    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        String token = HeaderUtil.resolveToken(
            request); //request에서 헤더의 Authorization 검증, 접두사 Bearer 제외하고 실제 Access 토큰 반환

        if (!StringUtils.hasText(token)) { // 빈 문자열("")**이나 공백만 있는 문자열은 false
            jwtErrorResponder.sendErrorResponse(response, ErrorCode.WRONG_AUTH_HEADER);
            return;
        }

        // 검증된 토큰은 사용자 정보로 Authentication 객체를 만들고 강제로 SecurityContextHolder에 세션을 생성
        // 이 세션은 Stateless로 관리되기 때문에 해당 요청이 끝나면 소멸
        try {
            jwtValidator.validateToken(token); // 토큰이 유효한지 검증
            Authentication authentication = jwtProvider.getAuthentication(
                token); // 인증 정보를 추출하여 UsernamePasswordAuthenticationToken형식으로 authentication에 저장
            SecurityContextHolder.getContext().setAuthentication(
                authentication); // 확인된 토큰을 기반으로 SecurityContextHolder에 일시적인 세션을 1개 만들어 authentication(유저 정보)를 일시적으로 저장하여 이 세션을 기반으로 요청을 진행
            filterChain.doFilter(request, response); // 다음 필터로 전달
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