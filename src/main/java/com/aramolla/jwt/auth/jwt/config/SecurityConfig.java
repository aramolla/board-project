package com.aramolla.jwt.auth.jwt.config;

import com.aramolla.jwt.auth.jwt.filter.JwtFilter;
import com.aramolla.jwt.auth.jwt.handler.JwtAccessDeniedHandler;
import com.aramolla.jwt.auth.jwt.handler.JwtAuthenticationEntryPoint;
import com.aramolla.jwt.auth.oauth2.handler.CustomFailureHandler;
import com.aramolla.jwt.auth.oauth2.handler.CustomSuccessHandler;
import com.aramolla.jwt.auth.oauth2.service.CustomOAuth2UserService;
import java.util.Collections;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;


@Configuration
@RequiredArgsConstructor
@EnableWebSecurity //security를 위한 config
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private final JwtFilter jwtFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final CustomSuccessHandler customSuccessHandler;
    private final CustomFailureHandler customFailureHandler;
    private final String[] adminUrl = {"/admin/**"};
    private final String[] permitAllUrl = {"/", "/error", "/auth/**", "/connect/**"};
    private final String[] hasRoleUrl = {"/posts/**", "/members/**"};

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        /*
        [Spring Security 필터 체인 순서]
        - CORS 필터 (CorsFilter): 특정 도메인에서 요청 허용
        - Exception Handling 필터 (JwtAuthenticationEntryPoint, JwtAccessDeniedHandler): 인증 실패 시 401(Unauthorized), 권한 없는 요청 시 403(Forbidden) 응답 처리
        - JWT 필터 (JwtFilter)
        - FilterSecurityInterceptor → permitAll(), hasRole() 등 접근 권한을 체크
        - OAuth2 로그인 필터 (OAuth2LoginAuthenticationFilter): OAuth2 인증을 사용하여 사용자 정보를 가져옴
        - 인가(Authorization) 필터
        */


        http // CSRF 필터, From 로그인 방식, HTTP Basic 인증 방식 비활성화, Session 설정 STATELESS
            .csrf((auth) -> auth.disable())
            .formLogin((auth) -> auth.disable())
            .httpBasic((auth) -> auth.disable())
            .sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .cors((cors) -> cors.configurationSource(getCorsConfiguration())); // cors 설정 추가

        //oauth2 - 벡엔드에서 모든 책임을 지는 방식으로 인증서버, 리소스서버 모두 벡엔드에서 갔다옴
        http
            .oauth2Login((oauth2) -> oauth2
                .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig
                    .userService(customOAuth2UserService))
                .successHandler(customSuccessHandler) // 로그인 성공 시 실행 핸들러
                .failureHandler(customFailureHandler) // 로그인 실패 시 실행 핸들러
            );

        //경로별 인가 작업
        http
            .authorizeHttpRequests((auth) -> auth
                .requestMatchers(permitAllUrl).permitAll() //  인가(Authorization) 검사를 건너뜀, 따라서 인증(Authentication)도 필요 없음
                .requestMatchers(adminUrl).hasRole("ADMIN")
                .requestMatchers(hasRoleUrl).hasAnyRole("ADMIN", "MEMBER")
                .anyRequest().authenticated());

        // 필터 추가
        http
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class); // UsernamePasswordAuthenticationFilter - 폼 로그인 방식을 사용하지 않으므로, 이 필터는 사용되지 않음.
        // 예외 처리 등록
        http
            .exceptionHandling(handle -> handle
                .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                .accessDeniedHandler(jwtAccessDeniedHandler)
            );

        return http.build();
    }

    //cors 설정 내용
    @Bean
    public CorsConfigurationSource getCorsConfiguration() {
        CorsConfiguration configuration = new CorsConfiguration();

        configuration.setAllowedOrigins(Collections.singletonList("http://localhost:3000"));
        configuration.setAllowedMethods(Collections.singletonList("*"));
        configuration.setAllowCredentials(true);
        configuration.setAllowedHeaders(Collections.singletonList("*")); // 사용할 header
        configuration.setMaxAge(3600L); // 허용 시간

        // 클라이언트로 헤더를 보낼때 Authorization형식으로 jwt를 넣어서 보내주기 때문에 Authorization형식 허용
        configuration.setExposedHeaders(Collections.singletonList("Authorization"));

        // URL 패턴에 따라 CORS 설정을 관리
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration); // 모든 URL 패턴 정의된 CORS 설정을 적용
        return source;

    }

}