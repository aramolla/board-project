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
    private final String[] permitAllUrl = {"/", "/error", "/auth/**"};
    private final String[] hasRoleUrl = {"/posts/**", "/members/**"};

    // TODO: 전부 다 찾아보세요.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        /*
        (jwt 방식 사용할 경우)
        - csrf를 disable설정
            -> 세션 방식에서는 세션이 계속 고정이라 csrf공격 방어가 필수적임
            -> jwt는 세션을 Stateless 방식으로 사용하기에 csrf disable
        - From 로그인 방식 disable
        - HTTP Basic 인증 방식 disable
        - Session 설정 STATELESS
         */
        http
            .csrf((auth) -> auth.disable())
            .formLogin((auth) -> auth.disable())
            .httpBasic((auth) -> auth.disable())
            .sessionManagement((session) -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .cors((cors) -> cors.configurationSource(getCorsConfiguration())); // cors 설정 추가

        //oauth2
        // customOAuth2UserService을 등록하여 리소스서버(google, naver의 사용자 정보 API)에서 데이터를 받아 OAuth2UserService에 데이터를 집어넣어줌
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
                .requestMatchers(permitAllUrl).permitAll() //모두 허용
                .requestMatchers(adminUrl).hasRole("ADMIN") //
                .requestMatchers(hasRoleUrl).hasAnyRole("ADMIN", "MEMBER")
                .anyRequest().authenticated()); //다른 요청들은 로그인한 사용자들만 접근할 수 있게 설정

        // 필터 추가 - jwtFilter를 UsernamePasswordAuthenticationFilter전에 등록하여 로그인 요펑을 가로채게 함
        http
            .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class);
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