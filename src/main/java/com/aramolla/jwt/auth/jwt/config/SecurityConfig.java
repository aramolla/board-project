package com.aramolla.jwt.auth.jwt.config;

import com.aramolla.jwt.auth.jwt.filter.JwtFilter;
import com.aramolla.jwt.auth.jwt.handler.JwtAccessDeniedHandler;
import com.aramolla.jwt.auth.jwt.handler.JwtAuthenticationEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    private final JwtFilter jwtFilter;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
    private final String[] adminUrl = {"/admin/**"};
    private final String[] permitAllUrl = {"/", "/error", "/auth/**"};
    private final String[] hasRoleUrl = {"/posts/**", "/members/**"};

    // TODO: 전부 다 찾아보세요.
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
            .csrf((auth) -> auth.disable())  // jwt를 이용한 Stateless 방식으로 사용하가에 csrf disable
            .formLogin((auth) -> auth.disable())    //From 로그인 방식 disable
            .httpBasic((auth) -> auth.disable())       //HTTP Basic 인증 방식 disable
            .sessionManagement((session) -> session       //세션 설정 : STATELESS - jwt 방식 사용할 경우
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        //경로별 인가 작업
        http
            .authorizeHttpRequests((auth) -> auth
                .requestMatchers(permitAllUrl).permitAll() //모두 허용
                .requestMatchers(adminUrl).hasRole("ADMIN") //
                .requestMatchers(hasRoleUrl).hasAnyRole("ADMIN", "MEMBER")
                .anyRequest().authenticated());
        // 1번째 인자 위치의 필터를 2번쨰 인자 필터 앞에 등록.
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

}