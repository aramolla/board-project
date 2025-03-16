package com.aramolla.jwt.auth.controller;

import com.aramolla.jwt.auth.dto.request.LoginRequest;
import com.aramolla.jwt.auth.dto.request.MemberCreateRequest;
import com.aramolla.jwt.auth.dto.response.AccessTokenResponse;
import com.aramolla.jwt.auth.jwt.dto.MemberTokens;
import com.aramolla.jwt.auth.service.AuthService;
import com.aramolla.jwt.global.response.ResponseData;
import com.aramolla.jwt.global.response.success.SuccessCode;
import com.aramolla.jwt.util.CookieUtil;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;


@RequestMapping("/auth")
@RequiredArgsConstructor
@RestController
@Slf4j
public class AuthController {

    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<ResponseData> signup(@RequestBody MemberCreateRequest request) {
        authService.create(request);
        return ResponseData.success(SuccessCode.CREATED_MEMBER);
    }

    @PostMapping("/login")
    public ResponseEntity<ResponseData<AccessTokenResponse>> login(HttpServletResponse response,
        @RequestBody LoginRequest request) {
        MemberTokens memberTokens = authService.login(request);
        // 같은 이름이 있다면 기존에 있던 쿠키 덮어짐.
        response.addCookie(CookieUtil.createCookie("refresh_token", memberTokens.refreshToken()));

        return ResponseData.success(SuccessCode.LOGIN_SUCCESS,
            new AccessTokenResponse(memberTokens.accessToken()));
    }

    @PostMapping("/reissue")
    public ResponseEntity<ResponseData<AccessTokenResponse>> reissue(HttpServletResponse response,
        @CookieValue("refresh_token") final String refreshTokenRequest) {

        log.info("refresh Token: " + refreshTokenRequest);
        MemberTokens memberTokens = authService.reissue(refreshTokenRequest);
        // 같은 이름이 있다면 기존에 있던 쿠키 덮어짐.
        response.addCookie(CookieUtil.createCookie("refresh_token", memberTokens.refreshToken()));
        return ResponseData.success(SuccessCode.REISSUE_SUCCESS, new AccessTokenResponse(memberTokens.accessToken()));

    }

}