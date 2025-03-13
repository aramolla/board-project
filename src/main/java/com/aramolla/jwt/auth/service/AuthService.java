package com.aramolla.jwt.auth.service;


import com.aramolla.jwt.auth.dto.request.LoginRequest;
import com.aramolla.jwt.auth.jwt.dto.MemberTokens;
import com.aramolla.jwt.auth.jwt.token.JwtCleaner;
import com.aramolla.jwt.auth.jwt.token.JwtProvider;
import com.aramolla.jwt.auth.jwt.token.JwtValidator;
import com.aramolla.jwt.member.domain.Member;
import com.aramolla.jwt.auth.dto.request.MemberCreateRequest;
import com.aramolla.jwt.member.repository.MemberRepository;
import com.aramolla.jwt.member.service.MemberService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor // final 이 붙은 필드들만 자동으로 생성자 주입을 만들어줌
@Slf4j //log.info(), log.error() 같은 로그 기능을 사용할 수 있도록 지원
public class AuthService {

    private final MemberService memberService;
    private final MemberRepository memberRepository;
    private final JwtProvider jwtProvider;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final JwtValidator jwtValidator;
    private final JwtCleaner jwtCleaner;

    public void create(MemberCreateRequest request) {
        // 1. 회원 id && nickname 존재 하는지 확인한다.
        if (memberRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("존재하는 이메일 입니다." + request.email());
        }
        Member member = Member.builder()
            .email(request.email())
            .password(bCryptPasswordEncoder.encode(request.password()))
            .build();

        memberRepository.save(member);
    }

    @Transactional
    public MemberTokens login(LoginRequest request) {
        // 1. 이메일 및 비밀번호 유효성 검증
        // 2. AT, RT 발급
        Member member = memberService.validateLogin(request.email(), request.password());

        return jwtProvider.createTokensAndSaveRefreshToken(
            member.getId(),
            member.getRole().getDisplayName()
        );
    }

    public MemberTokens reissue(String refreshToken) {

        jwtValidator.validateToken(refreshToken);
        Long memberId = jwtValidator.getMemberIdFromToken(refreshToken);
        String role = jwtValidator.getRoleFromToken(refreshToken);

        // TODO: redis에 저장되어있는 AT 유효성 체크 및 RT 변조 체크

        jwtCleaner.deleteRefreshToken(memberId);     // refresh token 은 일회용이라 삭제
        MemberTokens memberTokens = jwtProvider.createTokensAndSaveRefreshToken(memberId, role);// access token & refresh token 재발급
        log.info("memberTokens: " + memberTokens.accessToken());
        log.info("memberTokens: " + memberTokens.refreshToken());
        return memberTokens;
    }



}