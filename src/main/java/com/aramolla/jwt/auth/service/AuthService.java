package com.aramolla.jwt.auth.service;


import com.aramolla.jwt.auth.dto.request.LoginRequest;
import com.aramolla.jwt.auth.dto.request.MemberCreateRequest;
import com.aramolla.jwt.auth.jwt.dto.MemberTokens;
import com.aramolla.jwt.auth.jwt.token.JwtCleaner;
import com.aramolla.jwt.auth.jwt.token.JwtProvider;
import com.aramolla.jwt.auth.jwt.token.JwtValidator;
import com.aramolla.jwt.auth.oauth2.domain.SocialType;
import com.aramolla.jwt.member.domain.Member;
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
            .socialType(SocialType.LOCAL)
            .build();

        memberRepository.save(member);
    }

    @Transactional
    public MemberTokens login(LoginRequest request) {
        // 1. 이메일 및 비밀번호 유효성 검증
        // 2. AT, RT 발급
        Member member = memberService.validateLogin(request.email(), request.password());

        return jwtProvider.createTokensAndSaveRefreshToken(
            member.getEmail(),
            member.getRole()
        );
    }

    public MemberTokens reissue(String refreshToken) {

        // AT 재발급시 RT도 재발급(일회성)
        // -> 공격자가 탈취 후 새로 발급 받은 후 사용자가 재발급했을 때 DB RT와 사용자 RT가 다르기에 탈취 간주로 둘 다 폐기.
        MemberTokens memberTokens = jwtProvider.reissueToken(refreshToken);

        log.info("service accessToken: " + memberTokens.accessToken());
        log.info("service refreshToken: " + memberTokens.refreshToken());
        return memberTokens;
    }


}