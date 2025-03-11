package com.aramolla.jwt.member.service;

import com.aramolla.jwt.member.domain.Member;
import com.aramolla.jwt.member.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class MemberService { // 로그인 process

    private final MemberRepository memberRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public Member validateLogin(String email, String password) {
        Member member = validateMember(email);
        validatePassword(password,member.getPassword());
        return member;
    }

    private Member validateMember(String email) { //email 중복
        return memberRepository.findByEmail(email)
            .orElseThrow(() -> new IllegalArgumentException("존재하지 않는 회원입니다."));
    }

    private void validatePassword(String rawPassword, String encryptedPassword) { // passwoed확인
        // mathes(평문 패스워드, 암호화 패스워드) 순서로 해야 됨.
        if (!bCryptPasswordEncoder.matches(rawPassword, encryptedPassword)) {
            throw new IllegalArgumentException("옳바르지 않은 비밀번호입니다.");
        }
    }

}