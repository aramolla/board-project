package com.aramolla.jwt.member.domain;

import com.aramolla.jwt.auth.oauth2.domain.SocialType;
import com.aramolla.jwt.global.domain.BaseEntity;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

//JPA는 기본 생성자를 필요로 하지만, 우리는 불필요한 외부 객체 생성을 막고 싶을 때 protected 기본 생성자를 사용

@Entity
@NoArgsConstructor(access = AccessLevel.PROTECTED) //매게변수가 없는 기본생성자를 생, 생성자 protect권한으로 설정
@Getter
public class Member extends BaseEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id", updatable = false)
    private long id;

    @Column(name = "name", nullable = true) // LOCAL 회원가입 로직에 추가하고 nullable-false로 바꾸기
    private String name;

    @Column(name = "email", updatable = true, unique = true) // 소셜일 경우 - naver dkfk1640@naver.com
    private String email;

    @Column(name = "password")
    private String password;

    @Column(name = "role", nullable = false)
    @Enumerated(EnumType.STRING)
    private Role role;

    // OAuth2
    @Column(name = "social_type",nullable = false)
    @Enumerated(EnumType.STRING)
    private SocialType socialType; // TODO: 일반 로그인일 경우 Local

    @Column(name = "social_login_id",unique = true ,nullable = true)
    private String socialLoginId;

    //@AllArgsConstructor대신 필요항것만 builder로 생성자 만듬
    @Builder // JPA에서 NoArgsConstructor같은 빈 생성자가 없으면 에러 남
    public Member(
        String name,
        String email,
        String password,
        SocialType socialType,
        String socialLoginId
    ) {
        this.name = name;
        this.email = email;
        this.password = password;
        this.role = Role.MEMBER; // 기본값으로 'MEMBER'
        this.socialType = socialType;
        this.socialLoginId = socialLoginId;
    }

    public void updateUsername(String username) {
        this.email = username;
    }

    public void updatename(String nickname) {
        this.name = nickname;
    }

}