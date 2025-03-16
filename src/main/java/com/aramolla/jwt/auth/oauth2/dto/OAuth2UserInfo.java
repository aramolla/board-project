package com.aramolla.jwt.auth.oauth2.dto;

//사용할 설정 이름값들 정의해두기
public interface OAuth2UserInfo {

    //제공자 (Ex. naver, google, ...)
    String getProvider();
    //제공자에서 발급해주는 아이디(번호)
    String getProviderId();
    //이메일
    String getEmail();
    //사용자 실명 (설정한 이름)
    String getName();

}
