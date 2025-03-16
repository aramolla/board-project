package com.aramolla.jwt.auth.oauth2.dto;

import java.util.Map;

public class NaverUserInfo implements OAuth2UserInfo {

    private final Map<String, Object> attribute;

    public NaverUserInfo(Map<String, Object> attribute) {
        // 네이버 데이터 제공 방식은 json응답 방식에 response라는 키 내부에 우리가 원하는 데이터가 들어 있음
        this.attribute = (Map<String, Object>) attribute.get("response");
    }


    @Override
    public String getProvider() {
        return "naver";
    }

    @Override
    public String getProviderId() {
        return attribute.get("id").toString();
    }

    @Override
    public String getEmail() {
        return attribute.get("email").toString();
    }

    @Override
    public String getName() {
        return attribute.get("name").toString();
    }
}
