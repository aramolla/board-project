package com.aramolla.jwt.auth.oauth2.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import lombok.Getter;

@Getter
public enum SocialType {
    GOOGLE, NAVER, LOCAL;

    @JsonCreator // JSON 역직렬화
    public static SocialType from(String value) {
        return SocialType.valueOf(value.toUpperCase());
    }

}