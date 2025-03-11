package com.aramolla.jwt.auth.dto.request;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class MemberCreateRequest {

    private String email;
    private String password;

}