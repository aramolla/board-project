package com.aramolla.jwt.auth.oauth2.dto;

import com.aramolla.jwt.member.domain.Member;
import com.aramolla.jwt.member.domain.Role;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.OAuth2User;

public class CustomOAuth2User implements OAuth2User {

    private final Member member;
    private final Map<String, Object> attributes;

    public CustomOAuth2User(Member member, Map<String, Object> attributes) {
        this.member = member;
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> collection = new ArrayList<>();
        collection.add(new GrantedAuthority() {

            @Override
            public String getAuthority() {
                return member.getRole().getCode();
            }
        });
        return collection;
    }

    @Override
    public String getName() {
        return member.getName();
    }
    public String getUsername() {
        return member.getEmail();
    }

    public Long getId() {
        return member.getId();
    }

    public Role getrole(){
        return member.getRole();
    }

}
