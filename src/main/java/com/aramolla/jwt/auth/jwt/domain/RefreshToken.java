package com.aramolla.jwt.auth.jwt.domain;

import com.aramolla.jwt.member.domain.Role;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@Entity
public class RefreshToken {

    @Id
    private Long memberId;

    @Column(name = "refreshtoken", nullable = false)
    private String refreshToken;

    @Column(name = "role", nullable = false)
    @Enumerated(EnumType.STRING)
    private Role role;

    @Builder(builderClassName = "SaveBuilder", builderMethodName = "builder")
    public RefreshToken(
        String refreshToken,
        Long memberId,
        Role role
    ) {
        this.refreshToken = refreshToken;
        this.memberId = memberId;
        this.role = role;
    }

}


