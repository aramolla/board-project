package com.aramolla.jwt.auth.jwt.token;


import com.aramolla.jwt.auth.jwt.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class JwtCleaner {

    private final RefreshTokenRepository refreshTokenRepository;

    public void deleteRefreshToken(Long memberId) {
        refreshTokenRepository.deleteById(memberId);
    }
}