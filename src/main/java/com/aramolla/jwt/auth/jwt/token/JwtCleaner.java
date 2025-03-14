package com.aramolla.jwt.auth.jwt.token;


import com.aramolla.jwt.auth.jwt.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@RequiredArgsConstructor
public class JwtCleaner {

    private final RefreshTokenRepository refreshTokenRepository;

    @Transactional
    public void deleteRefreshToken(Long memberId) {
        refreshTokenRepository.deleteById(memberId);
    }
}