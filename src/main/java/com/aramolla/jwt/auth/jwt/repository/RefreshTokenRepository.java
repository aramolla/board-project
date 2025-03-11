package com.aramolla.jwt.auth.jwt.repository;

import com.aramolla.jwt.auth.jwt.domain.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

}