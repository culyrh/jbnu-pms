package jbnu.jbnupms.domain.user.repository;

import jbnu.jbnupms.domain.user.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {

    Optional<RefreshToken> findByUserId(Long userId);

    @Transactional
    @Modifying
    void deleteByUserId(Long userId);

    // 유효한 토큰만 조회 (토큰으로)
    @Query("SELECT rt FROM RefreshToken rt " +
            "WHERE rt.token = :token AND rt.expiresAt > :now")
    Optional<RefreshToken> findValidTokenByToken(
            @Param("token") String token,
            @Param("now") LocalDateTime now
    );

    // 유효한 토큰만 조회 (userId로)
    @Query("SELECT rt FROM RefreshToken rt " +
            "WHERE rt.userId = :userId AND rt.expiresAt > :now")
    Optional<RefreshToken> findValidTokenByUserId(
            @Param("userId") Long userId,
            @Param("now") LocalDateTime now
    );

    // UPSERT 추가
    @Transactional
    @Modifying
    @Query(value =
            "INSERT INTO refresh_tokens (user_id, token, expires_at, created_at) " +
                    "VALUES (:userId, :token, :expiresAt, :createdAt) " +
                    "ON CONFLICT (user_id) " +
                    "DO UPDATE SET " +
                    "token = EXCLUDED.token, " +
                    "expires_at = EXCLUDED.expires_at",
            nativeQuery = true)
    void upsertRefreshToken(
            @Param("userId") Long userId,
            @Param("token") String token,
            @Param("expiresAt") LocalDateTime expiresAt,
            @Param("createdAt") LocalDateTime createdAt
    );
}
