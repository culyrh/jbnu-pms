package jbnu.jbnupms.domain.user.service;

import jbnu.jbnupms.common.audit.UserAuditLogger;
import jbnu.jbnupms.common.exception.CustomException;
import jbnu.jbnupms.common.exception.ErrorCode;
import jbnu.jbnupms.domain.user.dto.RefreshTokenRequest;
import jbnu.jbnupms.security.jwt.JwtTokenProvider;
import jbnu.jbnupms.domain.user.dto.LoginRequest;
import jbnu.jbnupms.domain.user.dto.RegisterRequest;
import jbnu.jbnupms.domain.user.dto.TokenResponse;
import jbnu.jbnupms.domain.user.entity.RefreshToken;
import jbnu.jbnupms.domain.user.entity.User;
import jbnu.jbnupms.domain.user.repository.RefreshTokenRepository;
import jbnu.jbnupms.domain.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class AuthService {

    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtTokenProvider jwtTokenProvider;
    private final UserAuditLogger auditLogger;

    @Transactional
    public Long register(RegisterRequest request) {
        // 이메일 중복 확인
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new CustomException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }

        // 빌더 패턴 (엔티티 전체를 호출하지 않기 위해)
        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .name(request.getName())
                .provider("EMAIL")
                .build();

        User savedUser = userRepository.save(user);

        // 감사 로그 기록
        // todo (1): (예정) 레벨을 나눠서 원인 별로 로깅 기록 추가 (ip에서 로그인 시도/실패 기록) - 어노테이션 활용
        auditLogger.logRegister(
                savedUser.getId(),
                savedUser.getEmail(),
                savedUser.getName(),
                savedUser.getProvider()
        );

        return savedUser.getId();
    }

    // [V] email 중복 확인 조건문 제거
    // [V] 에러코드 반환 시에 아이디/패스워드 중 어떤게 틀렸는지 구분 필요
    @Transactional
    public TokenResponse login(LoginRequest request) {
        // 이메일/패스워드 불일치 구분
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new CustomException(ErrorCode.EMAIL_NOT_FOUND));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new CustomException(ErrorCode.INVALID_PASSWORD);
        }

        // Access Token은 항상 새로 생성
        String accessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getEmail());

        // Refresh Token 처리 (고정 만료 방식)
        String refreshToken = handleRefreshToken(user.getId());

        return TokenResponse.of(accessToken, refreshToken);
    }

    // [V] refresh token 전달 방식 (string-> request 객체)
    @Transactional
    public TokenResponse refresh(RefreshTokenRequest request) {
        // [V] : db단에서 쿼리문으로 조회하도록 수정 (만료 확인 로직 제거)
        // (EXPIRED_REFRESH_TOKEN 에러로 리프레시 토큰 만료가 확인되면 프론트에서 로그인 페이지로 유도합니다)
        RefreshToken refreshToken = refreshTokenRepository
                .findValidTokenByToken(request.getRefreshToken(), LocalDateTime.now())
                .orElseThrow(() -> new CustomException(ErrorCode.EXPIRED_REFRESH_TOKEN));

        // refresh token에 이메일이 포함되지 않으므로 access token 생성에 필요한 이메일을 User로 조회
        User user = userRepository.findActiveById(refreshToken.getUserId())
                .orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_FOUND));

        // access token만 새로 생성
        String newAccessToken = jwtTokenProvider.generateAccessToken(user.getId(), user.getEmail());

        return TokenResponse.of(newAccessToken, refreshToken.getToken());
    }

    // todo (6) (예정) : Redis 블랙리스트로 access token 무효화 구현하여 로그아웃
    //  -> [V] 액세스 토큰 만료시간 5분으로 수정
    //  -> accesstoken이 만료되지 않은 상황에서 계속 재사용 될 수 있는 상황
    @Transactional
    public void logout(Long userId) {
        log.info("User logged out: userId={}", userId);
    }

    /**
     * Refresh Token 처리 (고정 만료 방식 - 7일)
     * 1. 기존 토큰 유효하면 재사용
     * 2. 없거나 만료되었으면 새로 생성
     */
    // [V] 토큰이 만료된 경우와 토큰이 처음 생성되는 경우 모두를 포함하여 UPSERT 쿼리 하나로 처리
    // -> UPSERT 적용을 위해 refresh token의 user_id 필드에 unique 조건이 추가됨
    private String handleRefreshToken(Long userId) {
        return refreshTokenRepository
                .findValidTokenByUserId(userId, LocalDateTime.now())
                .map(RefreshToken::getToken)
                .orElseGet(() -> {
                    String newRefreshToken = jwtTokenProvider.generateRefreshToken(userId);

                    // UPSERT: 있으면 UPDATE, 없으면 INSERT (한 번의 쿼리)
                    refreshTokenRepository.upsertRefreshToken(
                            userId,
                            newRefreshToken,
                            LocalDateTime.now().plusDays(7),
                            LocalDateTime.now()
                    );

                    return newRefreshToken;
                });
    }
}