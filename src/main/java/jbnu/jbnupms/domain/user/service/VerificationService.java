package jbnu.jbnupms.domain.user.service;

import jbnu.jbnupms.common.exception.CustomException;
import jbnu.jbnupms.common.exception.ErrorCode;
import jbnu.jbnupms.domain.user.entity.VerificationCode;
import jbnu.jbnupms.domain.user.entity.VerificationType;
import jbnu.jbnupms.domain.user.repository.UserRepository;
import jbnu.jbnupms.domain.user.repository.VerificationCodeRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Random;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class VerificationService {

    private final VerificationCodeRepository verificationCodeRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;

    private static final int CODE_LENGTH = 6;
    private static final long CODE_EXPIRATION_SECONDS = 300L; // 5분

    /**
     * 인증 코드 발송
     */
    @Transactional
    public void sendVerificationCode(String email, VerificationType type) {
        // 회원가입 인증의 경우 이미 가입된 이메일인지 확인
        if (type == VerificationType.REGISTER && userRepository.existsByEmail(email)) {
            throw new CustomException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }

        // 비밀번호 재설정의 경우 가입된 이메일인지 확인
        if (type == VerificationType.PASSWORD_RESET && !userRepository.existsByEmail(email)) {
            throw new CustomException(ErrorCode.EMAIL_NOT_FOUND);
        }

        // 기존 인증 코드 삭제
        verificationCodeRepository.deleteByEmailAndType(email, type);

        // 6자리 랜덤 코드 생성
        String code = generateCode();

        // 인증 코드 저장 (Redis)
        VerificationCode verificationCode = VerificationCode.builder()
                .id(email + ":" + type.name())
                .email(email)
                .code(code)
                .type(type)
                .verified(false)
                .createdAt(LocalDateTime.now())
                .expiration(CODE_EXPIRATION_SECONDS)
                .build();

        verificationCodeRepository.save(verificationCode);

        // 이메일 발송
        emailService.sendVerificationEmail(email, code, type);

        log.info("Verification code sent: email={}, type={}", email, type);
    }

    /**
     * 인증 코드 확인 (선택적 - 프론트에서 즉시 피드백용)
     */
    @Transactional
    public void verifyCode(String email, String code, VerificationType type) {
        VerificationCode verificationCode = verificationCodeRepository
                .findByEmailAndType(email, type)
                .orElseThrow(() -> new CustomException(ErrorCode.VERIFICATION_CODE_NOT_FOUND));

        // 코드 일치 확인
        if (!verificationCode.getCode().equals(code)) {
            throw new CustomException(ErrorCode.VERIFICATION_CODE_MISMATCH);
        }

        // 이미 인증된 코드인 경우
        if (verificationCode.isVerified()) {
            log.info("Code already verified: email={}, type={}", email, type);
            return;
        }

        // 인증 완료 처리
        verificationCode.verify();
        verificationCodeRepository.save(verificationCode);

        log.info("Verification code verified: email={}, type={}", email, type);
    }

    /**
     * 인증 완료 여부 확인 (회원가입/비밀번호 재설정 시 호출)
     */
    public void validateVerification(String email, String code, VerificationType type) {
        VerificationCode verificationCode = verificationCodeRepository
                .findByEmailAndType(email, type)
                .orElseThrow(() -> new CustomException(ErrorCode.VERIFICATION_CODE_NOT_FOUND));

        // 코드 일치 확인
        if (!verificationCode.getCode().equals(code)) {
            throw new CustomException(ErrorCode.VERIFICATION_CODE_MISMATCH);
        }

        // 인증 완료 여부 확인
        if (!verificationCode.isVerified()) {
            throw new CustomException(ErrorCode.VERIFICATION_NOT_COMPLETED);
        }
    }

    /**
     * 인증 완료 후 삭제 (회원가입/비밀번호 재설정 완료 시)
     */
    @Transactional
    public void deleteVerificationCode(String email, VerificationType type) {
        // ID를 직접 구성하여 즉시 삭제
        // 저장할 때의 ID 규칙: email + ":" + type.name()
        String id = email + ":" + type.name();

        verificationCodeRepository.deleteById(id);

        log.info("Verification code deleted: email={}, type={}", email, type);
    }

    /**
     * 6자리 랜덤 코드 생성
     */
    private String generateCode() {
        Random random = new Random();
        int code = 100000 + random.nextInt(900000);
        return String.valueOf(code);
    }
}