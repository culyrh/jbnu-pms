package jbnu.jbnupms.domain.user.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;
import org.springframework.data.redis.core.TimeToLive;
import org.springframework.data.redis.core.index.Indexed;

import java.io.Serializable;
import java.time.LocalDateTime;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@RedisHash(value = "verification_code", timeToLive = 300)
public class VerificationCode implements Serializable {  // Serializable 구현

    @Id
    private String id; // email:type 형태 (예: "user@example.com:REGISTER")

    @Indexed
    private String email;

    private String code; // 6자리 인증 코드

    @Indexed  // type도 인덱싱
    private VerificationType type; // REGISTER, PASSWORD_RESET

    private boolean verified; // 인증 완료 여부

    private LocalDateTime createdAt;

    @TimeToLive
    private Long expiration; // 초 단위 (5분 = 300초)

    public void verify() {
        this.verified = true;
    }
}