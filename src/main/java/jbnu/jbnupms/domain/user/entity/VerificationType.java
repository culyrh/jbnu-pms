package jbnu.jbnupms.domain.user.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum VerificationType {
    REGISTER("REGISTER", "회원가입"),
    PASSWORD_RESET("PASSWORD_RESET", "비밀번호 재설정");

    private final String key;
    private final String description;
}