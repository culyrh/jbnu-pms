package jbnu.jbnupms.domain.user.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class EmailCheckResponse {
    private boolean available; // 사용 가능 여부
    private String message;

    public static EmailCheckResponse available() {
        return new EmailCheckResponse(true, "사용 가능한 이메일입니다.");
    }

    public static EmailCheckResponse unavailable() {
        return new EmailCheckResponse(false, "이미 사용 중인 이메일입니다.");
    }
}