package jbnu.jbnupms.domain.space.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jbnu.jbnupms.domain.space.entity.SpaceRole;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class SpaceInviteRequest {

    @NotBlank(message = "이메일은 필수입니다.")
    @Email(message = "올바른 이메일 형식이 아닙니다.")
    private String email;

    private SpaceRole role; // null이면 기본값 MEMBER
}
