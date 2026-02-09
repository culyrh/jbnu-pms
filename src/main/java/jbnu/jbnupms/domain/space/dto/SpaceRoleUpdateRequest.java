package jbnu.jbnupms.domain.space.dto;

import jakarta.validation.constraints.NotNull;
import jbnu.jbnupms.domain.space.entity.SpaceRole;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class SpaceRoleUpdateRequest {

    @NotNull(message = "역할은 필수입니다.")
    private SpaceRole role;
}
