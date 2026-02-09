package jbnu.jbnupms.domain.project.dto;

import jakarta.validation.constraints.NotNull;
import jbnu.jbnupms.domain.project.entity.ProjectRole;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class ProjectRoleUpdateRequest {

    @NotNull(message = "역할은 필수입니다.")
    private ProjectRole role;
}
