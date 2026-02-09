package jbnu.jbnupms.domain.space.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class SpaceUpdateRequest {
    @NotBlank(message = "스페이스 이름은 필수입니다.")
    private String name;
    private String description;
}
