package jbnu.jbnupms.domain.project.dto;

import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
public class ProjectUpdateRequest {

    private String name;
    private String description;
}