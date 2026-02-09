package jbnu.jbnupms.domain.project.dto;

import jbnu.jbnupms.domain.project.entity.Project;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
public class ProjectResponse {

    private Long id;
    private Long spaceId;
    private String name;
    private String description;
    private Double progress;
    private LocalDateTime updatedAt;

    public static ProjectResponse from(Project project) {
        return ProjectResponse.builder()
                .id(project.getId())
                .spaceId(project.getSpace().getId())
                .name(project.getName())
                .description(project.getDescription())
                .progress(project.getProgress())
                .updatedAt(project.getUpdatedAt())
                .build();
    }
}
