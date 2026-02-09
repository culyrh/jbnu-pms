package jbnu.jbnupms.domain.project.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum ProjectRole {
    ADMIN("ADMIN", "프로젝트 관리자"),
    MEMBER("MEMBER", "일반 멤버"),
    VIEWER("VIEWER", "읽기 전용 (참관자)");

    private final String key;
    private final String description;
}