package jbnu.jbnupms.domain.space.entity;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum SpaceRole {

    ADMIN("ADMIN", "스페이스 관리자"),
    MEMBER("MEMBER", "일반 멤버");

    private final String key;
    private final String description;
}
