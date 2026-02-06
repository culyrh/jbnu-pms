package jbnu.jbnupms.common.audit;

public enum UserAuditAction {
    REGISTER,           // 회원가입
    UPDATE_PROFILE,     // 프로필 업데이트
    CHANGE_PASSWORD,    // 비밀번호 변경
    DELETE,             // 회원 탈퇴
    ADMIN_UPDATE        // 관리자에 의한 정보 수정
}