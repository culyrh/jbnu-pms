package jbnu.jbnupms.domain.user.repository;

import jbnu.jbnupms.domain.user.entity.WithdrawnUser;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface WithdrawnUserRepository extends JpaRepository<WithdrawnUser, Long> {

    // 이메일로 탈퇴 회원 조회 (재가입 제한 확인용)
    Optional<WithdrawnUser> findByEmail(String email);

    // 보관 기간이 지난 데이터 배치 삭제용 (3년)
    @Query("SELECT w FROM WithdrawnUser w WHERE w.deletedDate <= :now")
    List<WithdrawnUser> findExpiredWithdrawnUsers(LocalDateTime now);

}