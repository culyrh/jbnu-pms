package jbnu.jbnupms.domain.user.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "withdrawn_users", indexes = {
        @Index(name = "idx_withdrawn_email", columnList = "email"),
        @Index(name = "idx_deleted_date", columnList = "deletedDate")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class WithdrawnUser {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100)
    private String email;

    @Column(columnDefinition = "TEXT")
    private String reason;

    @Column(nullable = false)
    private LocalDateTime withdrawnAt;

    @Column(nullable = false)
    private LocalDateTime deletedDate;

    @Builder
    public WithdrawnUser(String email, String reason) {
        this.email = email;
        this.reason = reason;
        this.withdrawnAt = LocalDateTime.now();
        // 법적 보관 기간 3년 후 삭제 예정
        this.deletedDate = LocalDateTime.now().plusYears(3);
    }
}