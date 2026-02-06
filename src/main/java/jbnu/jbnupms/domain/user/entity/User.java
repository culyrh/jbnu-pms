package jbnu.jbnupms.domain.user.entity;

import jakarta.persistence.*;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

@Entity
@Table(name = "users", indexes = {
        @Index(name = "idx_user_email", columnList = "email")
})
@EntityListeners(AuditingEntityListener.class)
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 100, unique = true)
    private String email;

    @Column(length = 60)
    private String password;

    @Column(nullable = false, length = 50)
    private String name;

    @Column(length = 1000)
    private String profileImage;

    @Column(length = 10, nullable = false)
    private String provider = "EMAIL";

    @Column(length = 255)
    private String providerId;

    @Column(nullable = false)
    private Boolean isDeleted = false;

    @Builder
    public User(String email, String password, String name, String profileImage, String provider, String providerId) {
        this.email = email;
        this.password = password;
        this.name = name;
        this.profileImage = profileImage;
        this.provider = provider != null ? provider : "EMAIL";
        this.providerId = providerId;
        this.isDeleted = false;
    }

    // 정보 수정을 위한 메서드
    public void updateName(String name) {
        this.name = name;
    }

    public void updatePassword(String password) {
        this.password = password;
    }

    public void updateProfileImage(String profileImage) {
        this.profileImage = profileImage;
    }

    public void softDelete() {
        this.isDeleted = true;
    }

    public void restore() {
        this.isDeleted = false;
    }
}