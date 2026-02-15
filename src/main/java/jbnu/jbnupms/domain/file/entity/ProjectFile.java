package jbnu.jbnupms.domain.file.entity;

import jakarta.persistence.*;
import jbnu.jbnupms.domain.project.entity.Project;
import jbnu.jbnupms.domain.user.entity.User;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "project_files", indexes = {
        @Index(name = "idx_project_file_task_file_id", columnList = "task_file_id")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ProjectFile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "project_id", nullable = false)
    private Project project;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "uploader_id", nullable = false)
    private User uploader;

    @Column(name = "task_file_id")
    private Long taskFileId;  // 태스크 파일에서 생성된 경우 해당 task_file의 ID 저장

    @Column(nullable = false, length = 255)
    private String fileName;

    @Column(nullable = false, length = 2048)
    private String fileUrl;

    private Long fileSize;

    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name = "is_deleted", nullable = false)
    private Boolean isDeleted = false;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        if (this.isDeleted == null) {
            this.isDeleted = false;
        }
    }

    @Builder
    public ProjectFile(Project project, User uploader, String fileName, String fileUrl, Long fileSize, Long taskFileId) {
        this.project = project;
        this.uploader = uploader;
        this.fileName = fileName;
        this.fileUrl = fileUrl;
        this.fileSize = fileSize;
        this.taskFileId = taskFileId;
    }

    public void softDelete() {
        this.isDeleted = true;
    }

    public boolean isUploader(Long userId) {
        return this.uploader.getId().equals(userId);
    }

    public boolean isFromTaskFile() {
        return this.taskFileId != null;
    }
}