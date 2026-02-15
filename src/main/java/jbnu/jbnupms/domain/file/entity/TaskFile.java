package jbnu.jbnupms.domain.file.entity;

import jakarta.persistence.*;
import jbnu.jbnupms.domain.project.entity.Project;
import jbnu.jbnupms.domain.task.entity.Task;
import jbnu.jbnupms.domain.user.entity.User;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "task_files", indexes = {
        @Index(name = "idx_task_file_task_id", columnList = "task_id"),
        @Index(name = "idx_task_file_project_id", columnList = "project_id")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class TaskFile {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "task_id", nullable = false)
    private Task task;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "project_id", nullable = false)
    private Project project;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "uploader_id", nullable = false)
    private User uploader;

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
    public TaskFile(Task task, Project project, User uploader, String fileName, String fileUrl, Long fileSize) {
        this.task = task;
        this.project = project;
        this.uploader = uploader;
        this.fileName = fileName;
        this.fileUrl = fileUrl;
        this.fileSize = fileSize;
    }

    public void softDelete() {
        this.isDeleted = true;
    }

    public boolean isUploader(Long userId) {
        return this.uploader.getId().equals(userId);
    }
}