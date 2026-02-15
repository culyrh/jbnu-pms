package jbnu.jbnupms.domain.file.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jbnu.jbnupms.domain.file.entity.ProjectFile;
import jbnu.jbnupms.domain.file.entity.TaskFile;
import lombok.Builder;
import lombok.Getter;

import java.time.LocalDateTime;

@Getter
@Builder
@Schema(description = "파일 응답")
public class FileResponse {

    @Schema(description = "파일 ID", example = "1")
    private Long id;

    @Schema(description = "파일명", example = "document.pdf")
    private String fileName;

    @Schema(description = "파일 URL", example = "https://s3.amazonaws.com/bucket/file.pdf")
    private String fileUrl;

    @Schema(description = "파일 크기 (Byte)", example = "1024000")
    private Long fileSize;

    @Schema(description = "업로더 ID", example = "1")
    private Long uploaderId;

    @Schema(description = "업로더 이름", example = "홍길동")
    private String uploaderName;

    @Schema(description = "업로더 이메일", example = "user@example.com")
    private String uploaderEmail;

    @Schema(description = "생성일시", example = "2024-02-13T10:30:00")
    private LocalDateTime createdAt;

    public static FileResponse fromProjectFile(ProjectFile file) {
        return FileResponse.builder()
                .id(file.getId())
                .fileName(file.getFileName())
                .fileUrl(file.getFileUrl())
                .fileSize(file.getFileSize())
                .uploaderId(file.getUploader().getId())
                .uploaderName(file.getUploader().getName())
                .uploaderEmail(file.getUploader().getEmail())
                .createdAt(file.getCreatedAt())
                .build();
    }

    public static FileResponse fromTaskFile(TaskFile file) {
        return FileResponse.builder()
                .id(file.getId())
                .fileName(file.getFileName())
                .fileUrl(file.getFileUrl())
                .fileSize(file.getFileSize())
                .uploaderId(file.getUploader().getId())
                .uploaderName(file.getUploader().getName())
                .uploaderEmail(file.getUploader().getEmail())
                .createdAt(file.getCreatedAt())
                .build();
    }
}