package jbnu.jbnupms.domain.file.repository;

import jbnu.jbnupms.domain.file.entity.ProjectFile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface ProjectFileRepository extends JpaRepository<ProjectFile, Long> {

    // 프로젝트의 모든 파일 조회 (삭제되지 않은 것)
    @Query("SELECT pf FROM ProjectFile pf WHERE pf.project.id = :projectId AND pf.isDeleted = false ORDER BY pf.createdAt DESC")
    List<ProjectFile> findByProjectId(@Param("projectId") Long projectId);

    // 파일 조회 (삭제되지 않은 것)
    @Query("SELECT pf FROM ProjectFile pf WHERE pf.id = :fileId AND pf.isDeleted = false")
    Optional<ProjectFile> findActiveById(@Param("fileId") Long fileId);

    // 특정 파일 조회 (project와 uploader 포함, 권한 검증용)
    @Query("SELECT pf FROM ProjectFile pf JOIN FETCH pf.project JOIN FETCH pf.uploader WHERE pf.id = :fileId AND pf.isDeleted = false")
    Optional<ProjectFile> findByIdWithProjectAndUploader(@Param("fileId") Long fileId);

    // 사용자가 업로드한 파일 조회 (삭제되지 않은 것)
    List<ProjectFile> findByUploaderIdAndIsDeletedFalseOrderByCreatedAtDesc(Long uploaderId);

    // taskFileId로 파일 조회 (태스크 파일 삭제 시 사용)
    @Query("SELECT pf FROM ProjectFile pf WHERE pf.taskFileId = :taskFileId AND pf.isDeleted = false")
    Optional<ProjectFile> findByTaskFileId(@Param("taskFileId") Long taskFileId);
}