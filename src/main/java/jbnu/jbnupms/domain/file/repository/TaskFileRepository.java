package jbnu.jbnupms.domain.file.repository;

import jbnu.jbnupms.domain.file.entity.TaskFile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;
import java.util.Optional;

public interface TaskFileRepository extends JpaRepository<TaskFile, Long> {

    // 태스크의 모든 파일 조회 (삭제되지 않은 것)
    @Query("SELECT tf FROM TaskFile tf WHERE tf.task.id = :taskId AND tf.isDeleted = false ORDER BY tf.createdAt DESC")
    List<TaskFile> findByTaskId(@Param("taskId") Long taskId);

    // 프로젝트의 모든 태스크 파일 조회 (삭제되지 않은 것)
    @Query("SELECT tf FROM TaskFile tf WHERE tf.project.id = :projectId AND tf.isDeleted = false ORDER BY tf.createdAt DESC")
    List<TaskFile> findByProjectId(@Param("projectId") Long projectId);

    // 파일 조회 (삭제되지 않은 것)
    @Query("SELECT tf FROM TaskFile tf WHERE tf.id = :fileId AND tf.isDeleted = false")
    Optional<TaskFile> findActiveById(@Param("fileId") Long fileId);

    // 특정 파일 조회 (task, project, uploader 포함, 권한 검증용)
    @Query("SELECT tf FROM TaskFile tf JOIN FETCH tf.task JOIN FETCH tf.project JOIN FETCH tf.uploader WHERE tf.id = :fileId AND tf.isDeleted = false")
    Optional<TaskFile> findByIdWithTaskAndProjectAndUploader(@Param("fileId") Long fileId);

    // 사용자가 업로드한 파일 조회 (삭제되지 않은 것)
    List<TaskFile> findByUploaderIdAndIsDeletedFalseOrderByCreatedAtDesc(Long uploaderId);
}