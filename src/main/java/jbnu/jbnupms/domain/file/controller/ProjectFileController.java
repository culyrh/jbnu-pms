package jbnu.jbnupms.domain.file.controller;

import io.swagger.v3.oas.annotations.Operation;
import jbnu.jbnupms.common.response.CommonResponse;
import jbnu.jbnupms.domain.file.dto.FileResponse;
import jbnu.jbnupms.domain.file.service.ProjectFileService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/projects/{projectId}/files")
@RequiredArgsConstructor
public class ProjectFileController {

    private final ProjectFileService projectFileService;

    @Operation(summary = "프로젝트 파일 업로드")
    @PostMapping(consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<CommonResponse<FileResponse>> uploadProjectFile(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long projectId,
            @RequestParam("file") MultipartFile file) {
        Long userId = Long.parseLong(userDetails.getUsername());
        FileResponse response = projectFileService.uploadProjectFile(projectId, file, userId);
        return ResponseEntity.ok(CommonResponse.success(response));
    }

    @Operation(summary = "프로젝트 파일 목록 조회")
    @GetMapping
    public ResponseEntity<CommonResponse<List<FileResponse>>> getProjectFiles(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long projectId) {
        Long userId = Long.parseLong(userDetails.getUsername());
        List<FileResponse> responses = projectFileService.getProjectFiles(projectId, userId);
        return ResponseEntity.ok(CommonResponse.success(responses));
    }

    @Operation(summary = "프로젝트 전체 파일 조회 (프로젝트 파일 + 태스크 파일)")
    @GetMapping("/all")
    public ResponseEntity<CommonResponse<List<FileResponse>>> getAllProjectFiles(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long projectId) {
        Long userId = Long.parseLong(userDetails.getUsername());
        List<FileResponse> responses = projectFileService.getAllProjectFiles(projectId, userId);
        return ResponseEntity.ok(CommonResponse.success(responses));
    }

    @Operation(summary = "프로젝트 파일 삭제")
    @DeleteMapping("/{fileId}")
    public ResponseEntity<CommonResponse<Void>> deleteProjectFile(
            @AuthenticationPrincipal UserDetails userDetails,
            @PathVariable Long projectId,
            @PathVariable Long fileId) {
        Long userId = Long.parseLong(userDetails.getUsername());
        projectFileService.deleteProjectFile(projectId, fileId, userId);
        return ResponseEntity.ok(CommonResponse.success(null));
    }
}