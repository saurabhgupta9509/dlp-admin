package com.ma.dlp.dto;

import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public  class USBFileAnalysis {
    private Integer totalFiles;
    private Integer totalFolders;
    private Long totalSize;
    private Map<String, Integer> fileTypes;
    private List<String> fileList;
    private List<String> suspiciousFiles;

    public List<String> getFileList() { return fileList; }
    public void setFileList(List<String> fileList) { this.fileList = fileList; }
    public Map<String, Integer> getFileTypes() { return fileTypes; }
    public void setFileTypes(Map<String, Integer> fileTypes) { this.fileTypes = fileTypes; }
    public List<String> getSuspiciousFiles() { return suspiciousFiles; }
    public void setSuspiciousFiles(List<String> suspiciousFiles) { this.suspiciousFiles = suspiciousFiles; }
    public Integer getTotalFiles() { return totalFiles; }
    public void setTotalFiles(Integer totalFiles) { this.totalFiles = totalFiles; }
    public Integer getTotalFolders() { return totalFolders; }
    public void setTotalFolders(Integer totalFolders) { this.totalFolders = totalFolders; }
    public Long getTotalSize() { return totalSize; }
    public void setTotalSize(Long totalSize) { this.totalSize = totalSize; }
}