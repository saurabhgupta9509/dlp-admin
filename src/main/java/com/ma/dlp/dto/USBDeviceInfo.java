package com.ma.dlp.dto;

import lombok.Data;

@Data
public class USBDeviceInfo {
    private String driveLetter;
    private String volumeName;
    private Long totalSize;
    private Long freeSpace;
    private String fileSystem;
    private String serialNumber;
    private Long insertionTime;

    public String getDriveLetter() { return driveLetter; }
    public void setDriveLetter(String driveLetter) { this.driveLetter = driveLetter; }
    public String getFileSystem() { return fileSystem; }
    public void setFileSystem(String fileSystem) { this.fileSystem = fileSystem; }
    public Long getFreeSpace() { return freeSpace; }
    public void setFreeSpace(Long freeSpace) { this.freeSpace = freeSpace; }
    public Long getInsertionTime() { return insertionTime; }
    public void setInsertionTime(Long insertionTime) { this.insertionTime = insertionTime; }
    public String getSerialNumber() { return serialNumber; }
    public void setSerialNumber(String serialNumber) { this.serialNumber = serialNumber; }
    public Long getTotalSize() { return totalSize; }
    public void setTotalSize(Long totalSize) { this.totalSize = totalSize; }
    public String getVolumeName() { return volumeName; }
    public void setVolumeName(String volumeName) { this.volumeName = volumeName; }
}