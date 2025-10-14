package com.ma.dlp.dto;

import com.ma.dlp.controller.AgentController;
import lombok.Data;

@Data
public class USBAlertRequest {
    private Long agentId;
    private String alertType;
    private USBDeviceInfo deviceInfo;
    private USBFileAnalysis fileAnalysis;
    private String actionTaken;
    private Long timestamp;

    public String getActionTaken() { return actionTaken; }
    public void setActionTaken(String actionTaken) { this.actionTaken = actionTaken; }
    public Long getAgentId() { return agentId; }
    public void setAgentId(Long agentId) { this.agentId = agentId; }
    public String getAlertType() { return alertType; }
    public void setAlertType(String alertType) { this.alertType = alertType; }
    public USBDeviceInfo getDeviceInfo() { return deviceInfo; }
    public void setDeviceInfo(USBDeviceInfo deviceInfo) { this.deviceInfo = deviceInfo; }
    public USBFileAnalysis getFileAnalysis() { return fileAnalysis; }
    public void setFileAnalysis(USBFileAnalysis fileAnalysis) { this.fileAnalysis = fileAnalysis; }
    public Long getTimestamp() { return timestamp; }
    public void setTimestamp(Long timestamp) { this.timestamp = timestamp; }
}

