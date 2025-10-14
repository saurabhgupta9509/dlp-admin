package com.ma.dlp.dto;

import lombok.Data;

@Data
public class AgentAlertRequest {
    private Long agentId;
    private String alertType;
    private String description;
    private String deviceInfo;
    private String fileDetails;
    private String severity;
    private String actionTaken;

    public String getActionTaken() { return actionTaken; }
    public void setActionTaken(String actionTaken) { this.actionTaken = actionTaken; }
    public Long getAgentId() { return agentId; }
    public void setAgentId(Long agentId) { this.agentId = agentId; }
    public String getAlertType() { return alertType; }
    public void setAlertType(String alertType) { this.alertType = alertType; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getDeviceInfo() { return deviceInfo; }
    public void setDeviceInfo(String deviceInfo) { this.deviceInfo = deviceInfo; }
    public String getFileDetails() { return fileDetails; }
    public void setFileDetails(String fileDetails) { this.fileDetails = fileDetails; }
    public String getSeverity() { return severity; }
    public void setSeverity(String severity) { this.severity = severity; }
}