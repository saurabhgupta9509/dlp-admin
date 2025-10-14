package com.ma.dlp.dto;

import com.ma.dlp.model.Alert;
import lombok.Data;
import java.util.Date;

@Data
public class AlertDTO {
    private Long id;
    private String alertType;
    private String description;
    private String severity;
    private String status;
    private String deviceInfo;
    private String fileDetails;
    private String actionTaken;
    private Date createdAt;
    private String agentName; // We use a simple name, not the full User object
    private Long agentId;

    public Long getAgentId() {
        return agentId;
    }

    public void setAgentId(Long agentId) {
        this.agentId = agentId;
    }

    public String getActionTaken() {
        return actionTaken;
    }

    public void setActionTaken(String actionTaken) {
        this.actionTaken = actionTaken;
    }

    public String getAgentName() {
        return agentName;
    }

    public void setAgentName(String agentName) {
        this.agentName = agentName;
    }

    public String getAlertType() {
        return alertType;
    }

    public void setAlertType(String alertType) {
        this.alertType = alertType;
    }

    public Date getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Date createdAt) {
        this.createdAt = createdAt;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getDeviceInfo() {
        return deviceInfo;
    }

    public void setDeviceInfo(String deviceInfo) {
        this.deviceInfo = deviceInfo;
    }

    public String getFileDetails() {
        return fileDetails;
    }

    public void setFileDetails(String fileDetails) {
        this.fileDetails = fileDetails;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    /**
     * Helper method to convert an Alert Entity to an AlertDTO
     */
    public static AlertDTO fromEntity(Alert alert) {
        AlertDTO dto = new AlertDTO();
        dto.setId(alert.getId());
        dto.setAlertType(alert.getAlertType());
        dto.setDescription(alert.getDescription());
        dto.setSeverity(alert.getSeverity());
        dto.setStatus(alert.getStatus());
        dto.setDeviceInfo(alert.getDeviceInfo());
        dto.setFileDetails(alert.getFileDetails());
        dto.setActionTaken(alert.getActionTaken());
        dto.setCreatedAt(alert.getCreatedAt());

        // This is the important part:
        // It safely gets the agent's name, even if the agent object is a lazy-loaded proxy.
        if (alert.getAgent() != null) {
            dto.setAgentName(alert.getAgent().getUsername());
            dto.setAgentId(alert.getAgent().getId());
        } else {
            dto.setAgentName("System or Unknown ");
        }

        return dto;
    }
}