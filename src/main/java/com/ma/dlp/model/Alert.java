// Alert.java
package com.ma.dlp.model;

import lombok.Data;
import jakarta.persistence.*;
import java.util.Date;

@Entity
@Table(name = "alerts")
@Data
public class Alert {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "agent_id")
    private User agent;

    @Column(nullable = false)
    private String alertType; // USB_INSERTION, FILE_BLOCKED, etc.

    @Column(columnDefinition = "TEXT")
    private String description;

    @Column(nullable = false)
    private String severity; // LOW, MEDIUM, HIGH, CRITICAL

    @Column(nullable = false)
    private String status; // PENDING, RESOLVED, IGNORED

    @Column(columnDefinition = "TEXT")
    private String deviceInfo;

    @Column(columnDefinition = "TEXT")
    private String fileDetails;

    private String actionTaken; // BLOCKED, ALLOWED, MONITORED

    @Column(nullable = false)
    private Date createdAt;

    private Date resolvedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = new Date();
        if (status == null) {
            status = "PENDING";
        }
        if (severity == null) {
            severity = "MEDIUM";
        }
    }

    public String getActionTaken() {
        return actionTaken;
    }

    public void setActionTaken(String actionTaken) {
        this.actionTaken = actionTaken;
    }

    public User getAgent() {
        return agent;
    }

    public void setAgent(User agent) {
        this.agent = agent;
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

    public Date getResolvedAt() {
        return resolvedAt;
    }

    public void setResolvedAt(Date resolvedAt) {
        this.resolvedAt = resolvedAt;
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
}