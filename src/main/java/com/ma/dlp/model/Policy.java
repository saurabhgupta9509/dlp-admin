// Policy.java
package com.ma.dlp.model;

import lombok.Data;
import jakarta.persistence.*;
import java.util.Date;

@Entity
@Table(name = "policies")
@Data
public class Policy {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    @Column(nullable = false)
    private String category; // USB, NETWORK, FILE

    @Column(name = "policy_type")
    private String policyType; // DEVICE_BLOCK, FILE_MONITOR, etc.

    @Column(nullable = false)
    private String action; // BLOCK, MONITOR, ALLOW

    private String target; // File extensions, domains, etc.
    private String description;
    private String severity; // LOW, MEDIUM, HIGH, CRITICAL

    private Date createdAt;
    private Date updatedAt;

    private String policyCode;
    private Boolean isActive;

    @Transient
    private Long agentId;

    @Transient
    private String agentHostname;

    @PrePersist
    protected void onCreate() {
        createdAt = new Date();
        updatedAt = new Date();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = new Date();
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
    }

    public String getAgentHostname() {
        return agentHostname;
    }

    public void setAgentHostname(String agentHostname) {
        this.agentHostname = agentHostname;
    }

    public Long getAgentId() {
        return agentId;
    }

    public void setAgentId(Long agentId) {
        this.agentId = agentId;
    }

    public String getCategory() {
        return category;
    }

    public void setCategory(String category) {
        this.category = category;
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

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Boolean getIsActive() { // This is the bug
        return isActive;
    }
    public void setIsActive(Boolean active) {
        isActive = active;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPolicyCode() {
        return policyCode;
    }

    public void setPolicyCode(String policyCode) {
        this.policyCode = policyCode;
    }

    public String getPolicyType() {
        return policyType;
    }

    public void setPolicyType(String policyType) {
        this.policyType = policyType;
    }

    public String getSeverity() {
        return severity;
    }

    public void setSeverity(String severity) {
        this.severity = severity;
    }

    public String getTarget() {
        return target;
    }

    public void setTarget(String target) {
        this.target = target;
    }

    public Date getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(Date updatedAt) {
        this.updatedAt = updatedAt;
    }
}