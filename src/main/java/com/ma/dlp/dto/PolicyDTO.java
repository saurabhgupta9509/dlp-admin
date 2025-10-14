// PolicyDTO.java
package com.ma.dlp.dto;


import com.ma.dlp.model.Policy;
import lombok.Data;
import java.util.Date;

@Data
public class PolicyDTO {
    private Long id;
    private String name;
    private String category;
    private String policyType;
    private String action;
    private String target;
    private String description;
    private String severity;
    private Date createdAt;

    public static PolicyDTO fromPolicy(Policy policy) {
        PolicyDTO dto = new PolicyDTO();
        dto.setId(policy.getId());
        dto.setName(policy.getName());
        dto.setCategory(policy.getCategory());
        dto.setPolicyType(policy.getPolicyType());
        dto.setAction(policy.getAction());
        dto.setTarget(policy.getTarget());
        dto.setDescription(policy.getDescription());
        dto.setSeverity(policy.getSeverity());
        dto.setCreatedAt(policy.getCreatedAt());
        return dto;
    }

    public String getAction() {
        return action;
    }

    public void setAction(String action) {
        this.action = action;
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

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
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
}