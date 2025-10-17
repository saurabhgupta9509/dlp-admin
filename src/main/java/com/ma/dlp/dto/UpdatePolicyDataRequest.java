package com.ma.dlp.dto;



import lombok.Data;

@Data
public class UpdatePolicyDataRequest {
    private Long agentId;
    private String policyCode;
    private String policyData; // This will be the JSON string

    public Long getAgentId() {
        return agentId;
    }

    public void setAgentId(Long agentId) {
        this.agentId = agentId;
    }

    public String getPolicyCode() {
        return policyCode;
    }

    public void setPolicyCode(String policyCode) {
        this.policyCode = policyCode;
    }

    public String getPolicyData() {
        return policyData;
    }

    public void setPolicyData(String policyData) {
        this.policyData = policyData;
    }
}