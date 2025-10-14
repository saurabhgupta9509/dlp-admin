package com.ma.dlp.dto;

import lombok.Data;

import java.util.List;

@Data
public  class CapabilityReportRequest {
    private Long agentId;
    private List<PolicyCapabilityDTO> capabilities;

    public Long getAgentId() {
        return agentId;
    }

    public void setAgentId(Long agentId) {
        this.agentId = agentId;
    }

    public List<PolicyCapabilityDTO> getCapabilities() {
        return capabilities;
    }

    public void setCapabilities(List<PolicyCapabilityDTO> capabilities) {
        this.capabilities = capabilities;
    }
}