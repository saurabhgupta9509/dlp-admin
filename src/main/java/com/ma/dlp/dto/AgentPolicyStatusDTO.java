package com.ma.dlp.dto;

import lombok.Data;

@Data
public class AgentPolicyStatusDTO {
    private Long agentId;
    private String hostname;
    private String agentStatus;
    private boolean isPolicyActive;

    public Long getAgentId() {
        return agentId;
    }

    public void setAgentId(Long agentId) {
        this.agentId = agentId;
    }

    public String getAgentStatus() {
        return agentStatus;
    }

    public void setAgentStatus(String agentStatus) {
        this.agentStatus = agentStatus;
    }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public boolean isPolicyActive() {
        return isPolicyActive;
    }

    public void setIsPolicyActive(boolean policyActive) {
        isPolicyActive = policyActive;
    }
}