package com.ma.dlp.dto;

import com.ma.dlp.model.Policy;
import lombok.Data;

import java.util.List;

@Data
public class AgentPoliciesResponse {
    private Long agentId;
    private List<Policy> policies;
    private Long timestamp;

    public Long getAgentId() { return agentId; }
    public void setAgentId(Long agentId) { this.agentId = agentId; }
    public List<Policy> getPolicies() { return policies; }
    public void setPolicies(List<Policy> policies) { this.policies = policies; }
    public Long getTimestamp() { return timestamp; }
    public void setTimestamp(Long timestamp) { this.timestamp = timestamp; }
}