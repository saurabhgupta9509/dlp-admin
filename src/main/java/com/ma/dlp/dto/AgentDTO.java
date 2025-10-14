// AgentDTO.java
package com.ma.dlp.dto;


import com.ma.dlp.model.User;
import lombok.Data;
import java.util.Date;

@Data
public class AgentDTO {
    private Long id;
    private String username;
    private String status;
    private String hostname;
    private String macAddress;
    private String ipAddress;
    private Date lastHeartbeat;
    private Date lastLogin;
    private int policyCount;
    private int capabilityCount;        // ADD THIS
    private int activePolicyCount;

    public static AgentDTO fromUser(User user) {
        AgentDTO dto = new AgentDTO();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setStatus(user.getStatus().toString());
        dto.setHostname(user.getHostname());
        dto.setMacAddress(user.getMacAddress());
        dto.setIpAddress(user.getIpAddress());
        dto.setLastHeartbeat(user.getLastHeartbeat());
        dto.setLastLogin(user.getLastLogin());

        dto.setPolicyCount(0);
        return dto;
    }

    public int getCapabilityCount() { return capabilityCount; }
    public void setCapabilityCount(int capabilityCount) { this.capabilityCount = capabilityCount; }
    public int getActivePolicyCount() { return activePolicyCount; }
    public void setActivePolicyCount(int activePolicyCount) { this.activePolicyCount = activePolicyCount; }

    public String getHostname() {
        return hostname;
    }

    public void setHostname(String hostname) {
        this.hostname = hostname;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public Date getLastHeartbeat() {
        return lastHeartbeat;
    }

    public void setLastHeartbeat(Date lastHeartbeat) {
        this.lastHeartbeat = lastHeartbeat;
    }

    public Date getLastLogin() {
        return lastLogin;
    }

    public void setLastLogin(Date lastLogin) {
        this.lastLogin = lastLogin;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    public int getPolicyCount() {
        return policyCount;
    }

    public void setPolicyCount(int policyCount) {
        this.policyCount = policyCount;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }
}