package com.ma.dlp.dto;

import lombok.Data;

@Data
public class AgentRegistrationRequest {
    private String hostname;
    private String macAddress;

    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }
    public String getMacAddress() { return macAddress; }
    public void setMacAddress(String macAddress) { this.macAddress = macAddress; }
}

