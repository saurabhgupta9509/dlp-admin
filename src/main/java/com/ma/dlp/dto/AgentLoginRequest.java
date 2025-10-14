package com.ma.dlp.dto;

import lombok.Data;

@Data
public class AgentLoginRequest {
    private String hostname;
    private String macAddress;
    private String username;
    private String password;

    public String getHostname() { return hostname; }
    public void setHostname(String hostname) { this.hostname = hostname; }
    public String getMacAddress() { return macAddress; }
    public void setMacAddress(String macAddress) { this.macAddress = macAddress; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
}
