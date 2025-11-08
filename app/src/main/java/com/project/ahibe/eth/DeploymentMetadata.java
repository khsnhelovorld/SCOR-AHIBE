package com.project.ahibe.eth;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonIgnoreProperties(ignoreUnknown = true)
public class DeploymentMetadata {

    @JsonProperty("address")
    private String address;

    @JsonProperty("network")
    private String network;

    @JsonProperty("deployedAt")
    private String deployedAt;

    public String address() {
        return address;
    }

    public String network() {
        return network;
    }

    public String deployedAt() {
        return deployedAt;
    }
}

