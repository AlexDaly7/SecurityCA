package com.securityca;

public class CommandOutput {
    boolean success;
    Packet packet;
    String error;

    public CommandOutput(Packet packet) {
        this.success = true;
        this.packet = packet;
    }

    public CommandOutput(String error) {
        this.success = false;
        this.error = error;
    }


}
