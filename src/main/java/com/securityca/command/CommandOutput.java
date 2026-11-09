package com.securityca.command;

import com.securityca.network.Packet;

public class CommandOutput {
    public boolean success;
    public Packet packet;
    public String message;

    public CommandOutput(Packet packet) {
        this.success = true;
        this.packet = packet;
    }

    public CommandOutput(String message, boolean success) {
        this.success = success;
        this.message = message;
    }


}
