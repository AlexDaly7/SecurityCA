package com.securityca.command;

import com.securityca.network.Packet;

public class CommandOutput {
    public boolean success;
    public Packet packet;
    public String error;

    public CommandOutput(Packet packet) {
        this.success = true;
        this.packet = packet;
    }

    public CommandOutput(String error) {
        this.success = false;
        this.error = error;
    }


}
