package com.securityca.command;

import com.securityca.network.Packet;

public class CommandOutput {
    public boolean success;
    public Packet packet;
    public String message;

    private CommandOutput(Packet packet) {
        this.success = true;
        this.packet = packet;
    }

    private CommandOutput(String message, boolean success) {
        this.success = success;
        this.message = message;
    }

    public static CommandOutput print(String msg) { return new CommandOutput(msg, true); }
    public static CommandOutput error(String msg) { return new CommandOutput(msg, false); }
    public static CommandOutput send(Packet p) { return new CommandOutput(p); }
}
