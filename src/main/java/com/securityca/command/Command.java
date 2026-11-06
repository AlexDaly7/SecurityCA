package com.securityca.command;

@FunctionalInterface
public interface Command {
    CommandOutput run(String[] args);
}
