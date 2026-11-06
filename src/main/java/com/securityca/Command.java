package com.securityca;

@FunctionalInterface
public interface Command {
    CommandOutput run(String[] args);
}
