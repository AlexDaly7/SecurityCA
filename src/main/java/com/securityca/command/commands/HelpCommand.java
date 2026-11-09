package com.securityca.command.commands;

import com.securityca.command.Command;
import com.securityca.command.CommandOutput;

public class HelpCommand implements Command {
    @Override
    public CommandOutput run(String[] args) {
        return new CommandOutput("""
                Commands:
                    FILE <path>  - upload a file
                    HELP        - show this message""", true);
    }
}
