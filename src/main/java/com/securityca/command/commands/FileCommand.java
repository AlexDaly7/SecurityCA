package com.securityca.command.commands;

import com.securityca.command.Command;
import com.securityca.command.CommandOutput;
import com.securityca.command.FileManager;

public class FileCommand implements Command {
    @Override
    public CommandOutput run(String[] args) {
        return FileManager.readFile(args[0]);
    }
}
