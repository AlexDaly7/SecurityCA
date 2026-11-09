package com.securityca.command;

import java.util.Arrays;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum Command {
    FILE("<path>", "upload a file", args -> args.length == 0 ? CommandOutput.error("Usage: FILE <path>") : FileManager.readFile(args[0])),
    HELP("", "show this message", _ -> CommandOutput.print(helpText()));

    private final String usage;
    private final String description;
    private final Function<String[], CommandOutput> action;

    Command(String usage, String description, Function<String[], CommandOutput> action) {
        this.usage = usage;
        this.description = description;
        this.action = action;
    }

    public CommandOutput run(String[] args) { return action.apply(args); }

    private static String helpText() {
        return "Commands:\n" + Arrays.stream(values())
                .map(c -> "    %-12s - %s".formatted(c.name() + " " + c.usage, c.description))
                .collect(Collectors.joining("\n"));
    }
}
