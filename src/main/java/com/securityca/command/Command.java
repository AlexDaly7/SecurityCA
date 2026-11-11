package com.securityca.command;

import com.securityca.manifest.ManifestManager;
import com.securityca.network.MessageManager;
import com.securityca.network.Packet;
import com.securityca.network.PacketType;

import java.util.Arrays;
import java.util.function.Function;
import java.util.stream.Collectors;

public enum Command {
    FILE("<path>", "upload a file", args -> args.length == 0 ? CommandOutput.error("Usage: FILE <path>") : FileManager.readFile(args[0])),
    LIST("", "list uploaded files", _ -> CommandOutput.print(listText())),
    HELP("", "show this message", _ -> CommandOutput.print(helpText())),
    DELETE("<path>", "delete a file", args -> args.length == 0 ? CommandOutput.error("Usage: DELETE <fileID>") : CommandOutput.send(new Packet(PacketType.DELETE, args[0].getBytes()))),
    FILEREQUEST("<path>", "request a file from the server", args -> args.length == 0 ? CommandOutput.error("Usage: FILEREQUEST <fileID>") : CommandOutput.send(new Packet(PacketType.FILEREQUEST, args[0].getBytes())));

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

    private static String listText() {
        var files = ManifestManager.getFiles();
        if (files.isEmpty()) return "No files uploaded.";

        return files.stream()
                .map(f -> f.id() + " " + f.name())
                .collect(Collectors.joining("\n"));
    }
}
