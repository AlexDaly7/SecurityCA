
void main(String[] args) throws Exception {
    int port = 5000;
    try (var socket = args.length == 0 ? listen(port) : new Socket(args[0], port);
        var in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        var out = new PrintWriter(socket.getOutputStream(), true)) {

        IO.println("Connected to " + socket.getInetAddress().getHostAddress() + ". Type messages, Ctrl + D or Ctrl + Z on Windows to quit.");

        Thread.startVirtualThread(() -> {
            try {
                String line;
                while ((line = in.readLine()) != null) IO.println("> " + line);
            } catch (IOException _) { }

            IO.println("Disconnected.");
            System.exit(0);
        });

        String line;
        while ((line = IO.readln()) != null) out.println(line);
    }
}

Socket listen(int port) throws IOException {
    try (var server = new ServerSocket(port)) {
        IO.print("Waiting for connection on port " + port + "...");
        return server.accept();
    }
}