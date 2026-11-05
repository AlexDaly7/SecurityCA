@FunctionalInterface
public interface Command {
    CommandOutput run(String[] args);
}
