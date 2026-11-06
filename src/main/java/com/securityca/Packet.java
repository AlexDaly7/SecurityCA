package com.securityca;

import java.util.Arrays;

public record Packet(PacketType type, byte[] data) {
    public byte[] toBytes() {
        var out = new byte[data.length + 1];
        out[0] = (byte) type.ordinal();
        System.arraycopy(data, 0, out, 1, data.length);
        return out;
    }

    public static Packet fromBytes(byte[] bytes) {
        var type = PacketType.values()[bytes[0]];
        var data = Arrays.copyOfRange(bytes, 1, bytes.length);
        return new Packet(type, data);
    }
}
