package ec.fin.sanjose.permission.util;
import ec.fin.sanjose.permission.model.*;

public class PermissionManager {
    // Total = 32b, Start = 26,  Size = 6, 2**6 = 64
    private static final int ROLE_MASK = 0xFC000000;

    // Total = 32b, Start = 0, Size = 26, 25
    private static final int PERM_MASK = 0x03FFFFFF;

    private final int token;

    public PermissionManager(Role role, Permission... permissions) {
        int flags = 0;
        for (Permission p : permissions) {
            flags |= (1 << p.getBit());
        }
        this.token = ((role.getId() & 0x3F) << 26) | (flags & PERM_MASK);
    }

    public PermissionManager(int rawToken) {
        this.token = rawToken;
    }

    public Role getRole() {
        return Role.fromId((token & ROLE_MASK) >>> 26);
    }

    public boolean has(Permission permission) {
        return (token & (1 << permission.getBit())) != 0;
    }

    public int toInt() {
        return token;
    }
}
