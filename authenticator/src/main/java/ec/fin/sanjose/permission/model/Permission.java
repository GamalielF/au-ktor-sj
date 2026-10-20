package ec.fin.sanjose.permission.model;

public enum Permission {
    PERM_1(0),   PERM_2(1),   PERM_3(2),   PERM_4(3),   PERM_5(4),
    PERM_6(5),   PERM_7(6),   PERM_8(7),   PERM_9(8),   PERM_10(9),
    PERM_11(10), PERM_12(11), PERM_13(12), PERM_14(13), PERM_15(14),
    PERM_16(15), PERM_17(16), PERM_18(17), PERM_19(18), PERM_20(19),
    PERM_21(20), PERM_22(21), PERM_23(22), PERM_24(23), PERM_25(24),
    PERM_MAX(25);

    private final int bit;
    Permission(int bit) { this.bit = bit; }
    public int getBit() { return bit; }
}
