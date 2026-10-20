package ec.fin.sanjose.permission.model;

public enum Role {
    ROLE_1(0),   ROLE_2(1),   ROLE_3(2),   ROLE_4(3),   ROLE_5(4),
    ROLE_6(5),   ROLE_7(6),   ROLE_8(7),   ROLE_9(8),   ROLE_10(9),
    ROLE_11(10), ROLE_12(11), ROLE_13(12), ROLE_14(13), ROLE_15(14),
    ROLE_16(15), ROLE_17(16), ROLE_18(17), ROLE_19(18), ROLE_20(19),
    ROLE_21(20), ROLE_22(21), ROLE_23(22), ROLE_24(23), ROLE_25(24),
    ROLE_26(25), ROLE_27(26), ROLE_28(27), ROLE_29(28), ROLE_30(29),
    ROLE_31(30), ROLE_32(31), ROLE_33(32), ROLE_34(33), ROLE_35(34),
    ROLE_36(35), ROLE_37(36), ROLE_38(37), ROLE_39(38), ROLE_40(39),
    ROLE_41(40), ROLE_42(41), ROLE_43(42), ROLE_44(43), ROLE_45(44),
    ROLE_46(45), ROLE_47(46), ROLE_48(47), ROLE_49(48), ROLE_50(49),
    ROLE_51(50), ROLE_52(51), ROLE_53(52), ROLE_54(53), ROLE_55(54),
    ROLE_56(55), ROLE_57(56), ROLE_58(57), ROLE_59(58), ROLE_60(59),
    ROLE_61(60), ROLE_62(61), ROLE_63(62), ROLE_MAX(63);

    private final int id;
    Role(int id) { this.id = id; }
    public int getId() { return id; }

    public static Role fromId(int id) {
        if (id < 0 || id > 63) return ROLE_1;
        return values()[id];
    }
}