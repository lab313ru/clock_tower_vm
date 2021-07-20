Mark1: (VarOrVal1,VarOrVal2,VarOrVal3,VarOrVal4,Val) is VarOrVal1;VarOrVal2;VarOrVal3;VarOrVal4;Val {}
Mark2: Mark1 is Mark1 {}
Mark3: Mark1 is Mark1 {}
Mark4: Mark1 is Mark1 {}
Mark5: Mark1 is Mark1 {}
Mark6: Mark1 is Mark1 {}
Mark7: Mark1 is Mark1 {}
Mark8: Mark1 is Mark1 {}
Mark9: Mark1 is Mark1 {}
Mark10: Mark1 is Mark1 {}

Mark: Mark1 is Mark1; VmEnd {}
Mark: Mark1,Mark2 is Mark1;Mark2; VmEnd {}
Mark: Mark1,Mark2,Mark3 is Mark1;Mark2;Mark3; VmEnd {}
Mark: Mark1,Mark2,Mark3,Mark4 is Mark1;Mark2;Mark3;Mark4; VmEnd {}
Mark: Mark1,Mark2,Mark3,Mark4,Mark5 is Mark1;Mark2;Mark3;Mark4;Mark5; VmEnd {}
Mark: Mark1,Mark2,Mark3,Mark4,Mark5,Mark6 is Mark1;Mark2;Mark3;Mark4;Mark5;Mark6; VmEnd {}
Mark: Mark1,Mark2,Mark3,Mark4,Mark5,Mark6,Mark7 is Mark1;Mark2;Mark3;Mark4;Mark5;Mark6;Mark7; VmEnd {}
Mark: Mark1,Mark2,Mark3,Mark4,Mark5,Mark6,Mark7;Mark8 is Mark1;Mark2;Mark3;Mark4;Mark5;Mark6;Mark7;Mark8; VmEnd {}
Mark: Mark1,Mark2,Mark3,Mark4,Mark5,Mark6,Mark7;Mark8,Mark9 is Mark1;Mark2;Mark3;Mark4;Mark5;Mark6;Mark7;Mark8;Mark9; VmEnd {}
Mark: Mark1,Mark2,Mark3,Mark4,Mark5,Mark6,Mark7;Mark8,Mark9;Mark10 is Mark1;Mark2;Mark3;Mark4;Mark5;Mark6;Mark7;Mark8;Mark9;Mark10; VmEnd {}
