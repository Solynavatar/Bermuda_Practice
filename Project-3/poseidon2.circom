pragma circom 2.0.0;

// Poseidon2 模板
template Poseidon2() {
    signal input in[3];
    signal output out;

    // 总共需要保存每一轮的状态：初始+5轮=6个状态
    signal state[6][3];

    // S-box 的中间结果数组：每一轮一个
    signal new_state0[5];
    signal new_state1[5];
    signal new_state2[5];

    // MDS 层的中间变量数组
    signal tmp0[5];
    signal tmp1[5];
    signal tmp2[5];

    // 初始化 state[0]
    state[0][0] <== in[0];
    state[0][1] <== in[1];
    state[0][2] <== in[2];

    // 5 轮循环
    for (var i = 0; i < 5; i++) {
        // S-box 层：平方
        new_state0[i] <== state[i][0] * state[i][0];
        new_state1[i] <== state[i][1] * state[i][1];
        new_state2[i] <== state[i][2] * state[i][2];

        // MDS 层：简单线性组合
        tmp0[i] <== new_state0[i] + new_state1[i];
        tmp1[i] <== new_state1[i] + new_state2[i];
        tmp2[i] <== new_state2[i] + new_state0[i];

        // 得到下一轮状态
        state[i+1][0] <== tmp0[i];
        state[i+1][1] <== tmp1[i];
        state[i+1][2] <== tmp2[i];
    }

    // 输出最后一轮的第一个状态
    out <== state[5][0];
}

// Main 模板
template Main() {
    signal input preimage[3]; // 隐私输入
    signal input hash;        // 公开输入

    component poseidon2Circuit = Poseidon2();

    // 连接输入
    for (var i = 0; i < 3; i++) {
        poseidon2Circuit.in[i] <== preimage[i];
    }

    // 强制输出等于公开输入
    hash === poseidon2Circuit.out;
}

// 主电路
component main = Main();

