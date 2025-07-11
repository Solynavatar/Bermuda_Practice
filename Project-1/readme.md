# Project 1

* 目录下分别为sm4.cpp，sm4.exe，sm4_optimization.cpp，sm4_optimization.exe。
* 其中，sm4.cpp是原始的 SM4 加密算法实现，sm4_optimization.cpp是经过优化后的 SM4 加密算法实现。

优化思路：
1. T-table & T'-table 查表加速：SM4 原始的 T 和 T' 变换涉及：S盒非线性变换（需要查表）和线性变换 L（多次左移和异或）这种组合本来需要多个移位+异或操作，比较慢。通过静态生成 4 张 T-table（共 4×256 个 uint32_t），把 S 盒和 L 合并进表格。T' 表同理，用于密钥扩展。查表比逐位运算快得多，尤其对 CPU 友好。
2. SIMD（AVX2）对批量加密的支持
代码中虽然未完全实现复杂的 AVX2 并行，但对齐数据结构（alignas(32)）准备好在需要时直接用 _mm256_* 指令。encryptBlocks 和 decryptBlocks 支持批量加密/解密（对多个 16 字节分组），为后续 SIMD 优化提供接口。在大数据量下，可以手动加 AVX2 优化实现一次处理多块。
3. 循环展开（Loop Unrolling）：SM4 有固定的 32 轮加密循环。为了减少循环分支带来的性能损耗，代码中在每次大循环处理 8 轮（在循环体里显式写出 8 次函数调用），让编译器更好做指令调度和流水线优化。
4. 密钥扩展预计算：SM4 轮密钥只跟密钥本身有关，和加密数据无关。每次加密/解密前调用 keyExpansion，一次性算好 32 个轮密钥，从而对批量加密只需算一次轮密钥，大幅减少重复计算。
5. 静态初始化标志：通过 static bool initialized 和 initTables() 保证 SBOX/T_TABLE/TP_TABLE 只需初始化一次，而不会在每次加密/解密都重新初始化，提高运行效率。
6. 工程层优化：使用 alignas(32) 对齐，配合 SIMD 更好利用缓存。
内联关键函数（inline）：减少函数调用开销。std::vector 管理动态数组，保证内存安全。



以下是原始的 SM4 算法运行结果：
![项目1测试结果](../images/proj1test.png '项目1测试结果')

以下是经过优化的 SM4 算法运行结果：
![项目1优化测试结果](../images/proj1test2.png '项目1优化测试结果')