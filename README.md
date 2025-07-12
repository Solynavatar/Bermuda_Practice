# Bermuda Warehouse Exercise

Homework for a course from July 7th to July 14th, 2025.

The experimental environment involved in this experiment is as follows:

| Tools | Usage |
| ---- | ---- |
| Visual Studio Code | For debugging and synchronizing Github repository updates |
| Pycharm 2025.1.1.1 | For testing some scripts quickly |
| Python 3.12 | Used in Project 2, 3, 5 |
| C++ 98 | Used in Project 1, 4 |
| g++ 15.1.0 | Compiling C++ codes |
| rustc 1.88.0* | Used in Project 3 |
| cargo 1.88.0* | Used in Project 3 |
| node.js 22.12.0* | Used in Project 3 |
| circom 2.2.2* | Used in Project 3 |

0*: The above marked with " * " are installed in VMware's Ubuntu 22.04 virtual machine. The default OS is Windows 11.

## Project 1
Project 1: SM4的软件实现和优化

内容详见：[Project 1](./Project-1/readme.md)

## Project 2
Project 2: 编程实现图片水印嵌入和提取（可依托开源项目二次开发），并进行鲁棒性测试，包括不限于翻转、平移、截取、调对比度等

内容详见：[Project 2](./Project-2/readme.md)

## Project 3
Project 3: 用circom实现poseidon2哈希算法的电路。

要求： 
1. poseidon2 哈希算法参数参考参考文档1的Table1，用(n,t,d)=(256,3,5)或(256,2,5).
2. 电路的公开输入用poseidon2哈希值，隐私输入为哈希原象，哈希算法的输入只考虑一个block即可。
3. 用Groth16算法生成证明。

内容详见：[Project 3](./Project-3/readme.md)

## Project 4

Project 4: SM3 的软件实现与优化。跟 SM4 一样，用 C 语言来做，然后不断改进效率

内容详见：[Project 4](./Project-4/readme.md)

## Project 5

Project 5: sm2 的软件实现优化。考虑到SM2用 C 语言来做比较复杂，大家看可以考虑用python来做 SM2 算法的基础实现以及各种算法的改进尝试

内容详见：[Project 5](./Project-5/readme.md)

## Project 6

Project 6:  来自刘巍然老师的报告  google password checkup，参考论文 [https://eprint.iacr.org/2019/723.pdf](https://eprint.iacr.org/2019/723.pdf) 的 section 3.1 ，也即 Figure 2 中展示的协议，尝试实现该协议，（编程语言不限）。

内容详见：[Project 6](./Project-6/readme.md)