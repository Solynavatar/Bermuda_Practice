# Bermuda Warehouse Exercise
Homework for a course from July 7th to July 14th, 2025.
## Project 1
Project 1: SM4的软件实现和优化
* 目录下分别为sm4.py，sm4_cli.py，example.py。

sm4.py中内涵了 SM4 算法在不同工作模式下的加密和解密的代码，并包含了ECC CBC CTR  OFB CFB工作模式。

sm4_cli.py提供了使用命令行启动加密和解密的方式。调用了argparse。

example.py是测试文件。测试结果如下：
![项目1测试结果](./images/proj1test.png '项目1测试结果')

## Project 2
Project 2: 编程实现图片水印嵌入和提取（可依托开源项目二次开发），并进行鲁棒性测试，包括不限于翻转、平移、截取、调对比度等
*目录下主要为watermark.py，original.jpeg，results，以及对图片进行鲁棒性测试的其他图像。

watermark.py包含了对于水印的嵌入和提取，并对其进行鲁棒性测试。

original.jpeg是目标图像。图像来源：https://www.youtube.com/watch?v=8_GOFK1kk1s

results目录包含了添加水印的结果watermarked.jpeg，提取的水印extracted_watermark.jpeg。

为original.jpeg添加白色水印文字“Solynavatar”的结果如下：
![项目2测试结果](./images/proj2test.jpeg '项目2测试结果')

## Project3
