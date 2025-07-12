# Project 2

本项目的文件结构如下：
```
Project-2
├── watermark.py   # 生成，提取水印并进行鲁棒性测试的 Python 脚本
├── original.jpeg   # 目标照片
└── results   # 结果照片以及测试鲁棒性所生成的照片
   ├── extracted_watermark.jpeg   # 提取的水印
   ├── test_contrasted.jpg
   ├── test_cropped.jpg
   ├── test_flipped.jpg
   ├── test_shifted.jpg
   └── watermarked.jpeg   # 添加水印后生成的照片
```

*目录下主要为watermark.py，original.jpeg，results，以及对图片进行鲁棒性测试的其他图像。

watermark.py包含了对于水印的嵌入和提取，并对其进行鲁棒性测试。

original.jpeg是目标图像。图像来源：https://www.youtube.com/watch?v=8_GOFK1kk1s

results目录包含了添加水印的结果watermarked.jpeg，提取的水印extracted_watermark.jpeg。

为original.jpeg添加白色水印文字“Solynavatar”的结果如下：

![项目2测试结果](../images/proj2test.jpeg '项目2测试结果')
