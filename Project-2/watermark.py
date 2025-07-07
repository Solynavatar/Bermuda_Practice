# watermark_tool.py
# 实现：图片水印嵌入与提取，并进行鲁棒性测试

from PIL import Image, ImageEnhance
import numpy as np
import cv2

def embed_watermark(image_path, watermark_text, output_path):
    """
    简单水印嵌入：将文字水印绘制到图像右下角，使用更大的字体
    """
    image = Image.open(image_path).convert("RGB")
    watermark = Image.new("RGBA", image.size)

    from PIL import ImageDraw, ImageFont
    draw = ImageDraw.Draw(watermark)

    # 调节字体大小（此处使用48号）
    font = ImageFont.truetype("arial.ttf", 48)

    bbox = draw.textbbox((0, 0), watermark_text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    position = (image.width - text_width - 10, image.height - text_height - 10)

    draw.text(position, watermark_text, fill=(255, 255, 255, 128), font=font)

    watermarked = Image.alpha_composite(image.convert("RGBA"), watermark)
    watermarked.convert("RGB").save(output_path)

def extract_watermark(image_path, reference_path):
    """
    简易提取：对比原图与水印图的差异，提取水印区域
    """
    img1 = cv2.imread(reference_path)
    img2 = cv2.imread(image_path)
    diff = cv2.absdiff(img2, img1)
    gray = cv2.cvtColor(diff, cv2.COLOR_BGR2GRAY)
    _, mask = cv2.threshold(gray, 30, 255, cv2.THRESH_BINARY)
    return mask

def robustness_test(image_path):
    """
    对水印图进行鲁棒性测试：翻转、平移、裁剪、调节对比度
    """
    image = Image.open(image_path)

    # 翻转
    flipped = image.transpose(Image.FLIP_LEFT_RIGHT)
    flipped.save("./results/test_flipped.jpg")

    # 平移
    arr = np.array(image)
    M = np.float32([[1, 0, 20], [0, 1, 20]])
    shifted = cv2.warpAffine(arr, M, (arr.shape[1], arr.shape[0]))
    Image.fromarray(shifted).save("./results/test_shifted.jpg")

    # 裁剪
    cropped = image.crop((10, 10, image.width - 10, image.height - 10))
    cropped.save("./results/test_cropped.jpg")

    # 调节对比度
    enhancer = ImageEnhance.Contrast(image)
    contrasted = enhancer.enhance(1.8)
    contrasted.save("./results/test_contrasted.jpg")

if __name__ == "__main__":
    # 示例：先嵌入水印
    embed_watermark("./original.jpeg", "Solynavatar", "./results/watermarked.jpeg")

    # 提取水印
    mask = extract_watermark("./results/watermarked.jpeg", "./original.jpeg")
    cv2.imwrite("./results/extracted_watermark.jpeg", mask)

    # 进行鲁棒性测试
    robustness_test("./results/watermarked.jpeg")

    print("水印嵌入、提取及鲁棒性测试完成！")

