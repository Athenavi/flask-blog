import io
import cv2
from PIL import Image


def generate_thumbnail(img_dir, img_thumbs):
    # 打开原始图像
    original_image = Image.open(img_dir)

    # 计算要裁剪的区域
    width, height = original_image.size
    if width > height:
        left = (width - height) / 2
        top = 0
        right = left + height
        bottom = height
    else:
        left = 0
        top = (height - width) / 2
        right = width
        bottom = top + width

    # 裁剪图像
    image = original_image.crop((left, top, right, bottom))

    # 设置缩略图的尺寸
    size = (160, 160)

    # 生成缩略图并确保为160x160
    thumb_image = image.resize(size, Image.LANCZOS)

    # Convert to RGB if the image has an alpha channel
    if thumb_image.mode == 'RGBA':
        thumb_image = thumb_image.convert('RGB')

    # 保存缩略图
    thumb_image.save(img_thumbs, format='JPEG')


def generate_video_thumbnail(video_path, thumb_path, time=1):
    # 用OpenCV打开视频文件
    cap = cv2.VideoCapture(video_path)

    # 设置要提取的帧的时间（以毫秒为单位）
    cap.set(cv2.CAP_PROP_POS_MSEC, time * 1000)

    # 读取该帧
    success, frame = cap.read()

    if not success:
        print("无法读取视频帧")
        return

    # 转换颜色通道，从BGR到RGB
    frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

    # 将NumPy数组转换为PIL图像
    image = Image.fromarray(frame_rgb)

    # 计算要裁剪的区域
    width, height = image.size
    if width > height:
        left = (width - height) / 2
        top = 0
        right = left + height
        bottom = height
    else:
        left = 0
        top = (height - width) / 2
        right = width
        bottom = top + width

    # 裁剪图像
    image = image.crop((left, top, right, bottom))

    # 设置缩略图的尺寸
    size = (160, 160)

    # 生成缩略图并确保为160x160
    thumb_image = image.resize(size, Image.LANCZOS)

    # 保存缩略图
    thumb_image.save(thumb_path)

    # 释放视频捕捉对象
    cap.release()


def handle_cover_resize(img, width, height):
    img = img.resize((width, height), Image.LANCZOS)
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='WEBP')
    img_byte_arr.seek(0)
    return img_byte_arr.getvalue()
