"""图像处理工具模块"""
import io
from typing import Tuple, Optional

from PIL import Image


def resize_image(input_path: str, output_path: str, max_size: Tuple[int, int] = (1920, 1080), quality: int = 85):
    """
    调整图像大小
    
    Args:
        input_path: 输入图像路径
        output_path: 输出图像路径
        max_size: 最大尺寸 (width, height)
        quality: JPEG质量 (1-100)
    """
    with Image.open(input_path) as img:
        # 保持宽高比进行缩放
        img.thumbnail(max_size, Image.Resampling.LANCZOS)

        # 保存图像
        img.save(output_path, optimize=True, quality=quality)


def optimize_image(input_path: str, output_path: str, quality: int = 85, max_size: Optional[Tuple[int, int]] = None):
    """
    优化图像大小和质量
    
    Args:
        input_path: 输入图像路径
        output_path: 输出图像路径
        quality: JPEG质量 (1-100)
        max_size: 最大尺寸 (width, height)，如果提供则会缩放
    """
    with Image.open(input_path) as img:
        if max_size:
            img.thumbnail(max_size, Image.Resampling.LANCZOS)

        # 确定输出格式
        output_format = img.format or 'JPEG'

        # 保存优化后的图像
        img.save(output_path, format=output_format, optimize=True, quality=quality)


def get_image_info(image_path: str) -> dict:
    """
    获取图像信息
    
    Args:
        image_path: 图像路径
    
    Returns:
        包含图像信息的字典
    """
    with Image.open(image_path) as img:
        return {
            'format': img.format,
            'mode': img.mode,
            'size': img.size,
            'width': img.width,
            'height': img.height
        }


def crop_image(input_path: str, output_path: str, box: Tuple[int, int, int, int]):
    """
    裁剪图像
    
    Args:
        input_path: 输入图像路径
        output_path: 输出图像路径
        box: 裁剪框 (left, top, right, bottom)
    """
    with Image.open(input_path) as img:
        cropped = img.crop(box)
        cropped.save(output_path)


def convert_image_format(input_path: str, output_path: str, format: str = 'JPEG'):
    """
    转换图像格式
    
    Args:
        input_path: 输入图像路径
        output_path: 输出图像路径
        format: 输出格式 ('JPEG', 'PNG', 'WEBP' 等)
    """
    with Image.open(input_path) as img:
        img.save(output_path, format=format)


def create_video_thumbnail(video_path: str, thumbnail_path: str, time: float = 1.0) -> bool:
    """
    创建视频缩略图
    注意：这个功能需要opencv-python，但在serverless环境中可能不可用
    
    Args:
        video_path: 视频路径
        thumbnail_path: 缩略图保存路径
        time: 提取缩略图的时间点（秒）
    
    Returns:
        bool: 是否成功
    """
    try:
        # 尝试导入cv2，如果不可用则返回False
        import cv2
        CV2_AVAILABLE = True
    except ImportError:
        cv2 = None
        CV2_AVAILABLE = False

    if not CV2_AVAILABLE:
        print("cv2 not available, video thumbnail creation is disabled")
        return False

    try:
        # 打开视频文件
        cap = cv2.VideoCapture(video_path)
        if not cap.isOpened():
            return False

        # 设置视频位置
        cap.set(cv2.CAP_PROP_POS_MSEC, time * 1000)

        # 读取帧
        ret, frame = cap.read()
        if not ret:
            cap.release()
            return False

        # 转换颜色空间 (BGR to RGB)
        frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)

        # 使用PIL保存图像
        img = Image.fromarray(frame_rgb)
        img.save(thumbnail_path, 'JPEG', quality=85)

        # 释放资源
        cap.release()
        return True
    except Exception as e:
        print(f"Error creating video thumbnail: {str(e)}")
        return False


def validate_image(image_path: str) -> Tuple[bool, str]:
    """
    验证图像文件
    
    Args:
        image_path: 图像路径
    
    Returns:
        (是否有效, 错误信息)
    """
    try:
        with Image.open(image_path) as img:
            # 尝试加载图像以验证其有效性
            img.verify()
        return True, ""
    except Exception as e:
        return False, str(e)


def get_image_size_from_bytes(image_bytes: bytes) -> Tuple[int, int]:
    """
    从字节数据获取图像尺寸
    
    Args:
        image_bytes: 图像字节数据
    
    Returns:
        (宽度, 高度)
    """
    img = Image.open(io.BytesIO(image_bytes))
    return img.size
