# utils/images.py
from PIL import Image
import io
from typing import Tuple
from exceptions.http_exceptions import InvalidImageError


# --- Constants ---


MAX_FILE_SIZE = 2 * 1024 * 1024  # 2MB in bytes
ALLOWED_CONTENT_TYPES = {
    'image/jpeg': 'JPEG',
    'image/png': 'PNG',
    'image/webp': 'WEBP'
}
MIN_DIMENSION = 100
MAX_DIMENSION = 2000


# --- Functions ---


def validate_and_process_image(
    image_data: bytes,
    content_type: str | None
) -> Tuple[bytes, str]:
    """
    Validates and processes an image file.
    Returns a tuple of (processed_image_data, content_type).
    Ensures the image is square by center-cropping.
    
    Raises:
        InvalidImageError: If the image is invalid or doesn't meet requirements
    """
    # Check file size
    if len(image_data) > MAX_FILE_SIZE:
        raise InvalidImageError(
            message="File too large (max 2MB)"
        )

    # Check file type
    if not content_type or content_type not in ALLOWED_CONTENT_TYPES:
        raise InvalidImageError(
            message="Invalid file type. Must be JPEG, PNG, or WebP"
        )

    try:
        # Open and validate image
        image: Image.Image = Image.open(io.BytesIO(image_data))
        width, height = image.size
    except Exception as e:
        raise InvalidImageError(
            message="Invalid image file"
        )

    # Check minimum dimensions
    if width < MIN_DIMENSION or height < MIN_DIMENSION:
        raise InvalidImageError(
            message=f"Image too small. Minimum dimension is {MIN_DIMENSION}px"
        )

    # Check maximum dimensions
    if width > MAX_DIMENSION or height > MAX_DIMENSION:
        raise InvalidImageError(
            message=f"Image too large. Maximum dimension is {MAX_DIMENSION}px"
        )

    # Crop to square
    min_dim = min(width, height)
    left = (width - min_dim) // 2
    top = (height - min_dim) // 2
    right = left + min_dim
    bottom = top + min_dim
    
    image = image.crop((left, top, right, bottom))

    # Get the format from the content type
    output_format = ALLOWED_CONTENT_TYPES[content_type]

    # Convert back to bytes
    output = io.BytesIO()
    image.save(output, format=output_format)
    output.seek(0)
    return output.getvalue(), content_type
