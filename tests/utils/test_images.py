import pytest
from PIL import Image
import io
from utils.core.images import (
    validate_and_process_image,
    InvalidImageError,
    MAX_FILE_SIZE,
    MIN_DIMENSION,
    MAX_DIMENSION
)

def create_test_image(width: int, height: int, format: str = 'PNG') -> bytes:
    """Helper function to create test images"""
    image = Image.new('RGB', (width, height), color='red')
    output = io.BytesIO()
    image.save(output, format=format)
    return output.getvalue()

def test_webp_dependencies_are_installed():
    """Test that webp dependencies are installed"""
    assert '.webp' in Image.registered_extensions(), "WebP dependencies are not installed (e.g., libwebp-dev on Linux)"

def test_valid_square_image():
    """Test processing a valid square image"""
    image_data = create_test_image(500, 500)
    processed_data, content_type = validate_and_process_image(image_data, 'image/png')
    
    # Verify the processed image
    processed_image = Image.open(io.BytesIO(processed_data))
    assert processed_image.size == (500, 500)
    assert content_type == 'image/png'

def test_valid_rectangular_image():
    """Test processing a valid rectangular image"""
    image_data = create_test_image(800, 600)
    processed_data, content_type = validate_and_process_image(image_data, 'image/png')
    
    # Verify the processed image
    processed_image = Image.open(io.BytesIO(processed_data))
    assert processed_image.size == (600, 600)
    assert content_type == 'image/png'

def test_minimum_size_image():
    """Test processing an image with minimum allowed dimensions"""
    image_data = create_test_image(MIN_DIMENSION, MIN_DIMENSION)
    processed_data, content_type = validate_and_process_image(image_data, 'image/png')
    
    processed_image = Image.open(io.BytesIO(processed_data))
    assert processed_image.size == (100, 100)

def test_too_small_image():
    """Test that too small images are rejected"""
    image_data = create_test_image(MIN_DIMENSION - 1, MIN_DIMENSION - 1)
    with pytest.raises(InvalidImageError) as exc_info:
        validate_and_process_image(image_data, 'image/png')
    assert "Image too small" in str(exc_info.value.detail)

def test_too_large_image():
    """Test that too large images are rejected"""
    image_data = create_test_image(MAX_DIMENSION + 1, MAX_DIMENSION + 1)
    with pytest.raises(InvalidImageError) as exc_info:
        validate_and_process_image(image_data, 'image/png')
    assert "Image too large" in str(exc_info.value.detail)

def test_invalid_file_type():
    """Test that invalid file types are rejected"""
    image_data = create_test_image(500, 500)
    with pytest.raises(InvalidImageError) as exc_info:
        validate_and_process_image(image_data, 'image/gif')
    assert "Invalid file type" in str(exc_info.value.detail)

def test_file_too_large():
    """Test that files exceeding MAX_FILE_SIZE are rejected"""
    # Create a large file that exceeds MAX_FILE_SIZE
    large_image_data = b'0' * (MAX_FILE_SIZE + 1)
    with pytest.raises(InvalidImageError) as exc_info:
        validate_and_process_image(large_image_data, 'image/png')
    assert "File too large" in str(exc_info.value.detail)

def test_corrupt_image_data():
    """Test that corrupt image data is rejected"""
    corrupt_data = b'not an image'
    with pytest.raises(InvalidImageError) as exc_info:
        validate_and_process_image(corrupt_data, 'image/png')
    assert "Invalid image file" in str(exc_info.value.detail)

def test_different_image_formats():
    """Test processing different valid image formats"""
    formats = [
        ('JPEG', 'image/jpeg'),
        ('PNG', 'image/png'),
        ('WEBP', 'image/webp')
    ]
    
    for format_name, content_type in formats:
        image_data = create_test_image(500, 500, format_name)
        processed_data, result_type = validate_and_process_image(image_data, content_type)
        
        # Verify the processed image
        processed_image = Image.open(io.BytesIO(processed_data))
        assert processed_image.size == (500, 500)
        # Output should match input format
        assert result_type == content_type
