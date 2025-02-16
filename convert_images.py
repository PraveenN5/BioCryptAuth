from PIL import Image
from pillow_avif import AvifImagePlugin
import os

def convert_to_jpg(input_path, output_path):
    """Convert image to JPG format"""
    try:
        # Register AVIF support
        AvifImagePlugin.register()
        
        # Open and convert image
        with Image.open(input_path) as img:
            # Convert to RGB mode if necessary
            if img.mode != 'RGB':
                img = img.convert('RGB')
            # Save as JPG
            img.save(output_path, 'JPEG')
        print(f"Successfully converted {input_path} to {output_path}")
    except Exception as e:
        print(f"Error converting {input_path}: {str(e)}")

def main():
    # Base directory
    base_dir = "C:/Users/goxth/Documents/COLLEGE WORKS/FINAL YEAR PROJECT"
    
    # Image conversions
    conversions = [
        {
            'input': 'adult-man-serene-face-expression-studio-portrait_53876-75419.avif',
            'output': 'adult-man-face.jpg'
        },
        {
            'input': 'Pupil-human-eye.webp',
            'output': 'Pupil-human-eye.jpg'
        },
        {
            'input': 'worldface-british-guy-white-background_53876-14467.avif',
            'output': 'worldface-british-guy.jpg'
        }
    ]
    
    # Convert each image
    for conv in conversions:
        input_path = os.path.join(base_dir, conv['input'])
        output_path = os.path.join(base_dir, conv['output'])
        convert_to_jpg(input_path, output_path)

if __name__ == "__main__":
    main() 