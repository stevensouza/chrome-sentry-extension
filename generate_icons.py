#!/usr/bin/env python3
"""
Generate Chrome Sentry icons with "CS" text
Creates icon16.png, icon32.png, icon48.png, icon128.png
"""

from PIL import Image, ImageDraw, ImageFont
import os

# Color scheme - orange/red like Tab Manager
BACKGROUND_COLOR = (216, 92, 42)  # #D85C2A
TEXT_COLOR = (255, 255, 255)      # White

def create_icon(size, output_path):
    """Create a single icon at specified size"""
    # Create image with rounded corners
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Draw rounded rectangle background
    corner_radius = int(size * 0.12)
    draw.rounded_rectangle(
        [(0, 0), (size, size)],
        radius=corner_radius,
        fill=BACKGROUND_COLOR
    )

    # Draw "CS" text
    font_size = int(size * 0.55)
    try:
        # Try to use Arial or system default bold font
        font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial Bold.ttf", font_size)
    except:
        try:
            font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", font_size)
        except:
            # Fallback to default
            font = ImageFont.load_default()

    # Get text bounding box for centering
    text = "CS"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]

    # Center the text
    x = (size - text_width) / 2 - bbox[0]
    y = (size - text_height) / 2 - bbox[1]

    draw.text((x, y), text, fill=TEXT_COLOR, font=font)

    # Save the icon
    img.save(output_path, 'PNG')
    print(f"Created {output_path}")

def main():
    """Generate all icon sizes"""
    # Get the icons directory
    script_dir = os.path.dirname(os.path.abspath(__file__))
    icons_dir = os.path.join(script_dir, 'icons')

    # Create icons directory if it doesn't exist
    os.makedirs(icons_dir, exist_ok=True)

    # Generate all sizes
    sizes = [16, 32, 48, 128]
    for size in sizes:
        output_path = os.path.join(icons_dir, f'icon{size}.png')
        create_icon(size, output_path)

    print("\n✅ All icons generated successfully!")
    print(f"📁 Location: {icons_dir}")

if __name__ == '__main__':
    main()
