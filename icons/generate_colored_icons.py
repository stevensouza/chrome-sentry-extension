#!/usr/bin/env python3
"""
Generate Chrome Sentry extension icons in 5 colors for dynamic risk indication
No badge number needed - icon color shows security score at a glance
"""

from PIL import Image, ImageDraw, ImageFont
import os

# Color schemes (5 levels - 20% increments)
COLORS = {
    'green': {
        'hex': '#16a34a',
        'name': 'Dark Green',
        'range': '81-100',
        'meaning': 'Excellent (Very safe)'
    },
    'light-green': {
        'hex': '#84cc16',
        'name': 'Light Green',
        'range': '61-80',
        'meaning': 'Good (Safe)'
    },
    'yellow': {
        'hex': '#eab308',
        'name': 'Yellow',
        'range': '41-60',
        'meaning': 'Fair (Moderate risk)'
    },
    'orange': {
        'hex': '#ea580c',
        'name': 'Orange',
        'range': '21-40',
        'meaning': 'Poor (Concerning)'
    },
    'red': {
        'hex': '#dc2626',
        'name': 'Red',
        'range': '0-20',
        'meaning': 'Critical (Dangerous)'
    }
}

WHITE_TEXT = "#ffffff"

# Icon sizes to generate
SIZES = [16, 32, 48, 128]

def hex_to_rgb(hex_color):
    """Convert hex color to RGB tuple"""
    hex_color = hex_color.lstrip('#')
    return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

def create_icon(size, bg_color_hex):
    """Create a single icon at the specified size with given background color"""
    # Create image with colored background
    img = Image.new('RGB', (size, size), hex_to_rgb(bg_color_hex))
    draw = ImageDraw.Draw(img)

    # Calculate font size (proportional to icon size)
    font_size = int(size * 0.44)

    # Try to load a system font - try Arial Bold specifically
    font = None
    try:
        # Try to find a working font
        import platform
        if platform.system() == 'Darwin':  # macOS
            try:
                font = ImageFont.truetype("/System/Library/Fonts/Supplemental/Arial Bold.ttf", font_size)
            except:
                pass
    except:
        pass

    # Draw "CS" text
    text = "CS"

    if font:
        # Use proper text measurement
        try:
            # Try newer method
            left, top, right, bottom = font.getbbox(text)
            text_width = right - left
            text_height = bottom - top
        except:
            # Fallback to older method
            text_width, text_height = draw.textsize(text, font=font)

        # Center text in left 60% of icon
        x = int(size * 0.30) - (text_width // 2)
        y = (size - text_height) // 2

        draw.text((x, y), text, fill=hex_to_rgb(WHITE_TEXT), font=font)
    else:
        # No font - draw manual letters using rectangles/shapes
        # This is a fallback that creates basic block letters

        # For "C"
        c_width = int(size * 0.18)
        c_height = int(size * 0.35)
        c_thick = int(size * 0.06)
        c_x = int(size * 0.12)
        c_y = (size - c_height) // 2

        # C outline
        draw.rectangle([c_x, c_y, c_x + c_width, c_y + c_thick], fill=hex_to_rgb(WHITE_TEXT))  # Top
        draw.rectangle([c_x, c_y, c_x + c_thick, c_y + c_height], fill=hex_to_rgb(WHITE_TEXT))  # Left
        draw.rectangle([c_x, c_y + c_height - c_thick, c_x + c_width, c_y + c_height], fill=hex_to_rgb(WHITE_TEXT))  # Bottom

        # For "S"
        s_width = int(size * 0.18)
        s_height = int(size * 0.35)
        s_thick = int(size * 0.06)
        s_x = int(size * 0.35)
        s_y = (size - s_height) // 2

        mid_y = s_y + s_height // 2

        # S shape (simplified)
        draw.rectangle([s_x, s_y, s_x + s_width, s_y + s_thick], fill=hex_to_rgb(WHITE_TEXT))  # Top
        draw.rectangle([s_x, s_y, s_x + s_thick, mid_y], fill=hex_to_rgb(WHITE_TEXT))  # Top left
        draw.rectangle([s_x, mid_y - s_thick//2, s_x + s_width, mid_y + s_thick//2], fill=hex_to_rgb(WHITE_TEXT))  # Middle
        draw.rectangle([s_x + s_width - s_thick, mid_y, s_x + s_width, s_y + s_height], fill=hex_to_rgb(WHITE_TEXT))  # Bottom right
        draw.rectangle([s_x, s_y + s_height - s_thick, s_x + s_width, s_y + s_height], fill=hex_to_rgb(WHITE_TEXT))  # Bottom

    return img

def main():
    """Generate all icon sizes for all 5 colors"""
    script_dir = os.path.dirname(os.path.abspath(__file__))

    print("🎨 Generating Chrome Sentry colored icons...")
    print(f"   Creating {len(COLORS)} color variations × {len(SIZES)} sizes = {len(COLORS) * len(SIZES)} icons\n")

    total_generated = 0

    for color_key, color_info in COLORS.items():
        print(f"📦 Generating {color_info['name']} icons ({color_info['hex']}):")
        print(f"   Score range: {color_info['range']} - {color_info['meaning']}")

        for size in SIZES:
            icon = create_icon(size, color_info['hex'])
            output_path = os.path.join(script_dir, f"icon{size}-{color_key}.png")

            icon.save(output_path, 'PNG')
            print(f"   ✓ Generated icon{size}-{color_key}.png")
            total_generated += 1

        print()

    print(f"✅ Successfully generated {total_generated} icons!\n")

    print("📋 Color-to-Score Mapping:")
    for color_key, color_info in COLORS.items():
        print(f"   {color_info['range']:>7} → {color_info['name']:<15} {color_info['hex']}")

    print("\n🔧 Next steps:")
    print("1. Update background/service-worker.js to use dynamic icon switching")
    print("2. Update manifest.json to set default icons (yellow recommended)")
    print("3. Reload extension in chrome://extensions/")
    print("4. Icon will now change color based on security score (no number badge)")

if __name__ == "__main__":
    main()
