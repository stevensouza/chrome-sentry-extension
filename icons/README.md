# Extension Icons

This folder should contain the extension icons in PNG format:

- `icon16.png` - 16x16 pixels (toolbar)
- `icon48.png` - 48x48 pixels (extensions management page)
- `icon128.png` - 128x128 pixels (Chrome Web Store)

## Creating Icons

You can create icons using any image editor or online tool. The icons should:

1. Be PNG format with transparency
2. Have a shield or security-related design
3. Be clear and recognizable at small sizes

## Quick Placeholder Generation

To generate simple placeholder icons, you can use ImageMagick:

```bash
# Create blue square icons as placeholders
convert -size 16x16 xc:#2563eb icon16.png
convert -size 48x48 xc:#2563eb icon48.png
convert -size 128x128 xc:#2563eb icon128.png
```

Or use an online tool like:
- https://favicon.io/favicon-generator/
- https://www.canva.com/
