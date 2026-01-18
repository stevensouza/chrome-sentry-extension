# Icon Design Specification

## Current Problem
The security score badge number completely obscures the "CS" letters in the current icon, making the branding invisible when the extension is active.

## New Design: Split Layout

### Design Concept
- **Left half**: CS letters (branding)
- **Right half**: Clear space for Chrome's badge overlay

### Technical Requirements

#### Badge Overlay Behavior
Chrome's badge API overlays text on the **right side** of extension icons. The badge number will appear in a colored circle on the right portion of the icon.

#### Icon Specifications

**All icons should be created in these sizes:**
- `icon16.png` - 16x16px
- `icon32.png` - 32x32px
- `icon48.png` - 48x48px
- `icon128.png` - 128x128px

### Design Layout

```
┌─────────────────────────┐
│         │               │
│   CS    │   [BADGE]     │
│         │   AREA        │
└─────────────────────────┘
  Left 60%    Right 40%
```

### Detailed Specifications

**Left Side (60% width):**
- Display "CS" letters clearly and prominently
- Use white or light colored text
- Orange/red background (current brand color: #ea580c or similar)
- Bold, sans-serif font
- Letters should be vertically and horizontally centered in left portion

**Right Side (40% width):**
- Leave mostly clear/simple for badge visibility
- Can use same background color as left side
- OR use slightly darker/lighter shade to subtly separate sections
- No text or complex graphics that would compete with badge number

**Badge Number Appearance:**
- Chrome will overlay a colored circle (green/orange/red based on score)
- Circle diameter: ~70-80% of icon height
- Position: Right side, vertically centered
- Number inside circle: White text, 1-3 digits (0-100)

### Color Specifications

**Current Colors:**
- Background: #ea580c (orange) or #dc2626 (red)
- "CS" text: White (#ffffff)

**Badge Colors (automatic, based on score):**
- Green #16a34a (score 80-100)
- Orange #ea580c (score 50-79)
- Red #dc2626 (score 0-49)

### Example Visual Description

**For 48x48 icon:**
```
Left section (0-29px width):
  - Solid orange background
  - "CS" letters in white, bold font
  - Letters sized to fit comfortably (approx 20-24px height)

Right section (29-48px width):
  - Same orange background OR slightly darker
  - Badge overlay will appear here (Chrome handles this)
  - ~34px diameter colored circle with white number
```

### Design Tips

1. **Test visibility**: Badge numbers should be clearly readable against your right-side background
2. **Color contrast**: If using same color on both sides, ensure white badge text is legible
3. **Font weight**: Use bold/heavy font for "CS" so letters remain recognizable at small sizes
4. **Simplicity**: Keep design clean - no gradients, shadows, or complex effects that reduce clarity

### Testing Checklist

After creating new icons:

- [ ] Replace icon files in `/icons/` directory
- [ ] Load extension in Chrome (`chrome://extensions/`)
- [ ] Verify "CS" letters are clearly visible in extension list
- [ ] Click extension icon in toolbar - verify popup shows correct combined score
- [ ] Check badge number (colored circle on right) is clearly readable
- [ ] Test at different zoom levels in Chrome
- [ ] Verify both light and dark Chrome themes

### Alternative Design Options

If split layout doesn't work well:

**Option 1: Stacked Layout**
- CS letters at top (smaller)
- Badge at bottom
- Vertical split instead of horizontal

**Option 2: Corner CS**
- Tiny "CS" in top-left corner
- Badge centered
- Minimal branding but always visible

**Option 3: Background Pattern**
- CS as watermark/background pattern
- Badge overlays in center
- Subtle branding throughout

---

## Current Files to Replace

Replace these files in the `/icons/` directory:
- `icon16.png` (currently 16x16)
- `icon32.png` (currently 32x32)
- `icon48.png` (currently 48x48)
- `icon128.png` (currently 128x128)

## Design Tools Recommendations

- **Figma**: Free, browser-based, good for icon design
- **Sketch**: Mac only, professional design tool
- **Adobe Illustrator**: Professional vector editor
- **GIMP**: Free, open-source alternative to Photoshop
- **Inkscape**: Free vector graphics editor

## Export Settings

- **Format**: PNG with transparency
- **Color mode**: RGB
- **Bit depth**: 24-bit (8-bit per channel) or 32-bit (with alpha)
- **Compression**: Standard PNG compression (lossless)
