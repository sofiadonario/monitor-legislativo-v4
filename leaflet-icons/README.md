# Leaflet Icons - Local Assets

These icons are downloaded from Leaflet CDN for security purposes.

## Source
- Original: https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/
- License: BSD-2-Clause (Leaflet)

## Files
- marker-icon.png - Default marker icon
- marker-icon-2x.png - High DPI version
- marker-shadow.png - Drop shadow for markers

## Security Note
Using local assets instead of CDN links improves security by:
1. Eliminating external dependencies
2. Preventing CDN compromise attacks
3. Ensuring resource availability offline
4. Maintaining consistent styling

## Download Commands
```bash
wget https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon.png
wget https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-icon-2x.png  
wget https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/images/marker-shadow.png
```