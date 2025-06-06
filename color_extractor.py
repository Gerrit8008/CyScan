#!/usr/bin/env python3
"""
Color Extractor for CybrScan Scanner Customization
Extracts dominant colors from website CSS and suggests branding colors
"""

import re
import requests
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import cssutils
from typing import Dict, List, Tuple, Optional
import colorsys
import webcolors

logger = logging.getLogger(__name__)

class ColorExtractor:
    """Extract and analyze colors from websites for branding customization"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        # Suppress cssutils warnings
        cssutils.log.setLevel(logging.CRITICAL)
    
    def analyze_website_colors(self, url: str) -> Dict:
        """Main method to analyze a website and extract color palette"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            logger.info(f"Analyzing colors for website: {url}")
            
            # Get the webpage content
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Extract colors from various sources
            colors = {
                'css_colors': self._extract_css_colors(soup, url),
                'inline_colors': self._extract_inline_colors(soup),
                'meta_colors': self._extract_meta_colors(soup),
                'logo_colors': self._extract_logo_info(soup, url)
            }
            
            # Analyze and suggest color palette
            palette = self._create_color_palette(colors)
            
            return {
                'success': True,
                'url': url,
                'extracted_colors': colors,
                'suggested_palette': palette,
                'recommendations': self._generate_recommendations(palette)
            }
            
        except Exception as e:
            logger.error(f"Error analyzing website colors: {e}")
            return {
                'success': False,
                'error': str(e),
                'suggested_palette': self._get_default_palette()
            }
    
    def _extract_css_colors(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract colors from external CSS files"""
        colors = []
        
        # Find all CSS link tags
        css_links = soup.find_all('link', {'rel': 'stylesheet'})
        
        for link in css_links[:5]:  # Limit to first 5 CSS files
            href = link.get('href')
            if href:
                try:
                    css_url = urljoin(base_url, href)
                    css_response = self.session.get(css_url, timeout=5)
                    css_content = css_response.text
                    
                    # Extract colors from CSS content
                    css_colors = self._parse_css_colors(css_content)
                    colors.extend(css_colors)
                    
                except Exception as e:
                    logger.debug(f"Error processing CSS file {href}: {e}")
                    continue
        
        # Also check for inline <style> tags
        style_tags = soup.find_all('style')
        for style in style_tags:
            if style.string:
                css_colors = self._parse_css_colors(style.string)
                colors.extend(css_colors)
        
        return list(set(colors))  # Remove duplicates
    
    def _parse_css_colors(self, css_content: str) -> List[str]:
        """Parse CSS content and extract color values"""
        colors = []
        
        # Patterns for different color formats
        patterns = [
            r'#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})',  # Hex colors
            r'rgb\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)',  # RGB colors
            r'rgba\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*[\d.]+\s*\)',  # RGBA colors
            r'hsl\(\s*(\d+)\s*,\s*(\d+)%\s*,\s*(\d+)%\s*\)',  # HSL colors
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, css_content, re.IGNORECASE)
            for match in matches:
                if isinstance(match, str):  # Hex colors
                    color = '#' + match
                    if self._is_valid_color(color):
                        colors.append(color.lower())
                elif len(match) == 3:  # RGB/HSL colors
                    try:
                        if 'rgb' in pattern:
                            r, g, b = map(int, match)
                            if all(0 <= val <= 255 for val in [r, g, b]):
                                hex_color = '#{:02x}{:02x}{:02x}'.format(r, g, b)
                                colors.append(hex_color)
                        elif 'hsl' in pattern:
                            h, s, l = int(match[0]), int(match[1]), int(match[2])
                            rgb = self._hsl_to_rgb(h, s/100, l/100)
                            hex_color = '#{:02x}{:02x}{:02x}'.format(*rgb)
                            colors.append(hex_color)
                    except (ValueError, TypeError):
                        continue
        
        # Also extract named colors
        named_color_pattern = r'\b(red|blue|green|yellow|orange|purple|pink|brown|black|white|gray|grey|navy|teal|cyan|magenta|lime|olive|maroon|aqua|fuchsia|silver)\b'
        named_colors = re.findall(named_color_pattern, css_content, re.IGNORECASE)
        
        for named_color in named_colors:
            try:
                hex_color = webcolors.name_to_hex(named_color.lower())
                colors.append(hex_color.lower())
            except ValueError:
                continue
        
        return colors
    
    def _extract_inline_colors(self, soup: BeautifulSoup) -> List[str]:
        """Extract colors from inline styles"""
        colors = []
        
        # Find all elements with style attributes
        styled_elements = soup.find_all(attrs={'style': True})
        
        for element in styled_elements:
            style = element.get('style', '')
            inline_colors = self._parse_css_colors(style)
            colors.extend(inline_colors)
        
        return list(set(colors))
    
    def _extract_meta_colors(self, soup: BeautifulSoup) -> Dict[str, str]:
        """Extract colors from meta tags (theme colors, etc.)"""
        meta_colors = {}
        
        # Theme color meta tag
        theme_color = soup.find('meta', {'name': 'theme-color'})
        if theme_color and theme_color.get('content'):
            meta_colors['theme_color'] = theme_color.get('content')
        
        # Apple mobile web app status bar style
        status_bar = soup.find('meta', {'name': 'apple-mobile-web-app-status-bar-style'})
        if status_bar and status_bar.get('content'):
            meta_colors['status_bar_style'] = status_bar.get('content')
        
        return meta_colors
    
    def _extract_logo_info(self, soup: BeautifulSoup, base_url: str) -> Dict:
        """Extract logo information and potential colors"""
        logo_info = {}
        
        # Look for common logo selectors
        logo_selectors = [
            'img[alt*="logo" i]',
            'img[src*="logo" i]',
            'img[class*="logo" i]',
            '.logo img',
            '#logo img',
            'header img',
            'nav img'
        ]
        
        for selector in logo_selectors:
            try:
                logo_img = soup.select_one(selector)
                if logo_img and logo_img.get('src'):
                    logo_url = urljoin(base_url, logo_img.get('src'))
                    logo_info['logo_url'] = logo_url
                    break
            except Exception:
                continue
        
        # Look for favicon
        favicon = soup.find('link', {'rel': 'icon'}) or soup.find('link', {'rel': 'shortcut icon'})
        if favicon and favicon.get('href'):
            favicon_url = urljoin(base_url, favicon.get('href'))
            logo_info['favicon_url'] = favicon_url
        
        return logo_info
    
    def _create_color_palette(self, colors: Dict) -> Dict[str, str]:
        """Create a cohesive color palette from extracted colors"""
        all_colors = []
        
        # Collect all extracted colors
        if colors['css_colors']:
            all_colors.extend(colors['css_colors'])
        if colors['inline_colors']:
            all_colors.extend(colors['inline_colors'])
        if colors['meta_colors']:
            all_colors.extend(colors['meta_colors'].values())
        
        # Remove duplicates and filter out black/white/gray
        unique_colors = list(set(all_colors))
        filtered_colors = [c for c in unique_colors if self._is_brand_color(c)]
        
        if not filtered_colors:
            return self._get_default_palette()
        
        # Analyze colors and create palette
        color_analysis = self._analyze_colors(filtered_colors)
        
        # Select primary color (most frequent or most saturated)
        primary_color = self._select_primary_color(color_analysis)
        
        # Generate complementary colors
        palette = {
            'primary_color': primary_color,
            'secondary_color': self._generate_secondary_color(primary_color),
            'accent_color': self._generate_accent_color(primary_color),
            'background_color': '#ffffff',
            'text_color': '#1f2937',
            'button_color': primary_color,
            'button_text_color': self._get_contrast_color(primary_color)
        }
        
        return palette
    
    def _analyze_colors(self, colors: List[str]) -> List[Dict]:
        """Analyze color properties (saturation, brightness, etc.)"""
        color_analysis = []
        
        for color in colors:
            try:
                # Convert hex to RGB
                rgb = tuple(int(color[i:i+2], 16) for i in (1, 3, 5))
                
                # Convert to HSL for analysis
                hsl = colorsys.rgb_to_hls(rgb[0]/255, rgb[1]/255, rgb[2]/255)
                
                analysis = {
                    'hex': color,
                    'rgb': rgb,
                    'hue': hsl[0] * 360,
                    'saturation': hsl[2] * 100,
                    'lightness': hsl[1] * 100,
                    'frequency': colors.count(color)
                }
                
                color_analysis.append(analysis)
                
            except Exception:
                continue
        
        return sorted(color_analysis, key=lambda x: (x['frequency'], x['saturation']), reverse=True)
    
    def _select_primary_color(self, color_analysis: List[Dict]) -> str:
        """Select the best primary color from analysis"""
        if not color_analysis:
            return '#2563eb'  # Default blue
        
        # Prefer colors with good saturation and frequency
        for color in color_analysis:
            if color['saturation'] > 30 and color['lightness'] > 20 and color['lightness'] < 80:
                return color['hex']
        
        # Fallback to first color
        return color_analysis[0]['hex']
    
    def _generate_secondary_color(self, primary_color: str) -> str:
        """Generate a secondary color based on primary"""
        try:
            # Convert to HSL
            rgb = tuple(int(primary_color[i:i+2], 16) for i in (1, 3, 5))
            hsl = colorsys.rgb_to_hls(rgb[0]/255, rgb[1]/255, rgb[2]/255)
            
            # Adjust hue by 30 degrees and reduce saturation
            new_hue = (hsl[0] + 30/360) % 1
            new_saturation = max(0.3, hsl[2] * 0.7)
            new_lightness = min(0.8, hsl[1] * 1.2)
            
            # Convert back to RGB
            rgb = colorsys.hls_to_rgb(new_hue, new_lightness, new_saturation)
            rgb = tuple(int(c * 255) for c in rgb)
            
            return '#{:02x}{:02x}{:02x}'.format(*rgb)
            
        except Exception:
            return '#6b7280'  # Default gray
    
    def _generate_accent_color(self, primary_color: str) -> str:
        """Generate an accent color based on primary"""
        try:
            # Convert to HSL
            rgb = tuple(int(primary_color[i:i+2], 16) for i in (1, 3, 5))
            hsl = colorsys.rgb_to_hls(rgb[0]/255, rgb[1]/255, rgb[2]/255)
            
            # Adjust hue by 120 degrees (complementary)
            new_hue = (hsl[0] + 120/360) % 1
            new_saturation = min(1.0, hsl[2] * 1.1)
            new_lightness = hsl[1]
            
            # Convert back to RGB
            rgb = colorsys.hls_to_rgb(new_hue, new_lightness, new_saturation)
            rgb = tuple(int(c * 255) for c in rgb)
            
            return '#{:02x}{:02x}{:02x}'.format(*rgb)
            
        except Exception:
            return '#10b981'  # Default green
    
    def _get_contrast_color(self, color: str) -> str:
        """Get appropriate text color (black or white) for contrast"""
        try:
            # Convert to RGB
            rgb = tuple(int(color[i:i+2], 16) for i in (1, 3, 5))
            
            # Calculate relative luminance
            def get_luminance(c):
                c = c / 255
                if c <= 0.03928:
                    return c / 12.92
                else:
                    return pow((c + 0.055) / 1.055, 2.4)
            
            r, g, b = [get_luminance(c) for c in rgb]
            luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b
            
            # Return white for dark colors, black for light colors
            return '#ffffff' if luminance < 0.5 else '#000000'
            
        except Exception:
            return '#ffffff'
    
    def _is_valid_color(self, color: str) -> bool:
        """Check if a color string is valid"""
        if not color.startswith('#'):
            return False
        
        hex_part = color[1:]
        if len(hex_part) not in [3, 6]:
            return False
        
        try:
            int(hex_part, 16)
            return True
        except ValueError:
            return False
    
    def _is_brand_color(self, color: str) -> bool:
        """Filter out non-brand colors (pure black, white, gray)"""
        if not self._is_valid_color(color):
            return False
        
        # Convert to RGB
        try:
            rgb = tuple(int(color[i:i+2], 16) for i in (1, 3, 5))
            
            # Check if it's too close to black, white, or gray
            if all(c < 20 for c in rgb):  # Too dark
                return False
            if all(c > 235 for c in rgb):  # Too light
                return False
            
            # Check if it's gray (all RGB values are similar)
            max_diff = max(rgb) - min(rgb)
            if max_diff < 30:  # Too gray
                return False
            
            return True
            
        except Exception:
            return False
    
    def _hsl_to_rgb(self, h: int, s: float, l: float) -> Tuple[int, int, int]:
        """Convert HSL to RGB"""
        rgb = colorsys.hls_to_rgb(h/360, l, s)
        return tuple(int(c * 255) for c in rgb)
    
    def _get_default_palette(self) -> Dict[str, str]:
        """Return a default color palette"""
        return {
            'primary_color': '#2563eb',
            'secondary_color': '#1e40af',
            'accent_color': '#3b82f6',
            'background_color': '#ffffff',
            'text_color': '#1f2937',
            'button_color': '#2563eb',
            'button_text_color': '#ffffff'
        }
    
    def _generate_recommendations(self, palette: Dict[str, str]) -> List[str]:
        """Generate recommendations for using the color palette"""
        recommendations = [
            f"Use {palette['primary_color']} as your main brand color for headers and important elements",
            f"Apply {palette['secondary_color']} for secondary buttons and accents", 
            f"Use {palette['accent_color']} sparingly for call-to-action elements",
            "Maintain good contrast ratios for accessibility",
            "Test your color choices across different devices and screen types"
        ]
        
        return recommendations

# Global instance
color_extractor = ColorExtractor()

def extract_website_colors(url: str) -> Dict:
    """Main function to extract colors from a website"""
    return color_extractor.analyze_website_colors(url)