"""Render docs/figures/*.svg to PNG.

This is optional and only needed if you want raster images for Word/PDF.

Requires:
  pip install cairosvg

Usage:
  python scripts/render_figures.py

Outputs:
  docs/figures/*.png
"""

from __future__ import annotations

import glob
import os
from pathlib import Path


def main() -> int:
    try:
        import cairosvg  # type: ignore
    except Exception as e:  # pragma: no cover
        raise SystemExit(
            "cairosvg is required. Install it with: pip install cairosvg\n\n"
            f"Import error: {e}"
        )

    repo_root = Path(__file__).resolve().parents[1]
    figures_dir = repo_root / "docs" / "figures"

    svgs = sorted(glob.glob(str(figures_dir / "*.svg")))
    if not svgs:
        print("No SVG files found under docs/figures")
        return 0

    for svg_path in svgs:
        svg_path = os.path.abspath(svg_path)
        png_path = os.path.splitext(svg_path)[0] + ".png"

        with open(svg_path, "rb") as f:
            svg_bytes = f.read()

        cairosvg.svg2png(bytestring=svg_bytes, write_to=png_path, scale=2.0)
        print(f"Rendered: {png_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
