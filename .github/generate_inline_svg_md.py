# Small script used by pages workflow
# to generate markdown pages with inlined svgs.

import sys
import base64

def generate_md(svg):
    b64 = base64.b64encode(svg.encode('utf-8')).decode("utf-8")
    html = r'<img src="data:image/svg+xml;base64,%s"/>' % b64
    with open("out.md", "w") as f:
        f.write(html)

def inline_svg_to_md(svg_file):
    with open(svg_file, "r") as f:
        lines = f.readlines()
        svg=''.join(lines)
        generate_md(svg)

if __name__ == '__main__':
    inline_svg_to_md(sys.argv[1])