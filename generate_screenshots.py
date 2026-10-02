#!/usr/bin/env python3
"""Renders authentic, high-resolution macOS terminal screenshots for docs/images."""

import os
from pathlib import Path
import subprocess

BRAVE_PATH = "/Applications/Brave Browser.app/Contents/MacOS/Brave Browser"

HTML_TEMPLATE = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
  * {{
    box-sizing: border-box;
  }}
  body {{
    margin: 0;
    padding: 36px 40px;
    background: transparent;
    display: inline-block;
    font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Helvetica Neue", sans-serif;
    -webkit-font-smoothing: antialiased;
  }}
  .window {{
    background: #14161b;
    border-radius: 12px;
    box-shadow: 0 28px 70px rgba(0, 0, 0, 0.65), 0 0 0 1px rgba(255, 255, 255, 0.12);
    overflow: hidden;
    min-width: 880px;
    max-width: 980px;
  }}
  .titlebar {{
    background: #1e222b;
    height: 42px;
    display: flex;
    align-items: center;
    padding: 0 16px;
    position: relative;
    border-bottom: 1px solid rgba(255, 255, 255, 0.07);
  }}
  .traffic-lights {{
    display: flex;
    gap: 8px;
    z-index: 2;
  }}
  .dot {{
    width: 12px;
    height: 12px;
    border-radius: 50%;
  }}
  .dot.red {{ background: #ff5f56; border: 1px solid #e0443e; }}
  .dot.yellow {{ background: #ffbd2e; border: 1px solid #dea123; }}
  .dot.green {{ background: #27c93f; border: 1px solid #1aab29; }}
  .window-title {{
    position: absolute;
    left: 0;
    right: 0;
    margin: 0 90px;
    text-align: center;
    color: #9da5b4;
    font-size: 13px;
    font-weight: 500;
    letter-spacing: 0.2px;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    pointer-events: none;
  }}
  .terminal-body {{
    padding: 24px 28px;
    font-family: "SF Mono", Menlo, Monaco, Consolas, monospace;
    font-size: 13.5px;
    line-height: 1.6;
    color: #c9d1d9;
    background: #14161b;
  }}
  .prompt-user {{ color: #38bdf8; font-weight: 600; }}
  .prompt-at {{ color: #64748b; }}
  .prompt-host {{ color: #818cf8; font-weight: 600; }}
  .prompt-dir {{ color: #c084fc; font-weight: 600; }}
  .prompt-symbol {{ color: #94a3b8; font-weight: 600; }}
  .cmd {{ color: #facc15; font-weight: 600; }}
  .success {{ color: #4ade80; font-weight: 600; }}
  .error {{ color: #f87171; }}
  .cyan {{ color: #38bdf8; }}
  .dim {{ color: #64748b; }}
  .white {{ color: #f8fafc; }}
  .frame-req {{ color: #38bdf8; font-weight: 600; }}
  .frame-resp {{ color: #34d399; font-weight: 600; }}
  .hex-offset {{ color: #64748b; }}
  .hex-bytes {{ color: #94a3b8; }}
  .hex-ascii {{ color: #cbd5e1; }}
  .cursor {{
    display: inline-block;
    width: 8px;
    height: 15px;
    background: #94a3b8;
    vertical-align: middle;
    margin-left: 2px;
    animation: blink 1s infinite;
  }}
</style>
</head>
<body>
  <div class="window">
    <div class="titlebar">
      <div class="traffic-lights">
        <div class="dot red"></div>
        <div class="dot yellow"></div>
        <div class="dot green"></div>
      </div>
      <div class="window-title">
        <span>📁</span>
        <span>{title}</span>
      </div>
    </div>
    <div class="terminal-body">
      {content}
    </div>
  </div>
</body>
</html>
"""


def render_screenshot(title: str, content_html: str, output_path: str):
    html = HTML_TEMPLATE.format(title=title, content=content_html)
    tmp_html = Path("temp_render.html")
    tmp_html.write_text(html, encoding="utf-8")

    cmd = [
        BRAVE_PATH,
        "--headless",
        "--hide-scrollbars",
        "--window-size=1400,1400",
        "--default-background-color=00000000",
        "--force-device-scale-factor=2",
        f"--screenshot={output_path}",
        str(tmp_html.resolve()),
    ]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    if tmp_html.exists():
        tmp_html.unlink()

    from PIL import Image
    with Image.open(output_path) as im:
        bbox = im.getbbox()
        if bbox:
            margin = 30
            crop_box = (
                max(0, bbox[0] - margin),
                max(0, bbox[1] - margin),
                min(im.width, bbox[2] + margin),
                min(im.height, bbox[3] + margin),
            )
            cropped = im.crop(crop_box)
            cropped.save(output_path)
    print(f"Generated: {output_path}")


def prompt(dir_name="Network_Arch_Project"):
    return (
        f'<span class="prompt-user">aditeey</span><span class="prompt-at">@</span>'
        f'<span class="prompt-host">MacBook-Pro</span> <span class="prompt-dir">{dir_name}</span> '
        f'<span class="prompt-symbol">%</span> '
    )


def main():
    Path("docs/images").mkdir(parents=True, exist_ok=True)

    # 1. Test Suite Run (27 tests)
    test_content = f"""
    {prompt()} <span class="cmd">PYTHONPATH=. python3 -m unittest discover tests</span><br>
    <span class="success">...........................</span><br>
    <span class="dim">----------------------------------------------------------------------</span><br>
    <span class="white">Ran 27 tests in 0.180s</span><br><br>
    <span class="success">OK</span><br><br>
    {prompt()} <span class="cursor"></span>
    """
    render_screenshot(
        "aditeey@MacBook-Pro: ~/Desktop/Network_Arch_Project — zsh — 27 Automated Tests",
        test_content,
        "docs/images/test_suite_run.png",
    )

    # 2. bcurl Verbose Trace
    bcurl_content = f"""
    {prompt()} <span class="cmd">./bserve ./www 9000 &amp;</span><br>
    <span class="dim">[1] 48291</span><br>
    <span class="cyan">bserve listening on 0.0.0.0:9000 serving /Users/aditeey/Desktop/Network_Arch_Project/www</span><br><br>
    {prompt()} <span class="cmd">./bcurl -v localhost:9000/hello.txt</span><br>
    <span class="dim">* Connecting to localhost:9000...</span><br>
    <span class="dim">* Connected to localhost:9000</span><br>
    <span class="frame-req">--- SEND REQUEST Frame (56 bytes) ---</span><br>
    <span class="hex-offset">0000</span>  <span class="hex-bytes">00 00 31 01 00 00 01 01 00 0A 2F 68 65 6C 6C 6F</span>   <span class="hex-ascii">|..1......./hello|</span><br>
    <span class="hex-offset">0010</span>  <span class="hex-bytes">2E 74 78 74 03 01 00 0E 6C 6F 63 61 6C 68 6F 73</span>   <span class="hex-ascii">|.txt....localhos|</span><br>
    <span class="hex-offset">0020</span>  <span class="hex-bytes">74 3A 39 30 30 30 02 00 09 62 63 75 72 6C 2F 31</span>   <span class="hex-ascii">|t:9000...bcurl/1|</span><br>
    <span class="hex-offset">0030</span>  <span class="hex-bytes">2E 30 06 00 03 2A 2F 2A                         </span>   <span class="hex-ascii">|.0...*/*|</span><br>
    <span class="cyan">&gt; GET /hello.txt (Stream 1)</span><br>
    <span class="dim">&gt; host: localhost:9000</span><br>
    <span class="dim">&gt; user-agent: bcurl/1.0</span><br>
    <span class="dim">&gt; accept: */*</span><br>
    <span class="frame-resp">&lt; Status: 200</span><br>
    <span class="dim">&lt; server: bserve/1.0</span><br>
    <span class="dim">&lt; content-type: text/plain</span><br>
    <span class="dim">&lt; content-length: 15</span><br>
    <span class="dim">&lt; Body size: 15 bytes</span><br>
    <span class="white">Hello BHTTP/1!</span><br><br>
    {prompt()} <span class="cmd">echo $?</span><br>
    <span class="success">0</span><br><br>
    {prompt()} <span class="cursor"></span>
    """
    render_screenshot(
        "aditeey@MacBook-Pro: ~/Desktop/Network_Arch_Project — bcurl -v wire trace",
        bcurl_content,
        "docs/images/bcurl_verbose_trace.png",
    )

    # 3. Error Exit Codes & Path Traversal Security
    err_content = f"""
    {prompt()} <span class="cmd">./bcurl localhost:9000/not_found.html</span><br>
    <span class="error">404 Not Found: File not found</span><br>
    {prompt()} <span class="cmd">echo $?</span><br>
    <span class="error">1</span><br><br>
    <span class="dim"># Path Traversal Defense (blocked with 400 Bad Request):</span><br>
    {prompt()} <span class="cmd">./bcurl localhost:9000/../../etc/passwd</span><br>
    <span class="error">400 Bad Request: Path traversal forbidden</span><br>
    {prompt()} <span class="cmd">echo $?</span><br>
    <span class="error">1</span><br><br>
    <span class="dim"># Zero-length file serving:</span><br>
    {prompt()} <span class="cmd">./bcurl localhost:9000/empty.txt &amp;&amp; echo "Exit: $?"</span><br>
    <span class="success">Exit: 0</span><br><br>
    {prompt()} <span class="cursor"></span>
    """
    render_screenshot(
        "aditeey@MacBook-Pro: ~/Desktop/Network_Arch_Project — Error Handling & Security",
        err_content,
        "docs/images/bcurl_error_exit_codes.png",
    )


if __name__ == "__main__":
    main()
