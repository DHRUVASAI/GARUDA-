import re

def update_index():
    with open('index.html', 'r', encoding='utf-8') as f:
        content = f.read()

    js_vars = """
const docStyle = getComputedStyle(document.documentElement);
const accentColor = docStyle.getPropertyValue('--accent').trim() || '#3b82f6';
const successColor = docStyle.getPropertyValue('--success').trim() || '#10b981';
const dangerColor = docStyle.getPropertyValue('--danger').trim() || '#ef4444';
const warnColor = docStyle.getPropertyValue('--warn').trim() || '#f59e0b';
const textColor = docStyle.getPropertyValue('--text-secondary').trim() || '#8b93a6';
const mutedColor = docStyle.getPropertyValue('--text-muted').trim() || '#3d4658';
"""

    if "const docStyle" not in content:
        content = content.replace("const API =", js_vars + "const API =")

    # Replace Chart.js colors
    content = content.replace("'#1f6feb'", "accentColor")
    content = content.replace("'#2ea043'", "successColor")
    content = content.replace("'#d29922'", "warnColor")
    content = content.replace("'#8b5cf6'", "accentColor") # purple -> accent

    # Chart.js background colors with alpha
    # Use color-mix for background colors
    content = content.replace("'rgba(31,111,235,0.1)'", "accentColor") # Simplification or color-mix
    # Actually, Chart.js supports standard CSS functions? Let's just pass the var and we can adjust opacity via Chart.js 'fill' opacity?
    # Chart.js can accept hex colors, but for backgroundColor, it's better to pass a canvas gradient or leave it. 
    # Let's replace rgba with color-mix
    content = content.replace("'rgba(31,111,235,0.1)'", "'color-mix(in srgb, ' + accentColor + ' 10%, transparent)'")
    content = content.replace("'rgba(46,160,67,0.1)'", "'color-mix(in srgb, ' + successColor + ' 10%, transparent)'")

    # SVG topology
    content = content.replace("'#8b949e'", "textColor")
    content = content.replace("'#da3633'", "dangerColor")
    
    # SVG Edge
    content = content.replace("hasRisky ? 'rgba(218,54,51,0.4)' : 'rgba(139,148,158,0.2)'", "hasRisky ? dangerColor : mutedColor")
    # Need to add opacity setting since we removed it from rgba
    content = content.replace("line.setAttribute('stroke-width', hasRisky ? '2' : '1.5');", "line.setAttribute('stroke-width', hasRisky ? '2' : '1.5');\n      line.setAttribute('opacity', hasRisky ? '0.4' : '0.2');")

    # Other Chart options labels color
    content = content.replace("color:'#8b949e'", "color: textColor")
    content = content.replace("color:'#484f58'", "color: mutedColor")

    # escAttr in device rendering
    content = content.replace("${d.ip}", "${escAttr(d.ip)}")
    content = content.replace("${d.mac}", "${escAttr(d.mac)}")
    content = content.replace("${d.vendor}", "${escAttr(d.vendor)}")
    content = content.replace("${d.name}", "${escAttr(d.name)}")
    content = content.replace("${d.hostname}", "${escAttr(d.hostname)}")

    with open('index.html', 'w', encoding='utf-8') as f:
        f.write(content)

update_index()
