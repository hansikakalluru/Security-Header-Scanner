from flask import Flask, request, render_template_string
from windows_header_checker import analyze_headers

app = Flask(__name__)

HTML_TEMPLATE = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Security Header Scanner</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; }
    .card { border: 1px solid #ddd; border-radius: 10px; padding: 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.08); }
    input[type="text"] { width: 70%; padding: 10px; margin-right: 10px; }
    button { padding: 10px 16px; cursor: pointer; }
    .result { margin-top: 20px; white-space: pre-wrap; background: #f8f9fa; padding: 15px; border-radius: 8px; }
    .status { font-weight: bold; margin-bottom: 10px; }
    .ok { color: green; }
    .missing { color: #b22222; }
  </style>
</head>
<body>
  <div class="card">
    <h1>Security Header Scanner</h1>
    <p>Enter a target website URL and click Scan to analyze its security headers.</p>
    <form method="post">
      <input type="text" name="url" placeholder="https://example.com" value="{{ url or '' }}" required>
      <button type="submit">Scan</button>
    </form>

    {% if result %}
      <div class="result">
        <div class="status">Target: {{ result.url }}</div>
        <div>Headers Found: {{ result.found }} | Headers Missing: {{ result.missing }}</div>
        <hr>
        {% for item in result.results %}
          <div>
            {% if item.present %}
              <strong class="ok">[+] {{ item.header }}</strong>
            {% else %}
              <strong class="missing">[-] {{ item.header }} MISSING</strong>
            {% endif %}
            <br>
            {% if item.present %}
              Value: {{ item.value }}
            {% endif %}
            <br>
            Vulnerability: {{ item.vulnerability }}
            <br>
            Mitigation: {{ item.mitigation }}
            <br><br>
          </div>
        {% endfor %}
      </div>
    {% endif %}
  </div>
</body>
</html>
"""

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    url = ''

    if request.method == 'POST':
        url = request.form.get('url', '').strip()
        if url:
            if not url.startswith('http'):
                url = 'https://' + url
            try:
                result = analyze_headers(url)
            except Exception as exc:
                result = {'url': url, 'found': 0, 'missing': 0, 'results': [], 'error': str(exc)}

    return render_template_string(HTML_TEMPLATE, result=result, url=url)


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
