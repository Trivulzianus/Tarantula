import json
import os

def generate_html(json_data, output_file):
    # Parse the JSON data if it's a string
    if isinstance(json_data, str):
        json_data = json.loads(json_data)
        
    # Convert to list if single object
    if isinstance(json_data, dict):
        json_data = [json_data]

    # HTML structure with basic styling
    html_template = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Vulnerability Analysis Report</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f4f4f9;
                color: #333;
                line-height: 1.6;
            }}
            .container {{
                width: 80%;
                margin: 20px auto;
                background: #fff;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            }}
            h1 {{
                color: #444;
                text-align: center;
                margin-bottom: 20px;
            }}
            h2 {{
                color: #555;
                margin-top: 20px;
                border-bottom: 2px solid #eee;
                padding-bottom: 5px;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }}
            table th, table td {{
                border: 1px solid #ddd;
                padding: 8px;
                text-align: left;
            }}
            table th {{
                background-color: #f4f4f9;
                font-weight: bold;
            }}
            .summary {{
                background: #f9f9f9;
                padding: 15px;
                border-left: 5px solid #007BFF;
                margin-bottom: 20px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Vulnerability Analysis Report</h1>
            {content}
        </div>
    </body>
    </html>
    """
    # Build the content dynamically from JSON
    content = ""
    for i, entry in enumerate(json_data, 1):
        if isinstance(entry, str):
            content += f"""
            <h2>Vulnerability #{i}</h2>
            <div class="summary">
                <h3>Summary:</h3>
                <p>{entry.replace("\n", "<br>")}</p>
            </div>
            """
        elif isinstance(entry, dict):
            content += f"""
            <h2>Vulnerability #{i}</h2>
            <div class="summary">
                <h3>Summary:</h3>
                <p>{entry.get("analysis", "").replace("\n", "<br>")}</p>
            </div>
            <h3>Request Details:</h3>
            <table>
                <tr><th>Method</th><td>{entry.get("method", "")}</td></tr>
                <tr><th>Endpoint</th><td>{entry.get("endpoint", "")}</td></tr>
                <tr><th>Payload</th><td>{entry.get("payload", "")}</td></tr>
                <tr><th>Parameter</th><td>{entry.get("parameter", "")}</td></tr>
                <tr><th>Subdirectory</th><td>{entry.get("subdirectory", "")}</td></tr>
                <tr><th>Confidence</th><td>{entry.get("confidence", "")}</td></tr>
            </table>
            <h3>Full Request:</h3>
            <pre style="background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow-x: auto;">
{entry.get("request", "No request data available")}
            </pre>
        """
    # Combine content with the template
    html_content = html_template.format(content=content)
    # Write to output file
    with open(output_file, "w", encoding='utf-8') as f:
        f.write(html_content)

# Load the JSON data
with open("c:/Users/tomer/OneDrive/Desktop/Tarantula/vulnerabilities.json", "r") as f:
    json_data = json.load(f)

try:
    with open("c:/Users/tomer/OneDrive/Desktop/Tarantula/vulnerabilities.json", "r") as f:
        json_data = json.load(f)
    print("JSON data loaded successfully.")
except Exception as e:
    print(f"An error occurred while loading JSON: {e}")

# Generate HTML Report

try:
    output_path = "c:/Users/tomer/OneDrive/Desktop/Tarantula/vulnerability_report.html"
    generate_html(json_data, output_path)
    print(f"HTML report successfully created at: {output_path}")
except Exception as e:
    print(f"An error occurred while generating the HTML report: {e}")