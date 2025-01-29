# URL Fuzzer

A GUI-based URL fuzzing tool for web application security testing. This tool helps identify potential vulnerabilities including SQL injection, XSS, RCE, and parameter pollution.

## Features

- Multiple vulnerability testing (SQL, XSS, RCE, Parameter Pollution)
- Custom payload support
- Multiple HTTP methods (GET, POST, PUT, DELETE)
- Proxy configuration
- Export results in multiple formats (TXT, JSON, CSV)
- Terminal-style output interface
- Progress tracking
- Response time analysis

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/url-fuzzer.git
cd url-fuzzer
```
2. Create a virtual environment (optional but recommended):
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```
3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Quick Start

1. Launch the URL Fuzzer GUI:
```bash
python url_fuzzer.py
```
2. Enter the target URL in the provided field.
3. Select the HTTP method (GET, POST, PUT, DELETE)
4. Click "Fuzz URL" to start scanning
5. Monitor the progress bar and results in real-time
6. Export or save results as needed

## Advanced Usage

### Custom Payloads

1. Create a text file containing custom payloads.
2. Click "Load Payloads" and select the file.
3. The tool will automatically include your payloads in the scan

### Proxy Configuration
1. Click "Set Proxy"
2. Enter your proxy URL (e.g., http://127.0.0.1:8080 )
3. The tool will route all requests through the specified proxy

### Exporting Results
1. Click "Save Results" for plain text output
2. Use "Export JSON" for structured JSON format
3. Use "Export CSV" for spreadsheet-compatible format

## Project Structure
```bash
url-fuzzer/
├── url.py              # Main application file
├── requirements.txt    # Python dependencies
├── payloads/
│   ├── sql.txt        # SQL injection payloads
│   ├── xss.txt        # XSS payloads
│   ├── rce.txt        # RCE payloads
│   └── param.txt      # Parameter pollution payloads
└── screenshots/        # Application screenshots
```

## Contributing

1. Fork the repository
2. Create your feature branch ( git checkout -b feature/AmazingFeature )
3. Commit your changes ( git commit -m 'Add some AmazingFeature' )
4. Push to the branch ( git push origin feature/AmazingFeature )
5. Open a Pull Request

## Security Considerations

- Always obtain explicit permission before testing any website
- Use the tool responsibly and ethically
- Be aware of local laws and regulations regarding security testing
- Consider using a proxy/VPN for anonymous testing

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
