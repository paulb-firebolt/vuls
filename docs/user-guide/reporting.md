# Report Generation

A comprehensive guide to generating professional vulnerability reports using the Vuls interactive HTML report generator and other reporting formats.

## Overview

The Vuls system provides multiple reporting options:

- **Interactive HTML Reports**: Modern, professional reports with charts and filtering
- **CSV Exports**: Structured data for analysis and tracking
- **JSON Outputs**: Machine-readable format for integration
- **Text Reports**: Simple summaries for quick review

## Interactive HTML Reports

### Features

#### 📊 **Interactive Dashboard**

- Executive summary with key metrics
- Real-time vulnerability statistics
- Color-coded severity indicators
- Package risk scoring

#### 📈 **Advanced Analytics**

- **Severity Distribution**: Donut chart showing vulnerability breakdown
- **Timeline Analysis**: Line chart of vulnerability publication dates
- **CVSS Score Distribution**: Bar chart of score ranges
- **Package Risk Assessment**: Horizontal bar chart of highest-risk packages

#### 🔍 **Powerful Filtering**

- Real-time search across CVE IDs, packages, and descriptions
- Severity level filtering (Critical/High/Medium/Low)
- CVSS score range sliders
- Advanced sorting options
- Filter statistics and clear functionality

#### 🎨 **Modern UI/UX**

- Responsive design (mobile/desktop)
- Dark/light theme toggle
- TailwindCSS styling with custom enhancements
- Smooth animations and transitions
- Print-friendly layout

#### 📤 **Export Capabilities**

- PDF export (via browser print)
- CSV export of filtered results
- Self-contained HTML reports

### Generating HTML Reports

#### Prerequisites

```bash
pip install jinja2  # or uv add jinja2
```

#### Basic Usage

```bash
cd vulnerability-reports

python generate_report.py \
  --input ../realistic_vulnerabilities.json \
  --output reports/vulnerability_report.html \
  --title "System Vulnerability Assessment Report"
```

#### Command Line Options

```bash
python generate_report.py [OPTIONS]

Options:
  -i, --input PATH        Input JSON file (required)
  -o, --output PATH       Output HTML file (required)
  -t, --title TEXT        Report title (default: "Vulnerability Report")
  --theme [light|dark]    Report theme (default: "light")
  --template-dir PATH     Template directory (default: "templates")
```

#### Example Commands

```bash
# Generate a basic report
python generate_report.py -i ../comprehensive_vulnerabilities.json -o reports/security_report.html

# Generate with custom title and dark theme
python generate_report.py \
  -i ../scan_results.json \
  -o reports/monthly_security_audit.html \
  -t "Monthly Security Audit - December 2024" \
  --theme dark

# Use custom template directory
python generate_report.py \
  -i ../vulnerabilities.json \
  -o reports/custom_report.html \
  --template-dir custom_templates/
```

### Input Data Format

The HTML report generator expects JSON data in the following format:

```json
{
  "total_vulnerabilities": 36,
  "packages_affected": 8,
  "vulnerability_breakdown": {
    "CRITICAL": 3,
    "HIGH": 8,
    "MEDIUM": 20,
    "LOW": 5,
    "unknown": 0
  },
  "high_risk_packages": [
    {
      "package": "git",
      "total_vulns": 10,
      "critical": 3,
      "high": 1,
      "medium": 4,
      "low": 2,
      "risk_score": 45
    }
  ],
  "vulnerabilities": [
    {
      "cve_id": "CVE-2022-4203",
      "definition_id": "oval:org.debian:def:...",
      "title": "CVE-2022-4203 openssl",
      "description": "Vulnerability description...",
      "affected_package": "openssl",
      "installed_version": "3.0.16-1~deb12u1",
      "cvss_score": 4.9,
      "severity": "MEDIUM",
      "summary": "Detailed summary...",
      "published_date": "2023-02-24 15:15:11.98+00:00"
    }
  ]
}
```

## Standard Vuls Reports

### JSON Reports

```bash
# Generate JSON report
docker compose run --rm vuls report -format-json

# Save to specific file
docker compose run --rm vuls report -format-json > reports/scan-$(date +%Y%m%d).json
```

### CSV Reports

```bash
# Generate CSV report
docker compose run --rm vuls report -format-csv

# Save to specific file
docker compose run --rm vuls report -format-csv > reports/vulnerabilities-$(date +%Y%m%d).csv
```

### Text Reports

```bash
# Generate full text report
docker compose run --rm vuls report -format-full-text

# Generate one-line summary
docker compose run --rm vuls report -format-one-line-text

# Generate list format
docker compose run --rm vuls report -format-list
```

## Report Automation

### Automated Report Generation Script

```bash
#!/bin/bash
# generate-reports.sh

set -e

DATE=$(date +%Y%m%d)
REPORT_DIR="reports/$(date +%Y-%m)"
mkdir -p "$REPORT_DIR"

echo "Generating vulnerability reports for $DATE..."

# Generate Vuls native reports
echo "Generating JSON report..."
docker compose run --rm vuls report -format-json > "$REPORT_DIR/scan-$DATE.json"

echo "Generating CSV report..."
docker compose run --rm vuls report -format-csv > "$REPORT_DIR/vulnerabilities-$DATE.csv"

echo "Generating text summary..."
docker compose run --rm vuls report -format-list > "$REPORT_DIR/summary-$DATE.txt"

# Process with comprehensive vulnerability checker
echo "Processing with enhanced vulnerability checker..."
python comprehensive_vulnerability_checker.py \
  --vuls-result "results/$(ls results/ | tail -1)" \
  --output "$REPORT_DIR/comprehensive-$DATE.json"

# Generate interactive HTML report
echo "Generating interactive HTML report..."
cd vulnerability-reports
python generate_report.py \
  -i "../$REPORT_DIR/comprehensive-$DATE.json" \
  -o "../$REPORT_DIR/interactive-report-$DATE.html" \
  -t "Vulnerability Assessment Report - $(date +%B\ %Y)"

echo "Reports generated in $REPORT_DIR/"
ls -la "$REPORT_DIR/"
```

### Integration with Vulnerability Scanners

#### With comprehensive_vulnerability_checker.py

```bash
# Run vulnerability scan
python comprehensive_vulnerability_checker.py \
  --vuls-result results/scan_result.json \
  --output comprehensive_vulnerabilities.json

# Generate HTML report
cd vulnerability-reports
python generate_report.py \
  -i ../comprehensive_vulnerabilities.json \
  -o reports/security_assessment.html \
  -t "Infrastructure Security Assessment"
```

#### Complete Workflow Example

```bash
#!/bin/bash
# complete-scan-and-report.sh

DATE=$(date +%Y%m%d)
SCAN_FILE="results/scan_${DATE}.json"
VULN_FILE="vulnerabilities_${DATE}.json"
REPORT_FILE="reports/security_report_${DATE}.html"

# Run Vuls scan
echo "Running vulnerability scan..."
docker compose run --rm vuls scan

# Process results
echo "Processing scan results..."
python comprehensive_vulnerability_checker.py \
  --vuls-result "$SCAN_FILE" \
  --output "$VULN_FILE"

# Generate HTML report
echo "Generating interactive report..."
cd vulnerability-reports
python generate_report.py \
  -i "../$VULN_FILE" \
  -o "../$REPORT_FILE" \
  -t "Security Assessment - $(date +%B\ %Y)"

echo "Complete! Report available at: $REPORT_FILE"
```

## Report Customization

### Custom Templates

The HTML report generator uses Jinja2 templates that can be customized:

```
vulnerability-reports/
├── templates/
│   └── vulnerability_report_template.html  # Main template
├── static/
│   ├── css/
│   │   └── custom.css                     # Custom styling
│   └── js/
│       └── report.js                      # Interactive functionality
```

#### Modifying the Template

1. Edit `templates/vulnerability_report_template.html`
2. Add new sections or charts
3. Customize layout and structure

#### Custom Styling

1. Edit `static/css/custom.css` for custom styles
2. Modify TailwindCSS classes in the template
3. Add custom animations and themes

#### Adding Functionality

1. Edit `static/js/report.js` for new interactive features
2. Add custom filtering logic
3. Implement additional chart types

### Report Themes

#### Light Theme (Default)

```bash
python generate_report.py \
  -i input.json \
  -o output.html \
  --theme light
```

#### Dark Theme

```bash
python generate_report.py \
  -i input.json \
  -o output.html \
  --theme dark
```

## Report Distribution

### Email Distribution

```bash
#!/bin/bash
# email-reports.sh

REPORT_FILE="reports/security_report_$(date +%Y%m%d).html"
RECIPIENTS="security-team@company.com,management@company.com"

# Generate report
./generate-reports.sh

# Email the report
mail -s "Monthly Vulnerability Report - $(date +%B\ %Y)" \
     -a "$REPORT_FILE" \
     "$RECIPIENTS" < email-template.txt
```

### Web Publishing

```bash
#!/bin/bash
# publish-reports.sh

REPORT_DIR="reports/$(date +%Y-%m)"
WEB_DIR="/var/www/security-reports"

# Copy reports to web directory
cp -r "$REPORT_DIR" "$WEB_DIR/"

# Set permissions
chmod -R 644 "$WEB_DIR/$(date +%Y-%m)"
chmod 755 "$WEB_DIR/$(date +%Y-%m)"

echo "Reports published to: https://internal.company.com/security-reports/$(date +%Y-%m)/"
```

### Automated Archival

```bash
#!/bin/bash
# archive-reports.sh

ARCHIVE_DIR="/backup/security-reports"
CURRENT_MONTH=$(date +%Y-%m)

# Create archive
tar -czf "$ARCHIVE_DIR/reports-$CURRENT_MONTH.tar.gz" "reports/$CURRENT_MONTH/"

# Clean up old reports (keep last 12 months)
find reports/ -type d -name "20*" -mtime +365 -exec rm -rf {} \;

echo "Reports archived to: $ARCHIVE_DIR/reports-$CURRENT_MONTH.tar.gz"
```

## Report Analysis

### Key Metrics to Track

#### Executive Summary Metrics

- Total vulnerabilities found
- Breakdown by severity (Critical/High/Medium/Low)
- Number of affected packages
- Systems scanned vs. systems with vulnerabilities

#### Trend Analysis

- Month-over-month vulnerability counts
- Time to remediation tracking
- Recurring vulnerabilities
- New vs. resolved vulnerabilities

#### Risk Assessment

- Package risk scores
- CVSS score distribution
- Vulnerability age analysis
- Exposure timeline

### Sample Analysis Queries

#### CSV Analysis with Command Line Tools

```bash
# Count vulnerabilities by severity
cut -d',' -f5 vulnerabilities.csv | sort | uniq -c

# Find highest CVSS scores
sort -t',' -k6 -nr vulnerabilities.csv | head -10

# Count vulnerabilities by package
cut -d',' -f4 vulnerabilities.csv | sort | uniq -c | sort -nr
```

#### Python Analysis Script

```python
#!/usr/bin/env python3
# analyze-vulnerabilities.py

import pandas as pd
import json
from datetime import datetime

def analyze_vulnerabilities(csv_file):
    """Analyze vulnerability data from CSV file."""
    df = pd.read_csv(csv_file)

    print("=== Vulnerability Analysis ===")
    print(f"Total vulnerabilities: {len(df)}")
    print(f"Unique packages affected: {df['package'].nunique()}")
    print(f"Average CVSS score: {df['cvss_score'].mean():.2f}")

    print("\n=== Severity Breakdown ===")
    severity_counts = df['severity'].value_counts()
    for severity, count in severity_counts.items():
        print(f"{severity}: {count}")

    print("\n=== Top 10 Vulnerable Packages ===")
    package_counts = df['package'].value_counts().head(10)
    for package, count in package_counts.items():
        print(f"{package}: {count}")

    print("\n=== High Risk Vulnerabilities (CVSS >= 7.0) ===")
    high_risk = df[df['cvss_score'] >= 7.0]
    print(f"Count: {len(high_risk)}")
    for _, vuln in high_risk.head(5).iterrows():
        print(f"  {vuln['cve_id']}: {vuln['package']} (CVSS: {vuln['cvss_score']})")

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python analyze-vulnerabilities.py <csv_file>")
        sys.exit(1)

    analyze_vulnerabilities(sys.argv[1])
```

## Browser Compatibility

The interactive HTML reports are compatible with:

- **Modern Browsers**: Chrome 90+, Firefox 88+, Safari 14+, Edge 90+
- **Features**: ES6+, CSS Grid, Flexbox, Chart.js
- **Mobile**: Responsive design works on all screen sizes

## Performance Considerations

### Large Datasets

- **Optimized for**: 1000+ vulnerabilities
- **Lazy Loading**: Vulnerability details loaded on demand
- **Debounced Search**: Smooth filtering experience
- **Virtual Scrolling**: Handles large lists efficiently

### Report Size Optimization

```bash
# Compress large HTML reports
gzip -9 reports/large-report.html

# Serve compressed reports
python -m http.server 8080 --directory reports/
```

## Security Considerations

### Report Security

- **Self-Contained**: No external dependencies in generated reports
- **No Data Transmission**: All processing happens locally
- **Safe HTML**: Jinja2 auto-escaping prevents XSS
- **Print Security**: Sensitive data can be excluded from print view

### Access Control

```bash
# Set restrictive permissions on report files
chmod 600 reports/*.html
chmod 700 reports/

# Use web server authentication for published reports
# Configure .htaccess or nginx auth for web-published reports
```

## Troubleshooting

### Common Issues

#### Template Not Found

```bash
# Ensure you're in the correct directory
cd vulnerability-reports
python generate_report.py ...
```

#### JSON Parse Error

```bash
# Validate your JSON input
python -m json.tool ../your_input.json
```

#### Permission Denied

```bash
# Check file permissions
chmod +x generate_report.py
chmod 755 reports/
```

#### Missing Dependencies

```bash
# Install required packages
uv add jinja2
```

### Debug Mode

```bash
# Add debug output
python -v generate_report.py -i input.json -o output.html
```

## Best Practices

### Report Generation

- Generate reports immediately after scans
- Use consistent naming conventions
- Include timestamps in filenames
- Archive historical reports

### Report Distribution

- Customize reports for different audiences
- Use appropriate security measures for sensitive data
- Automate distribution to stakeholders
- Provide both summary and detailed versions

### Report Analysis

- Track trends over time
- Focus on actionable metrics
- Correlate with remediation efforts
- Use reports to drive security improvements

---

The Vuls reporting system provides comprehensive options for generating professional vulnerability reports. Choose the format that best fits your needs and audience, and consider automating the process for regular assessments.
