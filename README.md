# Log Analyzer

A powerful log analyzer tool that parses and analyzes web server logs to provide insights on traffic patterns, user behavior, and potential security threats. This project supports both common log formats and Nginx log formats.

## Features

- **Log Parsing**: Supports parsing of both common and Nginx log formats.
- **Time-Based Analysis**: Analyzes traffic distribution over hours.
- **Top IPs**: Identifies the top IP addresses making requests.
- **User Behavior Analysis**: Provides insights into user sessions and behavior.
- **Security Event Detection**: Detects potential security threats such as SQL injection and XSS attempts.
- **Visualizations**: Generates visual representations of request distribution and status codes.
- **Report Generation**: Exports the analysis results in JSON format.

## Requirements

- Python 3.x
- Required Python packages:
  - `matplotlib`
  - `user-agents`
  - Any other dependencies specified in your `requirements.txt`

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/Priyansh5/log-analyzer.git
   cd log-analyzer
