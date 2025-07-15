#!/usr/bin/env python3
"""
Email Header Analyzer
A web application to analyze email headers and visualize routing information.
"""

import re
import email
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from flask import Flask, render_template_string, request, jsonify
import plotly.graph_objects as go
import plotly.utils

app = Flask(__name__)

class EmailHeaderAnalyzer:
    def __init__(self):
        self.security_headers = {
            'dkim-signature', 'domainkey-signature', 'authentication-results',
            'received-spf', 'dmarc-filter', 'arc-authentication-results',
            'arc-message-signature', 'arc-seal', 'x-ironport-av', 'x-trellix',
            'x-ms-exchange-organization-authsource', 'x-ms-exchange-organization-authas',
            'x-cse-connectionguid', 'x-cse-msgguid', 'x-mga-submission'
        }
        
        self.x_headers = set()
        
    def parse_received_header(self, received_line: str) -> Dict:
        """Parse a single Received header line"""
        # Remove extra whitespace and newlines
        received_line = re.sub(r'\s+', ' ', received_line.strip())
        
        # Extract timestamp - look for semicolon followed by date
        timestamp = None
        semicolon_pattern = r';\s*(.+)$'
        timestamp_match = re.search(semicolon_pattern, received_line)
        if timestamp_match:
            timestamp = timestamp_match.group(1).strip()
        
        # Extract from server information
        from_server = 'Unknown'
        from_pattern = r'from\s+([^\s\(]+)'
        from_match = re.search(from_pattern, received_line, re.IGNORECASE)
        if from_match:
            from_server = from_match.group(1).strip()
        
        # Extract by server information
        by_server = 'Unknown'
        by_pattern = r'by\s+([^\s\(]+)'
        by_match = re.search(by_pattern, received_line, re.IGNORECASE)
        if by_match:
            by_server = by_match.group(1).strip()
        
        # Extract protocol information
        protocol = 'Unknown'
        with_pattern = r'with\s+([^\s;]+)'
        with_match = re.search(with_pattern, received_line, re.IGNORECASE)
        if with_match:
            protocol = with_match.group(1).strip()
        else:
            via_pattern = r'via\s+([^\s;]+)'
            via_match = re.search(via_pattern, received_line, re.IGNORECASE)
            if via_match:
                protocol = via_match.group(1).strip()
        
        return {
            'from': from_server,
            'by': by_server,
            'protocol': protocol,
            'timestamp': timestamp,
            'full_line': received_line
        }
    
    def parse_raw_headers_properly(self, raw_headers: str) -> Dict:
        """Parse raw email headers properly handling RFC 2822 folding"""
        # First, normalize the line breaks - replace double newlines with single spaces
        # This handles cases where headers are formatted with extra line breaks
        normalized_headers = re.sub(r'\n\s*\n', '\n', raw_headers)
        
        # Also handle cases where continuation lines don't start with whitespace
        # Look for patterns where a line ends and the next line looks like a continuation
        lines = normalized_headers.split('\n')
        processed_lines = []
        
        i = 0
        while i < len(lines):
            line = lines[i].rstrip()
            
            # Skip empty lines
            if not line.strip():
                i += 1
                continue
            
            # Check if this is a header line (contains ':' and doesn't start with whitespace)
            # Also check that it doesn't start with numbers (which are likely continuation lines)
            is_header_line = (
                ':' in line and 
                not line.startswith(' ') and 
                not line.startswith('\t') and
                not re.match(r'^\d', line.strip())  # Don't treat lines starting with digits as headers
            )
            
            if is_header_line:
                # This is a new header
                processed_lines.append(line)
            else:
                # This might be a continuation line
                if processed_lines:
                    # Append to the previous line with a space
                    processed_lines[-1] += ' ' + line.strip()
                else:
                    # First line doesn't look like a header, skip it
                    pass
            
            i += 1
        
        # Now parse the processed lines
        headers = {}
        for line in processed_lines:
            if ':' in line:
                colon_pos = line.find(':')
                header_name = line[:colon_pos].strip()
                header_value = line[colon_pos + 1:].strip()
                
                # Store the header
                if header_name in headers:
                    # Multiple headers with same name - convert to list
                    if isinstance(headers[header_name], list):
                        headers[header_name].append(header_value)
                    else:
                        headers[header_name] = [headers[header_name], header_value]
                else:
                    headers[header_name] = header_value
        
        return headers
    
    def manual_header_parse(self, raw_headers: str) -> Dict:
        """Manual header parsing as fallback"""
        headers = {}
        lines = raw_headers.split('\n')
        
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # Skip empty lines
            if not line.strip():
                i += 1
                continue
            
            # Check if this is a header line (contains ':')
            if ':' in line and not line.startswith(' ') and not line.startswith('\t'):
                header_name, header_value = line.split(':', 1)
                header_name = header_name.strip()
                header_value = header_value.strip()
                
                # Look ahead for continuation lines
                i += 1
                while i < len(lines) and (lines[i].startswith(' ') or lines[i].startswith('\t')):
                    header_value += ' ' + lines[i].strip()
                    i += 1
                
                # Store the header
                if header_name in headers:
                    if isinstance(headers[header_name], list):
                        headers[header_name].append(header_value)
                    else:
                        headers[header_name] = [headers[header_name], header_value]
                else:
                    headers[header_name] = header_value
            else:
                i += 1
        
        return headers
    
    def calculate_delays(self, hops: List[Dict]) -> List[Dict]:
        """Calculate delays between hops"""
        if len(hops) < 2:
            return hops
            
        # Parse timestamps and calculate delays
        # NOTE: hops are in chronological order (oldest first), so we calculate
        # delay as the time it took to get FROM the current hop TO the next hop
        for i in range(len(hops) - 1):
            current_hop = hops[i]
            next_hop = hops[i + 1]
            
            try:
                if current_hop['timestamp'] and next_hop['timestamp']:
                    # Try to parse various timestamp formats
                    current_time = self.parse_timestamp(current_hop['timestamp'])
                    next_time = self.parse_timestamp(next_hop['timestamp'])
                    
                    if current_time and next_time:
                        # Calculate delay: next_time - current_time
                        # (time it took to get from current hop to next hop)
                        delay = (next_time - current_time).total_seconds()
                        current_hop['delay_seconds'] = delay
                        current_hop['delay_human'] = self.format_delay(delay)
                    else:
                        current_hop['delay_seconds'] = None
                        current_hop['delay_human'] = 'Unable to parse'
                else:
                    current_hop['delay_seconds'] = None
                    current_hop['delay_human'] = 'Missing timestamp'
            except Exception as e:
                current_hop['delay_seconds'] = None
                current_hop['delay_human'] = f'Error: {str(e)}'
        
        # The last hop doesn't have a delay (no next hop to compare to)
        if hops:
            hops[-1]['delay_seconds'] = None
            hops[-1]['delay_human'] = 'N/A'
        
        return hops
    
    def parse_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse various timestamp formats"""
        if not timestamp_str:
            return None
            
        timestamp_str = timestamp_str.strip()
        
        # Common formats found in email headers
        formats = [
            '%a, %d %b %Y %H:%M:%S %z',
            '%d %b %Y %H:%M:%S %z',
            '%a, %d %b %Y %H:%M:%S %Z',
            '%d %b %Y %H:%M:%S %Z',
            '%a, %d %b %Y %H:%M:%S',
            '%d %b %Y %H:%M:%S',
        ]
        
        for fmt in formats:
            try:
                return datetime.strptime(timestamp_str, fmt)
            except ValueError:
                continue
        
        # Try removing timezone abbreviation in parentheses
        paren_pattern = r'\s*\([^)]+\)\s*$'
        timestamp_clean = re.sub(paren_pattern, '', timestamp_str)
        if timestamp_clean != timestamp_str:
            for fmt in formats:
                try:
                    return datetime.strptime(timestamp_clean, fmt)
                except ValueError:
                    continue
        
        # Try extracting just the date/time portion
        simple_patterns = [
            r'(\w+,?\s+\d{1,2}\s+\w{3}\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[+-]\d{4})',
            r'(\d{1,2}\s+\w{3}\s+\d{4}\s+\d{1,2}:\d{2}:\d{2}\s+[+-]\d{4})',
            r'(\w+,?\s+\d{1,2}\s+\w{3}\s+\d{4}\s+\d{1,2}:\d{2}:\d{2})',
            r'(\d{1,2}\s+\w{3}\s+\d{4}\s+\d{1,2}:\d{2}:\d{2})',
        ]
        
        for pattern in simple_patterns:
            match = re.search(pattern, timestamp_str)
            if match:
                simplified_ts = match.group(1)
                for fmt in formats:
                    try:
                        return datetime.strptime(simplified_ts, fmt)
                    except ValueError:
                        continue
        
        return None
    
    def format_delay(self, seconds: float) -> str:
        """Format delay in human readable format"""
        if seconds < 0:
            return f"{abs(seconds):.1f}s (negative - possible reordering or clock skew)"
        elif seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds/60:.1f}m"
        else:
            return f"{seconds/3600:.1f}h"
    
    def analyze_headers(self, raw_headers: str) -> Dict:
        """Analyze email headers and return structured data"""
        # Parse headers using manual parsing (more reliable for raw headers)
        headers = self.parse_raw_headers_properly(raw_headers)
        
        # Extract basic info, handling both single values and lists
        def get_header_value(key):
            value = headers.get(key, 'N/A')
            if isinstance(value, list):
                return value[0] if value else 'N/A'
            return value
        
        basic_info = {
            'subject': get_header_value('Subject'),
            'message_id': get_header_value('Message-ID'),
            'date': get_header_value('Date'),
            'from': get_header_value('From'),
            'to': get_header_value('To')
        }
        
        # Parse Received headers - get all instances
        received_headers = []
        if 'Received' in headers:
            received_value = headers['Received']
            if isinstance(received_value, list):
                received_headers = received_value
            else:
                received_headers = [received_value]
        
        # IMPORTANT: Received headers are added in reverse chronological order
        # (newest first), so we need to reverse them to get chronological order
        # (oldest first) for proper delay calculation
        received_headers.reverse()
        
        # Parse each received header
        hops = []
        for received in received_headers:
            hop = self.parse_received_header(received)
            hops.append(hop)
        
        # Try to sort hops by timestamp to handle out-of-order cases
        # This helps with situations where the same server processes multiple steps
        hops_with_timestamps = []
        hops_without_timestamps = []
        
        for hop in hops:
            if hop['timestamp']:
                parsed_time = self.parse_timestamp(hop['timestamp'])
                if parsed_time:
                    hop['_parsed_timestamp'] = parsed_time
                    hops_with_timestamps.append(hop)
                else:
                    hops_without_timestamps.append(hop)
            else:
                hops_without_timestamps.append(hop)
        
        # Sort timestamped hops chronologically
        hops_with_timestamps.sort(key=lambda x: x['_parsed_timestamp'])
        
        # Combine: timestamped hops first (in chronological order), then others
        hops = hops_with_timestamps + hops_without_timestamps
        
        # Remove the temporary _parsed_timestamp field
        for hop in hops:
            if '_parsed_timestamp' in hop:
                del hop['_parsed_timestamp']
        
        # Calculate delays
        hops = self.calculate_delays(hops)
        
        # Categorize headers
        security_headers = {}
        x_headers = {}
        other_headers = {}
        
        for key, value in headers.items():
            key_lower = key.lower()
            if key_lower in self.security_headers:
                security_headers[key] = value
            elif key_lower.startswith('x-'):
                x_headers[key] = value
                self.x_headers.add(key_lower)
            elif key_lower not in ['received', 'subject', 'message-id', 'date', 'from', 'to']:
                other_headers[key] = value
        
        return {
            'basic_info': basic_info,
            'hops': hops,
            'security_headers': security_headers,
            'x_headers': x_headers,
            'other_headers': other_headers
        }
    
    def create_delay_visualization(self, hops: List[Dict]) -> str:
        """Create a visualization of delays between hops"""
        if not hops:
            return ""
        
        # Prepare data for visualization
        hop_labels = []
        delays = []
        colors = []
        
        for i, hop in enumerate(hops):
            hop_labels.append(f"Hop {i+1}<br>{hop['from']}<br>→ {hop['by']}")
            
            delay = hop.get('delay_seconds', 0)
            if delay is None:
                delay = 0
            delays.append(delay)
            
            # Color coding based on delay
            if delay <= 1:
                colors.append('#28a745')  # Green - fast
            elif delay <= 10:
                colors.append('#ffc107')  # Yellow - moderate
            elif delay <= 60:
                colors.append('#fd7e14')  # Orange - slow
            else:
                colors.append('#dc3545')  # Red - very slow
        
        # Create bar chart
        fig = go.Figure(data=[
            go.Bar(
                x=hop_labels,
                y=delays,
                marker_color=colors,
                text=[hop.get('delay_human', 'N/A') for hop in hops],
                textposition='auto',
            )
        ])
        
        fig.update_layout(
            title='Email Routing Delays',
            xaxis_title='Hops',
            yaxis_title='Delay (seconds)',
            yaxis_type='log',
            template='plotly_white',
            height=400,
            margin=dict(l=50, r=50, t=50, b=100)
        )
        
        return json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

# Initialize analyzer
analyzer = EmailHeaderAnalyzer()

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Email Header Analyzer</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background-color: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 { 
            color: #333; 
            text-align: center; 
            margin-bottom: 30px;
        }
        h2 { 
            color: #444; 
            border-bottom: 2px solid #007bff; 
            padding-bottom: 5px;
        }
        textarea { 
            width: 100%; 
            height: 200px; 
            font-family: monospace; 
            font-size: 12px;
            border: 1px solid #ddd;
            border-radius: 4px;
            padding: 10px;
            resize: vertical;
        }
        button { 
            background-color: #007bff; 
            color: white; 
            padding: 10px 20px; 
            border: none; 
            border-radius: 4px; 
            cursor: pointer;
            font-size: 16px;
            margin-top: 10px;
        }
        button:hover { 
            background-color: #0056b3; 
        }
        .section { 
            margin-bottom: 30px; 
        }
        .hop { 
            border: 1px solid #ddd; 
            padding: 15px; 
            margin-bottom: 10px; 
            border-radius: 4px;
            background-color: #f9f9f9;
        }
        .hop-header { 
            font-weight: bold; 
            color: #007bff;
            margin-bottom: 10px;
        }
        .delay { 
            color: #28a745; 
            font-weight: bold;
        }
        .delay.slow { 
            color: #ffc107; 
        }
        .delay.very-slow { 
            color: #dc3545; 
        }
        .basic-info { 
            background-color: #e9ecef; 
            padding: 15px; 
            border-radius: 4px;
            margin-bottom: 20px;
        }
        .basic-info div { 
            margin-bottom: 8px; 
        }
        .header-item { 
            background-color: #f8f9fa; 
            padding: 10px; 
            margin-bottom: 5px; 
            border-radius: 4px;
            border-left: 4px solid #007bff;
        }
        .header-name { 
            font-weight: bold; 
            color: #495057;
        }
        .header-value { 
            font-family: monospace; 
            font-size: 12px;
            margin-top: 5px;
            word-break: break-all;
        }
        .loading { 
            text-align: center; 
            color: #666; 
            font-style: italic;
        }
        .error { 
            color: #dc3545; 
            background-color: #f8d7da; 
            padding: 10px; 
            border-radius: 4px;
            margin-top: 10px;
        }
        #visualization { 
            margin-top: 20px; 
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📧 Email Header Analyzer</h1>
        
        <div class="section">
            <textarea id="headers" placeholder="Paste your email headers here..."></textarea>
            <button onclick="analyzeHeaders()">Analyze Headers</button>
        </div>
        
        <div id="results" style="display: none;">
            <div class="section">
                <h2>📋 Basic Information</h2>
                <div id="basic-info" class="basic-info"></div>
            </div>
            
            <div class="section">
                <h2>🔀 Routing Hops</h2>
                <div id="hops"></div>
            </div>
            
            <div class="section">
                <h2>📊 Delay Visualization</h2>
                <div id="visualization"></div>
            </div>
            
            <div class="section">
                <h2>🔒 Security Headers</h2>
                <div id="security-headers"></div>
            </div>
            
            <div class="section">
                <h2>⚡ X-Headers</h2>
                <div id="x-headers"></div>
            </div>
            
            <div class="section">
                <h2>📄 Other Headers</h2>
                <div id="other-headers"></div>
            </div>
            
            <div class="section">
                <h2>🐛 Debug Information</h2>
                <div id="debug-info"></div>
            </div>
        </div>
        
        <div id="loading" class="loading" style="display: none;">
            Analyzing headers...
        </div>
        
        <div id="error" class="error" style="display: none;"></div>
    </div>

    <script>
        function analyzeHeaders() {
            const headers = document.getElementById('headers').value;
            if (!headers.trim()) {
                alert('Please paste email headers first!');
                return;
            }
            
            document.getElementById('loading').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            document.getElementById('error').style.display = 'none';
            
            fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ headers: headers })
            })
            .then(response => response.json())
            .then(data => {
                document.getElementById('loading').style.display = 'none';
                
                if (data.error) {
                    document.getElementById('error').textContent = data.error;
                    document.getElementById('error').style.display = 'block';
                    return;
                }
                
                displayResults(data);
            })
            .catch(error => {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('error').textContent = 'Error analyzing headers: ' + error.message;
                document.getElementById('error').style.display = 'block';
            });
        }
        
        function displayResults(data) {
            // Basic info
            const basicInfo = data.basic_info;
            const basicInfoElement = document.getElementById('basic-info');
            if (basicInfoElement) {
                basicInfoElement.innerHTML = `
                    <div><strong>Subject:</strong> ${basicInfo.subject}</div>
                    <div><strong>Message ID:</strong> ${basicInfo.message_id}</div>
                    <div><strong>Date:</strong> ${basicInfo.date}</div>
                    <div><strong>From:</strong> ${basicInfo.from}</div>
                    <div><strong>To:</strong> ${basicInfo.to}</div>
                `;
            }
            
            // Hops
            const hopsElement = document.getElementById('hops');
            if (hopsElement) {
                const hopsHtml = data.hops.map((hop, index) => `
                    <div class="hop">
                        <div class="hop-header">Hop ${index + 1}</div>
                        <div><strong>From:</strong> ${hop.from}</div>
                        <div><strong>By:</strong> ${hop.by}</div>
                        <div><strong>Protocol:</strong> ${hop.protocol}</div>
                        <div><strong>Timestamp:</strong> ${hop.timestamp || 'N/A'}</div>
                        <div><strong>Delay:</strong> <span class="delay ${getDelayClass(hop.delay_seconds)}">${hop.delay_human || 'N/A'}</span></div>
                        <div style="margin-top: 10px; font-size: 12px; color: #666;">
                            <strong>Full header:</strong><br>
                            <code>${hop.full_line}</code>
                        </div>
                    </div>
                `).join('');
                hopsElement.innerHTML = hopsHtml;
            }
            
            // Visualization with error handling
            const visualizationElement = document.getElementById('visualization');
            const visualizationErrorElement = document.getElementById('visualization-error');
            
            if (data.visualization && typeof Plotly !== 'undefined' && visualizationElement) {
                try {
                    Plotly.newPlot('visualization', JSON.parse(data.visualization).data, JSON.parse(data.visualization).layout);
                    if (visualizationErrorElement) {
                        visualizationErrorElement.style.display = 'none';
                    }
                } catch (error) {
                    console.error('Plotly rendering error:', error);
                    if (visualizationErrorElement) {
                        visualizationErrorElement.style.display = 'block';
                    }
                }
            } else {
                if (visualizationErrorElement) {
                    visualizationErrorElement.style.display = 'block';
                }
            }
            
            // Security headers
            const securityHeadersElement = document.getElementById('security-headers');
            if (securityHeadersElement) {
                securityHeadersElement.innerHTML = formatHeaders(data.security_headers);
            }
            
            // X-headers
            const xHeadersElement = document.getElementById('x-headers');
            if (xHeadersElement) {
                xHeadersElement.innerHTML = formatHeaders(data.x_headers);
            }
            
            // Other headers
            const otherHeadersElement = document.getElementById('other-headers');
            if (otherHeadersElement) {
                otherHeadersElement.innerHTML = formatHeaders(data.other_headers);
            }
            
            // Debug information
            const debugInfoElement = document.getElementById('debug-info');
            if (data.debug && debugInfoElement) {
                debugInfoElement.innerHTML = `
                    <div style="background-color: #f8f9fa; padding: 15px; border-radius: 4px; font-family: monospace; font-size: 12px;">
                        <strong>Total Received Headers Found:</strong> ${data.debug.total_received_headers}<br>
                        <strong>Total Hops Generated:</strong> ${data.debug.total_hops}<br>
                        <strong>Sample Received Headers:</strong><br>
                        <pre style="margin-top: 10px; white-space: pre-wrap;">${JSON.stringify(data.debug.received_headers_sample, null, 2)}</pre>
                    </div>
                `;
            }
            
            const resultsElement = document.getElementById('results');
            if (resultsElement) {
                resultsElement.style.display = 'block';
            }
        }
        
        function formatHeaders(headers) {
            if (Object.keys(headers).length === 0) {
                return '<div style="color: #666; font-style: italic;">No headers found in this category</div>';
            }
            
            return Object.entries(headers).map(([key, value]) => {
                // Handle both single values and arrays
                const displayValue = Array.isArray(value) ? value[0] : value;
                return `
                    <div class="header-item">
                        <div class="header-name">${key}</div>
                        <div class="header-value">${displayValue}</div>
                    </div>
                `;
            }).join('');
        }
        
        function getDelayClass(seconds) {
            if (seconds === null || seconds === undefined) return '';
            if (seconds > 60) return 'very-slow';
            if (seconds > 10) return 'slow';
            return '';
        }
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        data = request.json
        headers = data.get('headers', '')
        
        if not headers:
            return jsonify({'error': 'No headers provided'})
        
        # Debug: Log first 500 characters of what we received
        debug_input = {
            'input_length': len(headers),
            'first_500_chars': headers[:500],
            'contains_received': 'Received:' in headers,
            'contains_from': 'From:' in headers,
            'line_count': len(headers.split('\n'))
        }
        
        # Analyze headers
        result = analyzer.analyze_headers(headers)
        
        # Add debug information
        parsed_headers = analyzer.parse_raw_headers_properly(headers)
        received_headers = []
        if 'Received' in parsed_headers:
            received_value = parsed_headers['Received']
            if isinstance(received_value, list):
                received_headers = received_value
            else:
                received_headers = [received_value]
        
        debug_info = {
            'input_debug': debug_input,
            'total_received_headers': len(received_headers),
            'received_headers_sample': received_headers[:3] if received_headers else [],
            'total_hops': len(result['hops']),
            'basic_info_found': {
                'subject': 'Subject' in parsed_headers,
                'from': 'From' in parsed_headers,
                'date': 'Date' in parsed_headers,
                'message_id': 'Message-ID' in parsed_headers,
                'to': 'To' in parsed_headers
            },
            'total_headers_found': len(parsed_headers),
            'sample_parsed_headers': list(parsed_headers.keys())[:10],
            'hop_timestamps_sample': [
                {
                    'hop_number': i+1,
                    'from': hop['from'],
                    'by': hop['by'],
                    'timestamp': hop['timestamp'],
                    'delay': hop.get('delay_human', 'N/A')
                }
                for i, hop in enumerate(result['hops'][:5])
            ]
        }
        
        result['debug'] = debug_info
        
        # Create visualization
        visualization = analyzer.create_delay_visualization(result['hops'])
        result['visualization'] = visualization
        
        return jsonify(result)
    
    except Exception as e:
        import traceback
        return jsonify({'error': f'Error analyzing headers: {str(e)}', 'traceback': traceback.format_exc()})

if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
