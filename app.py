from flask import Flask, request, jsonify, render_template_string
import re
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional

app = Flask(__name__)

class EmailHeaderAnalyzer:
    def __init__(self):
        pass
    
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

    def parse_timestamp(self, timestamp_str: str) -> datetime:
        """Parse various timestamp formats with timezone handling"""
        if not timestamp_str:
            return None
            
        # Clean up the timestamp string
        timestamp_str = timestamp_str.strip()
        
        # Common timestamp formats found in email headers
        formats = [
            '%a, %d %b %Y %H:%M:%S %z',      # Wed, 15 Nov 2023 14:25:43 +0000
            '%a, %d %b %Y %H:%M:%S %Z',      # Wed, 15 Nov 2023 14:25:43 UTC
            '%d %b %Y %H:%M:%S %z',          # 15 Nov 2023 14:25:43 +0000
            '%d %b %Y %H:%M:%S %Z',          # 15 Nov 2023 14:25:43 UTC
            '%a, %d %b %Y %H:%M:%S %z (%Z)', # Mon, 7 Jul 2025 08:38:42 +0100 (BST)
            '%Y-%m-%d %H:%M:%S %z',          # 2023-11-15 14:25:43 +0000
            '%Y-%m-%d %H:%M:%S',             # 2023-11-15 14:25:43 (no timezone)
            '%a, %d %b %Y %H:%M:%S',         # Wed, 15 Nov 2023 14:25:43 (no timezone)
            '%d %b %Y %H:%M:%S',             # 15 Nov 2023 14:25:43 (no timezone)
        ]
        
        # Try each format
        for fmt in formats:
            try:
                parsed_dt = datetime.strptime(timestamp_str, fmt)
                
                # If the datetime is offset-naive (no timezone), assume UTC
                if parsed_dt.tzinfo is None:
                    parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
                
                return parsed_dt
                
            except ValueError:
                continue
        
        # If standard formats fail, try email.utils.parsedate_tz
        try:
            import email.utils
            parsed_tuple = email.utils.parsedate_tz(timestamp_str)
            if parsed_tuple:
                # Convert to datetime
                timestamp = datetime(*parsed_tuple[:6])
                
                # Handle timezone offset (parsedate_tz returns offset in seconds)
                if parsed_tuple[9] is not None:
                    offset_seconds = parsed_tuple[9]
                    tz = timezone(timedelta(seconds=offset_seconds))
                    timestamp = timestamp.replace(tzinfo=tz)
                else:
                    # No timezone info, assume UTC
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                
                return timestamp
                
        except (ValueError, TypeError):
            pass
        
        # Last resort: try to extract just the date/time part and ignore timezone
        try:
            # Remove common timezone suffixes and try again
            clean_str = timestamp_str
            for tz_suffix in [' GMT', ' UTC', ' +0000', ' +0100', ' +0200', ' -0500', ' EST', ' PST', ' BST']:
                if clean_str.endswith(tz_suffix):
                    clean_str = clean_str[:-len(tz_suffix)]
                    break
            
            # Try parsing without timezone
            for fmt in ['%a, %d %b %Y %H:%M:%S', '%d %b %Y %H:%M:%S']:
                try:
                    parsed_dt = datetime.strptime(clean_str, fmt)
                    # Assume UTC if no timezone info
                    return parsed_dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
                    
        except Exception:
            pass
        
        return None

    def parse_received_header(self, received_header: str) -> Dict:
        """Parse a single Received header"""
        hop = {
            'from': 'Unknown',
            'by': 'Unknown', 
            'protocol': 'Unknown',
            'timestamp': None,
            'full_line': received_header
        }
        
        # Extract 'from' server
        from_match = re.search(r'from\s+([^\s]+)', received_header, re.IGNORECASE)
        if from_match:
            hop['from'] = from_match.group(1)
        
        # Extract 'by' server  
        by_match = re.search(r'by\s+([^\s]+)', received_header, re.IGNORECASE)
        if by_match:
            hop['by'] = by_match.group(1)
            
        # Extract protocol
        with_match = re.search(r'with\s+([^\s]+)', received_header, re.IGNORECASE)
        if with_match:
            hop['protocol'] = with_match.group(1)
        
        # Extract timestamp (usually after semicolon)
        timestamp_match = re.search(r';\s*(.+)$', received_header)
        if timestamp_match:
            hop['timestamp'] = timestamp_match.group(1).strip()
            
        return hop

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

    def create_visualization(self, hops: List[Dict]) -> str:
        """Create a Plotly visualization of email routing delays"""
        try:
            import plotly.graph_objects as go
            import plotly.io as pio
            
            # Prepare data for horizontal bar chart
            hop_labels = []
            delays = []
            colors = []
            delay_texts = []
            
            for i, hop in enumerate(hops):
                # Create hop label
                hop_label = f"Hop {i+1}<br>{hop['from']}<br>→ {hop['by']}"
                hop_labels.append(hop_label)
                
                # Get delay value (use 0 for missing/null delays for visualization)
                delay_val = hop.get('delay_seconds', 0) or 0
                delays.append(delay_val)
                
                # Color coding based on delay
                if delay_val == 0:
                    colors.append('#28a745')  # Green for no delay/missing
                elif delay_val < 0:
                    colors.append('#6c757d')  # Gray for negative (clock skew)
                elif delay_val < 5:
                    colors.append('#28a745')  # Green for fast (< 5 seconds)
                elif delay_val < 30:
                    colors.append('#ffc107')  # Yellow for moderate (5-30 seconds)
                elif delay_val < 300:
                    colors.append('#fd7e14')  # Orange for slow (30s-5min)
                else:
                    colors.append('#dc3545')  # Red for very slow (> 5 minutes)
                
                # Delay text for display
                delay_texts.append(hop.get('delay_human', 'N/A'))
            
            # Create horizontal bar chart (hops on Y-axis, delays on X-axis)
            fig = go.Figure(data=[
                go.Bar(
                    x=delays,               # DELAYS on X-axis (horizontal)
                    y=hop_labels,           # HOPS on Y-axis (vertical)
                    orientation='h',        # Horizontal bars
                    marker=dict(color=colors),
                    text=delay_texts,
                    textposition='auto',
                    hovertemplate='<b>%{y}</b><br>Delay: %{text}<br>Seconds: %{x}<extra></extra>'
                )
            ])
            
            # Update layout for horizontal chart
            fig.update_layout(
                title='Email Routing Delays',
                xaxis_title='Delay (seconds)',      # X-axis = delays (horizontal)
                yaxis_title='Routing Hops',         # Y-axis = hops (vertical)
                xaxis=dict(type='log' if any(d > 0 for d in delays) else 'linear'),
                height=max(400, len(hops) * 60),     # Dynamic height
                margin=dict(l=200, r=50, t=80, b=50), # More left margin for hop labels
                yaxis=dict(autorange='reversed'),    # Hop 1 at top
                showlegend=False
            )
            
            # Convert to JSON
            return pio.to_json(fig)
            
        except Exception as e:
            # Fallback: return empty visualization data
            return json.dumps({
                "data": [],
                "layout": {
                    "title": "Visualization Error",
                    "annotations": [{
                        "text": f"Could not generate chart: {str(e)}",
                        "showarrow": False,
                        "x": 0.5,
                        "y": 0.5
                    }]
                }
            })

    def analyze_headers(self, raw_headers: str) -> Dict:
        """Main analysis function"""
        parsed_headers = self.parse_raw_headers_properly(raw_headers)
        
        # Extract basic information
        basic_info = {
            'subject': parsed_headers.get('Subject', 'Not found'),
            'from': parsed_headers.get('From', 'Not found'),
            'to': parsed_headers.get('To', 'Not found'),
            'date': parsed_headers.get('Date', 'Not found'),
            'message_id': parsed_headers.get('Message-ID', 'Not found')
        }
        
        # Parse Received headers - get all instances
        received_headers = []
        if 'Received' in parsed_headers:
            received_value = parsed_headers['Received']
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
        
        for header_name, header_value in parsed_headers.items():
            if header_name.startswith('X-'):
                x_headers[header_name] = header_value
            elif header_name in ['Authentication-Results', 'DKIM-Signature', 'Received-SPF', 'X-IronPort-AV', 'X-Trellix']:
                security_headers[header_name] = header_value
            elif header_name not in ['Subject', 'From', 'To', 'Date', 'Message-ID', 'Received']:
                other_headers[header_name] = header_value
        
        # Debug information
        debug_input = {
            'input_length': len(raw_headers),
            'line_count': len(raw_headers.split('\n')),
            'contains_received': 'Received:' in raw_headers,
            'contains_from': 'From:' in raw_headers,
            'first_500_chars': raw_headers[:500]
        }
        
        debug_info = {
            'input_debug': debug_input,
            'total_received_headers': len(received_headers),
            'received_headers_sample': received_headers[:3] if received_headers else [],
            'total_hops': len(hops),
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
                for i, hop in enumerate(hops[:5])
            ]
        }
        
        result = {
            'basic_info': basic_info,
            'hops': hops,
            'security_headers': security_headers,
            'x_headers': x_headers,
            'other_headers': other_headers,
            'debug': debug_info
        }
        
        # Add visualization
        try:
            visualization = self.create_visualization(hops)
            result['visualization'] = visualization
        except Exception as e:
            result['visualization'] = None
            result['visualization_error'] = str(e)
        
        return result

# Initialize analyzer
analyzer = EmailHeaderAnalyzer()

# HTML template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Header Analyzer</title>
    <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f8f9fa;
        }
        
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        h1 {
            color: #2c3e50;
            text-align: center;
            margin-bottom: 30px;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }
        
        .section {
            margin-bottom: 30px;
            padding: 20px;
            background-color: #f8f9fa;
            border-radius: 6px;
            border-left: 4px solid #3498db;
        }
        
        h2 {
            color: #2c3e50;
            margin-top: 0;
            margin-bottom: 15px;
        }
        
        textarea {
            width: 100%;
            height: 200px;
            padding: 15px;
            border: 2px solid #ddd;
            border-radius: 4px;
            font-family: monospace;
            font-size: 14px;
            resize: vertical;
            box-sizing: border-box;
        }
        
        button {
            background-color: #3498db;
            color: white;
            padding: 12px 24px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            margin-top: 10px;
        }
        
        button:hover {
            background-color: #2980b9;
        }
        
        .hop {
            background-color: white;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 4px;
            border: 1px solid #ddd;
        }
        
        .hop-header {
            font-weight: bold;
            font-size: 18px;
            color: #2c3e50;
            margin-bottom: 10px;
            padding-bottom: 5px;
            border-bottom: 2px solid #3498db;
        }
        
        .delay {
            font-weight: bold;
            padding: 2px 6px;
            border-radius: 3px;
        }
        
        .delay-fast { background-color: #d4edda; color: #155724; }
        .delay-moderate { background-color: #fff3cd; color: #856404; }
        .delay-slow { background-color: #f8d7da; color: #721c24; }
        .delay-unknown { background-color: #e2e3e5; color: #6c757d; }
        
        .basic-info {
            background-color: white;
            padding: 15px;
            border-radius: 4px;
            border: 1px solid #ddd;
        }
        
        .basic-info div {
            margin-bottom: 8px;
        }
        
        .loading {
            text-align: center;
            padding: 20px;
            color: #6c757d;
        }
        
        code {
            background-color: #f1f1f1;
            padding: 2px 4px;
            border-radius: 2px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            word-break: break-all;
        }
        
        #visualization {
            min-height: 400px;
            width: 100%;
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
                <h2>📧 Basic Information</h2>
                <div id="basic-info"></div>
            </div>

            <div class="section">
                <h2>📊 Delay Visualization</h2>
                <div id="visualization"></div>
                <div id="visualization-error" style="display: none; background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; padding: 15px; border-radius: 4px; margin-top: 10px;">
                    <strong>⚠️ Chart could not be loaded</strong><br>
                    The visualization requires external resources from cdn.plot.ly. If you're behind a corporate proxy or firewall:<br>
                    <ul style="margin: 10px 0;">
                        <li>Have you accepted the Acceptable Use Policy (AUP) for external internet access?</li>
                        <li>Is cdn.plot.ly blocked by your network security policy?</li>
                        <li>Try refreshing the page after accepting any network access prompts</li>
                    </ul>
                    <small>The email analysis above is still fully functional - only the visual chart is affected.</small>
                </div>
            </div>

            <div class="section">
                <h2>🔄 Routing Hops</h2>
                <div id="hops"></div>
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
    </div>

    <script>
        function getDelayClass(delay_seconds) {
            if (!delay_seconds || delay_seconds === 0) return 'delay-unknown';
            if (delay_seconds < 0) return 'delay-unknown';
            if (delay_seconds < 5) return 'delay-fast';
            if (delay_seconds < 30) return 'delay-moderate';
            return 'delay-slow';
        }

        function formatHeaders(headers) {
            let html = '';
            for (let [key, value] of Object.entries(headers)) {
                if (Array.isArray(value)) {
                    for (let item of value) {
                        html += `<div><strong>${key}</strong><br>${item}</div>`;
                    }
                } else {
                    html += `<div><strong>${key}</strong><br>${value}</div>`;
                }
            }
            return html;
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
            
            // Visualization FIRST - right after basic info
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
            
            // Hops SECOND - after visualization
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

        function analyzeHeaders() {
            const headers = document.getElementById('headers').value;
            const loadingElement = document.getElementById('loading');
            const resultsElement = document.getElementById('results');
            
            if (!headers.trim()) {
                alert('Please paste email headers first');
                return;
            }
            
            loadingElement.style.display = 'block';
            resultsElement.style.display = 'none';
            
            // Send to Flask backend
            fetch('/analyze', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({headers: headers})
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    alert(`Error analyzing headers: ${data.error}`);
                } else {
                    displayResults(data);
                }
            })
            .catch(error => {
                alert(`Error analyzing headers: ${error.message}`);
            })
            .finally(() => {
                loadingElement.style.display = 'none';
            });
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
        data = request.get_json()
        headers = data.get('headers', '')
        
        if not headers:
            return jsonify({'error': 'No headers provided'}), 400
        
        result = analyzer.analyze_headers(headers)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)


