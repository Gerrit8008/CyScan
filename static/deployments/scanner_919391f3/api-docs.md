
# Scanner API Documentation

## Scanner: scanner_919391f3

### Base URL
```
https://your-domain.com/api/scanner/scanner_919391f3
```

### Authentication
All API requests require the API key in the Authorization header:
```
Authorization: Bearer cb2ece67e013476b8710a6c37c79478f
```

### Start a Scan

**POST** `/scan`

Start a new security scan.

#### Request Body
```json
{
    "target_url": "https://example.com",
    "contact_email": "user@example.com",
    "contact_name": "John Doe",
    "scan_types": ["port_scan", "ssl_check", "vulnerability_scan"]
}
```

#### Response
```json
{
    "status": "success",
    "scan_id": "scan_abc123def456",
    "message": "Scan started successfully",
    "estimated_completion": "2024-01-01T12:00:00Z"
}
```

### Get Scan Status

**GET** `/scan/{scan_id}`

Get the status and results of a scan.

#### Response
```json
{
    "status": "success",
    "scan_id": "scan_abc123def456",
    "scan_status": "completed",
    "progress": 100,
    "results": {
        "security_score": 85,
        "findings": [...],
        "recommendations": [...]
    },
    "created_at": "2024-01-01T12:00:00Z",
    "completed_at": "2024-01-01T12:05:00Z"
}
```

### Integration Examples

#### HTML Embed
```html
<iframe src="/scanner/scanner_919391f3/embed" 
        width="100%" 
        height="600" 
        frameborder="0">
</iframe>
```

#### JavaScript Integration
```javascript
// Include the scanner script
<script src="/scanner/scanner_919391f3/scanner-script.js"></script>

// Initialize
const scanner = new SecurityScanner({
    apiKey: 'cb2ece67e013476b8710a6c37c79478f',
    scannerUid: 'scanner_919391f3',
    apiBaseUrl: '/api/scanner/scanner_919391f3'
});
```

#### Direct API Call
```javascript
fetch('/api/scanner/scanner_919391f3/scan', {
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer cb2ece67e013476b8710a6c37c79478f'
    },
    body: JSON.stringify({
        target_url: 'https://example.com',
        contact_email: 'user@example.com',
        scan_types: ['port_scan', 'ssl_check']
    })
})
.then(response => response.json())
.then(data => console.log(data));
```

### Error Codes

- `400` - Bad Request (invalid parameters)
- `401` - Unauthorized (invalid API key)
- `404` - Scanner not found
- `429` - Rate limit exceeded
- `500` - Internal server error

### Rate Limits

- 10 scans per hour per IP address
- 100 API calls per hour per API key

### Support

For technical support, contact: admin@acmesecurity.com
        