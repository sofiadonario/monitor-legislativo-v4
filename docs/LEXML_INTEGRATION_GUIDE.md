# LexML Brasil Integration Guide

## Overview

This integration provides a robust solution for searching and monitoring Brazilian transport-related legislation using the LexML Brasil API. The system implements the SRU (Search/Retrieve via URL) protocol with CQL (Contextual Query Language) and includes automatic fallback to web scraping when the API is unavailable.

## Features

- **SRU 1.1/1.2 Protocol Support**: Full implementation of the standard search protocol
- **CQL Query Language**: Advanced search capabilities using Contextual Query Language
- **Automatic Fallback**: Seamless switch to web scraping when API returns errors
- **Deduplication**: Automatic removal of duplicate results based on URN
- **CSV Export**: Export results to CSV format for analysis
- **JSON Reports**: Comprehensive summary reports with statistics
- **Monitoring Service**: Continuous monitoring for new and updated legislation
- **Priority Alerts**: Automatic detection of important terms (e.g., "Rota 2030", "CONTRAN")

## Installation

1. Ensure Python 3.8+ is installed
2. Install required dependencies:
```bash
pip install requests
```

3. The integration files are located in:
- `core/api/lexml_integration.py` - Main integration class
- `core/api/lexml_monitor.py` - Monitoring service
- `fallback_scraper.py` - Web scraping fallback

## Basic Usage

### Simple Search Example

```python
from core.api.lexml_integration import LexMLIntegration

# Create integration instance
lexml = LexMLIntegration()

# Search all transport terms
results = lexml.search_all_terms("transport_terms.txt")

# Save to CSV
csv_file = lexml.save_results(results)
print(f"Results saved to: {csv_file}")

# Generate summary report
report = lexml.generate_summary_report(results)
print(f"Report saved to: {report}")
```

### Running the Example Script

```bash
python lexml_search_example.py
```

This will:
1. Search for all terms in `transport_terms.txt`
2. Try API first, fallback to web scraping if needed
3. Save results to CSV in `data/lexml_results/`
4. Generate a JSON summary report

## API Specifications

- **Base URL**: https://www.lexml.gov.br/busca/SRU
- **Protocol**: SRU 1.1/1.2
- **Query Language**: CQL (Contextual Query Language)
- **Response Format**: XML with Dublin Core metadata
- **Authentication**: None required

### Required Parameters

- `operation=searchRetrieve` (mandatory)
- `version=1.1` (mandatory)
- `query=[CQL query]` (mandatory)
- `maximumRecords=100` (optional, default 20)
- `startRecord=1` (optional, for pagination)

### CQL Query Examples

```
# Basic search
urn any "transporte"

# Multiple terms
urn any "transporte" and subject any "rodoviário"

# Exact match
autoridade = "Federal"

# Complex query
(urn any "transporte" or title any "logística") and autoridade = "Federal"
```

## Monitoring Service

The monitoring service tracks changes in legislation over time:

```python
from core.api.lexml_monitor import LexMLMonitor

# Create monitor
monitor = LexMLMonitor()

# Check for updates
updates = monitor.check_for_updates()

print(f"New documents: {updates['new_documents']}")
print(f"Updated documents: {updates['updated_documents']}")
print(f"Priority alerts: {updates['priority_alerts']}")

# Generate weekly report
report = monitor.generate_report(days=7)
```

### Configuration

Create `configs/lexml_monitor_config.json`:

```json
{
  "output_dir": "data/lexml_monitor",
  "state_file": "data/lexml_monitor/monitor_state.json",
  "check_interval_hours": 24,
  "priority_terms": [
    "Rota 2030",
    "CONTRAN",
    "ANTT",
    "combustível sustentável"
  ],
  "notification_settings": {
    "email_enabled": false,
    "webhook_enabled": true,
    "webhook_url": "https://your-webhook-url.com"
  }
}
```

## Search Terms

The `transport_terms.txt` file contains categorized search terms:

- General Transport Terms
- Fuels and Energy
- Energy Efficiency and Emissions
- Technology and Innovation
- Infrastructure
- Regulation
- Incentives and Taxation
- Rota 2030 and Paten
- Machinery and Equipment
- Operations and Services

## Output Files

### CSV Format

Results are saved with the following columns:
- `search_term` - Term used for search
- `urn` - Unique identifier
- `title` - Document title
- `document_date` - Publication date
- `document_type` - Type (Lei, Decreto, etc.)
- `authority` - Publishing authority
- `description` - Brief description
- `subjects` - Keywords/subjects
- `url` - Direct link to document
- `source` - "api" or "web_scraper"
- `date_searched` - When the search was performed

### Summary Report

JSON report includes:
- Execution statistics
- Results by document type
- Results by authority
- Results by year
- Results by search term
- Top 20 subjects

## Error Handling

The integration handles various error scenarios:

1. **API 500 Errors**: Automatically retries with exponential backoff
2. **Network Timeouts**: 30-second timeout with retry logic
3. **XML Parsing Errors**: Logged and skipped
4. **Rate Limiting**: 1-second delay between searches

When API fails after retries, the system automatically uses the web scraper fallback.

## Testing

Run the test suite:

```bash
pytest tests/integration/test_lexml_integration.py -v
```

## Troubleshooting

### Common Issues

1. **No results found**
   - Check if terms are correctly formatted in `transport_terms.txt`
   - Verify internet connection
   - Check API status at https://www.lexml.gov.br

2. **API returns 500 errors**
   - This is common - the fallback scraper will activate automatically
   - Results will show `source: "web_scraper"`

3. **Slow performance**
   - Rate limiting adds 1-second delays
   - Consider reducing number of search terms
   - Run searches during off-peak hours

### Logs

Check logs for detailed information:
- Console output shows progress
- `data/lexml_results/search_log.txt` contains detailed logs
- Monitor state saved in `data/lexml_monitor/monitor_state.json`

## Best Practices

1. **Search Terms**
   - Use specific terms for better results
   - Avoid very generic terms
   - Include variations (singular/plural)

2. **Monitoring**
   - Run daily checks for important terms
   - Set up webhook notifications for alerts
   - Review weekly reports

3. **Data Management**
   - Archive old CSV files monthly
   - Keep summary reports for trend analysis
   - Monitor disk space usage

## Support

For issues or questions:
1. Check the troubleshooting section
2. Review test cases for examples
3. Check API documentation at https://www.lexml.gov.br/api