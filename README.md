# LexML API Integration Kit

This kit contains all files needed to integrate LexML Brasil API into your project, with a working web scraper as fallback.

## Files Included

1. **claude_prompt.txt** - Complete prompt to give to Claude for creating the integration
2. **transport_terms.txt** - List of all transport-related search terms
3. **fallback_scraper.py** - Web scraper code for when API fails
4. **api_examples.json** - Working API examples and documentation
5. **requirements.txt** - Python dependencies
6. **lexml_working_scraper.py** - Complete working scraper (tested and verified)

## How to Use

### Option 1: Use Claude to Create Full Integration

1. Open Claude (claude.ai)
2. Copy the content from `claude_prompt.txt`
3. Attach these files to your Claude conversation:
   - transport_terms.txt
   - fallback_scraper.py
   - api_examples.json
   - requirements.txt

4. Claude will create a complete `lexml_integration.py` that:
   - Tries the API first
   - Automatically falls back to web scraping when API fails
   - Handles all error cases
   - Saves results to CSV

### Option 2: Use the Working Scraper Directly

If you need results immediately:

```bash
# Install dependencies
pip install requests

# Run the working scraper
python3 lexml_working_scraper.py
```

This will:
- Search all 80+ transport terms
- Save results to `~/lexml_results/`
- Create CSV file and summary report
- Take approximately 10-15 minutes

## Expected Output

Regardless of which option you use, you'll get:

- **lexml_transport_results_[timestamp].csv** - All search results
- **search_summary_[timestamp].txt** - Summary with statistics
- Results organized by search term
- Duplicate results removed automatically

## API Information

The LexML API uses:
- **Protocol**: SRU (Search/Retrieve via URL) v1.1/1.2
- **Query Language**: CQL (Contextual Query Language)
- **Base URL**: https://www.lexml.gov.br/busca/SRU
- **Response Format**: XML with Dublin Core metadata

### Known Issues
- API frequently returns 500 Internal Server Error
- That's why the fallback scraper is essential

## Quick Test

To test if the API is working:
```bash
curl -I "https://www.lexml.gov.br/busca/SRU?operation=explain"
```

If you get a 500 error, use the web scraper instead.