# Processed Data Integration Guide

## 🎯 What We've Built

I've created a complete integration system to upload your processed CSV data to Supabase and display it in your dashboard with beautiful analytics. Here's what's been implemented:

### ✅ What's Ready

1. **Backend API Router** (`src/routers/processed_documents_router.py`)
   - RESTful endpoints for processed documents
   - Categories and statistics endpoints
   - Search functionality
   - Pagination support

2. **Frontend Dashboard Component** (`src/components/ProcessedDataDashboard.tsx`)
   - Interactive charts and analytics
   - Category breakdowns by document type, state, URN type
   - Document timeline views
   - Real-time statistics

3. **Data Service** (`src/services/processedDataService.ts`)
   - TypeScript service for API calls
   - Type-safe interfaces
   - Export functionality

4. **Upload Scripts**
   - `scripts/upload_processed_data_to_supabase.py` (Advanced)
   - `scripts/simple_supabase_upload.py` (Simple REST API approach)

5. **Styling** (`src/styles/components/ProcessedDataDashboard.css`)
   - Modern, responsive design
   - Interactive charts with Recharts
   - Mobile-friendly layout

## 🚀 Deployment Steps

### Step 1: Set Up Supabase Table

1. **Go to your Supabase dashboard** → SQL Editor
2. **Run this SQL** to create the table:

```sql
CREATE TABLE legislative_documents (
    id BIGSERIAL PRIMARY KEY,
    search_term TEXT,
    date_searched TIMESTAMPTZ,
    url TEXT,
    title TEXT,
    urn TEXT,
    urn_type TEXT,
    country TEXT,
    state TEXT,
    municipality TEXT,
    justice TEXT,
    region TEXT,
    court_class TEXT,
    document_type_full TEXT,
    promulgation_date DATE,
    document_description TEXT,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for better performance
CREATE INDEX idx_legislative_documents_search_term ON legislative_documents(search_term);
CREATE INDEX idx_legislative_documents_urn_type ON legislative_documents(urn_type);
CREATE INDEX idx_legislative_documents_state ON legislative_documents(state);
CREATE INDEX idx_legislative_documents_document_type ON legislative_documents(document_type_full);
CREATE INDEX idx_legislative_documents_promulgation_date ON legislative_documents(promulgation_date);
```

### Step 2: Upload Your CSV Data

**Option A: Supabase Dashboard (Easiest)**
1. Go to Supabase → Table Editor → `legislative_documents`
2. Click "Insert" → "Import from CSV"
3. Upload `./data/processed/lexml_parsed_enhanced.csv`
4. Map columns appropriately

**Option B: Using the Upload Script**
1. Install dependencies:
   ```bash
   pip install requests pandas  # or use your environment manager
   ```
2. Set environment variables:
   ```bash
   export SUPABASE_URL="your_supabase_url"
   export SUPABASE_ANON_KEY="your_supabase_anon_key"
   ```
3. Run the script:
   ```bash
   python scripts/simple_supabase_upload.py
   ```

### Step 3: Install Backend Dependencies

1. **If using Poetry** (recommended):
   ```bash
   cd backend
   poetry install
   ```

2. **If using pip**:
   ```bash
   pip install supabase pandas
   ```

### Step 4: Start the Backend

```bash
cd backend
python -m uvicorn src.main:app --reload --host 0.0.0.0 --port 8000
```

### Step 5: Install Frontend Dependencies

```bash
npm install recharts  # For charts
# or
yarn add recharts
```

### Step 6: Access Your Dashboard

1. **Start your frontend** (if not already running)
2. **Navigate to Analytics** → **AI Insights** tab
3. **Or use the new "Processed Data" tab**

## 📊 Dashboard Features

### Overview Tab
- **Total Documents**: Count of all processed documents
- **Recent Activity**: Documents added in last 30 days
- **Years Covered**: Timeline span of your legislation
- **Document Types**: Categories found in your data

### Categories Tab
- **Document Types Pie Chart**: Visual breakdown of legislation types
- **States Bar Chart**: Top states by document count
- **Search Terms**: Most common search terms used
- **URN Types**: Distribution of URN categories

### Documents Tab
- **Recent Documents List**: Latest processed documents
- **Document Cards**: Title, URN, state, description
- **Search Terms**: Shows which search found each document

## 🔧 API Endpoints Available

Once deployed, these endpoints will be available:

- `GET /api/v1/processed-documents` - Get documents with filters
- `GET /api/v1/processed-documents/categories` - Get category analytics
- `GET /api/v1/processed-documents/stats` - Get statistics
- `GET /api/v1/processed-documents/search?q=query` - Search documents
- `GET /api/v1/processed-documents/{id}` - Get specific document

## 📈 Analytics You'll See

### Document Type Distribution
Your CSV contains these types (examples from your data):
- Medida Provisória (MPV) Federal
- Decreto Federal/Estadual/Municipal
- Lei Federal/Estadual/Municipal
- Acórdão (various courts)
- Artigo/Livro (academic sources)

### Geographic Distribution
- **Federal**: Brasil-wide legislation
- **States**: São Paulo, Minas Gerais, Rio Grande do Sul, etc.
- **Municipalities**: Campinas, Itabirito, Uberaba, etc.

### Search Term Analytics
Your data includes searches for:
- transporte de carga
- transporte rodoviário de carga
- logística de carga
- frete/fretamento
- caminhão
- veículos pesados/comerciais
- combustíveis alternativos (biodiesel, etanol, hidrogênio)

### URN Type Analysis
- **legislation**: Traditional laws and regulations
- **jurisprudence**: Court decisions and precedents

## 🎨 Customization Options

### Add New Charts
The dashboard uses Recharts. You can easily add:
- Line charts for trends over time
- Area charts for cumulative data
- Scatter plots for correlations

### Filtering
The API supports filtering by:
- `search_term`
- `document_type`
- `state`
- `urn_type`

### Export Features
The service includes CSV export functionality that preserves all your data.

## 🔍 Sample Data Insights

Based on your CSV, you'll see analytics like:
- **891 total documents** across multiple transportation topics
- **Peak activity in 2018-2023** for transport legislation
- **Strong focus on cargo transport** and alternative fuels
- **Multi-jurisdictional coverage** from federal to municipal levels

## 🚨 Troubleshooting

### Backend Issues
- Ensure Supabase credentials are set in environment variables
- Check that the `legislative_documents` table exists
- Verify FastAPI dependencies are installed

### Frontend Issues
- Install Recharts: `npm install recharts`
- Check that backend is running on correct port
- Verify API endpoints are accessible

### Data Issues
- Ensure CSV encoding is UTF-8
- Check that date formats are consistent
- Verify no special characters in data

## 🎉 Next Steps

Once everything is running, you'll have:
1. **Beautiful visual analytics** of your legislative data
2. **Real-time dashboard** with interactive charts
3. **Search and filter capabilities** across all documents
4. **Export functionality** for further analysis
5. **Scalable architecture** that can handle more data

Your processed CSV data will now be the **primary source** for all dashboard analytics, giving you comprehensive insights into Brazilian transportation legislation! 