# Custom Report Generation Engine for Monitor Legislativo v4
# Phase 5 Week 18: Advanced reporting system for Brazilian legislative data analysis
# Automated report generation with templates, charts, and academic formatting

import asyncio
import asyncpg
import json
import logging
import tempfile
from typing import Dict, List, Optional, Any, Union, Callable
from dataclasses import dataclass, field, asdict
from datetime import datetime, date, timedelta
from enum import Enum
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.io as pio
from jinja2 import Template, Environment, FileSystemLoader
from weasyprint import HTML, CSS
import uuid
from pathlib import Path
import io
import base64

logger = logging.getLogger(__name__)

class ReportType(Enum):
    """Types of reports that can be generated"""
    LEGISLATIVE_SUMMARY = "legislative_summary"
    TREND_ANALYSIS = "trend_analysis"
    COMPARATIVE_STUDY = "comparative_study"
    ACADEMIC_RESEARCH = "academic_research"
    REGULATORY_OVERVIEW = "regulatory_overview"
    PERFORMANCE_METRICS = "performance_metrics"
    COMPLIANCE_AUDIT = "compliance_audit"
    USAGE_STATISTICS = "usage_statistics"
    CUSTOM_QUERY = "custom_query"

class ReportFormat(Enum):
    """Output formats for reports"""
    PDF = "pdf"
    HTML = "html"
    WORD = "word"
    POWERPOINT = "powerpoint"
    MARKDOWN = "markdown"
    JUPYTER = "jupyter"
    LATEX = "latex"

class ChartType(Enum):
    """Chart types for data visualization"""
    LINE = "line"
    BAR = "bar"
    PIE = "pie"
    SCATTER = "scatter"
    HISTOGRAM = "histogram"
    HEATMAP = "heatmap"
    TREEMAP = "treemap"
    SUNBURST = "sunburst"
    TIMELINE = "timeline"
    SANKEY = "sankey"
    WORDCLOUD = "wordcloud"

@dataclass
class ReportSection:
    """Individual section within a report"""
    section_id: str
    title: str
    content_type: str  # "text", "chart", "table", "analysis"
    content: str
    data: Optional[Dict[str, Any]] = None
    chart_config: Optional[Dict[str, Any]] = None
    order: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ReportTemplate:
    """Report template configuration"""
    template_id: str
    name: str
    description: str
    report_type: ReportType
    sections: List[ReportSection]
    default_parameters: Dict[str, Any] = field(default_factory=dict)
    sql_queries: Dict[str, str] = field(default_factory=dict)
    chart_templates: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    styling: Dict[str, Any] = field(default_factory=dict)
    created_by: Optional[str] = None
    is_public: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['report_type'] = self.report_type.value
        result['sections'] = [section.to_dict() for section in self.sections]
        return result

@dataclass
class ReportRequest:
    """Request for report generation"""
    request_id: str
    user_id: str
    template_id: str
    parameters: Dict[str, Any]
    output_format: ReportFormat
    title: Optional[str] = None
    description: Optional[str] = None
    custom_sections: List[ReportSection] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['output_format'] = self.output_format.value
        result['custom_sections'] = [section.to_dict() for section in self.custom_sections]
        return result

@dataclass
class GeneratedReport:
    """Generated report metadata and content"""
    report_id: str
    request_id: str
    user_id: str
    title: str
    template_used: str
    output_format: ReportFormat
    file_path: Optional[str] = None
    file_size: Optional[int] = None
    generation_time: Optional[float] = None
    status: str = "pending"  # pending, generating, completed, failed
    error_message: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.now)
    expires_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['output_format'] = self.output_format.value
        result['created_at'] = self.created_at.isoformat()
        if self.expires_at:
            result['expires_at'] = self.expires_at.isoformat()
        return result

class CustomReportGenerator:
    """
    Advanced report generation system for Brazilian legislative data analysis
    
    Features:
    - Template-based report generation
    - Multiple output formats (PDF, HTML, Word, etc.)
    - Interactive charts and visualizations
    - Academic formatting and citations
    - Automated data analysis and insights
    - Custom SQL query execution
    - Responsive design for web and print
    - Batch report generation
    """
    
    def __init__(self, db_config: Dict[str, str], templates_path: str = "templates", 
                 output_path: str = "/tmp/reports"):
        self.db_config = db_config
        self.templates_path = Path(templates_path)
        self.output_path = Path(output_path)
        
        # Create directories
        self.templates_path.mkdir(parents=True, exist_ok=True)
        self.output_path.mkdir(parents=True, exist_ok=True)
        
        # Jinja2 template environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_path)),
            autoescape=True
        )
        
        # Chart styling
        plt.style.use('seaborn-v0_8')
        sns.set_palette("husl")
        
        # Pre-built templates
        self.builtin_templates = {}
        
        # Active report generations
        self.active_reports: Dict[str, GeneratedReport] = {}
    
    async def initialize(self) -> None:
        """Initialize report generator tables and templates"""
        await self._create_report_tables()
        await self._create_builtin_templates()
        logger.info("Custom report generator initialized")
    
    async def _create_report_tables(self) -> None:
        """Create report system database tables"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Report templates table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS report_templates (
                    template_id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(200) NOT NULL,
                    description TEXT NULL,
                    report_type VARCHAR(30) NOT NULL,
                    template_data JSONB NOT NULL,
                    created_by VARCHAR(100) NULL,
                    is_public BOOLEAN DEFAULT FALSE,
                    usage_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Generated reports table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS generated_reports (
                    report_id VARCHAR(36) PRIMARY KEY,
                    request_id VARCHAR(36) NOT NULL,
                    user_id VARCHAR(100) NOT NULL,
                    title VARCHAR(500) NOT NULL,
                    template_id VARCHAR(36) NOT NULL,
                    output_format VARCHAR(20) NOT NULL,
                    file_path VARCHAR(500) NULL,
                    file_size BIGINT NULL,
                    generation_time FLOAT NULL,
                    status VARCHAR(20) DEFAULT 'pending',
                    error_message TEXT NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    expires_at TIMESTAMP NULL
                );
            """)
            
            # Report requests table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS report_requests (
                    request_id VARCHAR(36) PRIMARY KEY,
                    user_id VARCHAR(100) NOT NULL,
                    template_id VARCHAR(36) NOT NULL,
                    parameters JSONB NOT NULL,
                    output_format VARCHAR(20) NOT NULL,
                    title VARCHAR(500) NULL,
                    description TEXT NULL,
                    status VARCHAR(20) DEFAULT 'pending',
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Create indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_report_templates_type ON report_templates(report_type);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_report_templates_public ON report_templates(is_public);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_generated_reports_user ON generated_reports(user_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_generated_reports_status ON generated_reports(status);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_report_requests_user ON report_requests(user_id);")
            
            logger.info("Report system tables created successfully")
        
        finally:
            await conn.close()
    
    async def _create_builtin_templates(self) -> None:
        """Create built-in report templates"""
        
        # Legislative Summary Template
        legislative_summary = ReportTemplate(
            template_id="legislative_summary_v1",
            name="Legislative Summary Report",
            description="Comprehensive summary of legislative documents and trends",
            report_type=ReportType.LEGISLATIVE_SUMMARY,
            sections=[
                ReportSection(
                    section_id="executive_summary",
                    title="Executive Summary",
                    content_type="text",
                    content="Overview of legislative activity in the specified period.",
                    order=1
                ),
                ReportSection(
                    section_id="document_statistics",
                    title="Document Statistics",
                    content_type="chart",
                    content="Document count by type and institution",
                    chart_config={"type": "bar", "x": "document_type", "y": "count"},
                    order=2
                ),
                ReportSection(
                    section_id="trend_analysis",
                    title="Trend Analysis",
                    content_type="chart",
                    content="Legislative activity trends over time",
                    chart_config={"type": "line", "x": "date", "y": "document_count"},
                    order=3
                ),
                ReportSection(
                    section_id="keyword_analysis",
                    title="Keyword Analysis",
                    content_type="chart",
                    content="Most frequent keywords and topics",
                    chart_config={"type": "wordcloud", "text_field": "keywords"},
                    order=4
                ),
                ReportSection(
                    section_id="institutional_breakdown",
                    title="Institutional Breakdown",
                    content_type="chart",
                    content="Documents by regulatory institution",
                    chart_config={"type": "pie", "values": "count", "names": "institution"},
                    order=5
                )
            ],
            sql_queries={
                "document_stats": """
                    SELECT document_type, institution, COUNT(*) as count
                    FROM legislative_documents 
                    WHERE published_date BETWEEN %(date_from)s AND %(date_to)s
                    GROUP BY document_type, institution
                    ORDER BY count DESC
                """,
                "daily_trends": """
                    SELECT DATE(published_date) as date, COUNT(*) as document_count
                    FROM legislative_documents
                    WHERE published_date BETWEEN %(date_from)s AND %(date_to)s
                    GROUP BY DATE(published_date)
                    ORDER BY date
                """,
                "keyword_frequency": """
                    SELECT keyword, COUNT(*) as frequency
                    FROM (
                        SELECT unnest(string_to_array(keywords, ',')) as keyword
                        FROM legislative_documents
                        WHERE published_date BETWEEN %(date_from)s AND %(date_to)s
                        AND keywords IS NOT NULL
                    ) t
                    WHERE trim(keyword) != ''
                    GROUP BY keyword
                    ORDER BY frequency DESC
                    LIMIT 50
                """
            },
            default_parameters={
                "date_from": (date.today() - timedelta(days=90)).isoformat(),
                "date_to": date.today().isoformat(),
                "include_charts": True,
                "include_statistics": True
            },
            styling={
                "primary_color": "#1565c0",
                "secondary_color": "#0d47a1",
                "font_family": "Arial, sans-serif",
                "page_size": "A4",
                "margins": "2cm"
            },
            is_public=True
        )
        
        # Trend Analysis Template
        trend_analysis = ReportTemplate(
            template_id="trend_analysis_v1",
            name="Legislative Trend Analysis",
            description="Detailed analysis of legislative trends and patterns",
            report_type=ReportType.TREND_ANALYSIS,
            sections=[
                ReportSection(
                    section_id="overview",
                    title="Trend Overview",
                    content_type="text",
                    content="Analysis of legislative trends and patterns over time.",
                    order=1
                ),
                ReportSection(
                    section_id="volume_trends",
                    title="Document Volume Trends",
                    content_type="chart",
                    content="Legislative document volume over time",
                    chart_config={"type": "line", "x": "month", "y": "volume", "color": "document_type"},
                    order=2
                ),
                ReportSection(
                    section_id="seasonal_patterns",
                    title="Seasonal Patterns",
                    content_type="chart",
                    content="Seasonal patterns in legislative activity",
                    chart_config={"type": "heatmap", "x": "month", "y": "day_of_week", "z": "activity_level"},
                    order=3
                ),
                ReportSection(
                    section_id="comparative_analysis",
                    title="Year-over-Year Comparison",
                    content_type="chart",
                    content="Comparison of legislative activity across years",
                    chart_config={"type": "bar", "x": "year", "y": "count", "color": "category"},
                    order=4
                )
            ],
            sql_queries={
                "monthly_volume": """
                    SELECT 
                        DATE_TRUNC('month', published_date) as month,
                        document_type,
                        COUNT(*) as volume
                    FROM legislative_documents
                    WHERE published_date BETWEEN %(date_from)s AND %(date_to)s
                    GROUP BY month, document_type
                    ORDER BY month, document_type
                """,
                "seasonal_activity": """
                    SELECT 
                        EXTRACT(month FROM published_date) as month,
                        EXTRACT(dow FROM published_date) as day_of_week,
                        COUNT(*) as activity_level
                    FROM legislative_documents
                    WHERE published_date BETWEEN %(date_from)s AND %(date_to)s
                    GROUP BY month, day_of_week
                """,
                "yearly_comparison": """
                    SELECT 
                        EXTRACT(year FROM published_date) as year,
                        document_type as category,
                        COUNT(*) as count
                    FROM legislative_documents
                    WHERE published_date BETWEEN %(date_from)s AND %(date_to)s
                    GROUP BY year, category
                    ORDER BY year, category
                """
            },
            default_parameters={
                "date_from": (date.today() - timedelta(days=365*2)).isoformat(),
                "date_to": date.today().isoformat(),
                "granularity": "monthly",
                "compare_years": True
            },
            is_public=True
        )
        
        # Performance Metrics Template
        performance_metrics = ReportTemplate(
            template_id="performance_metrics_v1",
            name="System Performance Metrics",
            description="Comprehensive system performance and usage analytics",
            report_type=ReportType.PERFORMANCE_METRICS,
            sections=[
                ReportSection(
                    section_id="summary",
                    title="Performance Summary",
                    content_type="text",
                    content="Overview of system performance metrics and KPIs.",
                    order=1
                ),
                ReportSection(
                    section_id="api_performance",
                    title="API Performance",
                    content_type="chart",
                    content="API response times and throughput",
                    chart_config={"type": "line", "x": "timestamp", "y": "response_time"},
                    order=2
                ),
                ReportSection(
                    section_id="user_activity",
                    title="User Activity",
                    content_type="chart",
                    content="User engagement and activity patterns",
                    chart_config={"type": "bar", "x": "date", "y": "active_users"},
                    order=3
                ),
                ReportSection(
                    section_id="search_analytics",
                    title="Search Analytics",
                    content_type="chart",
                    content="Search query patterns and success rates",
                    chart_config={"type": "pie", "values": "count", "names": "query_type"},
                    order=4
                )
            ],
            sql_queries={
                "api_metrics": """
                    SELECT 
                        DATE_TRUNC('hour', timestamp) as timestamp,
                        AVG(response_time) as response_time,
                        COUNT(*) as request_count
                    FROM api_metrics
                    WHERE timestamp BETWEEN %(date_from)s AND %(date_to)s
                    GROUP BY timestamp
                    ORDER BY timestamp
                """,
                "user_activity": """
                    SELECT 
                        DATE(created_at) as date,
                        COUNT(DISTINCT user_id) as active_users,
                        COUNT(*) as total_actions
                    FROM user_activity_log
                    WHERE created_at BETWEEN %(date_from)s AND %(date_to)s
                    GROUP BY date
                    ORDER BY date
                """,
                "search_patterns": """
                    SELECT 
                        query_type,
                        COUNT(*) as count,
                        AVG(results_count) as avg_results
                    FROM search_queries
                    WHERE created_at BETWEEN %(date_from)s AND %(date_to)s
                    GROUP BY query_type
                    ORDER BY count DESC
                """
            },
            default_parameters={
                "date_from": (date.today() - timedelta(days=30)).isoformat(),
                "date_to": date.today().isoformat(),
                "include_sla_metrics": True
            },
            is_public=True
        )
        
        # Store built-in templates
        self.builtin_templates = {
            "legislative_summary_v1": legislative_summary,
            "trend_analysis_v1": trend_analysis,
            "performance_metrics_v1": performance_metrics
        }
        
        # Save to database
        for template in self.builtin_templates.values():
            await self.save_template(template)
    
    async def save_template(self, template: ReportTemplate) -> None:
        """Save report template to database"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO report_templates 
                (template_id, name, description, report_type, template_data, 
                 created_by, is_public, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (template_id) 
                DO UPDATE SET
                    name = $2, description = $3, template_data = $5,
                    updated_at = $9
            """, template.template_id, template.name, template.description,
                template.report_type.value, json.dumps(template.to_dict()),
                template.created_by, template.is_public, datetime.now(), datetime.now())
            
            logger.info(f"Template saved: {template.template_id}")
        
        finally:
            await conn.close()
    
    async def generate_report(self, request: ReportRequest) -> str:
        """Generate report based on request"""
        
        report_id = str(uuid.uuid4())
        
        # Create report record
        report = GeneratedReport(
            report_id=report_id,
            request_id=request.request_id,
            user_id=request.user_id,
            title=request.title or "Generated Report",
            template_used=request.template_id,
            output_format=request.output_format,
            expires_at=datetime.now() + timedelta(days=7)
        )
        
        self.active_reports[report_id] = report
        
        try:
            start_time = datetime.now()
            
            # Update status
            report.status = "generating"
            await self._save_report_record(report)
            
            # Load template
            template = await self._load_template(request.template_id)
            if not template:
                raise ValueError(f"Template not found: {request.template_id}")
            
            # Execute data queries
            data_context = await self._execute_template_queries(template, request.parameters)
            
            # Generate visualizations
            charts = await self._generate_charts(template, data_context)
            
            # Render report content
            content = await self._render_report_content(template, request, data_context, charts)
            
            # Export to requested format
            file_path = await self._export_report(content, request.output_format, report_id)
            
            # Update completion
            end_time = datetime.now()
            generation_time = (end_time - start_time).total_seconds()
            
            report.status = "completed"
            report.file_path = file_path
            report.file_size = Path(file_path).stat().st_size
            report.generation_time = generation_time
            
            await self._save_report_record(report)
            
            logger.info(f"Report generated successfully: {report_id}")
            return report_id
        
        except Exception as e:
            logger.error(f"Report generation failed: {report_id} - {str(e)}")
            report.status = "failed"
            report.error_message = str(e)
            await self._save_report_record(report)
            raise
    
    async def _load_template(self, template_id: str) -> Optional[ReportTemplate]:
        """Load report template"""
        
        # Check built-in templates first
        if template_id in self.builtin_templates:
            return self.builtin_templates[template_id]
        
        # Load from database
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            row = await conn.fetchrow("""
                SELECT template_data FROM report_templates 
                WHERE template_id = $1
            """, template_id)
            
            if not row:
                return None
            
            template_data = json.loads(row['template_data'])
            
            # Reconstruct template object
            sections = [ReportSection(**section) for section in template_data['sections']]
            
            template = ReportTemplate(
                template_id=template_data['template_id'],
                name=template_data['name'],
                description=template_data['description'],
                report_type=ReportType(template_data['report_type']),
                sections=sections,
                default_parameters=template_data.get('default_parameters', {}),
                sql_queries=template_data.get('sql_queries', {}),
                chart_templates=template_data.get('chart_templates', {}),
                styling=template_data.get('styling', {}),
                created_by=template_data.get('created_by'),
                is_public=template_data.get('is_public', False)
            )
            
            return template
        
        finally:
            await conn.close()
    
    async def _execute_template_queries(self, template: ReportTemplate, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute SQL queries defined in template"""
        
        conn = await asyncpg.connect(**self.db_config)
        data_context = {}
        
        try:
            for query_name, query_sql in template.sql_queries.items():
                try:
                    # Execute query with parameters
                    rows = await conn.fetch(query_sql, **parameters)
                    
                    # Convert to list of dictionaries
                    data_context[query_name] = [dict(row) for row in rows]
                    
                    logger.debug(f"Executed query '{query_name}': {len(rows)} rows")
                
                except Exception as e:
                    logger.error(f"Query execution failed '{query_name}': {e}")
                    data_context[query_name] = []
            
            return data_context
        
        finally:
            await conn.close()
    
    async def _generate_charts(self, template: ReportTemplate, data_context: Dict[str, Any]) -> Dict[str, str]:
        """Generate charts based on template configuration"""
        
        charts = {}
        
        for section in template.sections:
            if section.content_type == "chart" and section.chart_config:
                try:
                    chart_data = self._get_chart_data(section, data_context)
                    if chart_data:
                        chart_html = await self._create_chart(section.chart_config, chart_data, section.section_id)
                        charts[section.section_id] = chart_html
                
                except Exception as e:
                    logger.error(f"Chart generation failed for section '{section.section_id}': {e}")
                    charts[section.section_id] = f"<p>Chart generation failed: {str(e)}</p>"
        
        return charts
    
    def _get_chart_data(self, section: ReportSection, data_context: Dict[str, Any]) -> Optional[List[Dict]]:
        """Extract chart data from context"""
        
        # Try to find matching data based on section name or content
        for query_name, data in data_context.items():
            if query_name in section.section_id.lower() or section.section_id in query_name:
                return data
        
        # Fallback: use first available data
        if data_context:
            return list(data_context.values())[0]
        
        return None
    
    async def _create_chart(self, chart_config: Dict[str, Any], data: List[Dict], chart_id: str) -> str:
        """Create interactive chart using Plotly"""
        
        if not data:
            return "<p>No data available for chart</p>"
        
        df = pd.DataFrame(data)
        chart_type = chart_config.get("type", "bar")
        
        try:
            if chart_type == "bar":
                fig = px.bar(df, 
                           x=chart_config.get("x"), 
                           y=chart_config.get("y"),
                           color=chart_config.get("color"),
                           title=f"Bar Chart - {chart_id}")
            
            elif chart_type == "line":
                fig = px.line(df,
                            x=chart_config.get("x"),
                            y=chart_config.get("y"),
                            color=chart_config.get("color"),
                            title=f"Line Chart - {chart_id}")
            
            elif chart_type == "pie":
                fig = px.pie(df,
                           values=chart_config.get("values"),
                           names=chart_config.get("names"),
                           title=f"Pie Chart - {chart_id}")
            
            elif chart_type == "scatter":
                fig = px.scatter(df,
                               x=chart_config.get("x"),
                               y=chart_config.get("y"),
                               color=chart_config.get("color"),
                               size=chart_config.get("size"),
                               title=f"Scatter Plot - {chart_id}")
            
            elif chart_type == "histogram":
                fig = px.histogram(df,
                                 x=chart_config.get("x"),
                                 nbins=chart_config.get("bins", 20),
                                 title=f"Histogram - {chart_id}")
            
            elif chart_type == "heatmap":
                # Create pivot table for heatmap
                pivot_df = df.pivot_table(
                    values=chart_config.get("z"),
                    index=chart_config.get("y"),
                    columns=chart_config.get("x"),
                    aggfunc='mean'
                )
                fig = px.imshow(pivot_df,
                              title=f"Heatmap - {chart_id}",
                              aspect="auto")
            
            elif chart_type == "treemap":
                fig = px.treemap(df,
                               path=chart_config.get("path", []),
                               values=chart_config.get("values"),
                               title=f"Treemap - {chart_id}")
            
            elif chart_type == "sunburst":
                fig = px.sunburst(df,
                                path=chart_config.get("path", []),
                                values=chart_config.get("values"),
                                title=f"Sunburst - {chart_id}")
            
            else:
                # Default to bar chart
                fig = px.bar(df,
                           x=df.columns[0] if len(df.columns) > 0 else None,
                           y=df.columns[1] if len(df.columns) > 1 else None,
                           title=f"Chart - {chart_id}")
            
            # Customize layout
            fig.update_layout(
                font=dict(family="Arial, sans-serif", size=12),
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                showlegend=True,
                margin=dict(l=20, r=20, t=50, b=20)
            )
            
            # Convert to HTML
            return fig.to_html(include_plotlyjs='cdn', div_id=f"chart_{chart_id}")
        
        except Exception as e:
            logger.error(f"Chart creation failed: {e}")
            return f"<p>Error creating chart: {str(e)}</p>"
    
    async def _render_report_content(self, template: ReportTemplate, request: ReportRequest, 
                                   data_context: Dict[str, Any], charts: Dict[str, str]) -> str:
        """Render complete report content"""
        
        # Prepare template context
        context = {
            "title": request.title or template.name,
            "description": request.description or template.description,
            "generation_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "user_id": request.user_id,
            "parameters": request.parameters,
            "data": data_context,
            "charts": charts,
            "sections": [],
            "styling": template.styling
        }
        
        # Process each section
        for section in sorted(template.sections, key=lambda s: s.order):
            section_content = {
                "id": section.section_id,
                "title": section.title,
                "content_type": section.content_type,
                "content": section.content,
                "order": section.order
            }
            
            if section.content_type == "chart":
                section_content["chart_html"] = charts.get(section.section_id, "")
            
            elif section.content_type == "table":
                # Generate table from data
                table_data = self._get_chart_data(section, data_context)
                if table_data:
                    section_content["table_html"] = self._create_table_html(table_data)
            
            elif section.content_type == "analysis":
                # Generate automated analysis
                analysis_text = await self._generate_analysis(section, data_context)
                section_content["analysis"] = analysis_text
            
            context["sections"].append(section_content)
        
        # Load and render HTML template
        html_template = self._get_html_template(template)
        rendered_html = html_template.render(**context)
        
        return rendered_html
    
    def _get_html_template(self, template: ReportTemplate) -> Template:
        """Get HTML template for report rendering"""
        
        # Default HTML template
        default_template = """
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{{ title }}</title>
            <style>
                body {
                    font-family: {{ styling.font_family or 'Arial, sans-serif' }};
                    margin: 0;
                    padding: 20px;
                    line-height: 1.6;
                    color: #333;
                }
                .header {
                    background-color: {{ styling.primary_color or '#1565c0' }};
                    color: white;
                    padding: 20px;
                    margin-bottom: 30px;
                    border-radius: 5px;
                }
                .section {
                    margin-bottom: 30px;
                    padding: 20px;
                    border: 1px solid #ddd;
                    border-radius: 5px;
                }
                .section h2 {
                    color: {{ styling.primary_color or '#1565c0' }};
                    border-bottom: 2px solid {{ styling.primary_color or '#1565c0' }};
                    padding-bottom: 10px;
                }
                .chart-container {
                    margin: 20px 0;
                    text-align: center;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin: 20px 0;
                }
                th, td {
                    border: 1px solid #ddd;
                    padding: 12px;
                    text-align: left;
                }
                th {
                    background-color: {{ styling.secondary_color or '#f5f5f5' }};
                    font-weight: bold;
                }
                .footer {
                    margin-top: 50px;
                    padding: 20px;
                    border-top: 1px solid #ddd;
                    font-size: 0.9em;
                    color: #666;
                }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{ title }}</h1>
                <p>{{ description }}</p>
                <p><strong>Generated:</strong> {{ generation_date }}</p>
            </div>
            
            {% for section in sections %}
            <div class="section">
                <h2>{{ section.title }}</h2>
                
                {% if section.content_type == "text" %}
                    <p>{{ section.content }}</p>
                
                {% elif section.content_type == "chart" %}
                    <div class="chart-container">
                        {{ section.chart_html | safe }}
                    </div>
                
                {% elif section.content_type == "table" %}
                    {{ section.table_html | safe }}
                
                {% elif section.content_type == "analysis" %}
                    <div class="analysis">
                        {{ section.analysis | safe }}
                    </div>
                
                {% endif %}
            </div>
            {% endfor %}
            
            <div class="footer">
                <p>Generated by Monitor Legislativo v4 | User: {{ user_id }}</p>
                <p>Report Parameters: {{ parameters | tojson }}</p>
            </div>
        </body>
        </html>
        """
        
        return Template(default_template)
    
    def _create_table_html(self, data: List[Dict]) -> str:
        """Create HTML table from data"""
        
        if not data:
            return "<p>No data available</p>"
        
        df = pd.DataFrame(data)
        
        # Limit rows for display
        if len(df) > 100:
            df = df.head(100)
            truncated_note = f"<p><em>Note: Table truncated to first 100 rows (total: {len(data)} rows)</em></p>"
        else:
            truncated_note = ""
        
        table_html = df.to_html(classes="data-table", index=False, escape=False)
        
        return f"{table_html}{truncated_note}"
    
    async def _generate_analysis(self, section: ReportSection, data_context: Dict[str, Any]) -> str:
        """Generate automated analysis text"""
        
        # Get relevant data
        section_data = self._get_chart_data(section, data_context)
        
        if not section_data:
            return "No data available for analysis."
        
        df = pd.DataFrame(section_data)
        analysis_parts = []
        
        # Basic statistics
        if not df.empty:
            analysis_parts.append(f"<p><strong>Data Summary:</strong> {len(df)} records analyzed.</p>")
            
            # Identify numeric columns
            numeric_cols = df.select_dtypes(include=['number']).columns
            if len(numeric_cols) > 0:
                analysis_parts.append("<p><strong>Key Statistics:</strong></p><ul>")
                
                for col in numeric_cols[:3]:  # Limit to first 3 numeric columns
                    mean_val = df[col].mean()
                    max_val = df[col].max()
                    min_val = df[col].min()
                    analysis_parts.append(
                        f"<li>{col}: Average = {mean_val:.2f}, Range = {min_val:.2f} to {max_val:.2f}</li>"
                    )
                
                analysis_parts.append("</ul>")
            
            # Identify categorical patterns
            categorical_cols = df.select_dtypes(include=['object']).columns
            if len(categorical_cols) > 0:
                analysis_parts.append("<p><strong>Categorical Analysis:</strong></p><ul>")
                
                for col in categorical_cols[:2]:  # Limit to first 2 categorical columns
                    top_values = df[col].value_counts().head(3)
                    if not top_values.empty:
                        top_list = ", ".join([f"{val} ({count})" for val, count in top_values.items()])
                        analysis_parts.append(f"<li>Top {col}: {top_list}</li>")
                
                analysis_parts.append("</ul>")
        
        return "".join(analysis_parts) if analysis_parts else "No significant patterns detected."
    
    async def _export_report(self, content: str, output_format: ReportFormat, report_id: str) -> str:
        """Export report to specified format"""
        
        if output_format == ReportFormat.HTML:
            file_path = self.output_path / f"report_{report_id}.html"
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return str(file_path)
        
        elif output_format == ReportFormat.PDF:
            file_path = self.output_path / f"report_{report_id}.pdf"
            
            # Convert HTML to PDF using WeasyPrint
            html_doc = HTML(string=content)
            html_doc.write_pdf(str(file_path))
            
            return str(file_path)
        
        elif output_format == ReportFormat.MARKDOWN:
            file_path = self.output_path / f"report_{report_id}.md"
            
            # Convert HTML to Markdown (basic conversion)
            markdown_content = self._html_to_markdown(content)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(markdown_content)
            
            return str(file_path)
        
        else:
            # Default to HTML
            return await self._export_report(content, ReportFormat.HTML, report_id)
    
    def _html_to_markdown(self, html_content: str) -> str:
        """Basic HTML to Markdown conversion"""
        import re
        
        # Simple regex-based conversion
        markdown = html_content
        
        # Headers
        markdown = re.sub(r'<h1>(.*?)</h1>', r'# \1\n', markdown)
        markdown = re.sub(r'<h2>(.*?)</h2>', r'## \1\n', markdown)
        markdown = re.sub(r'<h3>(.*?)</h3>', r'### \1\n', markdown)
        
        # Paragraphs
        markdown = re.sub(r'<p>(.*?)</p>', r'\1\n\n', markdown)
        
        # Lists
        markdown = re.sub(r'<ul>', '', markdown)
        markdown = re.sub(r'</ul>', '\n', markdown)
        markdown = re.sub(r'<li>(.*?)</li>', r'- \1\n', markdown)
        
        # Bold and italic
        markdown = re.sub(r'<strong>(.*?)</strong>', r'**\1**', markdown)
        markdown = re.sub(r'<em>(.*?)</em>', r'*\1*', markdown)
        
        # Remove remaining HTML tags
        markdown = re.sub(r'<[^>]+>', '', markdown)
        
        # Clean up extra whitespace
        markdown = re.sub(r'\n{3,}', '\n\n', markdown)
        
        return markdown.strip()
    
    async def _save_report_record(self, report: GeneratedReport) -> None:
        """Save generated report record to database"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO generated_reports 
                (report_id, request_id, user_id, title, template_id, output_format,
                 file_path, file_size, generation_time, status, error_message,
                 created_at, expires_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                ON CONFLICT (report_id)
                DO UPDATE SET
                    status = $10, file_path = $7, file_size = $8,
                    generation_time = $9, error_message = $11
            """, report.report_id, report.request_id, report.user_id, report.title,
                report.template_used, report.output_format.value, report.file_path,
                report.file_size, report.generation_time, report.status,
                report.error_message, report.created_at, report.expires_at)
        
        finally:
            await conn.close()
    
    async def get_report_status(self, report_id: str) -> Optional[Dict[str, Any]]:
        """Get report generation status"""
        
        # Check active reports first
        if report_id in self.active_reports:
            return self.active_reports[report_id].to_dict()
        
        # Load from database
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            row = await conn.fetchrow("""
                SELECT * FROM generated_reports WHERE report_id = $1
            """, report_id)
            
            if row:
                result = dict(row)
                if result['created_at']:
                    result['created_at'] = result['created_at'].isoformat()
                if result['expires_at']:
                    result['expires_at'] = result['expires_at'].isoformat()
                return result
            
            return None
        
        finally:
            await conn.close()
    
    async def download_report(self, report_id: str, user_id: str) -> Optional[str]:
        """Get download path for completed report"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            row = await conn.fetchrow("""
                SELECT file_path, status, user_id
                FROM generated_reports 
                WHERE report_id = $1
            """, report_id)
            
            if not row or row['user_id'] != user_id:
                return None
            
            if row['status'] != 'completed' or not row['file_path']:
                return None
            
            # Check if file exists
            if not Path(row['file_path']).exists():
                return None
            
            return row['file_path']
        
        finally:
            await conn.close()
    
    async def get_available_templates(self, user_id: str = None) -> List[Dict[str, Any]]:
        """Get available report templates"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Get public templates and user's private templates
            if user_id:
                templates = await conn.fetch("""
                    SELECT template_id, name, description, report_type, 
                           is_public, usage_count, created_at
                    FROM report_templates 
                    WHERE is_public = TRUE OR created_by = $1
                    ORDER BY usage_count DESC, name
                """, user_id)
            else:
                templates = await conn.fetch("""
                    SELECT template_id, name, description, report_type,
                           is_public, usage_count, created_at
                    FROM report_templates 
                    WHERE is_public = TRUE
                    ORDER BY usage_count DESC, name
                """)
            
            result = []
            for template in templates:
                template_data = dict(template)
                if template_data['created_at']:
                    template_data['created_at'] = template_data['created_at'].isoformat()
                result.append(template_data)
            
            return result
        
        finally:
            await conn.close()

# Factory function for easy creation
async def create_report_generator(db_config: Dict[str, str], templates_path: str = "templates", 
                                output_path: str = "/tmp/reports") -> CustomReportGenerator:
    """Create and initialize custom report generator"""
    generator = CustomReportGenerator(db_config, templates_path, output_path)
    await generator.initialize()
    return generator

# Export main classes
__all__ = [
    'CustomReportGenerator',
    'ReportTemplate',
    'ReportSection', 
    'ReportRequest',
    'GeneratedReport',
    'ReportType',
    'ReportFormat',
    'ChartType',
    'create_report_generator'
]