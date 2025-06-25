# Advanced Data Visualization Engine for Monitor Legislativo v4
# Phase 5 Week 18: Interactive visualization tools for Brazilian legislative data
# Real-time dashboards, custom charts, and advanced analytics visualization

import asyncio
import asyncpg
import json
import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Optional, Any, Union, Tuple
from dataclasses import dataclass, field, asdict
from datetime import datetime, date, timedelta
from enum import Enum
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.io as pio
import matplotlib.pyplot as plt
import seaborn as sns
from wordcloud import WordCloud
import networkx as nx
import folium
from folium import plugins
import uuid
from pathlib import Path
import base64
import io

logger = logging.getLogger(__name__)

class VisualizationType(Enum):
    """Types of visualizations available"""
    BAR_CHART = "bar_chart"
    LINE_CHART = "line_chart"
    PIE_CHART = "pie_chart"
    SCATTER_PLOT = "scatter_plot"
    HISTOGRAM = "histogram"
    HEATMAP = "heatmap"
    TREEMAP = "treemap"
    SUNBURST = "sunburst"
    WORDCLOUD = "wordcloud"
    NETWORK_GRAPH = "network_graph"
    GEOGRAPHIC_MAP = "geographic_map"
    TIMELINE = "timeline"
    SANKEY_DIAGRAM = "sankey_diagram"
    BUBBLE_CHART = "bubble_chart"
    VIOLIN_PLOT = "violin_plot"
    BOX_PLOT = "box_plot"
    RADAR_CHART = "radar_chart"
    GANTT_CHART = "gantt_chart"
    FUNNEL_CHART = "funnel_chart"
    PARALLEL_COORDINATES = "parallel_coordinates"

class DashboardLayout(Enum):
    """Dashboard layout types"""
    SINGLE_COLUMN = "single_column"
    TWO_COLUMN = "two_column"
    THREE_COLUMN = "three_column"
    GRID = "grid"
    MASONRY = "masonry"
    CUSTOM = "custom"

class InteractionType(Enum):
    """Types of chart interactions"""
    HOVER = "hover"
    CLICK = "click"
    SELECT = "select"
    ZOOM = "zoom"
    FILTER = "filter"
    DRILL_DOWN = "drill_down"
    CROSS_FILTER = "cross_filter"

@dataclass
class VisualizationConfig:
    """Configuration for individual visualizations"""
    viz_id: str
    title: str
    type: VisualizationType
    data_source: str
    query: str
    x_axis: Optional[str] = None
    y_axis: Optional[str] = None
    color_field: Optional[str] = None
    size_field: Optional[str] = None
    group_by: List[str] = field(default_factory=list)
    filters: Dict[str, Any] = field(default_factory=dict)
    styling: Dict[str, Any] = field(default_factory=dict)
    interactions: List[InteractionType] = field(default_factory=list)
    refresh_interval: Optional[int] = None  # in seconds
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['type'] = self.type.value
        result['interactions'] = [i.value for i in self.interactions]
        return result

@dataclass
class DashboardConfig:
    """Configuration for dashboard layout and behavior"""
    dashboard_id: str
    title: str
    description: str
    layout: DashboardLayout
    visualizations: List[VisualizationConfig]
    filters: Dict[str, Any] = field(default_factory=dict)
    styling: Dict[str, Any] = field(default_factory=dict)
    auto_refresh: bool = False
    refresh_interval: int = 300  # 5 minutes default
    created_by: Optional[str] = None
    is_public: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['layout'] = self.layout.value
        result['visualizations'] = [viz.to_dict() for viz in self.visualizations]
        return result

@dataclass
class DataMetrics:
    """Metrics calculated from data"""
    total_records: int
    unique_values: Dict[str, int]
    null_counts: Dict[str, int]
    data_types: Dict[str, str]
    numeric_stats: Dict[str, Dict[str, float]]
    categorical_stats: Dict[str, Dict[str, int]]
    correlations: Optional[Dict[str, Dict[str, float]]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

class AdvancedVisualizationEngine:
    """
    Advanced data visualization engine for Brazilian legislative data analysis
    
    Features:
    - Interactive charts and dashboards
    - Real-time data updates
    - Custom visualization templates
    - Geographic and network visualizations
    - Advanced analytics and metrics
    - Export capabilities
    - Mobile-responsive design
    - Accessibility features
    """
    
    def __init__(self, db_config: Dict[str, str], output_path: str = "/tmp/visualizations"):
        self.db_config = db_config
        self.output_path = Path(output_path)
        self.output_path.mkdir(parents=True, exist_ok=True)
        
        # Set default Plotly theme
        pio.templates.default = "plotly_white"
        
        # Color palettes for Brazilian legislative data
        self.color_palettes = {
            "government": ["#1565c0", "#0d47a1", "#1976d2", "#42a5f5", "#90caf9"],
            "institutions": ["#2e7d32", "#388e3c", "#4caf50", "#66bb6a", "#81c784"],
            "document_types": ["#f57c00", "#ff9800", "#ffb74d", "#ffcc02", "#fff176"],
            "regulatory": ["#7b1fa2", "#8e24aa", "#9c27b0", "#ab47bc", "#ba68c8"],
            "timeline": ["#d32f2f", "#f44336", "#ef5350", "#e57373", "#ef9a9a"]
        }
        
        # Predefined visualization templates
        self.visualization_templates = {}
        
        # Active dashboards cache
        self.dashboard_cache: Dict[str, Dict[str, Any]] = {}
    
    async def initialize(self) -> None:
        """Initialize visualization engine tables and templates"""
        await self._create_visualization_tables()
        await self._create_predefined_templates()
        logger.info("Advanced visualization engine initialized")
    
    async def _create_visualization_tables(self) -> None:
        """Create visualization system database tables"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Dashboards table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS dashboards (
                    dashboard_id VARCHAR(36) PRIMARY KEY,
                    title VARCHAR(300) NOT NULL,
                    description TEXT NULL,
                    layout VARCHAR(20) NOT NULL,
                    configuration JSONB NOT NULL,
                    created_by VARCHAR(100) NULL,
                    is_public BOOLEAN DEFAULT FALSE,
                    view_count INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Visualizations table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS visualizations (
                    viz_id VARCHAR(36) PRIMARY KEY,
                    dashboard_id VARCHAR(36) NULL,
                    title VARCHAR(300) NOT NULL,
                    type VARCHAR(30) NOT NULL,
                    configuration JSONB NOT NULL,
                    data_cache JSONB NULL,
                    last_updated TIMESTAMP NULL,
                    created_by VARCHAR(100) NULL,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Visualization templates table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS visualization_templates (
                    template_id VARCHAR(36) PRIMARY KEY,
                    name VARCHAR(200) NOT NULL,
                    description TEXT NULL,
                    type VARCHAR(30) NOT NULL,
                    template_config JSONB NOT NULL,
                    category VARCHAR(50) NULL,
                    is_builtin BOOLEAN DEFAULT FALSE,
                    usage_count INTEGER DEFAULT 0,
                    created_by VARCHAR(100) NULL,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Dashboard views tracking
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS dashboard_views (
                    view_id VARCHAR(36) PRIMARY KEY,
                    dashboard_id VARCHAR(36) NOT NULL,
                    user_id VARCHAR(100) NULL,
                    session_id VARCHAR(100) NULL,
                    view_duration INTEGER NULL,
                    interactions JSONB NULL,
                    viewed_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Create indexes
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboards_public ON dashboards(is_public);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboards_created_by ON dashboards(created_by);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_visualizations_dashboard ON visualizations(dashboard_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_visualizations_type ON visualizations(type);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_viz_templates_type ON visualization_templates(type);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_dashboard_views_dashboard ON dashboard_views(dashboard_id);")
            
            logger.info("Visualization system tables created successfully")
        
        finally:
            await conn.close()
    
    async def _create_predefined_templates(self) -> None:
        """Create predefined visualization templates for Brazilian legislative data"""
        
        # Legislative Activity Timeline
        timeline_template = VisualizationConfig(
            viz_id="legislative_timeline_template",
            title="Legislative Activity Timeline",
            type=VisualizationType.LINE_CHART,
            data_source="legislative_documents",
            query="""
                SELECT DATE(published_date) as date, 
                       COUNT(*) as document_count,
                       document_type
                FROM legislative_documents 
                WHERE published_date >= NOW() - INTERVAL '1 year'
                GROUP BY DATE(published_date), document_type
                ORDER BY date
            """,
            x_axis="date",
            y_axis="document_count",
            color_field="document_type",
            styling={
                "color_palette": "government",
                "line_width": 2,
                "show_markers": True
            },
            interactions=[InteractionType.HOVER, InteractionType.ZOOM],
            refresh_interval=3600  # 1 hour
        )
        
        # Institutional Document Distribution
        institution_pie = VisualizationConfig(
            viz_id="institution_distribution_template",
            title="Documents by Institution",
            type=VisualizationType.PIE_CHART,
            data_source="legislative_documents",
            query="""
                SELECT institution, COUNT(*) as count
                FROM legislative_documents 
                WHERE published_date >= NOW() - INTERVAL '6 months'
                GROUP BY institution
                ORDER BY count DESC
                LIMIT 10
            """,
            color_field="institution",
            styling={
                "color_palette": "institutions",
                "show_values": True,
                "hole_size": 0.3
            },
            interactions=[InteractionType.HOVER, InteractionType.CLICK]
        )
        
        # Document Type Heatmap
        type_heatmap = VisualizationConfig(
            viz_id="document_type_heatmap_template",
            title="Document Types by Month",
            type=VisualizationType.HEATMAP,
            data_source="legislative_documents",
            query="""
                SELECT 
                    EXTRACT(month FROM published_date) as month,
                    document_type,
                    COUNT(*) as count
                FROM legislative_documents 
                WHERE published_date >= NOW() - INTERVAL '2 years'
                GROUP BY month, document_type
            """,
            x_axis="month",
            y_axis="document_type",
            color_field="count",
            styling={
                "colorscale": "Blues",
                "show_scale": True
            },
            interactions=[InteractionType.HOVER]
        )
        
        # Keyword Word Cloud
        keyword_cloud = VisualizationConfig(
            viz_id="keyword_wordcloud_template",
            title="Most Frequent Keywords",
            type=VisualizationType.WORDCLOUD,
            data_source="legislative_documents",
            query="""
                SELECT keyword, COUNT(*) as frequency
                FROM (
                    SELECT unnest(string_to_array(keywords, ',')) as keyword
                    FROM legislative_documents
                    WHERE keywords IS NOT NULL
                    AND published_date >= NOW() - INTERVAL '3 months'
                ) t
                WHERE trim(keyword) != ''
                GROUP BY keyword
                ORDER BY frequency DESC
                LIMIT 100
            """,
            styling={
                "max_words": 100,
                "background_color": "white",
                "color_palette": "viridis"
            }
        )
        
        # Geographic Distribution (for federal vs state legislation)
        geographic_map = VisualizationConfig(
            viz_id="geographic_distribution_template",
            title="Legislative Activity by Region",
            type=VisualizationType.GEOGRAPHIC_MAP,
            data_source="legislative_documents",
            query="""
                SELECT 
                    CASE 
                        WHEN institution LIKE '%Federal%' THEN 'Federal'
                        WHEN institution LIKE '%São Paulo%' THEN 'SP'
                        WHEN institution LIKE '%Rio%' THEN 'RJ'
                        WHEN institution LIKE '%Minas%' THEN 'MG'
                        ELSE 'Other'
                    END as region,
                    COUNT(*) as count,
                    AVG(EXTRACT(epoch FROM (NOW() - published_date))/86400) as avg_age_days
                FROM legislative_documents 
                WHERE published_date >= NOW() - INTERVAL '1 year'
                GROUP BY region
            """,
            styling={
                "map_style": "OpenStreetMap",
                "color_palette": "regulatory"
            },
            interactions=[InteractionType.HOVER, InteractionType.CLICK]
        )
        
        # Regulatory Agency Network
        agency_network = VisualizationConfig(
            viz_id="agency_network_template",
            title="Regulatory Agency Collaboration Network",
            type=VisualizationType.NETWORK_GRAPH,
            data_source="legislative_documents",
            query="""
                SELECT 
                    d1.regulatory_agency as source,
                    d2.regulatory_agency as target,
                    COUNT(*) as weight
                FROM legislative_documents d1
                JOIN legislative_documents d2 ON d1.document_id != d2.document_id
                WHERE d1.regulatory_agency IS NOT NULL 
                AND d2.regulatory_agency IS NOT NULL
                AND d1.published_date >= NOW() - INTERVAL '6 months'
                AND d2.published_date >= NOW() - INTERVAL '6 months'
                GROUP BY d1.regulatory_agency, d2.regulatory_agency
                HAVING COUNT(*) > 5
            """,
            styling={
                "node_size_field": "degree",
                "edge_width_field": "weight",
                "layout": "spring",
                "color_palette": "regulatory"
            },
            interactions=[InteractionType.HOVER, InteractionType.CLICK]
        )
        
        self.visualization_templates = {
            "legislative_timeline": timeline_template,
            "institution_distribution": institution_pie,
            "document_type_heatmap": type_heatmap,
            "keyword_wordcloud": keyword_cloud,
            "geographic_distribution": geographic_map,
            "agency_network": agency_network
        }
        
        # Save templates to database
        for template_id, template in self.visualization_templates.items():
            await self._save_visualization_template(template_id, template)
    
    async def _save_visualization_template(self, template_id: str, template: VisualizationConfig) -> None:
        """Save visualization template to database"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO visualization_templates 
                (template_id, name, description, type, template_config, 
                 category, is_builtin, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                ON CONFLICT (template_id) 
                DO UPDATE SET
                    name = $2, template_config = $5, category = $6
            """, template_id, template.title, "Built-in template for " + template.title,
                template.type.value, json.dumps(template.to_dict()),
                "legislative_analysis", True, datetime.now())
        
        finally:
            await conn.close()
    
    async def create_visualization(self, config: VisualizationConfig) -> str:
        """Create a new visualization"""
        
        # Execute data query
        data = await self._execute_visualization_query(config)
        
        # Generate visualization based on type
        if config.type == VisualizationType.BAR_CHART:
            chart_html = await self._create_bar_chart(data, config)
        elif config.type == VisualizationType.LINE_CHART:
            chart_html = await self._create_line_chart(data, config)
        elif config.type == VisualizationType.PIE_CHART:
            chart_html = await self._create_pie_chart(data, config)
        elif config.type == VisualizationType.SCATTER_PLOT:
            chart_html = await self._create_scatter_plot(data, config)
        elif config.type == VisualizationType.HISTOGRAM:
            chart_html = await self._create_histogram(data, config)
        elif config.type == VisualizationType.HEATMAP:
            chart_html = await self._create_heatmap(data, config)
        elif config.type == VisualizationType.TREEMAP:
            chart_html = await self._create_treemap(data, config)
        elif config.type == VisualizationType.SUNBURST:
            chart_html = await self._create_sunburst(data, config)
        elif config.type == VisualizationType.WORDCLOUD:
            chart_html = await self._create_wordcloud(data, config)
        elif config.type == VisualizationType.NETWORK_GRAPH:
            chart_html = await self._create_network_graph(data, config)
        elif config.type == VisualizationType.GEOGRAPHIC_MAP:
            chart_html = await self._create_geographic_map(data, config)
        elif config.type == VisualizationType.TIMELINE:
            chart_html = await self._create_timeline(data, config)
        elif config.type == VisualizationType.SANKEY_DIAGRAM:
            chart_html = await self._create_sankey_diagram(data, config)
        elif config.type == VisualizationType.BUBBLE_CHART:
            chart_html = await self._create_bubble_chart(data, config)
        elif config.type == VisualizationType.VIOLIN_PLOT:
            chart_html = await self._create_violin_plot(data, config)
        elif config.type == VisualizationType.BOX_PLOT:
            chart_html = await self._create_box_plot(data, config)
        elif config.type == VisualizationType.RADAR_CHART:
            chart_html = await self._create_radar_chart(data, config)
        else:
            # Default to bar chart
            chart_html = await self._create_bar_chart(data, config)
        
        # Save visualization
        await self._save_visualization(config, data, chart_html)
        
        return chart_html
    
    async def _execute_visualization_query(self, config: VisualizationConfig) -> List[Dict[str, Any]]:
        """Execute data query for visualization"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Apply filters to query if any
            query = config.query
            if config.filters:
                # Simple filter application - would need more sophisticated handling in production
                for key, value in config.filters.items():
                    if isinstance(value, str):
                        query = query.replace(f"%(filter_{key})s", f"'{value}'")
                    else:
                        query = query.replace(f"%(filter_{key})s", str(value))
            
            rows = await conn.fetch(query)
            return [dict(row) for row in rows]
        
        except Exception as e:
            logger.error(f"Query execution failed for visualization {config.viz_id}: {e}")
            return []
        
        finally:
            await conn.close()
    
    async def _create_bar_chart(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create interactive bar chart"""
        
        if not data:
            return "<p>No data available for bar chart</p>"
        
        df = pd.DataFrame(data)
        colors = self._get_color_palette(config.styling.get("color_palette", "government"))
        
        fig = px.bar(
            df,
            x=config.x_axis,
            y=config.y_axis,
            color=config.color_field,
            title=config.title,
            color_discrete_sequence=colors
        )
        
        # Apply styling
        fig.update_layout(
            font=dict(family="Arial, sans-serif", size=12),
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            showlegend=True,
            margin=dict(l=40, r=40, t=60, b=40)
        )
        
        # Add interactions
        if InteractionType.HOVER in config.interactions:
            fig.update_traces(hovertemplate='<b>%{x}</b><br>%{y}<extra></extra>')
        
        return fig.to_html(include_plotlyjs='cdn', div_id=f"viz_{config.viz_id}")
    
    async def _create_line_chart(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create interactive line chart"""
        
        if not data:
            return "<p>No data available for line chart</p>"
        
        df = pd.DataFrame(data)
        colors = self._get_color_palette(config.styling.get("color_palette", "timeline"))
        
        fig = px.line(
            df,
            x=config.x_axis,
            y=config.y_axis,
            color=config.color_field,
            title=config.title,
            color_discrete_sequence=colors,
            markers=config.styling.get("show_markers", False)
        )
        
        # Apply styling
        line_width = config.styling.get("line_width", 2)
        fig.update_traces(line=dict(width=line_width))
        
        fig.update_layout(
            font=dict(family="Arial, sans-serif", size=12),
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            showlegend=True,
            margin=dict(l=40, r=40, t=60, b=40)
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id=f"viz_{config.viz_id}")
    
    async def _create_pie_chart(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create interactive pie chart"""
        
        if not data:
            return "<p>No data available for pie chart</p>"
        
        df = pd.DataFrame(data)
        colors = self._get_color_palette(config.styling.get("color_palette", "institutions"))
        
        # Get values and names columns
        values_col = None
        names_col = None
        
        for col in df.columns:
            if col.lower() in ['count', 'value', 'amount', 'quantity']:
                values_col = col
            elif col.lower() in ['name', 'category', 'label', 'type']:
                names_col = col
        
        if not values_col:
            values_col = df.columns[-1]  # Last column as values
        if not names_col:
            names_col = df.columns[0]   # First column as names
        
        fig = px.pie(
            df,
            values=values_col,
            names=names_col,
            title=config.title,
            color_discrete_sequence=colors,
            hole=config.styling.get("hole_size", 0)
        )
        
        # Show values if requested
        if config.styling.get("show_values", True):
            fig.update_traces(textposition='inside', textinfo='percent+label')
        
        fig.update_layout(
            font=dict(family="Arial, sans-serif", size=12),
            showlegend=True,
            margin=dict(l=40, r=40, t=60, b=40)
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id=f"viz_{config.viz_id}")
    
    async def _create_scatter_plot(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create interactive scatter plot"""
        
        if not data:
            return "<p>No data available for scatter plot</p>"
        
        df = pd.DataFrame(data)
        colors = self._get_color_palette(config.styling.get("color_palette", "government"))
        
        fig = px.scatter(
            df,
            x=config.x_axis,
            y=config.y_axis,
            color=config.color_field,
            size=config.size_field,
            title=config.title,
            color_discrete_sequence=colors
        )
        
        fig.update_layout(
            font=dict(family="Arial, sans-serif", size=12),
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            showlegend=True,
            margin=dict(l=40, r=40, t=60, b=40)
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id=f"viz_{config.viz_id}")
    
    async def _create_histogram(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create interactive histogram"""
        
        if not data:
            return "<p>No data available for histogram</p>"
        
        df = pd.DataFrame(data)
        colors = self._get_color_palette(config.styling.get("color_palette", "government"))
        
        fig = px.histogram(
            df,
            x=config.x_axis,
            color=config.color_field,
            title=config.title,
            nbins=config.styling.get("bins", 20),
            color_discrete_sequence=colors
        )
        
        fig.update_layout(
            font=dict(family="Arial, sans-serif", size=12),
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            showlegend=True,
            margin=dict(l=40, r=40, t=60, b=40)
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id=f"viz_{config.viz_id}")
    
    async def _create_heatmap(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create interactive heatmap"""
        
        if not data:
            return "<p>No data available for heatmap</p>"
        
        df = pd.DataFrame(data)
        
        # Create pivot table for heatmap
        if config.x_axis and config.y_axis and config.color_field:
            pivot_df = df.pivot_table(
                values=config.color_field,
                index=config.y_axis,
                columns=config.x_axis,
                aggfunc='mean'
            )
        else:
            # Use correlation matrix if no specific fields
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            if len(numeric_cols) > 1:
                pivot_df = df[numeric_cols].corr()
            else:
                return "<p>Insufficient numeric data for heatmap</p>"
        
        colorscale = config.styling.get("colorscale", "Blues")
        show_scale = config.styling.get("show_scale", True)
        
        fig = px.imshow(
            pivot_df,
            title=config.title,
            color_continuous_scale=colorscale,
            aspect="auto"
        )
        
        if not show_scale:
            fig.update_layout(coloraxis_showscale=False)
        
        fig.update_layout(
            font=dict(family="Arial, sans-serif", size=12),
            margin=dict(l=40, r=40, t=60, b=40)
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id=f"viz_{config.viz_id}")
    
    async def _create_treemap(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create interactive treemap"""
        
        if not data:
            return "<p>No data available for treemap</p>"
        
        df = pd.DataFrame(data)
        colors = self._get_color_palette(config.styling.get("color_palette", "government"))
        
        # Determine path columns
        path_cols = config.group_by if config.group_by else [df.columns[0]]
        values_col = None
        
        for col in df.columns:
            if col.lower() in ['count', 'value', 'amount', 'size']:
                values_col = col
                break
        
        if not values_col:
            values_col = df.columns[-1]
        
        fig = px.treemap(
            df,
            path=path_cols,
            values=values_col,
            title=config.title,
            color_discrete_sequence=colors
        )
        
        fig.update_layout(
            font=dict(family="Arial, sans-serif", size=12),
            margin=dict(l=10, r=10, t=60, b=10)
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id=f"viz_{config.viz_id}")
    
    async def _create_sunburst(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create interactive sunburst chart"""
        
        if not data:
            return "<p>No data available for sunburst</p>"
        
        df = pd.DataFrame(data)
        colors = self._get_color_palette(config.styling.get("color_palette", "government"))
        
        # Determine path columns
        path_cols = config.group_by if config.group_by else [df.columns[0]]
        values_col = None
        
        for col in df.columns:
            if col.lower() in ['count', 'value', 'amount', 'size']:
                values_col = col
                break
        
        if not values_col:
            values_col = df.columns[-1]
        
        fig = px.sunburst(
            df,
            path=path_cols,
            values=values_col,
            title=config.title,
            color_discrete_sequence=colors
        )
        
        fig.update_layout(
            font=dict(family="Arial, sans-serif", size=12),
            margin=dict(l=10, r=10, t=60, b=10)
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id=f"viz_{config.viz_id}")
    
    async def _create_wordcloud(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create word cloud visualization"""
        
        if not data:
            return "<p>No data available for word cloud</p>"
        
        df = pd.DataFrame(data)
        
        # Find text and frequency columns
        text_col = None
        freq_col = None
        
        for col in df.columns:
            if col.lower() in ['word', 'keyword', 'text', 'term']:
                text_col = col
            elif col.lower() in ['count', 'frequency', 'value', 'weight']:
                freq_col = col
        
        if not text_col:
            text_col = df.columns[0]
        if not freq_col:
            freq_col = df.columns[-1]
        
        # Create word frequency dictionary
        word_freq = dict(zip(df[text_col], df[freq_col]))
        
        # Generate word cloud
        max_words = config.styling.get("max_words", 100)
        background_color = config.styling.get("background_color", "white")
        
        wordcloud = WordCloud(
            width=800,
            height=400,
            max_words=max_words,
            background_color=background_color,
            colormap=config.styling.get("color_palette", "viridis")
        ).generate_from_frequencies(word_freq)
        
        # Convert to base64 image
        img_buffer = io.BytesIO()
        wordcloud.to_image().save(img_buffer, format='PNG')
        img_str = base64.b64encode(img_buffer.getvalue()).decode()
        
        # Create HTML
        html = f"""
        <div id="viz_{config.viz_id}" style="text-align: center;">
            <h3>{config.title}</h3>
            <img src="data:image/png;base64,{img_str}" 
                 alt="Word Cloud" style="max-width: 100%; height: auto;">
        </div>
        """
        
        return html
    
    async def _create_network_graph(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create network graph visualization"""
        
        if not data:
            return "<p>No data available for network graph</p>"
        
        df = pd.DataFrame(data)
        
        # Create NetworkX graph
        G = nx.Graph()
        
        # Add edges
        for _, row in df.iterrows():
            source = row.get('source', '')
            target = row.get('target', '')
            weight = row.get('weight', 1)
            
            if source and target:
                G.add_edge(source, target, weight=weight)
        
        if len(G.nodes()) == 0:
            return "<p>No valid network data found</p>"
        
        # Calculate positions
        layout = config.styling.get("layout", "spring")
        if layout == "spring":
            pos = nx.spring_layout(G, k=1, iterations=50)
        elif layout == "circular":
            pos = nx.circular_layout(G)
        else:
            pos = nx.random_layout(G)
        
        # Create Plotly traces
        edge_trace = []
        node_trace = []
        
        # Edges
        for edge in G.edges():
            x0, y0 = pos[edge[0]]
            x1, y1 = pos[edge[1]]
            edge_trace.extend([x0, x1, None])
            edge_trace.extend([y0, y1, None])
        
        # Nodes
        node_x = []
        node_y = []
        node_text = []
        node_size = []
        
        for node in G.nodes():
            x, y = pos[node]
            node_x.append(x)
            node_y.append(y)
            node_text.append(node)
            node_size.append(G.degree(node) * 5 + 10)  # Size based on degree
        
        # Create figure
        fig = go.Figure()
        
        # Add edges
        fig.add_trace(go.Scatter(
            x=edge_trace[::3],
            y=edge_trace[1::3],
            mode='lines',
            line=dict(width=1, color='lightgray'),
            hoverinfo='none',
            showlegend=False
        ))
        
        # Add nodes
        colors = self._get_color_palette(config.styling.get("color_palette", "regulatory"))
        
        fig.add_trace(go.Scatter(
            x=node_x,
            y=node_y,
            mode='markers+text',
            marker=dict(
                size=node_size,
                color=colors[0],
                line=dict(width=2, color='white')
            ),
            text=node_text,
            textposition="middle center",
            hoverinfo='text',
            showlegend=False
        ))
        
        fig.update_layout(
            title=config.title,
            showlegend=False,
            hovermode='closest',
            margin=dict(b=20, l=5, r=5, t=40),
            annotations=[
                dict(
                    text="Network connections between entities",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.005, y=-0.002,
                    xanchor='left', yanchor='bottom',
                    font=dict(color="gray", size=12)
                )
            ],
            xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
            yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id=f"viz_{config.viz_id}")
    
    async def _create_geographic_map(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create geographic map visualization"""
        
        if not data:
            return "<p>No data available for geographic map</p>"
        
        df = pd.DataFrame(data)
        
        # Create folium map centered on Brazil
        m = folium.Map(
            location=[-14.235, -51.9253],  # Center of Brazil
            zoom_start=4,
            tiles=config.styling.get("map_style", "OpenStreetMap")
        )
        
        # Add markers or choropleth based on data
        if 'latitude' in df.columns and 'longitude' in df.columns:
            # Point data
            for _, row in df.iterrows():
                lat = row['latitude']
                lon = row['longitude']
                popup_text = f"{row.get('name', 'Location')}: {row.get('count', 'N/A')}"
                
                folium.Marker(
                    [lat, lon],
                    popup=popup_text,
                    tooltip=popup_text
                ).add_to(m)
        
        else:
            # Regional data - create a simple visualization
            # This would need proper geographic data for Brazilian states/regions
            for _, row in df.iterrows():
                region = row.get('region', 'Unknown')
                count = row.get('count', 0)
                
                # Simple marker placement (would need real coordinates)
                if region == 'Federal':
                    lat, lon = -15.7942, -47.8822  # Brasília
                elif region == 'SP':
                    lat, lon = -23.5505, -46.6333   # São Paulo
                elif region == 'RJ':
                    lat, lon = -22.9068, -43.1729   # Rio de Janeiro
                elif region == 'MG':
                    lat, lon = -19.9167, -43.9345   # Belo Horizonte
                else:
                    lat, lon = -14.235, -51.9253    # Center of Brazil
                
                folium.CircleMarker(
                    [lat, lon],
                    radius=min(count / 10 + 5, 50),  # Size based on count
                    popup=f"{region}: {count} documents",
                    color='blue',
                    fill=True,
                    fillColor='lightblue'
                ).add_to(m)
        
        # Convert to HTML
        map_html = m._repr_html_()
        
        return f"""
        <div id="viz_{config.viz_id}">
            <h3>{config.title}</h3>
            {map_html}
        </div>
        """
    
    async def _create_timeline(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create timeline visualization"""
        
        if not data:
            return "<p>No data available for timeline</p>"
        
        df = pd.DataFrame(data)
        
        # Ensure date column exists
        date_col = config.x_axis or 'date'
        if date_col not in df.columns:
            return "<p>No date column found for timeline</p>"
        
        # Convert to datetime
        df[date_col] = pd.to_datetime(df[date_col])
        
        # Create timeline using scatter plot with custom styling
        colors = self._get_color_palette(config.styling.get("color_palette", "timeline"))
        
        fig = px.scatter(
            df,
            x=date_col,
            y=config.y_axis,
            color=config.color_field,
            size=config.size_field,
            title=config.title,
            color_discrete_sequence=colors
        )
        
        # Add trend line if requested
        if config.styling.get("show_trend", False):
            fig.add_scatter(
                x=df[date_col],
                y=df[config.y_axis].rolling(window=7).mean(),
                mode='lines',
                name='Trend',
                line=dict(color='red', dash='dash')
            )
        
        fig.update_layout(
            font=dict(family="Arial, sans-serif", size=12),
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            showlegend=True,
            margin=dict(l=40, r=40, t=60, b=40)
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id=f"viz_{config.viz_id}")
    
    async def _create_sankey_diagram(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create Sankey diagram"""
        
        if not data:
            return "<p>No data available for Sankey diagram</p>"
        
        df = pd.DataFrame(data)
        
        # Create nodes and links for Sankey
        all_nodes = set()
        links = []
        
        for _, row in df.iterrows():
            source = row.get('source', '')
            target = row.get('target', '')
            value = row.get('value', 1)
            
            if source and target:
                all_nodes.add(source)
                all_nodes.add(target)
                links.append((source, target, value))
        
        # Create node list
        node_list = list(all_nodes)
        node_dict = {node: i for i, node in enumerate(node_list)}
        
        # Create Sankey data
        sankey_data = {
            'node': {
                'label': node_list,
                'color': self._get_color_palette(config.styling.get("color_palette", "government"))[:len(node_list)]
            },
            'link': {
                'source': [node_dict[link[0]] for link in links],
                'target': [node_dict[link[1]] for link in links],
                'value': [link[2] for link in links]
            }
        }
        
        fig = go.Figure(data=[go.Sankey(**sankey_data)])
        
        fig.update_layout(
            title_text=config.title,
            font_size=12,
            margin=dict(l=40, r=40, t=60, b=40)
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id=f"viz_{config.viz_id}")
    
    async def _create_bubble_chart(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create bubble chart"""
        
        if not data:
            return "<p>No data available for bubble chart</p>"
        
        df = pd.DataFrame(data)
        colors = self._get_color_palette(config.styling.get("color_palette", "government"))
        
        fig = px.scatter(
            df,
            x=config.x_axis,
            y=config.y_axis,
            size=config.size_field,
            color=config.color_field,
            hover_name=df.columns[0],
            title=config.title,
            color_discrete_sequence=colors
        )
        
        fig.update_layout(
            font=dict(family="Arial, sans-serif", size=12),
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            showlegend=True,
            margin=dict(l=40, r=40, t=60, b=40)
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id=f"viz_{config.viz_id}")
    
    async def _create_violin_plot(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create violin plot"""
        
        if not data:
            return "<p>No data available for violin plot</p>"
        
        df = pd.DataFrame(data)
        colors = self._get_color_palette(config.styling.get("color_palette", "government"))
        
        fig = px.violin(
            df,
            x=config.x_axis,
            y=config.y_axis,
            color=config.color_field,
            title=config.title,
            color_discrete_sequence=colors
        )
        
        fig.update_layout(
            font=dict(family="Arial, sans-serif", size=12),
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            showlegend=True,
            margin=dict(l=40, r=40, t=60, b=40)
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id=f"viz_{config.viz_id}")
    
    async def _create_box_plot(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create box plot"""
        
        if not data:
            return "<p>No data available for box plot</p>"
        
        df = pd.DataFrame(data)
        colors = self._get_color_palette(config.styling.get("color_palette", "government"))
        
        fig = px.box(
            df,
            x=config.x_axis,
            y=config.y_axis,
            color=config.color_field,
            title=config.title,
            color_discrete_sequence=colors
        )
        
        fig.update_layout(
            font=dict(family="Arial, sans-serif", size=12),
            plot_bgcolor='rgba(0,0,0,0)',
            paper_bgcolor='rgba(0,0,0,0)',
            showlegend=True,
            margin=dict(l=40, r=40, t=60, b=40)
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id=f"viz_{config.viz_id}")
    
    async def _create_radar_chart(self, data: List[Dict], config: VisualizationConfig) -> str:
        """Create radar chart"""
        
        if not data:
            return "<p>No data available for radar chart</p>"
        
        df = pd.DataFrame(data)
        
        # Create radar chart using Plotly
        fig = go.Figure()
        
        # Get numeric columns for radar
        numeric_cols = df.select_dtypes(include=[np.number]).columns[:6]  # Limit to 6 dimensions
        
        if len(numeric_cols) < 3:
            return "<p>Need at least 3 numeric dimensions for radar chart</p>"
        
        # Add traces for each row (or category)
        colors = self._get_color_palette(config.styling.get("color_palette", "government"))
        
        if config.color_field and config.color_field in df.columns:
            # Multiple series
            for i, (category, group) in enumerate(df.groupby(config.color_field)):
                values = group[numeric_cols].mean().tolist()
                values.append(values[0])  # Close the radar
                
                fig.add_trace(go.Scatterpolar(
                    r=values,
                    theta=list(numeric_cols) + [numeric_cols[0]],
                    fill='toself',
                    name=str(category),
                    line_color=colors[i % len(colors)]
                ))
        else:
            # Single series
            values = df[numeric_cols].mean().tolist()
            values.append(values[0])  # Close the radar
            
            fig.add_trace(go.Scatterpolar(
                r=values,
                theta=list(numeric_cols) + [numeric_cols[0]],
                fill='toself',
                name='Data',
                line_color=colors[0]
            ))
        
        fig.update_layout(
            polar=dict(
                radialaxis=dict(visible=True)
            ),
            title=config.title,
            showlegend=True,
            margin=dict(l=40, r=40, t=60, b=40)
        )
        
        return fig.to_html(include_plotlyjs='cdn', div_id=f"viz_{config.viz_id}")
    
    def _get_color_palette(self, palette_name: str) -> List[str]:
        """Get color palette by name"""
        return self.color_palettes.get(palette_name, self.color_palettes["government"])
    
    async def _save_visualization(self, config: VisualizationConfig, data: List[Dict], chart_html: str) -> None:
        """Save visualization to database"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO visualizations 
                (viz_id, title, type, configuration, data_cache, last_updated, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (viz_id)
                DO UPDATE SET
                    configuration = $4, data_cache = $5, last_updated = $6
            """, config.viz_id, config.title, config.type.value,
                json.dumps(config.to_dict()), json.dumps(data),
                datetime.now(), datetime.now())
        
        finally:
            await conn.close()
    
    async def create_dashboard(self, dashboard_config: DashboardConfig) -> str:
        """Create interactive dashboard with multiple visualizations"""
        
        # Generate individual visualizations
        visualization_htmls = {}
        for viz_config in dashboard_config.visualizations:
            try:
                html = await self.create_visualization(viz_config)
                visualization_htmls[viz_config.viz_id] = html
            except Exception as e:
                logger.error(f"Failed to create visualization {viz_config.viz_id}: {e}")
                visualization_htmls[viz_config.viz_id] = f"<p>Error: {str(e)}</p>"
        
        # Create dashboard HTML
        dashboard_html = await self._render_dashboard(dashboard_config, visualization_htmls)
        
        # Save dashboard
        await self._save_dashboard(dashboard_config, dashboard_html)
        
        # Cache dashboard
        self.dashboard_cache[dashboard_config.dashboard_id] = {
            "config": dashboard_config.to_dict(),
            "html": dashboard_html,
            "last_updated": datetime.now()
        }
        
        return dashboard_html
    
    async def _render_dashboard(self, config: DashboardConfig, visualizations: Dict[str, str]) -> str:
        """Render complete dashboard HTML"""
        
        # Dashboard CSS
        css = """
        <style>
            .dashboard {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .dashboard-header {
                background: linear-gradient(135deg, #1565c0, #0d47a1);
                color: white;
                padding: 20px;
                border-radius: 10px;
                margin-bottom: 20px;
                box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            }
            .dashboard-title {
                margin: 0;
                font-size: 2.5em;
                font-weight: 300;
            }
            .dashboard-description {
                margin: 10px 0 0 0;
                opacity: 0.9;
                font-size: 1.1em;
            }
            .visualization-grid {
                display: grid;
                gap: 20px;
                margin-bottom: 20px;
            }
            .visualization-card {
                background: white;
                border-radius: 10px;
                padding: 20px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                transition: transform 0.2s ease;
            }
            .visualization-card:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 20px rgba(0,0,0,0.15);
            }
            .grid-single-column { grid-template-columns: 1fr; }
            .grid-two-column { grid-template-columns: 1fr 1fr; }
            .grid-three-column { grid-template-columns: 1fr 1fr 1fr; }
            .grid-layout { grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); }
            .dashboard-footer {
                text-align: center;
                padding: 20px;
                color: #666;
                border-top: 1px solid #ddd;
                margin-top: 40px;
            }
            @media (max-width: 768px) {
                .visualization-grid {
                    grid-template-columns: 1fr !important;
                }
                .dashboard {
                    padding: 10px;
                }
            }
        </style>
        """
        
        # Grid CSS class based on layout
        layout_class = {
            DashboardLayout.SINGLE_COLUMN: "grid-single-column",
            DashboardLayout.TWO_COLUMN: "grid-two-column", 
            DashboardLayout.THREE_COLUMN: "grid-three-column",
            DashboardLayout.GRID: "grid-layout",
            DashboardLayout.MASONRY: "grid-layout",
            DashboardLayout.CUSTOM: "grid-layout"
        }.get(config.layout, "grid-layout")
        
        # Generate visualization cards
        viz_cards = []
        for viz_config in sorted(config.visualizations, key=lambda x: x.viz_id):
            viz_html = visualizations.get(viz_config.viz_id, "<p>Visualization not available</p>")
            
            card_html = f"""
            <div class="visualization-card" id="card_{viz_config.viz_id}">
                {viz_html}
            </div>
            """
            viz_cards.append(card_html)
        
        # Complete dashboard HTML
        dashboard_html = f"""
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>{config.title}</title>
            {css}
            <script src="https://cdn.plot.ly/plotly-latest.min.js"></script>
        </head>
        <body>
            <div class="dashboard">
                <div class="dashboard-header">
                    <h1 class="dashboard-title">{config.title}</h1>
                    <p class="dashboard-description">{config.description}</p>
                    <p style="font-size: 0.9em; opacity: 0.8;">
                        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
                        {' | Auto-refresh: ' + str(config.refresh_interval) + 's' if config.auto_refresh else ''}
                    </p>
                </div>
                
                <div class="visualization-grid {layout_class}">
                    {''.join(viz_cards)}
                </div>
                
                <div class="dashboard-footer">
                    <p>Monitor Legislativo v4 - Advanced Data Visualization Engine</p>
                    <p>Dashboard ID: {config.dashboard_id}</p>
                </div>
            </div>
            
            <script>
                // Auto-refresh functionality
                {f'''
                setInterval(function() {{
                    window.location.reload();
                }}, {config.refresh_interval * 1000});
                ''' if config.auto_refresh else ''}
                
                // Responsive behavior
                window.addEventListener('resize', function() {{
                    // Trigger plotly relayout for responsive charts
                    var plotDivs = document.querySelectorAll('[id^="viz_"]');
                    plotDivs.forEach(function(div) {{
                        if (window.Plotly) {{
                            Plotly.Plots.resize(div);
                        }}
                    }});
                }});
            </script>
        </body>
        </html>
        """
        
        return dashboard_html
    
    async def _save_dashboard(self, config: DashboardConfig, html: str) -> None:
        """Save dashboard to database"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO dashboards 
                (dashboard_id, title, description, layout, configuration, 
                 created_by, is_public, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
                ON CONFLICT (dashboard_id)
                DO UPDATE SET
                    title = $2, description = $3, configuration = $5,
                    updated_at = $9
            """, config.dashboard_id, config.title, config.description,
                config.layout.value, json.dumps(config.to_dict()),
                config.created_by, config.is_public, datetime.now(), datetime.now())
            
            # Save dashboard HTML to file
            file_path = self.output_path / f"dashboard_{config.dashboard_id}.html"
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html)
                
        finally:
            await conn.close()
    
    async def get_dashboard(self, dashboard_id: str) -> Optional[str]:
        """Get dashboard HTML"""
        
        # Check cache first
        if dashboard_id in self.dashboard_cache:
            cached = self.dashboard_cache[dashboard_id]
            # Check if cache is still valid (15 minutes)
            if (datetime.now() - cached["last_updated"]).seconds < 900:
                return cached["html"]
        
        # Load from file
        file_path = self.output_path / f"dashboard_{dashboard_id}.html"
        if file_path.exists():
            with open(file_path, 'r', encoding='utf-8') as f:
                return f.read()
        
        return None
    
    async def calculate_data_metrics(self, data: List[Dict]) -> DataMetrics:
        """Calculate comprehensive metrics from data"""
        
        if not data:
            return DataMetrics(
                total_records=0,
                unique_values={},
                null_counts={},
                data_types={},
                numeric_stats={},
                categorical_stats={}
            )
        
        df = pd.DataFrame(data)
        
        # Basic metrics
        total_records = len(df)
        unique_values = {col: df[col].nunique() for col in df.columns}
        null_counts = {col: df[col].isnull().sum() for col in df.columns}
        data_types = {col: str(df[col].dtype) for col in df.columns}
        
        # Numeric statistics
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        numeric_stats = {}
        for col in numeric_cols:
            numeric_stats[col] = {
                "mean": float(df[col].mean()),
                "median": float(df[col].median()),
                "std": float(df[col].std()),
                "min": float(df[col].min()),
                "max": float(df[col].max()),
                "q1": float(df[col].quantile(0.25)),
                "q3": float(df[col].quantile(0.75))
            }
        
        # Categorical statistics
        categorical_cols = df.select_dtypes(include=['object']).columns
        categorical_stats = {}
        for col in categorical_cols:
            value_counts = df[col].value_counts().head(10)
            categorical_stats[col] = {str(k): int(v) for k, v in value_counts.items()}
        
        # Correlations for numeric data
        correlations = None
        if len(numeric_cols) > 1:
            corr_matrix = df[numeric_cols].corr()
            correlations = {
                col1: {col2: float(corr_matrix.loc[col1, col2]) 
                       for col2 in numeric_cols}
                for col1 in numeric_cols
            }
        
        return DataMetrics(
            total_records=total_records,
            unique_values=unique_values,
            null_counts=null_counts,
            data_types=data_types,
            numeric_stats=numeric_stats,
            categorical_stats=categorical_stats,
            correlations=correlations
        )

# Factory function for easy creation
async def create_visualization_engine(db_config: Dict[str, str], output_path: str = "/tmp/visualizations") -> AdvancedVisualizationEngine:
    """Create and initialize advanced visualization engine"""
    engine = AdvancedVisualizationEngine(db_config, output_path)
    await engine.initialize()
    return engine

# Export main classes
__all__ = [
    'AdvancedVisualizationEngine',
    'VisualizationConfig',
    'DashboardConfig',
    'DataMetrics',
    'VisualizationType',
    'DashboardLayout',
    'InteractionType',
    'create_visualization_engine'
]