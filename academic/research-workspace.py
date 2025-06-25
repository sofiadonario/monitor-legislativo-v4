# Academic Research Workspace for Monitor Legislativo v4
# Phase 5 Week 17: Collaborative research environment for Brazilian legislative studies
# Advanced tools for academic research, collaboration, and project management

import asyncio
import asyncpg
import json
import logging
import uuid
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)

class ProjectStatus(Enum):
    """Research project status"""
    PLANNING = "planning"
    ACTIVE = "active"
    ON_HOLD = "on_hold"
    COMPLETED = "completed"
    ARCHIVED = "archived"

class CollaborationRole(Enum):
    """Collaboration roles in research projects"""
    OWNER = "owner"                    # Project creator and owner
    PRINCIPAL_INVESTIGATOR = "pi"      # Principal investigator
    CO_INVESTIGATOR = "co_investigator" # Co-investigator
    RESEARCH_ASSISTANT = "research_assistant"  # Research assistant
    STUDENT = "student"                # Graduate/undergraduate student
    COLLABORATOR = "collaborator"      # External collaborator
    REVIEWER = "reviewer"              # Peer reviewer
    VIEWER = "viewer"                  # Read-only access

class DocumentAnnotationType(Enum):
    """Types of document annotations"""
    HIGHLIGHT = "highlight"
    NOTE = "note"
    QUESTION = "question"
    CITATION = "citation"
    KEYWORD = "keyword"
    METHODOLOGY = "methodology"
    FINDING = "finding"
    CONTRADICTION = "contradiction"

class ResearchPhase(Enum):
    """Research project phases"""
    LITERATURE_REVIEW = "literature_review"
    DATA_COLLECTION = "data_collection"
    ANALYSIS = "analysis"
    WRITING = "writing"
    REVISION = "revision"
    PUBLICATION = "publication"

@dataclass
class ResearchProject:
    """Academic research project"""
    project_id: str
    title: str
    description: str
    research_question: str
    methodology: str
    status: ProjectStatus
    owner_id: str
    created_at: datetime
    updated_at: datetime
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    current_phase: Optional[ResearchPhase] = None
    keywords: List[str] = field(default_factory=list)
    funding_source: Optional[str] = None
    institution: Optional[str] = None
    ethical_approval: Optional[str] = None
    data_management_plan: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['status'] = self.status.value
        if self.current_phase:
            result['current_phase'] = self.current_phase.value
        result['created_at'] = self.created_at.isoformat()
        result['updated_at'] = self.updated_at.isoformat()
        if self.start_date:
            result['start_date'] = self.start_date.isoformat()
        if self.end_date:
            result['end_date'] = self.end_date.isoformat()
        return result

@dataclass
class ProjectCollaborator:
    """Project collaborator information"""
    collaboration_id: str
    project_id: str
    user_id: str
    role: CollaborationRole
    permissions: List[str]
    added_at: datetime
    added_by: str
    is_active: bool = True
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['role'] = self.role.value
        result['added_at'] = self.added_at.isoformat()
        return result

@dataclass
class DocumentAnnotation:
    """Document annotation for research"""
    annotation_id: str
    project_id: str
    document_id: str
    user_id: str
    annotation_type: DocumentAnnotationType
    content: str
    document_selection: Optional[str] = None  # Selected text
    position_data: Optional[Dict[str, Any]] = None  # Position in document
    tags: List[str] = field(default_factory=list)
    is_private: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['annotation_type'] = self.annotation_type.value
        result['created_at'] = self.created_at.isoformat()
        result['updated_at'] = self.updated_at.isoformat()
        return result

@dataclass
class ResearchNote:
    """Research note within a project"""
    note_id: str
    project_id: str
    user_id: str
    title: str
    content: str
    note_type: str  # "observation", "hypothesis", "methodology", "finding"
    linked_documents: List[str] = field(default_factory=list)
    linked_annotations: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    is_shared: bool = False
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['created_at'] = self.created_at.isoformat()
        result['updated_at'] = self.updated_at.isoformat()
        return result

@dataclass
class ResearchTimeline:
    """Research project timeline entry"""
    timeline_id: str
    project_id: str
    user_id: str
    event_type: str  # "milestone", "task", "deadline", "note"
    title: str
    description: str
    scheduled_date: datetime
    completed_date: Optional[datetime] = None
    is_completed: bool = False
    priority: str = "medium"  # low, medium, high
    created_at: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['scheduled_date'] = self.scheduled_date.isoformat()
        if self.completed_date:
            result['completed_date'] = self.completed_date.isoformat()
        result['created_at'] = self.created_at.isoformat()
        return result

class ResearchWorkspaceManager:
    """
    Comprehensive research workspace for academic collaboration on Brazilian legislative studies
    
    Features:
    - Project management and collaboration
    - Document annotation and analysis
    - Research note-taking and organization
    - Timeline and milestone tracking
    - Citation and bibliography management
    - Data export and integration
    - Academic integrity and version control
    """
    
    def __init__(self, db_config: Dict[str, str]):
        self.db_config = db_config
        
        # Default permission sets for roles
        self.role_permissions = {
            CollaborationRole.OWNER: [
                "project_edit", "project_delete", "collaborate_manage", 
                "document_annotate", "note_create", "timeline_manage", "export_data"
            ],
            CollaborationRole.PRINCIPAL_INVESTIGATOR: [
                "project_edit", "collaborate_manage", "document_annotate", 
                "note_create", "timeline_manage", "export_data"
            ],
            CollaborationRole.CO_INVESTIGATOR: [
                "project_view", "document_annotate", "note_create", 
                "timeline_view", "export_data"
            ],
            CollaborationRole.RESEARCH_ASSISTANT: [
                "project_view", "document_annotate", "note_create", "timeline_view"
            ],
            CollaborationRole.STUDENT: [
                "project_view", "document_annotate", "note_create"
            ],
            CollaborationRole.COLLABORATOR: [
                "project_view", "document_annotate", "note_create"
            ],
            CollaborationRole.REVIEWER: [
                "project_view", "document_view", "note_view"
            ],
            CollaborationRole.VIEWER: [
                "project_view", "document_view"
            ]
        }
    
    async def initialize(self) -> None:
        """Initialize research workspace tables"""
        await self._create_workspace_tables()
        logger.info("Research workspace initialized")
    
    async def _create_workspace_tables(self) -> None:
        """Create research workspace database tables"""
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Research projects table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS research_projects (
                    project_id VARCHAR(36) PRIMARY KEY,
                    title VARCHAR(500) NOT NULL,
                    description TEXT NOT NULL,
                    research_question TEXT NOT NULL,
                    methodology TEXT NOT NULL,
                    status VARCHAR(20) NOT NULL DEFAULT 'planning',
                    owner_id VARCHAR(100) NOT NULL,
                    current_phase VARCHAR(30) NULL,
                    keywords JSONB DEFAULT '[]'::jsonb,
                    funding_source VARCHAR(200) NULL,
                    institution VARCHAR(200) NULL,
                    ethical_approval VARCHAR(100) NULL,
                    data_management_plan TEXT NULL,
                    start_date TIMESTAMP NULL,
                    end_date TIMESTAMP NULL,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Project collaborators table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS project_collaborators (
                    collaboration_id VARCHAR(36) PRIMARY KEY,
                    project_id VARCHAR(36) NOT NULL REFERENCES research_projects(project_id) ON DELETE CASCADE,
                    user_id VARCHAR(100) NOT NULL,
                    role VARCHAR(30) NOT NULL,
                    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
                    is_active BOOLEAN DEFAULT TRUE,
                    added_at TIMESTAMP DEFAULT NOW(),
                    added_by VARCHAR(100) NOT NULL
                );
            """)
            
            # Document annotations table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS document_annotations (
                    annotation_id VARCHAR(36) PRIMARY KEY,
                    project_id VARCHAR(36) NOT NULL REFERENCES research_projects(project_id) ON DELETE CASCADE,
                    document_id VARCHAR(100) NOT NULL,
                    user_id VARCHAR(100) NOT NULL,
                    annotation_type VARCHAR(20) NOT NULL,
                    content TEXT NOT NULL,
                    document_selection TEXT NULL,
                    position_data JSONB NULL,
                    tags JSONB DEFAULT '[]'::jsonb,
                    is_private BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Research notes table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS research_notes (
                    note_id VARCHAR(36) PRIMARY KEY,
                    project_id VARCHAR(36) NOT NULL REFERENCES research_projects(project_id) ON DELETE CASCADE,
                    user_id VARCHAR(100) NOT NULL,
                    title VARCHAR(500) NOT NULL,
                    content TEXT NOT NULL,
                    note_type VARCHAR(30) NOT NULL,
                    linked_documents JSONB DEFAULT '[]'::jsonb,
                    linked_annotations JSONB DEFAULT '[]'::jsonb,
                    tags JSONB DEFAULT '[]'::jsonb,
                    is_shared BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT NOW(),
                    updated_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Research timeline table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS research_timeline (
                    timeline_id VARCHAR(36) PRIMARY KEY,
                    project_id VARCHAR(36) NOT NULL REFERENCES research_projects(project_id) ON DELETE CASCADE,
                    user_id VARCHAR(100) NOT NULL,
                    event_type VARCHAR(20) NOT NULL,
                    title VARCHAR(300) NOT NULL,
                    description TEXT NOT NULL,
                    scheduled_date TIMESTAMP NOT NULL,
                    completed_date TIMESTAMP NULL,
                    is_completed BOOLEAN DEFAULT FALSE,
                    priority VARCHAR(10) DEFAULT 'medium',
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Project documents table (links documents to projects)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS project_documents (
                    link_id VARCHAR(36) PRIMARY KEY,
                    project_id VARCHAR(36) NOT NULL REFERENCES research_projects(project_id) ON DELETE CASCADE,
                    document_id VARCHAR(100) NOT NULL,
                    added_by VARCHAR(100) NOT NULL,
                    relevance_score FLOAT DEFAULT 0.0,
                    notes TEXT NULL,
                    added_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Research exports table (track data exports)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS research_exports (
                    export_id VARCHAR(36) PRIMARY KEY,
                    project_id VARCHAR(36) NOT NULL REFERENCES research_projects(project_id) ON DELETE CASCADE,
                    user_id VARCHAR(100) NOT NULL,
                    export_type VARCHAR(30) NOT NULL,
                    export_format VARCHAR(20) NOT NULL,
                    file_path VARCHAR(500) NULL,
                    metadata JSONB DEFAULT '{}'::jsonb,
                    created_at TIMESTAMP DEFAULT NOW()
                );
            """)
            
            # Create indexes for performance
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_projects_owner ON research_projects(owner_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_projects_status ON research_projects(status);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_collaborators_project ON project_collaborators(project_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_collaborators_user ON project_collaborators(user_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_annotations_project ON document_annotations(project_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_annotations_document ON document_annotations(document_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_notes_project ON research_notes(project_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_project ON research_timeline(project_id);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_timeline_date ON research_timeline(scheduled_date);")
            await conn.execute("CREATE INDEX IF NOT EXISTS idx_project_docs_project ON project_documents(project_id);")
            
            logger.info("Research workspace tables created successfully")
        
        finally:
            await conn.close()
    
    async def create_project(self, title: str, description: str, research_question: str,
                           methodology: str, owner_id: str, keywords: List[str] = None,
                           funding_source: str = None, institution: str = None) -> str:
        """Create a new research project"""
        
        project_id = str(uuid.uuid4())
        
        project = ResearchProject(
            project_id=project_id,
            title=title,
            description=description,
            research_question=research_question,
            methodology=methodology,
            status=ProjectStatus.PLANNING,
            owner_id=owner_id,
            created_at=datetime.now(),
            updated_at=datetime.now(),
            keywords=keywords or [],
            funding_source=funding_source,
            institution=institution
        )
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO research_projects 
                (project_id, title, description, research_question, methodology, status, 
                 owner_id, keywords, funding_source, institution, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            """, project_id, title, description, research_question, methodology,
                project.status.value, owner_id, json.dumps(keywords or []),
                funding_source, institution, project.created_at, project.updated_at)
            
            # Add owner as principal investigator
            await self.add_collaborator(
                project_id=project_id,
                user_id=owner_id,
                role=CollaborationRole.OWNER,
                added_by=owner_id
            )
            
            logger.info(f"Research project created: {project_id} - {title}")
            return project_id
        
        finally:
            await conn.close()
    
    async def add_collaborator(self, project_id: str, user_id: str, 
                             role: CollaborationRole, added_by: str,
                             custom_permissions: List[str] = None) -> str:
        """Add collaborator to research project"""
        
        collaboration_id = str(uuid.uuid4())
        permissions = custom_permissions or self.role_permissions.get(role, [])
        
        collaborator = ProjectCollaborator(
            collaboration_id=collaboration_id,
            project_id=project_id,
            user_id=user_id,
            role=role,
            permissions=permissions,
            added_at=datetime.now(),
            added_by=added_by
        )
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO project_collaborators 
                (collaboration_id, project_id, user_id, role, permissions, added_at, added_by)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
            """, collaboration_id, project_id, user_id, role.value,
                json.dumps(permissions), collaborator.added_at, added_by)
            
            logger.info(f"Collaborator added: {user_id} to project {project_id} as {role.value}")
            return collaboration_id
        
        finally:
            await conn.close()
    
    async def annotate_document(self, project_id: str, document_id: str, user_id: str,
                              annotation_type: DocumentAnnotationType, content: str,
                              document_selection: str = None, position_data: Dict[str, Any] = None,
                              tags: List[str] = None, is_private: bool = False) -> str:
        """Add annotation to a document"""
        
        annotation_id = str(uuid.uuid4())
        
        annotation = DocumentAnnotation(
            annotation_id=annotation_id,
            project_id=project_id,
            document_id=document_id,
            user_id=user_id,
            annotation_type=annotation_type,
            content=content,
            document_selection=document_selection,
            position_data=position_data,
            tags=tags or [],
            is_private=is_private
        )
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO document_annotations 
                (annotation_id, project_id, document_id, user_id, annotation_type, 
                 content, document_selection, position_data, tags, is_private, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            """, annotation_id, project_id, document_id, user_id, annotation_type.value,
                content, document_selection, json.dumps(position_data) if position_data else None,
                json.dumps(tags or []), is_private, annotation.created_at, annotation.updated_at)
            
            logger.info(f"Document annotation created: {annotation_id}")
            return annotation_id
        
        finally:
            await conn.close()
    
    async def create_research_note(self, project_id: str, user_id: str, title: str,
                                 content: str, note_type: str, linked_documents: List[str] = None,
                                 linked_annotations: List[str] = None, tags: List[str] = None,
                                 is_shared: bool = False) -> str:
        """Create a research note"""
        
        note_id = str(uuid.uuid4())
        
        note = ResearchNote(
            note_id=note_id,
            project_id=project_id,
            user_id=user_id,
            title=title,
            content=content,
            note_type=note_type,
            linked_documents=linked_documents or [],
            linked_annotations=linked_annotations or [],
            tags=tags or [],
            is_shared=is_shared
        )
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO research_notes 
                (note_id, project_id, user_id, title, content, note_type, 
                 linked_documents, linked_annotations, tags, is_shared, created_at, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            """, note_id, project_id, user_id, title, content, note_type,
                json.dumps(linked_documents or []), json.dumps(linked_annotations or []),
                json.dumps(tags or []), is_shared, note.created_at, note.updated_at)
            
            logger.info(f"Research note created: {note_id} - {title}")
            return note_id
        
        finally:
            await conn.close()
    
    async def add_timeline_event(self, project_id: str, user_id: str, event_type: str,
                               title: str, description: str, scheduled_date: datetime,
                               priority: str = "medium") -> str:
        """Add event to project timeline"""
        
        timeline_id = str(uuid.uuid4())
        
        timeline_event = ResearchTimeline(
            timeline_id=timeline_id,
            project_id=project_id,
            user_id=user_id,
            event_type=event_type,
            title=title,
            description=description,
            scheduled_date=scheduled_date,
            priority=priority
        )
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO research_timeline 
                (timeline_id, project_id, user_id, event_type, title, description, 
                 scheduled_date, priority, created_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            """, timeline_id, project_id, user_id, event_type, title, description,
                scheduled_date, priority, timeline_event.created_at)
            
            logger.info(f"Timeline event added: {timeline_id} - {title}")
            return timeline_id
        
        finally:
            await conn.close()
    
    async def link_document_to_project(self, project_id: str, document_id: str,
                                     added_by: str, relevance_score: float = 0.0,
                                     notes: str = None) -> str:
        """Link a document to a research project"""
        
        link_id = str(uuid.uuid4())
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO project_documents 
                (link_id, project_id, document_id, added_by, relevance_score, notes, added_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT DO NOTHING
            """, link_id, project_id, document_id, added_by, relevance_score, notes, datetime.now())
            
            logger.info(f"Document linked to project: {document_id} -> {project_id}")
            return link_id
        
        finally:
            await conn.close()
    
    async def get_project_details(self, project_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive project details"""
        
        # Check user access
        if not await self._check_user_access(project_id, user_id, "project_view"):
            return None
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Get project data
            project_data = await conn.fetchrow("""
                SELECT * FROM research_projects WHERE project_id = $1
            """, project_id)
            
            if not project_data:
                return None
            
            # Get collaborators
            collaborators = await conn.fetch("""
                SELECT * FROM project_collaborators 
                WHERE project_id = $1 AND is_active = TRUE
            """, project_id)
            
            # Get recent annotations
            annotations = await conn.fetch("""
                SELECT * FROM document_annotations 
                WHERE project_id = $1 
                ORDER BY created_at DESC LIMIT 50
            """, project_id)
            
            # Get research notes
            notes = await conn.fetch("""
                SELECT * FROM research_notes 
                WHERE project_id = $1 AND (is_shared = TRUE OR user_id = $2)
                ORDER BY updated_at DESC
            """, project_id, user_id)
            
            # Get timeline events
            timeline = await conn.fetch("""
                SELECT * FROM research_timeline 
                WHERE project_id = $1 
                ORDER BY scheduled_date ASC
            """, project_id)
            
            # Get linked documents
            documents = await conn.fetch("""
                SELECT * FROM project_documents 
                WHERE project_id = $1 
                ORDER BY added_at DESC
            """, project_id)
            
            return {
                "project": dict(project_data),
                "collaborators": [dict(collab) for collab in collaborators],
                "annotations": [dict(ann) for ann in annotations],
                "notes": [dict(note) for note in notes],
                "timeline": [dict(event) for event in timeline],
                "documents": [dict(doc) for doc in documents]
            }
        
        finally:
            await conn.close()
    
    async def get_user_projects(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all projects accessible to a user"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            projects = await conn.fetch("""
                SELECT DISTINCT p.*, pc.role, pc.permissions
                FROM research_projects p
                JOIN project_collaborators pc ON p.project_id = pc.project_id
                WHERE pc.user_id = $1 AND pc.is_active = TRUE
                ORDER BY p.updated_at DESC
            """, user_id)
            
            return [dict(project) for project in projects]
        
        finally:
            await conn.close()
    
    async def search_annotations(self, project_id: str, user_id: str, query: str,
                               annotation_types: List[DocumentAnnotationType] = None,
                               tags: List[str] = None) -> List[Dict[str, Any]]:
        """Search annotations within a project"""
        
        if not await self._check_user_access(project_id, user_id, "project_view"):
            return []
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Build search query
            conditions = ["project_id = $1"]
            params = [project_id]
            param_count = 1
            
            # Add text search
            if query:
                param_count += 1
                conditions.append(f"(content ILIKE ${param_count} OR document_selection ILIKE ${param_count})")
                params.append(f"%{query}%")
            
            # Add annotation type filter
            if annotation_types:
                param_count += 1
                type_values = [at.value for at in annotation_types]
                conditions.append(f"annotation_type = ANY(${param_count})")
                params.append(type_values)
            
            # Add tag filter
            if tags:
                param_count += 1
                conditions.append(f"tags ?| ${param_count}")
                params.append(tags)
            
            # Add privacy filter
            param_count += 1
            conditions.append(f"(is_private = FALSE OR user_id = ${param_count})")
            params.append(user_id)
            
            where_clause = " AND ".join(conditions)
            
            annotations = await conn.fetch(f"""
                SELECT * FROM document_annotations 
                WHERE {where_clause}
                ORDER BY created_at DESC
                LIMIT 100
            """, *params)
            
            return [dict(ann) for ann in annotations]
        
        finally:
            await conn.close()
    
    async def generate_project_report(self, project_id: str, user_id: str,
                                    include_annotations: bool = True,
                                    include_notes: bool = True,
                                    include_timeline: bool = True) -> Dict[str, Any]:
        """Generate comprehensive project report"""
        
        if not await self._check_user_access(project_id, user_id, "export_data"):
            raise PermissionError("Insufficient permissions to generate report")
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            # Get project summary
            project_data = await conn.fetchrow("""
                SELECT * FROM research_projects WHERE project_id = $1
            """, project_id)
            
            if not project_data:
                raise ValueError("Project not found")
            
            report = {
                "project_info": dict(project_data),
                "generated_at": datetime.now().isoformat(),
                "generated_by": user_id,
                "statistics": {}
            }
            
            # Calculate statistics
            stats = {}
            
            # Document count
            doc_count = await conn.fetchval("""
                SELECT COUNT(*) FROM project_documents WHERE project_id = $1
            """, project_id)
            stats["total_documents"] = doc_count
            
            # Annotation count by type
            if include_annotations:
                annotation_stats = await conn.fetch("""
                    SELECT annotation_type, COUNT(*) as count
                    FROM document_annotations 
                    WHERE project_id = $1 
                    GROUP BY annotation_type
                """, project_id)
                stats["annotations_by_type"] = {row['annotation_type']: row['count'] for row in annotation_stats}
                
                # Get all annotations
                annotations = await conn.fetch("""
                    SELECT * FROM document_annotations 
                    WHERE project_id = $1 
                    ORDER BY created_at DESC
                """, project_id)
                report["annotations"] = [dict(ann) for ann in annotations]
            
            # Note count by type
            if include_notes:
                note_stats = await conn.fetch("""
                    SELECT note_type, COUNT(*) as count
                    FROM research_notes 
                    WHERE project_id = $1 
                    GROUP BY note_type
                """, project_id)
                stats["notes_by_type"] = {row['note_type']: row['count'] for row in note_stats}
                
                # Get all notes
                notes = await conn.fetch("""
                    SELECT * FROM research_notes 
                    WHERE project_id = $1 
                    ORDER BY created_at DESC
                """, project_id)
                report["notes"] = [dict(note) for note in notes]
            
            # Timeline statistics
            if include_timeline:
                timeline_stats = await conn.fetch("""
                    SELECT 
                        event_type,
                        COUNT(*) as total,
                        COUNT(*) FILTER (WHERE is_completed = TRUE) as completed
                    FROM research_timeline 
                    WHERE project_id = $1 
                    GROUP BY event_type
                """, project_id)
                stats["timeline_by_type"] = {
                    row['event_type']: {"total": row['total'], "completed": row['completed']}
                    for row in timeline_stats
                }
                
                # Get timeline events
                timeline = await conn.fetch("""
                    SELECT * FROM research_timeline 
                    WHERE project_id = $1 
                    ORDER BY scheduled_date ASC
                """, project_id)
                report["timeline"] = [dict(event) for event in timeline]
            
            # Collaborator count
            collab_count = await conn.fetchval("""
                SELECT COUNT(*) FROM project_collaborators 
                WHERE project_id = $1 AND is_active = TRUE
            """, project_id)
            stats["total_collaborators"] = collab_count
            
            report["statistics"] = stats
            
            return report
        
        finally:
            await conn.close()
    
    async def _check_user_access(self, project_id: str, user_id: str, required_permission: str) -> bool:
        """Check if user has required permission for project"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            collaborator = await conn.fetchrow("""
                SELECT permissions FROM project_collaborators 
                WHERE project_id = $1 AND user_id = $2 AND is_active = TRUE
            """, project_id, user_id)
            
            if not collaborator:
                return False
            
            permissions = json.loads(collaborator['permissions'])
            return required_permission in permissions
        
        finally:
            await conn.close()
    
    async def export_project_data(self, project_id: str, user_id: str, 
                                export_format: str = "json") -> str:
        """Export project data in various formats"""
        
        if not await self._check_user_access(project_id, user_id, "export_data"):
            raise PermissionError("Insufficient permissions to export data")
        
        # Generate comprehensive report
        report_data = await self.generate_project_report(
            project_id, user_id, True, True, True
        )
        
        export_id = str(uuid.uuid4())
        
        # Convert to requested format
        if export_format.lower() == "json":
            exported_data = json.dumps(report_data, indent=2, ensure_ascii=False)
        elif export_format.lower() == "csv":
            exported_data = self._convert_to_csv(report_data)
        else:
            raise ValueError(f"Unsupported export format: {export_format}")
        
        # Log export
        await self._log_export(project_id, user_id, "full_project", export_format, export_id)
        
        return exported_data
    
    def _convert_to_csv(self, report_data: Dict[str, Any]) -> str:
        """Convert report data to CSV format"""
        import csv
        import io
        
        output = io.StringIO()
        
        # Write project info
        writer = csv.writer(output)
        writer.writerow(["Project Information"])
        writer.writerow(["Title", report_data["project_info"]["title"]])
        writer.writerow(["Description", report_data["project_info"]["description"]])
        writer.writerow(["Status", report_data["project_info"]["status"]])
        writer.writerow([])
        
        # Write annotations
        if "annotations" in report_data:
            writer.writerow(["Annotations"])
            writer.writerow(["ID", "Type", "Content", "Document", "User", "Created"])
            for ann in report_data["annotations"]:
                writer.writerow([
                    ann["annotation_id"],
                    ann["annotation_type"],
                    ann["content"][:100] + "..." if len(ann["content"]) > 100 else ann["content"],
                    ann["document_id"],
                    ann["user_id"],
                    ann["created_at"]
                ])
            writer.writerow([])
        
        # Write notes
        if "notes" in report_data:
            writer.writerow(["Research Notes"])
            writer.writerow(["ID", "Title", "Type", "Content", "User", "Created"])
            for note in report_data["notes"]:
                writer.writerow([
                    note["note_id"],
                    note["title"],
                    note["note_type"],
                    note["content"][:100] + "..." if len(note["content"]) > 100 else note["content"],
                    note["user_id"],
                    note["created_at"]
                ])
        
        return output.getvalue()
    
    async def _log_export(self, project_id: str, user_id: str, export_type: str,
                        export_format: str, export_id: str) -> None:
        """Log data export for audit purposes"""
        
        conn = await asyncpg.connect(**self.db_config)
        
        try:
            await conn.execute("""
                INSERT INTO research_exports 
                (export_id, project_id, user_id, export_type, export_format, created_at)
                VALUES ($1, $2, $3, $4, $5, $6)
            """, export_id, project_id, user_id, export_type, export_format, datetime.now())
        
        finally:
            await conn.close()

# Factory function for easy creation
async def create_research_workspace(db_config: Dict[str, str]) -> ResearchWorkspaceManager:
    """Create and initialize research workspace manager"""
    workspace = ResearchWorkspaceManager(db_config)
    await workspace.initialize()
    return workspace

# Export main classes
__all__ = [
    'ResearchWorkspaceManager',
    'ResearchProject',
    'ProjectCollaborator',
    'DocumentAnnotation',
    'ResearchNote',
    'ResearchTimeline',
    'ProjectStatus',
    'CollaborationRole',
    'DocumentAnnotationType',
    'ResearchPhase',
    'create_research_workspace'
]