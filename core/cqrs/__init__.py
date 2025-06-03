"""
CQRS (Command Query Responsibility Segregation) for Monitor Legislativo v4
Separates read and write operations for complex queries

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

from .commands import (
    Command,
    CommandHandler,
    CommandBus,
    CreatePropositionCommand,
    UpdatePropositionCommand,
    DeletePropositionCommand,
    CreateAlertCommand,
    UpdateUserPreferencesCommand,
    command_bus
)

from .queries import (
    Query,
    QueryHandler,
    QueryBus,
    GetPropositionQuery,
    SearchPropositionsQuery,
    GetUserAlertsQuery,
    GetAnalyticsQuery,
    GetTrendingTopicsQuery,
    query_bus
)

from .events import (
    DomainEvent,
    EventStore,
    EventProjector,
    PropositionCreatedEvent,
    PropositionUpdatedEvent,
    UserActionEvent,
    event_store
)

from .projections import (
    Projection,
    ProjectionManager,
    PropositionSummaryProjection,
    UserActivityProjection,
    AnalyticsProjection,
    SearchIndexProjection,
    projection_manager
)

from .read_models import (
    ReadModel,
    PropositionReadModel,
    UserReadModel,
    AnalyticsReadModel,
    TrendingTopicsReadModel
)

__all__ = [
    # Commands
    "Command",
    "CommandHandler", 
    "CommandBus",
    "CreatePropositionCommand",
    "UpdatePropositionCommand",
    "DeletePropositionCommand",
    "CreateAlertCommand",
    "UpdateUserPreferencesCommand",
    "command_bus",
    
    # Queries
    "Query",
    "QueryHandler",
    "QueryBus", 
    "GetPropositionQuery",
    "SearchPropositionsQuery",
    "GetUserAlertsQuery",
    "GetAnalyticsQuery",
    "GetTrendingTopicsQuery",
    "query_bus",
    
    # Events
    "DomainEvent",
    "EventStore",
    "EventProjector",
    "PropositionCreatedEvent",
    "PropositionUpdatedEvent", 
    "UserActionEvent",
    "event_store",
    
    # Projections
    "Projection",
    "ProjectionManager",
    "PropositionSummaryProjection",
    "UserActivityProjection",
    "AnalyticsProjection",
    "SearchIndexProjection",
    "projection_manager",
    
    # Read Models
    "ReadModel",
    "PropositionReadModel",
    "UserReadModel",
    "AnalyticsReadModel",
    "TrendingTopicsReadModel"
]