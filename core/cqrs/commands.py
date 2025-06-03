"""
Command Side of CQRS for Monitor Legislativo v4
Handles write operations and business logic

Developed by: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães
Organization: MackIntegridade
Financing: MackPesquisa
"""

import asyncio
import logging
from typing import Dict, Any, Optional, List, Type, Callable
from datetime import datetime
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import uuid

from ..events import event_bus, Event, EventType

logger = logging.getLogger(__name__)

@dataclass
class Command(ABC):
    """Base command class"""
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=datetime.now)
    user_id: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

class CommandHandler(ABC):
    """Base command handler"""
    
    @abstractmethod
    async def handle(self, command: Command) -> Any:
        """Handle the command"""
        pass

class CommandBus:
    """Command bus for dispatching commands to handlers"""
    
    def __init__(self):
        self.handlers: Dict[Type[Command], CommandHandler] = {}
        self.middleware: List[Callable] = []
        
    def register_handler(self, command_type: Type[Command], handler: CommandHandler) -> None:
        """Register a command handler"""
        self.handlers[command_type] = handler
        logger.info(f"Registered handler for {command_type.__name__}")
    
    def add_middleware(self, middleware: Callable) -> None:
        """Add middleware to command pipeline"""
        self.middleware.append(middleware)
    
    async def dispatch(self, command: Command) -> Any:
        """Dispatch command to appropriate handler"""
        command_type = type(command)
        
        if command_type not in self.handlers:
            raise ValueError(f"No handler registered for {command_type.__name__}")
        
        handler = self.handlers[command_type]
        
        # Apply middleware
        async def execute():
            return await handler.handle(command)
        
        for middleware in self.middleware:
            execute = middleware(execute, command)
        
        try:
            result = await execute()
            logger.info(f"Command {command_type.__name__} executed successfully")
            return result
        except Exception as e:
            logger.error(f"Error executing command {command_type.__name__}: {e}")
            raise

# Command Definitions

@dataclass
class CreatePropositionCommand(Command):
    """Command to create a new proposition"""
    source: str
    type: str
    number: str
    year: int
    title: str
    summary: str
    author: str
    status: str = "active"
    keywords: List[str] = field(default_factory=list)

@dataclass
class UpdatePropositionCommand(Command):
    """Command to update an existing proposition"""
    proposition_id: str
    updates: Dict[str, Any]

@dataclass
class DeletePropositionCommand(Command):
    """Command to delete a proposition"""
    proposition_id: str
    reason: str = "Administrative action"

@dataclass
class CreateAlertCommand(Command):
    """Command to create a user alert"""
    name: str
    query: str
    frequency: str = "daily"
    enabled: bool = True

@dataclass
class UpdateUserPreferencesCommand(Command):
    """Command to update user preferences"""
    preferences: Dict[str, Any]

@dataclass
class BulkImportPropositionsCommand(Command):
    """Command to bulk import propositions"""
    propositions: List[Dict[str, Any]]
    source: str
    import_options: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SyncPropositionCommand(Command):
    """Command to sync proposition with external source"""
    proposition_id: str
    force_update: bool = False

# Command Handlers

class CreatePropositionHandler(CommandHandler):
    """Handler for creating propositions"""
    
    async def handle(self, command: CreatePropositionCommand) -> Dict[str, Any]:
        """Create a new proposition"""
        try:
            # Generate proposition ID
            proposition_id = f"prop_{command.source}_{command.number}_{command.year}"
            
            # Create proposition data
            proposition_data = {
                "id": proposition_id,
                "source": command.source,
                "type": command.type,
                "number": command.number,
                "year": command.year,
                "title": command.title,
                "summary": command.summary,
                "author": command.author,
                "status": command.status,
                "keywords": command.keywords,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat()
            }
            
            # Store in database (simplified - would use actual DB)
            logger.info(f"Creating proposition: {proposition_id}")
            
            # Publish domain event
            event = Event(
                type=EventType.PROPOSITION_CREATED,
                source="command_handler",
                data=proposition_data,
                metadata={"command_id": command.id, "user_id": command.user_id}
            )
            
            await event_bus.publish(event)
            
            return {
                "proposition_id": proposition_id,
                "status": "created",
                "message": "Proposition created successfully"
            }
            
        except Exception as e:
            logger.error(f"Error creating proposition: {e}")
            raise

class UpdatePropositionHandler(CommandHandler):
    """Handler for updating propositions"""
    
    async def handle(self, command: UpdatePropositionCommand) -> Dict[str, Any]:
        """Update an existing proposition"""
        try:
            proposition_id = command.proposition_id
            updates = command.updates
            
            # Add timestamp
            updates["updated_at"] = datetime.now().isoformat()
            
            # Update in database (simplified)
            logger.info(f"Updating proposition: {proposition_id}")
            
            # Publish domain event
            event = Event(
                type=EventType.PROPOSITION_UPDATED,
                source="command_handler",
                data={
                    "proposition_id": proposition_id,
                    "changes": updates
                },
                metadata={"command_id": command.id, "user_id": command.user_id}
            )
            
            await event_bus.publish(event)
            
            return {
                "proposition_id": proposition_id,
                "status": "updated",
                "message": "Proposition updated successfully"
            }
            
        except Exception as e:
            logger.error(f"Error updating proposition: {e}")
            raise

class DeletePropositionHandler(CommandHandler):
    """Handler for deleting propositions"""
    
    async def handle(self, command: DeletePropositionCommand) -> Dict[str, Any]:
        """Delete a proposition"""
        try:
            proposition_id = command.proposition_id
            
            # Soft delete in database (simplified)
            logger.info(f"Deleting proposition: {proposition_id}")
            
            # Publish domain event
            event = Event(
                type=EventType.PROPOSITION_ARCHIVED,
                source="command_handler",
                data={
                    "proposition_id": proposition_id,
                    "reason": command.reason,
                    "deleted_at": datetime.now().isoformat()
                },
                metadata={"command_id": command.id, "user_id": command.user_id}
            )
            
            await event_bus.publish(event)
            
            return {
                "proposition_id": proposition_id,
                "status": "deleted",
                "message": "Proposition deleted successfully"
            }
            
        except Exception as e:
            logger.error(f"Error deleting proposition: {e}")
            raise

class CreateAlertHandler(CommandHandler):
    """Handler for creating user alerts"""
    
    async def handle(self, command: CreateAlertCommand) -> Dict[str, Any]:
        """Create a user alert"""
        try:
            alert_id = f"alert_{command.user_id}_{uuid.uuid4().hex[:8]}"
            
            alert_data = {
                "id": alert_id,
                "user_id": command.user_id,
                "name": command.name,
                "query": command.query,
                "frequency": command.frequency,
                "enabled": command.enabled,
                "created_at": datetime.now().isoformat()
            }
            
            # Store alert (simplified)
            logger.info(f"Creating alert: {alert_id}")
            
            # Publish event
            event = Event(
                type=EventType.USER_SUBSCRIBED,
                source="command_handler",
                data=alert_data,
                metadata={"command_id": command.id}
            )
            
            await event_bus.publish(event)
            
            return {
                "alert_id": alert_id,
                "status": "created",
                "message": "Alert created successfully"
            }
            
        except Exception as e:
            logger.error(f"Error creating alert: {e}")
            raise

class UpdateUserPreferencesHandler(CommandHandler):
    """Handler for updating user preferences"""
    
    async def handle(self, command: UpdateUserPreferencesCommand) -> Dict[str, Any]:
        """Update user preferences"""
        try:
            user_id = command.user_id
            preferences = command.preferences
            
            # Update preferences (simplified)
            logger.info(f"Updating preferences for user: {user_id}")
            
            # Publish event
            event = Event(
                type=EventType.USER_LOGIN,  # Reusing existing event type
                source="command_handler",
                data={
                    "user_id": user_id,
                    "preferences": preferences,
                    "updated_at": datetime.now().isoformat()
                },
                metadata={"command_id": command.id}
            )
            
            await event_bus.publish(event)
            
            return {
                "user_id": user_id,
                "status": "updated",
                "message": "Preferences updated successfully"
            }
            
        except Exception as e:
            logger.error(f"Error updating preferences: {e}")
            raise

class BulkImportPropositionsHandler(CommandHandler):
    """Handler for bulk importing propositions"""
    
    async def handle(self, command: BulkImportPropositionsCommand) -> Dict[str, Any]:
        """Bulk import propositions"""
        try:
            propositions = command.propositions
            source = command.source
            import_options = command.import_options
            
            results = {
                "total": len(propositions),
                "imported": 0,
                "failed": 0,
                "errors": []
            }
            
            for prop_data in propositions:
                try:
                    # Create individual commands
                    create_cmd = CreatePropositionCommand(
                        source=source,
                        type=prop_data.get("type", ""),
                        number=prop_data.get("number", ""),
                        year=prop_data.get("year", datetime.now().year),
                        title=prop_data.get("title", ""),
                        summary=prop_data.get("summary", ""),
                        author=prop_data.get("author", ""),
                        status=prop_data.get("status", "active"),
                        keywords=prop_data.get("keywords", []),
                        user_id=command.user_id
                    )
                    
                    # Execute command
                    await command_bus.dispatch(create_cmd)
                    results["imported"] += 1
                    
                except Exception as e:
                    results["failed"] += 1
                    results["errors"].append({
                        "proposition": prop_data.get("number", "unknown"),
                        "error": str(e)
                    })
            
            logger.info(f"Bulk import completed: {results['imported']} imported, {results['failed']} failed")
            
            return {
                "status": "completed",
                "results": results,
                "message": f"Bulk import completed: {results['imported']} imported"
            }
            
        except Exception as e:
            logger.error(f"Error in bulk import: {e}")
            raise

# Middleware Functions

async def logging_middleware(next_handler, command: Command):
    """Logging middleware for commands"""
    start_time = datetime.now()
    command_name = type(command).__name__
    
    logger.info(f"Executing command: {command_name} (ID: {command.id})")
    
    try:
        result = await next_handler()
        duration = (datetime.now() - start_time).total_seconds()
        logger.info(f"Command {command_name} completed in {duration:.3f}s")
        return result
    except Exception as e:
        duration = (datetime.now() - start_time).total_seconds()
        logger.error(f"Command {command_name} failed after {duration:.3f}s: {e}")
        raise

async def validation_middleware(next_handler, command: Command):
    """Validation middleware for commands"""
    # Basic validation
    if not command.id:
        raise ValueError("Command ID is required")
    
    if not command.timestamp:
        raise ValueError("Command timestamp is required")
    
    # Command-specific validation
    if isinstance(command, CreatePropositionCommand):
        if not command.title or not command.summary:
            raise ValueError("Title and summary are required for propositions")
    
    return await next_handler()

async def authorization_middleware(next_handler, command: Command):
    """Authorization middleware for commands"""
    # Basic authorization check
    if not command.user_id:
        # Allow system commands without user_id
        if not isinstance(command, (BulkImportPropositionsCommand, SyncPropositionCommand)):
            logger.warning(f"Command {type(command).__name__} executed without user context")
    
    # Role-based authorization would go here
    # For now, allow all commands
    
    return await next_handler()

# Global command bus instance
command_bus = CommandBus()

# Register handlers
command_bus.register_handler(CreatePropositionCommand, CreatePropositionHandler())
command_bus.register_handler(UpdatePropositionCommand, UpdatePropositionHandler())
command_bus.register_handler(DeletePropositionCommand, DeletePropositionHandler())
command_bus.register_handler(CreateAlertCommand, CreateAlertHandler())
command_bus.register_handler(UpdateUserPreferencesCommand, UpdateUserPreferencesHandler())
command_bus.register_handler(BulkImportPropositionsCommand, BulkImportPropositionsHandler())

# Add middleware
command_bus.add_middleware(logging_middleware)
command_bus.add_middleware(validation_middleware)
command_bus.add_middleware(authorization_middleware)