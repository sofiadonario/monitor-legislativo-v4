/**
 * Real-Time Annotations Component
 * Live collaborative annotation system with real-time synchronization
 */
import React, { useState, useEffect, useRef, useCallback } from 'react';
import { LegislativeDocument } from '../../types';
import { 
  Annotation, 
  AnnotationReply, 
  Reaction,
  CursorPosition,
  collaborationService 
} from '../../services/collaborationService';

interface RealTimeAnnotationsProps {
  sessionId: string;
  document: LegislativeDocument;
  userId: string;
  username: string;
  onAnnotationCreate?: (annotation: Annotation) => void;
  onAnnotationUpdate?: (annotation: Annotation) => void;
  showOtherCursors?: boolean;
  enableLiveTyping?: boolean;
}

export const RealTimeAnnotations: React.FC<RealTimeAnnotationsProps> = ({
  sessionId,
  document,
  userId,
  username,
  onAnnotationCreate,
  onAnnotationUpdate,
  showOtherCursors = true,
  enableLiveTyping = true
}) => {
  // State management
  const [annotations, setAnnotations] = useState<Annotation[]>([]);
  const [selectedAnnotation, setSelectedAnnotation] = useState<Annotation | null>(null);
  const [isCreatingAnnotation, setIsCreatingAnnotation] = useState(false);
  const [currentSelection, setCurrentSelection] = useState<{
    text: string;
    startOffset: number;
    endOffset: number;
    coordinates: { x: number; y: number };
  } | null>(null);
  
  // Annotation creation state
  const [newAnnotation, setNewAnnotation] = useState({
    text: '',
    type: 'comment' as Annotation['type'],
    tags: [] as string[],
    priority: 'medium' as 'low' | 'medium' | 'high',
    visibility: 'public' as 'public' | 'private' | 'team'
  });

  // Real-time state
  const [otherCursors, setOtherCursors] = useState<Map<string, CursorPosition>>(new Map());
  const [liveTypers, setLiveTypers] = useState<Map<string, { user: string; text: string }>>(new Map());
  
  // Refs
  const documentRef = useRef<HTMLDivElement>(null);
  const selectionTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  /**
   * Load annotations for the document
   */
  useEffect(() => {
    loadAnnotations();
    
    // Set up WebSocket connection for real-time updates
    const ws = new WebSocket(`ws://localhost:8000/collaboration/${sessionId}/annotations`);
    
    ws.onmessage = (event) => {
      const update = JSON.parse(event.data);
      handleRealTimeUpdate(update);
    };

    return () => {
      ws.close();
    };
  }, [sessionId, document.id]);

  /**
   * Track text selection
   */
  useEffect(() => {
    const handleSelection = () => {
      const selection = window.getSelection();
      if (selection && selection.rangeCount > 0 && !selection.isCollapsed) {
        const range = selection.getRangeAt(0);
        const rect = range.getBoundingClientRect();
        
        setCurrentSelection({
          text: selection.toString().trim(),
          startOffset: range.startOffset,
          endOffset: range.endOffset,
          coordinates: {
            x: rect.left + rect.width / 2,
            y: rect.top
          }
        });

        // Auto-hide selection after 5 seconds
        if (selectionTimeoutRef.current) {
          clearTimeout(selectionTimeoutRef.current);
        }
        selectionTimeoutRef.current = setTimeout(() => {
          setCurrentSelection(null);
        }, 5000);
      } else {
        setCurrentSelection(null);
      }
    };

    document.addEventListener('selectionchange', handleSelection);
    return () => {
      document.removeEventListener('selectionchange', handleSelection);
      if (selectionTimeoutRef.current) {
        clearTimeout(selectionTimeoutRef.current);
      }
    };
  }, []);

  /**
   * Track mouse movement for cursor position
   */
  useEffect(() => {
    if (!showOtherCursors) return;

    const handleMouseMove = (event: MouseEvent) => {
      if (documentRef.current && documentRef.current.contains(event.target as Node)) {
        collaborationService.updateCursorPosition(
          sessionId,
          userId,
          username,
          document.id,
          { x: event.clientX, y: event.clientY }
        );
      }
    };

    document.addEventListener('mousemove', handleMouseMove);
    return () => document.removeEventListener('mousemove', handleMouseMove);
  }, [sessionId, userId, username, document.id, showOtherCursors]);

  /**
   * Load annotations from collaboration service
   */
  const loadAnnotations = async (): Promise<void> => {
    try {
      // In a real implementation, this would fetch from the service
      // For now, we'll use empty array
      setAnnotations([]);
    } catch (error) {
      console.error('Failed to load annotations:', error);
    }
  };

  /**
   * Handle real-time updates from WebSocket
   */
  const handleRealTimeUpdate = (update: any): void => {
    switch (update.type) {
      case 'annotation_added':
        if (update.data.annotation.userId !== userId) {
          setAnnotations(prev => [...prev, update.data.annotation]);
        }
        break;
      
      case 'annotation_updated':
        setAnnotations(prev => 
          prev.map(ann => 
            ann.id === update.data.annotation.id ? update.data.annotation : ann
          )
        );
        break;
      
      case 'cursor_moved':
        if (update.userId !== userId && showOtherCursors) {
          setOtherCursors(prev => new Map(prev.set(update.userId, update.data.cursorPosition)));
        }
        break;
      
      case 'live_typing':
        if (update.userId !== userId && enableLiveTyping) {
          setLiveTypers(prev => new Map(prev.set(update.userId, {
            user: update.data.username,
            text: update.data.text
          })));
        }
        break;
    }
  };

  /**
   * Create new annotation
   */
  const handleCreateAnnotation = useCallback(async (): Promise<void> => {
    if (!currentSelection || !newAnnotation.text.trim()) return;

    try {
      const annotation = await collaborationService.createAnnotation(
        sessionId,
        document.id,
        userId,
        newAnnotation.text,
        newAnnotation.type,
        {
          startOffset: currentSelection.startOffset,
          endOffset: currentSelection.endOffset,
          selectedText: currentSelection.text,
          context: getContextAroundSelection(currentSelection),
          coordinates: currentSelection.coordinates
        },
        {
          tags: newAnnotation.tags,
          priority: newAnnotation.priority,
          visibility: newAnnotation.visibility
        }
      );

      setAnnotations(prev => [...prev, annotation]);
      setCurrentSelection(null);
      setIsCreatingAnnotation(false);
      setNewAnnotation({
        text: '',
        type: 'comment',
        tags: [],
        priority: 'medium',
        visibility: 'public'
      });

      if (onAnnotationCreate) {
        onAnnotationCreate(annotation);
      }
    } catch (error) {
      console.error('Failed to create annotation:', error);
    }
  }, [sessionId, document.id, userId, currentSelection, newAnnotation, onAnnotationCreate]);

  /**
   * Add reaction to annotation
   */
  const handleAddReaction = useCallback(async (
    annotationId: string, 
    reactionType: Reaction['type']
  ): Promise<void> => {
    try {
      // Update local state optimistically
      setAnnotations(prev => prev.map(ann => {
        if (ann.id === annotationId) {
          const existingReaction = ann.reactions.find(r => r.userId === userId);
          
          if (existingReaction) {
            // Update existing reaction
            return {
              ...ann,
              reactions: ann.reactions.map(r => 
                r.userId === userId ? { ...r, type: reactionType } : r
              )
            };
          } else {
            // Add new reaction
            return {
              ...ann,
              reactions: [...ann.reactions, {
                userId,
                type: reactionType,
                timestamp: new Date()
              }]
            };
          }
        }
        return ann;
      }));
    } catch (error) {
      console.error('Failed to add reaction:', error);
    }
  }, [userId]);

  /**
   * Reply to annotation
   */
  const handleReplyToAnnotation = useCallback(async (
    annotationId: string,
    replyText: string
  ): Promise<void> => {
    if (!replyText.trim()) return;

    try {
      const reply: AnnotationReply = {
        id: Math.random().toString(36).substr(2, 9),
        annotationId,
        userId,
        username,
        text: replyText,
        timestamp: new Date(),
        reactions: []
      };

      setAnnotations(prev => prev.map(ann => 
        ann.id === annotationId 
          ? { ...ann, replies: [...ann.replies, reply] }
          : ann
      ));
    } catch (error) {
      console.error('Failed to reply to annotation:', error);
    }
  }, [userId, username]);

  /**
   * Get context around selection
   */
  const getContextAroundSelection = (selection: typeof currentSelection): string => {
    if (!selection) return '';
    
    // Simple context extraction - in a real implementation, 
    // this would be more sophisticated
    const fullText = document.content || '';
    const start = Math.max(0, selection.startOffset - 50);
    const end = Math.min(fullText.length, selection.endOffset + 50);
    
    return fullText.substring(start, end);
  };

  /**
   * Get annotation position styles
   */
  const getAnnotationStyle = (annotation: Annotation): React.CSSProperties => {
    if (annotation.position.coordinates) {
      return {
        position: 'absolute',
        left: annotation.position.coordinates.x,
        top: annotation.position.coordinates.y,
        transform: 'translate(-50%, -100%)'
      };
    }
    return {};
  };

  /**
   * Format timestamp
   */
  const formatTimestamp = (date: Date): string => {
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const minutes = Math.floor(diff / (1000 * 60));
    
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (minutes < 1440) return `${Math.floor(minutes / 60)}h ago`;
    return date.toLocaleDateString();
  };

  return (
    <div className="real-time-annotations">
      {/* Document Content with Annotations */}
      <div ref={documentRef} className="document-content">
        {/* Document text would be rendered here with highlights for annotations */}
        <div className="document-text">
          {document.content}
        </div>

        {/* Other Users' Cursors */}
        {showOtherCursors && Array.from(otherCursors.values()).map((cursor) => (
          <div
            key={cursor.userId}
            className="other-cursor"
            style={{
              position: 'absolute',
              left: cursor.position.x,
              top: cursor.position.y,
              pointerEvents: 'none',
              zIndex: 1000
            }}
          >
            <div className="cursor-indicator">
              <div className="cursor-line"></div>
              <div className="cursor-label">{cursor.username}</div>
            </div>
          </div>
        ))}

        {/* Selection Toolbar */}
        {currentSelection && !isCreatingAnnotation && (
          <div
            className="selection-toolbar"
            style={{
              position: 'absolute',
              left: currentSelection.coordinates.x,
              top: currentSelection.coordinates.y - 50,
              transform: 'translate(-50%, 0)',
              zIndex: 1001
            }}
          >
            <button
              onClick={() => setIsCreatingAnnotation(true)}
              className="add-annotation-btn"
              title="Add annotation"
            >
              💬 Annotate
            </button>
            <button
              onClick={() => setNewAnnotation(prev => ({ ...prev, type: 'highlight' }))}
              className="highlight-btn"
              title="Highlight"
            >
              🖍️ Highlight
            </button>
            <button
              onClick={() => setNewAnnotation(prev => ({ ...prev, type: 'question' }))}
              className="question-btn"
              title="Ask question"
            >
              ❓ Question
            </button>
          </div>
        )}

        {/* Annotation Creation Modal */}
        {isCreatingAnnotation && currentSelection && (
          <div
            className="annotation-creation-modal"
            style={{
              position: 'absolute',
              left: currentSelection.coordinates.x,
              top: currentSelection.coordinates.y + 10,
              transform: 'translate(-50%, 0)',
              zIndex: 1002
            }}
          >
            <div className="modal-header">
              <h4>Add Annotation</h4>
              <button
                onClick={() => setIsCreatingAnnotation(false)}
                className="close-btn"
              >
                ✕
              </button>
            </div>

            <div className="selected-text">
              "{currentSelection.text}"
            </div>

            <div className="annotation-form">
              <div className="form-row">
                <select
                  value={newAnnotation.type}
                  onChange={(e) => setNewAnnotation(prev => ({ ...prev, type: e.target.value as any }))}
                  className="annotation-type-select"
                >
                  <option value="comment">💬 Comment</option>
                  <option value="highlight">🖍️ Highlight</option>
                  <option value="note">📝 Note</option>
                  <option value="question">❓ Question</option>
                  <option value="suggestion">💡 Suggestion</option>
                  <option value="critique">⚠️ Critique</option>
                </select>

                <select
                  value={newAnnotation.priority}
                  onChange={(e) => setNewAnnotation(prev => ({ ...prev, priority: e.target.value as any }))}
                  className="priority-select"
                >
                  <option value="low">Low Priority</option>
                  <option value="medium">Medium Priority</option>
                  <option value="high">High Priority</option>
                </select>
              </div>

              <textarea
                value={newAnnotation.text}
                onChange={(e) => setNewAnnotation(prev => ({ ...prev, text: e.target.value }))}
                placeholder="Write your annotation..."
                className="annotation-text"
                rows={3}
                autoFocus
              />

              <div className="form-row">
                <input
                  type="text"
                  placeholder="Add tags (comma-separated)"
                  value={newAnnotation.tags.join(', ')}
                  onChange={(e) => setNewAnnotation(prev => ({ 
                    ...prev, 
                    tags: e.target.value.split(',').map(t => t.trim()).filter(t => t)
                  }))}
                  className="tags-input"
                />

                <select
                  value={newAnnotation.visibility}
                  onChange={(e) => setNewAnnotation(prev => ({ ...prev, visibility: e.target.value as any }))}
                  className="visibility-select"
                >
                  <option value="public">👥 Public</option>
                  <option value="team">🔒 Team Only</option>
                  <option value="private">🔐 Private</option>
                </select>
              </div>

              <div className="form-actions">
                <button
                  onClick={() => setIsCreatingAnnotation(false)}
                  className="cancel-btn"
                >
                  Cancel
                </button>
                <button
                  onClick={handleCreateAnnotation}
                  className="create-btn"
                  disabled={!newAnnotation.text.trim()}
                >
                  Create Annotation
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Existing Annotations */}
        {annotations.map((annotation) => (
          <div
            key={annotation.id}
            className={`annotation-marker ${annotation.type}`}
            style={getAnnotationStyle(annotation)}
            onClick={() => setSelectedAnnotation(annotation)}
          >
            <div className="annotation-icon">
              {annotation.type === 'comment' && '💬'}
              {annotation.type === 'highlight' && '🖍️'}
              {annotation.type === 'note' && '📝'}
              {annotation.type === 'question' && '❓'}
              {annotation.type === 'suggestion' && '💡'}
              {annotation.type === 'critique' && '⚠️'}
            </div>
          </div>
        ))}
      </div>

      {/* Annotations Sidebar */}
      <div className="annotations-sidebar">
        <div className="sidebar-header">
          <h3>Annotations ({annotations.length})</h3>
          <div className="annotation-filters">
            <button className="filter-btn active">All</button>
            <button className="filter-btn">Comments</button>
            <button className="filter-btn">Questions</button>
            <button className="filter-btn">Suggestions</button>
          </div>
        </div>

        <div className="annotations-list">
          {annotations.map((annotation) => (
            <div
              key={annotation.id}
              className={`annotation-item ${selectedAnnotation?.id === annotation.id ? 'selected' : ''}`}
              onClick={() => setSelectedAnnotation(annotation)}
            >
              <div className="annotation-header">
                <div className="annotation-meta">
                  <span className="annotation-type-icon">
                    {annotation.type === 'comment' && '💬'}
                    {annotation.type === 'highlight' && '🖍️'}
                    {annotation.type === 'note' && '📝'}
                    {annotation.type === 'question' && '❓'}
                    {annotation.type === 'suggestion' && '💡'}
                    {annotation.type === 'critique' && '⚠️'}
                  </span>
                  <span className="annotation-author">{annotation.username}</span>
                  <span className="annotation-time">{formatTimestamp(annotation.timestamp)}</span>
                </div>
                <div className={`priority-badge ${annotation.priority}`}>
                  {annotation.priority}
                </div>
              </div>

              <div className="annotation-content">
                <div className="selected-text-preview">
                  "{annotation.position.selectedText}"
                </div>
                <div className="annotation-text">
                  {annotation.text}
                </div>
              </div>

              <div className="annotation-actions">
                <div className="reactions">
                  {['like', 'agree', 'disagree', 'important'].map((reactionType) => {
                    const reactionCount = annotation.reactions.filter(r => r.type === reactionType).length;
                    const userReacted = annotation.reactions.some(r => r.userId === userId && r.type === reactionType);
                    
                    return (
                      <button
                        key={reactionType}
                        onClick={() => handleAddReaction(annotation.id, reactionType as any)}
                        className={`reaction-btn ${userReacted ? 'active' : ''}`}
                        title={reactionType}
                      >
                        {reactionType === 'like' && '👍'}
                        {reactionType === 'agree' && '✅'}
                        {reactionType === 'disagree' && '❌'}
                        {reactionType === 'important' && '⭐'}
                        {reactionCount > 0 && <span className="reaction-count">{reactionCount}</span>}
                      </button>
                    );
                  })}
                </div>

                <button
                  onClick={() => {/* Show reply form */}}
                  className="reply-btn"
                >
                  💬 Reply ({annotation.replies.length})
                </button>
              </div>

              {annotation.replies.length > 0 && (
                <div className="annotation-replies">
                  {annotation.replies.map((reply) => (
                    <div key={reply.id} className="reply-item">
                      <div className="reply-header">
                        <span className="reply-author">{reply.username}</span>
                        <span className="reply-time">{formatTimestamp(reply.timestamp)}</span>
                      </div>
                      <div className="reply-text">{reply.text}</div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}

          {annotations.length === 0 && (
            <div className="empty-annotations">
              <p>No annotations yet. Select text to create your first annotation!</p>
            </div>
          )}
        </div>
      </div>

      {/* Live Typing Indicators */}
      {enableLiveTyping && Array.from(liveTypers.values()).map((typer, index) => (
        <div key={index} className="live-typing-indicator">
          <span className="typing-user">{typer.user}</span> is typing...
          <div className="typing-animation">
            <span></span>
            <span></span>
            <span></span>
          </div>
        </div>
      ))}
    </div>
  );
};