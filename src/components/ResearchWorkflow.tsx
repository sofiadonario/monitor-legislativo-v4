import React, { useState, useEffect, useRef } from 'react';
import GlassCard from './GlassCard';
import '../styles/glassmorphism.css';

interface ResearchProject {
  id: string;
  title: string;
  description: string;
  status: 'planning' | 'active' | 'completed' | 'archived';
  created_date: string;
  last_modified: string;
  tags: string[];
  documents: string[];
  notes: ResearchNote[];
  bibliography: BibliographyItem[];
  collaborators: string[];
  progress: number;
  metadata: Record<string, any>;
}

interface ResearchNote {
  id: string;
  title: string;
  content: string;
  document_id?: string;
  document_section?: string;
  tags: string[];
  created_date: string;
  last_modified: string;
  type: 'general' | 'annotation' | 'insight' | 'citation' | 'methodology';
  importance: 'low' | 'medium' | 'high' | 'critical';
  highlights: TextHighlight[];
}

interface TextHighlight {
  id: string;
  text: string;
  start_position: number;
  end_position: number;
  color: string;
  note?: string;
  created_date: string;
}

interface BibliographyItem {
  id: string;
  type: 'lei' | 'decreto' | 'portaria' | 'resolucao' | 'artigo' | 'livro' | 'website';
  title: string;
  authors: string[];
  source: string;
  date: string;
  url?: string;
  urn?: string;
  citation_abnt: string;
  citation_apa: string;
  citation_chicago: string;
  citation_vancouver: string;
  notes: string;
  importance: 'primary' | 'secondary' | 'reference';
  status: 'to_read' | 'reading' | 'read' | 'cited';
  tags: string[];
}

interface WritingAssistance {
  project_id: string;
  outline: OutlineSection[];
  word_count: number;
  target_word_count: number;
  writing_goals: WritingGoal[];
  suggestions: WritingSuggestion[];
  academic_style_check: StyleCheck;
}

interface OutlineSection {
  id: string;
  title: string;
  level: number;
  content: string;
  word_count: number;
  status: 'planned' | 'writing' | 'complete';
  subsections: OutlineSection[];
}

interface WritingGoal {
  id: string;
  description: string;
  target_date: string;
  target_words: number;
  completed: boolean;
}

interface WritingSuggestion {
  type: 'structure' | 'citation' | 'clarity' | 'academic_tone';
  suggestion: string;
  priority: 'low' | 'medium' | 'high';
  section?: string;
}

interface StyleCheck {
  academic_tone_score: number;
  citation_compliance: number;
  structure_score: number;
  clarity_score: number;
  issues: string[];
  recommendations: string[];
}

interface ResearchWorkflowProps {
  className?: string;
  onProjectChange?: (project: ResearchProject) => void;
}

const ResearchWorkflow: React.FC<ResearchWorkflowProps> = ({
  className = "",
  onProjectChange
}) => {
  const [currentProject, setCurrentProject] = useState<ResearchProject | null>(null);
  const [projects, setProjects] = useState<ResearchProject[]>([]);
  const [activeTab, setActiveTab] = useState<'overview' | 'documents' | 'notes' | 'bibliography' | 'writing' | 'collaboration'>('overview');
  const [selectedNote, setSelectedNote] = useState<ResearchNote | null>(null);
  const [isCreatingProject, setIsCreatingProject] = useState(false);
  const [isCreatingNote, setIsCreatingNote] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [filterTags, setFilterTags] = useState<string[]>([]);
  const [showAdvancedFilters, setShowAdvancedFilters] = useState(false);

  const editorRef = useRef<HTMLTextAreaElement>(null);

  // Load projects from localStorage
  useEffect(() => {
    const savedProjects = localStorage.getItem('research_projects');
    if (savedProjects) {
      try {
        const parsedProjects = JSON.parse(savedProjects);
        setProjects(parsedProjects);
        if (parsedProjects.length > 0 && !currentProject) {
          setCurrentProject(parsedProjects[0]);
        }
      } catch (error) {
        console.error('Error loading research projects:', error);
      }
    }
  }, []);

  // Save projects to localStorage
  const saveProjects = (updatedProjects: ResearchProject[]) => {
    setProjects(updatedProjects);
    localStorage.setItem('research_projects', JSON.stringify(updatedProjects));
  };

  // Create new research project
  const createNewProject = (projectData: Partial<ResearchProject>) => {
    const newProject: ResearchProject = {
      id: `project_${Date.now()}`,
      title: projectData.title || 'Novo Projeto de Pesquisa',
      description: projectData.description || '',
      status: 'planning',
      created_date: new Date().toISOString(),
      last_modified: new Date().toISOString(),
      tags: projectData.tags || [],
      documents: [],
      notes: [],
      bibliography: [],
      collaborators: [],
      progress: 0,
      metadata: {}
    };

    const updatedProjects = [...projects, newProject];
    saveProjects(updatedProjects);
    setCurrentProject(newProject);
    setIsCreatingProject(false);

    if (onProjectChange) {
      onProjectChange(newProject);
    }
  };

  // Create new research note
  const createNewNote = (noteData: Partial<ResearchNote>) => {
    if (!currentProject) return;

    const newNote: ResearchNote = {
      id: `note_${Date.now()}`,
      title: noteData.title || 'Nova Nota',
      content: noteData.content || '',
      document_id: noteData.document_id,
      document_section: noteData.document_section,
      tags: noteData.tags || [],
      created_date: new Date().toISOString(),
      last_modified: new Date().toISOString(),
      type: noteData.type || 'general',
      importance: noteData.importance || 'medium',
      highlights: []
    };

    const updatedProject = {
      ...currentProject,
      notes: [...currentProject.notes, newNote],
      last_modified: new Date().toISOString()
    };

    const updatedProjects = projects.map(p => p.id === currentProject.id ? updatedProject : p);
    saveProjects(updatedProjects);
    setCurrentProject(updatedProject);
    setIsCreatingNote(false);
  };

  // Update project
  const updateProject = (updates: Partial<ResearchProject>) => {
    if (!currentProject) return;

    const updatedProject = {
      ...currentProject,
      ...updates,
      last_modified: new Date().toISOString()
    };

    const updatedProjects = projects.map(p => p.id === currentProject.id ? updatedProject : p);
    saveProjects(updatedProjects);
    setCurrentProject(updatedProject);

    if (onProjectChange) {
      onProjectChange(updatedProject);
    }
  };

  // Add document to bibliography
  const addToBibliography = (document: any) => {
    if (!currentProject) return;

    const bibliographyItem: BibliographyItem = {
      id: `bib_${Date.now()}`,
      type: document.tipo_documento?.toLowerCase() || 'lei',
      title: document.title || 'Documento sem título',
      authors: document.autor ? [document.autor] : [],
      source: document.fonte || 'LexML',
      date: document.data_evento || document.data_publicacao || '',
      url: document.url,
      urn: document.urn,
      citation_abnt: generateABNTCitation(document),
      citation_apa: generateAPACitation(document),
      citation_chicago: generateChicagoCitation(document),
      citation_vancouver: generateVancouverCitation(document),
      notes: '',
      importance: 'secondary',
      status: 'to_read',
      tags: []
    };

    const updatedProject = {
      ...currentProject,
      bibliography: [...currentProject.bibliography, bibliographyItem],
      last_modified: new Date().toISOString()
    };

    const updatedProjects = projects.map(p => p.id === currentProject.id ? updatedProject : p);
    saveProjects(updatedProjects);
    setCurrentProject(updatedProject);
  };

  // Generate citations
  const generateABNTCitation = (document: any): string => {
    const title = document.title || 'Documento sem título';
    const author = document.autor || document.autoridade || 'BRASIL';
    const date = document.data_evento || document.data_publicacao || '';
    const source = document.fonte || 'LexML';
    
    return `${author.toUpperCase()}. ${title}. ${source}, ${date}. Disponível em: ${document.url || 'URL não disponível'}. Acesso em: ${new Date().toLocaleDateString('pt-BR')}.`;
  };

  const generateAPACitation = (document: any): string => {
    const title = document.title || 'Documento sem título';
    const author = document.autor || document.autoridade || 'Brasil';
    const date = document.data_evento || document.data_publicacao || '';
    
    return `${author}. (${date}). ${title}. ${document.fonte || 'LexML'}. ${document.url || 'URL não disponível'}`;
  };

  const generateChicagoCitation = (document: any): string => {
    const title = document.title || 'Documento sem título';
    const author = document.autor || document.autoridade || 'Brasil';
    const date = document.data_evento || document.data_publicacao || '';
    
    return `${author}. "${title}" ${document.fonte || 'LexML'}, ${date}. ${document.url || 'URL não disponível'}.`;
  };

  const generateVancouverCitation = (document: any): string => {
    const title = document.title || 'Documento sem título';
    const author = document.autor || document.autoridade || 'Brasil';
    const date = document.data_evento || document.data_publicacao || '';
    
    return `${author}. ${title}. ${document.fonte || 'LexML'}. ${date}. Available from: ${document.url || 'URL não disponível'}`;
  };

  // Filter notes based on search and tags
  const filteredNotes = currentProject?.notes.filter(note => {
    const matchesSearch = !searchQuery || 
      note.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
      note.content.toLowerCase().includes(searchQuery.toLowerCase());
    
    const matchesTags = filterTags.length === 0 || 
      filterTags.some(tag => note.tags.includes(tag));
    
    return matchesSearch && matchesTags;
  }) || [];

  // Calculate project statistics
  const projectStats = currentProject ? {
    totalNotes: currentProject.notes.length,
    totalDocuments: currentProject.documents.length,
    bibliographyItems: currentProject.bibliography.length,
    completionPercentage: Math.round((currentProject.progress || 0) * 100),
    criticalNotes: currentProject.notes.filter(n => n.importance === 'critical').length,
    recentActivity: currentProject.notes.filter(n => {
      const noteDate = new Date(n.last_modified);
      const weekAgo = new Date();
      weekAgo.setDate(weekAgo.getDate() - 7);
      return noteDate > weekAgo;
    }).length
  } : null;

  if (!currentProject && projects.length === 0) {
    return (
      <div className={`research-workflow ${className}`}>
        <GlassCard variant="academic" className="text-center py-12">
          <h2 className="text-2xl font-bold text-gray-700 mb-4">
            Bem-vindo ao Fluxo de Pesquisa Acadêmica
          </h2>
          <p className="text-gray-600 mb-6">
            Organize sua pesquisa legislativa com ferramentas acadêmicas profissionais
          </p>
          <button
            onClick={() => setIsCreatingProject(true)}
            className="glass-button-primary px-6 py-3 text-lg"
          >
            🚀 Criar Primeiro Projeto
          </button>
        </GlassCard>

        {/* Create Project Modal */}
        {isCreatingProject && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <GlassCard variant="academic" className="w-full max-w-2xl mx-4">
              <h3 className="text-xl font-bold mb-4">Novo Projeto de Pesquisa</h3>
              <form onSubmit={(e) => {
                e.preventDefault();
                const formData = new FormData(e.target as HTMLFormElement);
                createNewProject({
                  title: formData.get('title') as string,
                  description: formData.get('description') as string,
                  tags: (formData.get('tags') as string).split(',').map(t => t.trim()).filter(Boolean)
                });
              }}>
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Título do Projeto
                    </label>
                    <input
                      name="title"
                      type="text"
                      required
                      className="glass-input"
                      placeholder="Ex: Regulamentação do Transporte Urbano no Brasil"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Descrição
                    </label>
                    <textarea
                      name="description"
                      rows={3}
                      className="glass-input"
                      placeholder="Descreva os objetivos e escopo da sua pesquisa..."
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Tags (separadas por vírgula)
                    </label>
                    <input
                      name="tags"
                      type="text"
                      className="glass-input"
                      placeholder="transporte, regulamentação, urbano"
                    />
                  </div>
                </div>
                <div className="flex gap-3 mt-6">
                  <button
                    type="submit"
                    className="glass-button-primary flex-1"
                  >
                    Criar Projeto
                  </button>
                  <button
                    type="button"
                    onClick={() => setIsCreatingProject(false)}
                    className="glass-button-secondary flex-1"
                  >
                    Cancelar
                  </button>
                </div>
              </form>
            </GlassCard>
          </div>
        )}
      </div>
    );
  }

  return (
    <div className={`research-workflow ${className}`}>
      {/* Project Header */}
      <GlassCard variant="academic" className="mb-6">
        <div className="flex justify-between items-start">
          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2">
              <h1 className="text-2xl font-bold text-gray-800">
                {currentProject?.title}
              </h1>
              <span className={`
                px-3 py-1 rounded-full text-sm font-medium
                ${currentProject?.status === 'active' ? 'bg-green-100 text-green-700' :
                  currentProject?.status === 'completed' ? 'bg-blue-100 text-blue-700' :
                  currentProject?.status === 'planning' ? 'bg-yellow-100 text-yellow-700' :
                  'bg-gray-100 text-gray-700'
                }
              `}>
                {currentProject?.status === 'active' ? 'Ativo' :
                 currentProject?.status === 'completed' ? 'Concluído' :
                 currentProject?.status === 'planning' ? 'Planejamento' : 'Arquivado'}
              </span>
            </div>
            <p className="text-gray-600 mb-3">{currentProject?.description}</p>
            <div className="flex flex-wrap gap-2 mb-3">
              {currentProject?.tags.map(tag => (
                <span key={tag} className="glass-badge text-sm">
                  {tag}
                </span>
              ))}
            </div>
            {projectStats && (
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                <div className="text-center">
                  <div className="font-bold text-lg text-blue-600">{projectStats.totalNotes}</div>
                  <div className="text-gray-600">Notas</div>
                </div>
                <div className="text-center">
                  <div className="font-bold text-lg text-green-600">{projectStats.bibliographyItems}</div>
                  <div className="text-gray-600">Bibliografia</div>
                </div>
                <div className="text-center">
                  <div className="font-bold text-lg text-purple-600">{projectStats.completionPercentage}%</div>
                  <div className="text-gray-600">Progresso</div>
                </div>
                <div className="text-center">
                  <div className="font-bold text-lg text-orange-600">{projectStats.recentActivity}</div>
                  <div className="text-gray-600">Atividade 7d</div>
                </div>
              </div>
            )}
          </div>
          
          {/* Project Actions */}
          <div className="flex gap-2 ml-4">
            <button
              onClick={() => setIsCreatingProject(true)}
              className="glass-button-secondary px-3 py-2 text-sm"
            >
              🔄 Trocar Projeto
            </button>
            <button
              onClick={() => setIsCreatingNote(true)}
              className="glass-button-primary px-3 py-2 text-sm"
            >
              ➕ Nova Nota
            </button>
          </div>
        </div>
      </GlassCard>

      {/* Navigation Tabs */}
      <div className="flex flex-wrap gap-2 mb-6">
        {[
          { key: 'overview', label: '📊 Visão Geral', icon: '📊' },
          { key: 'documents', label: '📄 Documentos', icon: '📄' },
          { key: 'notes', label: '📝 Notas', icon: '📝' },
          { key: 'bibliography', label: '📚 Bibliografia', icon: '📚' },
          { key: 'writing', label: '✍️ Redação', icon: '✍️' },
          { key: 'collaboration', label: '👥 Colaboração', icon: '👥' }
        ].map(tab => (
          <button
            key={tab.key}
            onClick={() => setActiveTab(tab.key as any)}
            className={`
              px-4 py-2 rounded-lg font-medium transition-all
              ${activeTab === tab.key 
                ? 'glass-card bg-blue-50 text-blue-700 border-blue-200' 
                : 'glass-button-secondary'
              }
            `}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {/* Progress Overview */}
          <GlassCard variant="analysis">
            <h3 className="text-lg font-bold mb-4">📈 Progresso do Projeto</h3>
            <div className="space-y-4">
              <div>
                <div className="flex justify-between text-sm mb-1">
                  <span>Progresso Geral</span>
                  <span>{projectStats?.completionPercentage}%</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div 
                    className="bg-blue-600 h-2 rounded-full transition-all"
                    style={{ width: `${projectStats?.completionPercentage}%` }}
                  ></div>
                </div>
              </div>
            </div>
          </GlassCard>

          {/* Recent Activity */}
          <GlassCard variant="research">
            <h3 className="text-lg font-bold mb-4">⚡ Atividade Recente</h3>
            <div className="space-y-3">
              {currentProject?.notes.slice(0, 5).map(note => (
                <div key={note.id} className="flex items-center gap-3 p-3 bg-gray-50 rounded">
                  <span className={`
                    w-2 h-2 rounded-full
                    ${note.importance === 'critical' ? 'bg-red-500' :
                      note.importance === 'high' ? 'bg-orange-500' :
                      note.importance === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                    }
                  `}></span>
                  <div className="flex-1">
                    <div className="font-medium">{note.title}</div>
                    <div className="text-sm text-gray-600">
                      {new Date(note.last_modified).toLocaleDateString('pt-BR')}
                    </div>
                  </div>
                  <span className="glass-badge text-xs">{note.type}</span>
                </div>
              ))}
            </div>
          </GlassCard>
        </div>
      )}

      {activeTab === 'notes' && (
        <div className="space-y-6">
          {/* Notes Search and Filter */}
          <GlassCard variant="research">
            <div className="flex flex-col md:flex-row gap-4">
              <div className="flex-1">
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Buscar nas notas..."
                  className="glass-input"
                />
              </div>
              <button
                onClick={() => setShowAdvancedFilters(!showAdvancedFilters)}
                className="glass-button-secondary px-4 py-2"
              >
                🔍 Filtros
              </button>
            </div>
            
            {showAdvancedFilters && (
              <div className="mt-4 pt-4 border-t border-gray-200">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Importância
                    </label>
                    <select className="glass-input text-sm">
                      <option value="">Todas</option>
                      <option value="critical">Crítica</option>
                      <option value="high">Alta</option>
                      <option value="medium">Média</option>
                      <option value="low">Baixa</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Tipo
                    </label>
                    <select className="glass-input text-sm">
                      <option value="">Todos</option>
                      <option value="general">Geral</option>
                      <option value="annotation">Anotação</option>
                      <option value="insight">Insight</option>
                      <option value="citation">Citação</option>
                      <option value="methodology">Metodologia</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Período
                    </label>
                    <select className="glass-input text-sm">
                      <option value="">Todo período</option>
                      <option value="today">Hoje</option>
                      <option value="week">Esta semana</option>
                      <option value="month">Este mês</option>
                    </select>
                  </div>
                </div>
              </div>
            )}
          </GlassCard>

          {/* Notes List */}
          <div className="grid gap-4">
            {filteredNotes.map(note => (
              <GlassCard key={note.id} variant="light" className="hover:shadow-lg transition-shadow">
                <div className="flex justify-between items-start">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-2">
                      <h4 className="font-bold text-lg">{note.title}</h4>
                      <span className={`
                        w-3 h-3 rounded-full
                        ${note.importance === 'critical' ? 'bg-red-500' :
                          note.importance === 'high' ? 'bg-orange-500' :
                          note.importance === 'medium' ? 'bg-yellow-500' : 'bg-green-500'
                        }
                      `}></span>
                    </div>
                    <p className="text-gray-600 mb-3 line-clamp-3">
                      {note.content.substring(0, 200)}...
                    </p>
                    <div className="flex flex-wrap gap-2 mb-2">
                      {note.tags.map(tag => (
                        <span key={tag} className="glass-badge text-xs">
                          {tag}
                        </span>
                      ))}
                      <span className="glass-badge text-xs bg-blue-100 text-blue-700">
                        {note.type}
                      </span>
                    </div>
                    <div className="text-sm text-gray-500">
                      Modificado em {new Date(note.last_modified).toLocaleDateString('pt-BR')}
                    </div>
                  </div>
                  <div className="flex gap-2 ml-4">
                    <button
                      onClick={() => setSelectedNote(note)}
                      className="glass-button-secondary px-3 py-1 text-sm"
                    >
                      📖 Ver
                    </button>
                    <button className="glass-button-secondary px-3 py-1 text-sm">
                      ✏️ Editar
                    </button>
                  </div>
                </div>
              </GlassCard>
            ))}
          </div>
        </div>
      )}

      {activeTab === 'bibliography' && (
        <GlassCard variant="academic">
          <h3 className="text-lg font-bold mb-4">📚 Bibliografia do Projeto</h3>
          {currentProject?.bibliography.length === 0 ? (
            <div className="text-center py-8">
              <p className="text-gray-600 mb-4">Nenhum item na bibliografia ainda</p>
              <p className="text-sm text-gray-500">
                Use a pesquisa para adicionar documentos à sua bibliografia
              </p>
            </div>
          ) : (
            <div className="space-y-4">
              {currentProject?.bibliography.map(item => (
                <div key={item.id} className="border border-gray-200 rounded-lg p-4">
                  <div className="flex justify-between items-start mb-2">
                    <h4 className="font-bold">{item.title}</h4>
                    <span className={`
                      px-2 py-1 rounded text-xs font-medium
                      ${item.importance === 'primary' ? 'bg-red-100 text-red-700' :
                        item.importance === 'secondary' ? 'bg-yellow-100 text-yellow-700' :
                        'bg-gray-100 text-gray-700'
                      }
                    `}>
                      {item.importance}
                    </span>
                  </div>
                  <div className="text-sm text-gray-600 mb-3">
                    <div><strong>Fonte:</strong> {item.source}</div>
                    <div><strong>Data:</strong> {item.date}</div>
                    {item.authors.length > 0 && (
                      <div><strong>Autores:</strong> {item.authors.join(', ')}</div>
                    )}
                  </div>
                  <div className="text-sm">
                    <strong>ABNT:</strong> {item.citation_abnt}
                  </div>
                </div>
              ))}
            </div>
          )}
        </GlassCard>
      )}

      {/* Create Note Modal */}
      {isCreatingNote && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <GlassCard variant="academic" className="w-full max-w-4xl mx-4 max-h-[90vh] overflow-y-auto">
            <h3 className="text-xl font-bold mb-4">Nova Nota de Pesquisa</h3>
            <form onSubmit={(e) => {
              e.preventDefault();
              const formData = new FormData(e.target as HTMLFormElement);
              createNewNote({
                title: formData.get('title') as string,
                content: formData.get('content') as string,
                type: formData.get('type') as any,
                importance: formData.get('importance') as any,
                tags: (formData.get('tags') as string).split(',').map(t => t.trim()).filter(Boolean)
              });
            }}>
              <div className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Título da Nota
                    </label>
                    <input
                      name="title"
                      type="text"
                      required
                      className="glass-input"
                      placeholder="Ex: Análise do Art. 5º da Lei 12.587/2012"
                    />
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Tipo de Nota
                    </label>
                    <select name="type" className="glass-input">
                      <option value="general">Geral</option>
                      <option value="annotation">Anotação</option>
                      <option value="insight">Insight</option>
                      <option value="citation">Citação</option>
                      <option value="methodology">Metodologia</option>
                    </select>
                  </div>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Importância
                    </label>
                    <select name="importance" className="glass-input">
                      <option value="low">Baixa</option>
                      <option value="medium">Média</option>
                      <option value="high">Alta</option>
                      <option value="critical">Crítica</option>
                    </select>
                  </div>
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Tags (separadas por vírgula)
                    </label>
                    <input
                      name="tags"
                      type="text"
                      className="glass-input"
                      placeholder="transporte, regulamentação, política"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Conteúdo da Nota
                  </label>
                  <textarea
                    name="content"
                    rows={10}
                    required
                    className="glass-input"
                    placeholder="Digite o conteúdo da sua nota de pesquisa..."
                  />
                </div>
              </div>
              <div className="flex gap-3 mt-6">
                <button
                  type="submit"
                  className="glass-button-primary flex-1"
                >
                  Criar Nota
                </button>
                <button
                  type="button"
                  onClick={() => setIsCreatingNote(false)}
                  className="glass-button-secondary flex-1"
                >
                  Cancelar
                </button>
              </div>
            </form>
          </GlassCard>
        </div>
      )}

      {/* View Note Modal */}
      {selectedNote && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <GlassCard variant="academic" className="w-full max-w-4xl mx-4 max-h-[90vh] overflow-y-auto">
            <div className="flex justify-between items-start mb-4">
              <div>
                <h3 className="text-xl font-bold">{selectedNote.title}</h3>
                <div className="flex items-center gap-2 mt-2">
                  <span className="glass-badge">{selectedNote.type}</span>
                  <span className={`
                    px-2 py-1 rounded text-xs font-medium
                    ${selectedNote.importance === 'critical' ? 'bg-red-100 text-red-700' :
                      selectedNote.importance === 'high' ? 'bg-orange-100 text-orange-700' :
                      selectedNote.importance === 'medium' ? 'bg-yellow-100 text-yellow-700' :
                      'bg-green-100 text-green-700'
                    }
                  `}>
                    {selectedNote.importance}
                  </span>
                </div>
              </div>
              <button
                onClick={() => setSelectedNote(null)}
                className="glass-button-secondary px-3 py-2"
              >
                ✕ Fechar
              </button>
            </div>
            
            <div className="prose max-w-none">
              <div className="whitespace-pre-wrap bg-gray-50 p-4 rounded-lg">
                {selectedNote.content}
              </div>
            </div>
            
            {selectedNote.tags.length > 0 && (
              <div className="flex flex-wrap gap-2 mt-4">
                {selectedNote.tags.map(tag => (
                  <span key={tag} className="glass-badge">
                    {tag}
                  </span>
                ))}
              </div>
            )}
            
            <div className="text-sm text-gray-500 mt-4">
              Criado em {new Date(selectedNote.created_date).toLocaleDateString('pt-BR')} • 
              Modificado em {new Date(selectedNote.last_modified).toLocaleDateString('pt-BR')}
            </div>
          </GlassCard>
        </div>
      )}
    </div>
  );
};

export default ResearchWorkflow;