import React, { useState, useEffect } from 'react';
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
  notes_count: number;
  bibliography_count: number;
  collaborators: string[];
  progress: number;
  deadline?: string;
  objectives: string[];
  methodology: string;
  metadata: Record<string, any>;
}

interface ProjectTemplate {
  id: string;
  name: string;
  description: string;
  defaultObjectives: string[];
  defaultTags: string[];
  defaultMethodology: string;
}

interface ResearchProjectProps {
  onProjectSelect?: (project: ResearchProject) => void;
  selectedProjectId?: string;
  className?: string;
}

const ResearchProject: React.FC<ResearchProjectProps> = ({
  onProjectSelect,
  selectedProjectId,
  className = ""
}) => {
  const [projects, setProjects] = useState<ResearchProject[]>([]);
  const [filteredProjects, setFilteredProjects] = useState<ResearchProject[]>([]);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [showTemplateModal, setShowTemplateModal] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [sortBy, setSortBy] = useState<'title' | 'created_date' | 'last_modified' | 'progress'>('last_modified');
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>('desc');
  const [selectedTemplate, setSelectedTemplate] = useState<ProjectTemplate | null>(null);

  // Project templates for common research types
  const projectTemplates: ProjectTemplate[] = [
    {
      id: 'transport_regulation',
      name: 'Regulamentação de Transporte',
      description: 'Pesquisa sobre regulamentação e políticas de transporte no Brasil',
      defaultObjectives: [
        'Analisar marcos regulatórios do transporte brasileiro',
        'Identificar gaps na legislação vigente',
        'Propor melhorias no framework regulatório',
        'Comparar com modelos internacionais'
      ],
      defaultTags: ['transporte', 'regulamentação', 'ANTT', 'política pública'],
      defaultMethodology: 'Revisão sistemática da literatura e análise documental de normas regulatórias brasileiras, com foco em documentos da ANTT, ANTAQ e ANAC.'
    },
    {
      id: 'environmental_impact',
      name: 'Impacto Ambiental',
      description: 'Estudo de impactos ambientais de políticas públicas',
      defaultObjectives: [
        'Avaliar impactos ambientais de políticas setoriais',
        'Analisar efetividade de instrumentos de controle',
        'Identificar conflitos normativos ambientais',
        'Propor melhorias na gestão ambiental'
      ],
      defaultTags: ['meio ambiente', 'IBAMA', 'licenciamento', 'sustentabilidade'],
      defaultMethodology: 'Análise de conteúdo de documentos normativos e estudos de impacto ambiental, com abordagem quali-quantitativa.'
    },
    {
      id: 'energy_policy',
      name: 'Política Energética',
      description: 'Análise de políticas energéticas e matriz energética brasileira',
      defaultObjectives: [
        'Examinar evolução da matriz energética brasileira',
        'Analisar políticas de incentivo a energias renováveis',
        'Avaliar eficiência regulatória do setor',
        'Identificar tendências futuras'
      ],
      defaultTags: ['energia', 'ANEEL', 'renováveis', 'matriz energética'],
      defaultMethodology: 'Análise longitudinal de dados regulatórios e documentos de política energética, com métodos mistos de pesquisa.'
    },
    {
      id: 'digital_governance',
      name: 'Governança Digital',
      description: 'Pesquisa sobre transformação digital no setor público',
      defaultObjectives: [
        'Mapear iniciativas de governo digital',
        'Analisar marcos normativos de transformação digital',
        'Avaliar impactos na prestação de serviços públicos',
        'Identificar desafios de implementação'
      ],
      defaultTags: ['governo digital', 'tecnologia', 'administração pública', 'inovação'],
      defaultMethodology: 'Estudo de caso múltiplo com análise documental e entrevistas com gestores públicos.'
    },
    {
      id: 'social_policy',
      name: 'Política Social',
      description: 'Análise de políticas públicas sociais e seus impactos',
      defaultObjectives: [
        'Examinar evolução de políticas sociais',
        'Avaliar efetividade de programas sociais',
        'Analisar coordenação federativa',
        'Identificar inovações em gestão social'
      ],
      defaultTags: ['política social', 'federalismo', 'gestão pública', 'avaliação'],
      defaultMethodology: 'Análise de políticas públicas com abordagem neo-institucionalista e métodos de avaliação de impacto.'
    }
  ];

  // Load projects from localStorage
  useEffect(() => {
    const savedProjects = localStorage.getItem('research_projects');
    if (savedProjects) {
      try {
        const parsedProjects = JSON.parse(savedProjects);
        setProjects(parsedProjects);
      } catch (error) {
        console.error('Error loading research projects:', error);
      }
    }
  }, []);

  // Filter and sort projects
  useEffect(() => {
    let filtered = projects.filter(project => {
      const matchesSearch = !searchQuery || 
        project.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        project.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        project.tags.some(tag => tag.toLowerCase().includes(searchQuery.toLowerCase()));
      
      const matchesStatus = !statusFilter || project.status === statusFilter;
      
      return matchesSearch && matchesStatus;
    });

    // Sort projects
    filtered.sort((a, b) => {
      let aValue = a[sortBy];
      let bValue = b[sortBy];
      
      if (sortBy === 'created_date' || sortBy === 'last_modified') {
        aValue = new Date(aValue as string).getTime();
        bValue = new Date(bValue as string).getTime();
      }
      
      if (sortOrder === 'asc') {
        return aValue > bValue ? 1 : -1;
      } else {
        return aValue < bValue ? 1 : -1;
      }
    });

    setFilteredProjects(filtered);
  }, [projects, searchQuery, statusFilter, sortBy, sortOrder]);

  // Save projects to localStorage
  const saveProjects = (updatedProjects: ResearchProject[]) => {
    setProjects(updatedProjects);
    localStorage.setItem('research_projects', JSON.stringify(updatedProjects));
  };

  // Create new project
  const createProject = (projectData: Partial<ResearchProject>) => {
    const newProject: ResearchProject = {
      id: `project_${Date.now()}`,
      title: projectData.title || 'Novo Projeto',
      description: projectData.description || '',
      status: 'planning',
      created_date: new Date().toISOString(),
      last_modified: new Date().toISOString(),
      tags: projectData.tags || [],
      documents: [],
      notes_count: 0,
      bibliography_count: 0,
      collaborators: [],
      progress: 0,
      objectives: projectData.objectives || [],
      methodology: projectData.methodology || '',
      metadata: {}
    };

    const updatedProjects = [...projects, newProject];
    saveProjects(updatedProjects);
    setShowCreateModal(false);
    setSelectedTemplate(null);

    if (onProjectSelect) {
      onProjectSelect(newProject);
    }
  };

  // Create project from template
  const createFromTemplate = (template: ProjectTemplate, customData: Partial<ResearchProject>) => {
    createProject({
      ...customData,
      tags: [...template.defaultTags, ...(customData.tags || [])],
      objectives: [...template.defaultObjectives, ...(customData.objectives || [])],
      methodology: template.defaultMethodology
    });
  };

  // Update project
  const updateProject = (projectId: string, updates: Partial<ResearchProject>) => {
    const updatedProjects = projects.map(project =>
      project.id === projectId
        ? { ...project, ...updates, last_modified: new Date().toISOString() }
        : project
    );
    saveProjects(updatedProjects);
  };

  // Delete project
  const deleteProject = (projectId: string) => {
    if (confirm('Tem certeza que deseja excluir este projeto? Esta ação não pode ser desfeita.')) {
      const updatedProjects = projects.filter(project => project.id !== projectId);
      saveProjects(updatedProjects);
    }
  };

  // Duplicate project
  const duplicateProject = (project: ResearchProject) => {
    const duplicatedProject: ResearchProject = {
      ...project,
      id: `project_${Date.now()}`,
      title: `${project.title} (Cópia)`,
      created_date: new Date().toISOString(),
      last_modified: new Date().toISOString(),
      status: 'planning',
      progress: 0,
      documents: [],
      notes_count: 0,
      bibliography_count: 0
    };

    const updatedProjects = [...projects, duplicatedProject];
    saveProjects(updatedProjects);
  };

  // Get project statistics
  const getProjectStats = () => {
    return {
      total: projects.length,
      active: projects.filter(p => p.status === 'active').length,
      completed: projects.filter(p => p.status === 'completed').length,
      planning: projects.filter(p => p.status === 'planning').length,
      averageProgress: projects.length > 0 
        ? Math.round(projects.reduce((sum, p) => sum + p.progress, 0) / projects.length * 100)
        : 0
    };
  };

  const stats = getProjectStats();

  return (
    <div className={`research-project-manager ${className}`}>
      {/* Header with Statistics */}
      <GlassCard variant="academic" className="mb-6">
        <div className="flex justify-between items-start">
          <div>
            <h2 className="text-2xl font-bold text-gray-800 mb-2">
              Gerenciamento de Projetos de Pesquisa
            </h2>
            <p className="text-gray-600">
              Organize e acompanhe seus projetos de pesquisa acadêmica
            </p>
          </div>
          <div className="flex gap-3">
            <button
              onClick={() => setShowTemplateModal(true)}
              className="glass-button-secondary px-4 py-2"
            >
              📋 Usar Template
            </button>
            <button
              onClick={() => setShowCreateModal(true)}
              className="glass-button-primary px-4 py-2"
            >
              ➕ Novo Projeto
            </button>
          </div>
        </div>

        {/* Statistics */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mt-6">
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-600">{stats.total}</div>
            <div className="text-sm text-gray-600">Total</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-green-600">{stats.active}</div>
            <div className="text-sm text-gray-600">Ativos</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-blue-600">{stats.completed}</div>
            <div className="text-sm text-gray-600">Concluídos</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-yellow-600">{stats.planning}</div>
            <div className="text-sm text-gray-600">Planejamento</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-purple-600">{stats.averageProgress}%</div>
            <div className="text-sm text-gray-600">Progresso Médio</div>
          </div>
        </div>
      </GlassCard>

      {/* Search and Filters */}
      <GlassCard variant="light" className="mb-6">
        <div className="flex flex-col md:flex-row gap-4">
          <div className="flex-1">
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Buscar projetos por título, descrição ou tags..."
              className="glass-input"
            />
          </div>
          <div className="flex gap-3">
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="glass-input"
            >
              <option value="">Todos os status</option>
              <option value="planning">Planejamento</option>
              <option value="active">Ativo</option>
              <option value="completed">Concluído</option>
              <option value="archived">Arquivado</option>
            </select>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as any)}
              className="glass-input"
            >
              <option value="last_modified">Última modificação</option>
              <option value="created_date">Data de criação</option>
              <option value="title">Título</option>
              <option value="progress">Progresso</option>
            </select>
            <button
              onClick={() => setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')}
              className="glass-button-secondary px-3"
            >
              {sortOrder === 'asc' ? '🔼' : '🔽'}
            </button>
          </div>
        </div>
      </GlassCard>

      {/* Projects Grid */}
      {filteredProjects.length === 0 ? (
        <GlassCard variant="light" className="text-center py-12">
          <h3 className="text-xl font-bold text-gray-600 mb-4">
            {projects.length === 0 ? 'Nenhum projeto criado ainda' : 'Nenhum projeto encontrado'}
          </h3>
          <p className="text-gray-500 mb-6">
            {projects.length === 0 
              ? 'Crie seu primeiro projeto de pesquisa para começar'
              : 'Tente ajustar os filtros de busca'
            }
          </p>
          {projects.length === 0 && (
            <div className="flex gap-3 justify-center">
              <button
                onClick={() => setShowTemplateModal(true)}
                className="glass-button-secondary px-6 py-3"
              >
                📋 Usar Template
              </button>
              <button
                onClick={() => setShowCreateModal(true)}
                className="glass-button-primary px-6 py-3"
              >
                ➕ Criar Projeto
              </button>
            </div>
          )}
        </GlassCard>
      ) : (
        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {filteredProjects.map(project => (
            <GlassCard 
              key={project.id} 
              variant="research" 
              className={`
                hover:shadow-lg transition-all cursor-pointer
                ${selectedProjectId === project.id ? 'ring-2 ring-blue-500' : ''}
              `}
              onClick={() => onProjectSelect && onProjectSelect(project)}
            >
              <div className="flex justify-between items-start mb-3">
                <h3 className="font-bold text-lg text-gray-800 line-clamp-2">
                  {project.title}
                </h3>
                <span className={`
                  px-2 py-1 rounded-full text-xs font-medium whitespace-nowrap ml-2
                  ${project.status === 'active' ? 'bg-green-100 text-green-700' :
                    project.status === 'completed' ? 'bg-blue-100 text-blue-700' :
                    project.status === 'planning' ? 'bg-yellow-100 text-yellow-700' :
                    'bg-gray-100 text-gray-700'
                  }
                `}>
                  {project.status === 'active' ? 'Ativo' :
                   project.status === 'completed' ? 'Concluído' :
                   project.status === 'planning' ? 'Planejamento' : 'Arquivado'}
                </span>
              </div>

              <p className="text-gray-600 text-sm line-clamp-3 mb-4">
                {project.description}
              </p>

              {/* Progress Bar */}
              <div className="mb-4">
                <div className="flex justify-between text-sm mb-1">
                  <span className="text-gray-600">Progresso</span>
                  <span className="font-medium">{Math.round(project.progress * 100)}%</span>
                </div>
                <div className="w-full bg-gray-200 rounded-full h-2">
                  <div 
                    className="bg-blue-600 h-2 rounded-full transition-all"
                    style={{ width: `${project.progress * 100}%` }}
                  ></div>
                </div>
              </div>

              {/* Tags */}
              <div className="flex flex-wrap gap-1 mb-4">
                {project.tags.slice(0, 3).map(tag => (
                  <span key={tag} className="glass-badge text-xs">
                    {tag}
                  </span>
                ))}
                {project.tags.length > 3 && (
                  <span className="glass-badge text-xs">
                    +{project.tags.length - 3}
                  </span>
                )}
              </div>

              {/* Project Stats */}
              <div className="grid grid-cols-3 gap-2 text-center text-sm mb-4">
                <div>
                  <div className="font-bold text-blue-600">{project.notes_count}</div>
                  <div className="text-gray-600 text-xs">Notas</div>
                </div>
                <div>
                  <div className="font-bold text-green-600">{project.bibliography_count}</div>
                  <div className="text-gray-600 text-xs">Bibliografia</div>
                </div>
                <div>
                  <div className="font-bold text-purple-600">{project.documents.length}</div>
                  <div className="text-gray-600 text-xs">Documentos</div>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex gap-2">
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    onProjectSelect && onProjectSelect(project);
                  }}
                  className="glass-button-primary flex-1 py-2 text-sm"
                >
                  📖 Abrir
                </button>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    duplicateProject(project);
                  }}
                  className="glass-button-secondary px-3 py-2 text-sm"
                >
                  📋
                </button>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    deleteProject(project.id);
                  }}
                  className="glass-button-secondary px-3 py-2 text-sm text-red-600 hover:bg-red-50"
                >
                  🗑️
                </button>
              </div>

              {/* Last Modified */}
              <div className="text-xs text-gray-500 mt-3">
                Modificado em {new Date(project.last_modified).toLocaleDateString('pt-BR')}
              </div>
            </GlassCard>
          ))}
        </div>
      )}

      {/* Create Project Modal */}
      {showCreateModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <GlassCard variant="academic" className="w-full max-w-3xl mx-4 max-h-[90vh] overflow-y-auto">
            <h3 className="text-xl font-bold mb-4">Novo Projeto de Pesquisa</h3>
            <form onSubmit={(e) => {
              e.preventDefault();
              const formData = new FormData(e.target as HTMLFormElement);
              createProject({
                title: formData.get('title') as string,
                description: formData.get('description') as string,
                tags: (formData.get('tags') as string).split(',').map(t => t.trim()).filter(Boolean),
                objectives: (formData.get('objectives') as string).split('\n').filter(Boolean),
                methodology: formData.get('methodology') as string,
                deadline: formData.get('deadline') as string || undefined
              });
            }}>
              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Título do Projeto *
                  </label>
                  <input
                    name="title"
                    type="text"
                    required
                    className="glass-input"
                    placeholder="Ex: Análise da Regulamentação do Transporte Urbano no Brasil"
                  />
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Descrição *
                  </label>
                  <textarea
                    name="description"
                    rows={3}
                    required
                    className="glass-input"
                    placeholder="Descreva os objetivos gerais e escopo da pesquisa..."
                  />
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Tags (separadas por vírgula)
                    </label>
                    <input
                      name="tags"
                      type="text"
                      className="glass-input"
                      placeholder="transporte, regulamentação, ANTT"
                    />
                  </div>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-1">
                      Prazo (opcional)
                    </label>
                    <input
                      name="deadline"
                      type="date"
                      className="glass-input"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Objetivos Específicos (um por linha)
                  </label>
                  <textarea
                    name="objectives"
                    rows={4}
                    className="glass-input"
                    placeholder="Analisar marcos regulatórios do transporte brasileiro&#10;Identificar gaps na legislação vigente&#10;Propor melhorias no framework regulatório"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-1">
                    Metodologia
                  </label>
                  <textarea
                    name="methodology"
                    rows={3}
                    className="glass-input"
                    placeholder="Descreva a metodologia de pesquisa que será utilizada..."
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
                  onClick={() => setShowCreateModal(false)}
                  className="glass-button-secondary flex-1"
                >
                  Cancelar
                </button>
              </div>
            </form>
          </GlassCard>
        </div>
      )}

      {/* Template Selection Modal */}
      {showTemplateModal && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
          <GlassCard variant="academic" className="w-full max-w-4xl mx-4 max-h-[90vh] overflow-y-auto">
            <h3 className="text-xl font-bold mb-4">Escolher Template de Projeto</h3>
            <p className="text-gray-600 mb-6">
              Selecione um template para acelerar a criação do seu projeto de pesquisa
            </p>
            
            <div className="grid gap-4 md:grid-cols-2">
              {projectTemplates.map(template => (
                <div
                  key={template.id}
                  onClick={() => setSelectedTemplate(template)}
                  className={`
                    p-4 border rounded-lg cursor-pointer transition-all
                    ${selectedTemplate?.id === template.id 
                      ? 'border-blue-500 bg-blue-50' 
                      : 'border-gray-200 hover:border-gray-300'
                    }
                  `}
                >
                  <h4 className="font-bold text-lg mb-2">{template.name}</h4>
                  <p className="text-gray-600 text-sm mb-3">{template.description}</p>
                  <div className="flex flex-wrap gap-1">
                    {template.defaultTags.map(tag => (
                      <span key={tag} className="glass-badge text-xs">
                        {tag}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>

            {selectedTemplate && (
              <div className="mt-6 p-4 bg-blue-50 rounded-lg border border-blue-200">
                <h4 className="font-bold mb-2">Objetivos do Template:</h4>
                <ul className="list-disc list-inside text-sm space-y-1 mb-3">
                  {selectedTemplate.defaultObjectives.map((objective, index) => (
                    <li key={index}>{objective}</li>
                  ))}
                </ul>
                <div className="text-sm">
                  <strong>Metodologia:</strong> {selectedTemplate.defaultMethodology}
                </div>
              </div>
            )}

            <div className="flex gap-3 mt-6">
              <button
                onClick={() => {
                  if (selectedTemplate) {
                    setShowTemplateModal(false);
                    setShowCreateModal(true);
                    // Pre-fill form with template data would be handled in the form
                  }
                }}
                disabled={!selectedTemplate}
                className="glass-button-primary flex-1 disabled:opacity-50"
              >
                Usar Template Selecionado
              </button>
              <button
                onClick={() => {
                  setShowTemplateModal(false);
                  setSelectedTemplate(null);
                }}
                className="glass-button-secondary flex-1"
              >
                Cancelar
              </button>
            </div>
          </GlassCard>
        </div>
      )}
    </div>
  );
};

export default ResearchProject;