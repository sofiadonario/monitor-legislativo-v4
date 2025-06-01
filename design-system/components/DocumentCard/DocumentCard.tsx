import React from 'react';
import { FileText, Calendar, Building, Tag, ExternalLink } from 'lucide-react';
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from '../Card/Card';
import { Badge } from '../Badge/Badge';

export interface DocumentCardProps {
  id: string;
  title: string;
  description?: string;
  type: 'lei' | 'decreto' | 'medida_provisoria' | 'projeto_lei' | 'emenda';
  number: string;
  year: number;
  status: 'active' | 'archived' | 'pending' | 'approved' | 'rejected';
  source: 'camara' | 'senado' | 'planalto';
  publishedDate?: Date;
  tags?: string[];
  url?: string;
  onClick?: () => void;
}

const typeLabels = {
  lei: 'Lei',
  decreto: 'Decreto',
  medida_provisoria: 'Medida Provisória',
  projeto_lei: 'Projeto de Lei',
  emenda: 'Emenda',
};

const statusLabels = {
  active: 'Ativo',
  archived: 'Arquivado',
  pending: 'Em Tramitação',
  approved: 'Aprovado',
  rejected: 'Rejeitado',
};

const sourceColors = {
  camara: 'bg-government-camara text-white',
  senado: 'bg-government-senado text-white',
  planalto: 'bg-government-federal text-white',
};

export const DocumentCard: React.FC<DocumentCardProps> = ({
  title,
  description,
  type,
  number,
  year,
  status,
  source,
  publishedDate,
  tags,
  url,
  onClick,
}) => {
  return (
    <Card
      variant="elevated"
      clickable={!!onClick}
      onClick={onClick}
      className="hover:shadow-lg transition-all duration-200"
    >
      <CardHeader>
        <div className="flex items-start justify-between">
          <div className="flex-1">
            <div className="flex items-center gap-2 mb-2">
              <FileText className="h-4 w-4 text-neutral-500" />
              <span className="text-sm font-medium text-neutral-600">
                {typeLabels[type]} {number}/{year}
              </span>
            </div>
            <CardTitle className="line-clamp-2">{title}</CardTitle>
            {description && (
              <CardDescription className="line-clamp-2 mt-2">{description}</CardDescription>
            )}
          </div>
          {url && (
            <a
              href={url}
              target="_blank"
              rel="noopener noreferrer"
              className="ml-4 p-2 text-neutral-500 hover:text-primary-500 transition-colors"
              onClick={(e) => e.stopPropagation()}
            >
              <ExternalLink className="h-4 w-4" />
            </a>
          )}
        </div>
      </CardHeader>
      
      <CardContent>
        <div className="flex flex-wrap items-center gap-2 mb-3">
          <Badge variant={status === 'active' || status === 'approved' ? 'success' : status === 'rejected' ? 'error' : 'warning'}>
            {statusLabels[status]}
          </Badge>
          <Badge className={sourceColors[source]}>
            <Building className="h-3 w-3 mr-1" />
            {source.charAt(0).toUpperCase() + source.slice(1)}
          </Badge>
        </div>
        
        {publishedDate && (
          <div className="flex items-center gap-2 text-sm text-neutral-600 mb-3">
            <Calendar className="h-4 w-4" />
            <span>
              Publicado em {new Intl.DateTimeFormat('pt-BR').format(publishedDate)}
            </span>
          </div>
        )}
        
        {tags && tags.length > 0 && (
          <div className="flex flex-wrap items-center gap-2">
            <Tag className="h-4 w-4 text-neutral-500" />
            {tags.map((tag) => (
              <Badge key={tag} variant="outline" size="sm">
                {tag}
              </Badge>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
};