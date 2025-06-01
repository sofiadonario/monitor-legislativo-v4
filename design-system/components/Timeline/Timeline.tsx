import React from 'react';
import { Check, Clock, AlertCircle, XCircle } from 'lucide-react';

export interface TimelineEvent {
  id: string;
  title: string;
  description?: string;
  date: Date;
  status?: 'completed' | 'current' | 'upcoming' | 'cancelled';
  icon?: React.ReactNode;
  metadata?: Record<string, any>;
}

export interface TimelineProps {
  events: TimelineEvent[];
  orientation?: 'vertical' | 'horizontal';
}

const statusIcons = {
  completed: <Check className="h-4 w-4" />,
  current: <Clock className="h-4 w-4" />,
  upcoming: <AlertCircle className="h-4 w-4" />,
  cancelled: <XCircle className="h-4 w-4" />,
};

const statusColors = {
  completed: 'bg-success-500 text-white',
  current: 'bg-primary-500 text-white',
  upcoming: 'bg-neutral-300 text-neutral-600',
  cancelled: 'bg-error-500 text-white',
};

const lineColors = {
  completed: 'bg-success-200',
  current: 'bg-primary-200',
  upcoming: 'bg-neutral-200',
  cancelled: 'bg-error-200',
};

export const Timeline: React.FC<TimelineProps> = ({ events, orientation = 'vertical' }) => {
  if (orientation === 'horizontal') {
    return <HorizontalTimeline events={events} />;
  }

  return (
    <div className="relative">
      {events.map((event, index) => {
        const isLast = index === events.length - 1;
        const status = event.status || 'upcoming';

        return (
          <div key={event.id} className="relative flex pb-8 last:pb-0">
            {/* Line */}
            {!isLast && (
              <div
                className={`absolute left-4 top-8 bottom-0 w-0.5 ${lineColors[status]}`}
              />
            )}

            {/* Icon */}
            <div
              className={`relative z-10 flex h-8 w-8 items-center justify-center rounded-full ${statusColors[status]}`}
            >
              {event.icon || statusIcons[status]}
            </div>

            {/* Content */}
            <div className="ml-4 flex-1">
              <div className="flex items-center gap-2 mb-1">
                <h4 className="text-base font-semibold text-neutral-900">
                  {event.title}
                </h4>
                <time className="text-sm text-neutral-500">
                  {new Intl.DateTimeFormat('pt-BR', {
                    day: 'numeric',
                    month: 'short',
                    year: 'numeric',
                  }).format(event.date)}
                </time>
              </div>
              {event.description && (
                <p className="text-sm text-neutral-600 mt-1">{event.description}</p>
              )}
              {event.metadata && (
                <div className="mt-2 flex flex-wrap gap-2">
                  {Object.entries(event.metadata).map(([key, value]) => (
                    <span
                      key={key}
                      className="text-xs bg-neutral-100 text-neutral-700 px-2 py-1 rounded"
                    >
                      {key}: {value}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
};

const HorizontalTimeline: React.FC<{ events: TimelineEvent[] }> = ({ events }) => {
  return (
    <div className="relative overflow-x-auto">
      <div className="flex items-center min-w-max">
        {events.map((event, index) => {
          const isLast = index === events.length - 1;
          const status = event.status || 'upcoming';

          return (
            <div key={event.id} className="flex items-center">
              <div className="relative">
                {/* Icon */}
                <div
                  className={`relative z-10 flex h-8 w-8 items-center justify-center rounded-full ${statusColors[status]}`}
                >
                  {event.icon || statusIcons[status]}
                </div>

                {/* Content */}
                <div className="absolute top-10 left-1/2 transform -translate-x-1/2 w-32 text-center">
                  <h4 className="text-sm font-semibold text-neutral-900 line-clamp-2">
                    {event.title}
                  </h4>
                  <time className="text-xs text-neutral-500 mt-1 block">
                    {new Intl.DateTimeFormat('pt-BR', {
                      day: 'numeric',
                      month: 'short',
                    }).format(event.date)}
                  </time>
                </div>
              </div>

              {/* Line */}
              {!isLast && (
                <div className={`h-0.5 w-24 ${lineColors[status]}`} />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};