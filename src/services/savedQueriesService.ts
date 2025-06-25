import { SavedQuery, SearchFilters } from '../types';

const STORAGE_KEY = 'monitor_legislativo_saved_queries';

class SavedQueriesService {
  private static instance: SavedQueriesService;
  private queries: SavedQuery[] = [];

  private constructor() {
    this.loadQueries();
  }

  static getInstance(): SavedQueriesService {
    if (!SavedQueriesService.instance) {
      SavedQueriesService.instance = new SavedQueriesService();
    }
    return SavedQueriesService.instance;
  }

  private loadQueries(): void {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        this.queries = JSON.parse(stored);
      }
    } catch (error) {
      console.error('Error loading saved queries:', error);
      this.queries = [];
    }
  }

  private saveQueries(): void {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(this.queries));
    } catch (error) {
      console.error('Error saving queries:', error);
    }
  }

  private generateId(): string {
    return `query_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  getAllQueries(): SavedQuery[] {
    return [...this.queries].sort((a, b) => 
      new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime()
    );
  }

  getPublicQueries(): SavedQuery[] {
    return this.queries.filter(q => q.isPublic);
  }

  getRecentQueries(limit: number = 5): SavedQuery[] {
    return this.getAllQueries().slice(0, limit);
  }

  getPopularQueries(limit: number = 5): SavedQuery[] {
    return [...this.queries]
      .sort((a, b) => b.timesUsed - a.timesUsed)
      .slice(0, limit);
  }

  getQueryById(id: string): SavedQuery | undefined {
    return this.queries.find(q => q.id === id);
  }

  saveQuery(
    name: string,
    filters: SearchFilters,
    options: {
      description?: string;
      isPublic?: boolean;
      tags?: string[];
    } = {}
  ): SavedQuery {
    const now = new Date().toISOString();
    const query: SavedQuery = {
      id: this.generateId(),
      name: name.trim(),
      description: options.description?.trim(),
      filters: { ...filters },
      createdAt: now,
      updatedAt: now,
      timesUsed: 0,
      isPublic: options.isPublic || false,
      tags: options.tags || []
    };

    this.queries.push(query);
    this.saveQueries();
    return query;
  }

  updateQuery(id: string, updates: Partial<Omit<SavedQuery, 'id' | 'createdAt'>>): SavedQuery | null {
    const index = this.queries.findIndex(q => q.id === id);
    if (index === -1) return null;

    const query = this.queries[index];
    this.queries[index] = {
      ...query,
      ...updates,
      updatedAt: new Date().toISOString()
    };

    this.saveQueries();
    return this.queries[index];
  }

  deleteQuery(id: string): boolean {
    const index = this.queries.findIndex(q => q.id === id);
    if (index === -1) return false;

    this.queries.splice(index, 1);
    this.saveQueries();
    return true;
  }

  useQuery(id: string): SavedQuery | null {
    const query = this.getQueryById(id);
    if (!query) return null;

    query.timesUsed++;
    query.updatedAt = new Date().toISOString();
    this.saveQueries();
    return query;
  }

  duplicateQuery(id: string, newName: string): SavedQuery | null {
    const original = this.getQueryById(id);
    if (!original) return null;

    return this.saveQuery(newName, original.filters, {
      description: original.description,
      isPublic: false, // Duplicates are private by default
      tags: [...original.tags]
    });
  }

  searchQueries(searchTerm: string): SavedQuery[] {
    const term = searchTerm.toLowerCase();
    return this.queries.filter(query =>
      query.name.toLowerCase().includes(term) ||
      query.description?.toLowerCase().includes(term) ||
      query.tags.some(tag => tag.toLowerCase().includes(term)) ||
      query.filters.searchTerm.toLowerCase().includes(term)
    );
  }

  getQueriesByTag(tag: string): SavedQuery[] {
    return this.queries.filter(query => 
      query.tags.some(t => t.toLowerCase() === tag.toLowerCase())
    );
  }

  getAllTags(): string[] {
    const tags = new Set<string>();
    this.queries.forEach(query => {
      query.tags.forEach(tag => tags.add(tag));
    });
    return Array.from(tags).sort();
  }

  exportQueries(): string {
    return JSON.stringify(this.queries, null, 2);
  }

  importQueries(jsonData: string): { success: boolean; imported: number; errors: string[] } {
    try {
      const imported = JSON.parse(jsonData);
      if (!Array.isArray(imported)) {
        return { success: false, imported: 0, errors: ['Invalid format: expected array'] };
      }

      const errors: string[] = [];
      let importedCount = 0;

      imported.forEach((item, index) => {
        try {
          if (!this.isValidQuery(item)) {
            errors.push(`Query ${index + 1}: Invalid format`);
            return;
          }

          // Check if query with same name already exists
          const existing = this.queries.find(q => q.name === item.name);
          if (existing) {
            errors.push(`Query "${item.name}": Name already exists`);
            return;
          }

          const query: SavedQuery = {
            ...item,
            id: this.generateId(),
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
            timesUsed: 0
          };

          this.queries.push(query);
          importedCount++;
        } catch (error) {
          errors.push(`Query ${index + 1}: ${error instanceof Error ? error.message : 'Unknown error'}`);
        }
      });

      if (importedCount > 0) {
        this.saveQueries();
      }

      return {
        success: importedCount > 0,
        imported: importedCount,
        errors
      };
    } catch (error) {
      return {
        success: false,
        imported: 0,
        errors: [`Parse error: ${error instanceof Error ? error.message : 'Unknown error'}`]
      };
    }
  }

  private isValidQuery(item: any): item is Omit<SavedQuery, 'id' | 'createdAt' | 'updatedAt'> {
    return (
      typeof item === 'object' &&
      item !== null &&
      typeof item.name === 'string' &&
      item.name.trim().length > 0 &&
      typeof item.filters === 'object' &&
      item.filters !== null &&
      typeof item.filters.searchTerm === 'string' &&
      Array.isArray(item.filters.documentTypes) &&
      Array.isArray(item.filters.states) &&
      Array.isArray(item.filters.keywords) &&
      typeof item.isPublic === 'boolean' &&
      Array.isArray(item.tags)
    );
  }

  clearAllQueries(): void {
    this.queries = [];
    this.saveQueries();
  }

  getStats(): {
    total: number;
    public: number;
    private: number;
    mostUsed: SavedQuery | null;
    totalUsage: number;
  } {
    const total = this.queries.length;
    const publicQueries = this.queries.filter(q => q.isPublic).length;
    const totalUsage = this.queries.reduce((sum, q) => sum + q.timesUsed, 0);
    const mostUsed = this.queries.length > 0
      ? this.queries.reduce((max, q) => q.timesUsed > max.timesUsed ? q : max)
      : null;

    return {
      total,
      public: publicQueries,
      private: total - publicQueries,
      mostUsed,
      totalUsage
    };
  }
}

export const savedQueriesService = SavedQueriesService.getInstance();
export default savedQueriesService;