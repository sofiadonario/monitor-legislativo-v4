# Loading States Pattern Guide

## Overview
Loading states are crucial for providing feedback to users during asynchronous operations. This guide outlines best practices for implementing loading states across Monitor Legislativo.

## Types of Loading States

### 1. Full Page Loading
Used when loading an entire page or major section.

```tsx
<div className="flex items-center justify-center min-h-screen">
  <div className="text-center">
    <Spinner size="lg" />
    <p className="mt-4 text-neutral-600">Carregando dados legislativos...</p>
  </div>
</div>
```

### 2. Component Loading
For loading specific components while keeping the rest of the interface interactive.

```tsx
<Card>
  {isLoading ? (
    <div className="flex items-center justify-center py-8">
      <Spinner size="md" />
    </div>
  ) : (
    <CardContent>...</CardContent>
  )}
</Card>
```

### 3. Skeleton Loading
Provides a preview of the content structure while loading.

```tsx
<div className="space-y-4">
  {isLoading ? (
    <>
      <Skeleton className="h-8 w-3/4" />
      <Skeleton className="h-4 w-full" />
      <Skeleton className="h-4 w-5/6" />
    </>
  ) : (
    <DocumentCard {...document} />
  )}
</div>
```

### 4. Inline Loading
For small, inline operations like button actions.

```tsx
<Button isLoading={isSubmitting} disabled={isSubmitting}>
  {isSubmitting ? 'Salvando...' : 'Salvar Alterações'}
</Button>
```

### 5. Progressive Loading
Load content in stages to improve perceived performance.

```tsx
const [basicData, setBasicData] = useState(null);
const [detailedData, setDetailedData] = useState(null);

useEffect(() => {
  // Load basic data first
  fetchBasicData().then(setBasicData);
  
  // Then load detailed data
  fetchDetailedData().then(setDetailedData);
}, []);
```

## Best Practices

### 1. Loading Time Considerations

- **< 0.5s**: No loading indicator needed
- **0.5s - 2s**: Show subtle loading indicator
- **> 2s**: Show prominent loading with progress or message

### 2. Contextual Messages
Provide context-specific loading messages:

```tsx
const loadingMessages = {
  documents: "Carregando documentos legislativos...",
  legislators: "Buscando informações de parlamentares...",
  votes: "Processando dados de votação...",
};
```

### 3. Error States
Always pair loading states with error handling:

```tsx
if (isLoading) return <LoadingState />;
if (error) return <ErrorState error={error} onRetry={refetch} />;
return <Content data={data} />;
```

### 4. Accessibility
- Include aria-busy="true" during loading
- Provide screen reader announcements
- Ensure loading indicators have proper labels

```tsx
<div aria-busy={isLoading} aria-live="polite">
  {isLoading && (
    <span className="sr-only">Carregando conteúdo</span>
  )}
</div>
```

## Implementation Examples

### List Loading Pattern
```tsx
const DocumentList = () => {
  const { data, isLoading, error } = useDocuments();
  
  if (error) return <ErrorMessage error={error} />;
  
  return (
    <div className="space-y-4">
      {isLoading ? (
        // Show 3 skeleton items while loading
        Array.from({ length: 3 }).map((_, i) => (
          <DocumentSkeleton key={i} />
        ))
      ) : (
        data?.map(doc => (
          <DocumentCard key={doc.id} {...doc} />
        ))
      )}
    </div>
  );
};
```

### Data Table Loading
```tsx
const DataTable = () => {
  const { data, isLoading } = useTableData();
  
  return (
    <Table>
      <TableHeader>...</TableHeader>
      <TableBody>
        {isLoading ? (
          <TableRow>
            <TableCell colSpan={columns.length} className="text-center py-8">
              <Spinner className="mx-auto" />
              <p className="mt-2 text-neutral-600">
                Carregando dados...
              </p>
            </TableCell>
          </TableRow>
        ) : (
          data?.map(row => <TableRow key={row.id}>...</TableRow>)
        )}
      </TableBody>
    </Table>
  );
};
```

### Form Submission Loading
```tsx
const DocumentForm = () => {
  const [isSubmitting, setIsSubmitting] = useState(false);
  
  const handleSubmit = async (data) => {
    setIsSubmitting(true);
    try {
      await submitDocument(data);
      toast.success('Documento salvo com sucesso!');
    } catch (error) {
      toast.error('Erro ao salvar documento');
    } finally {
      setIsSubmitting(false);
    }
  };
  
  return (
    <form onSubmit={handleSubmit}>
      <fieldset disabled={isSubmitting}>
        {/* Form fields */}
      </fieldset>
      
      <Button type="submit" isLoading={isSubmitting}>
        Salvar Documento
      </Button>
    </form>
  );
};
```

## Anti-Patterns to Avoid

1. **Flashing Loading States**: Use delay before showing loader
2. **Missing Error Handling**: Always handle errors gracefully
3. **Blocking the Entire UI**: Keep unrelated parts interactive
4. **Generic Messages**: Use context-specific loading text
5. **No Progress Indication**: Show progress for long operations