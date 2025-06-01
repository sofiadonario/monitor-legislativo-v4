# User Onboarding Flow Design

## Overview

The Monitor Legislativo onboarding flow is designed to quickly familiarize new users with the platform's core functionality while highlighting the expertise and credibility of the MackIntegridade team.

## Onboarding Goals

1. **Quick Value Recognition**: Users understand the platform's value within 2 minutes
2. **Core Feature Discovery**: Users learn the 3 main features (Search, Alerts, Export)
3. **Confidence Building**: Users trust the MackIntegridade/MackPesquisa backing
4. **First Success**: Users complete their first successful search

## Onboarding Flow Steps

### Step 1: Welcome & Attribution (30 seconds)
**Screen**: Welcome Modal

```tsx
<WelcomeModal>
  <Header>
    <Logo />
    <h1>Bem-vindo ao Monitor Legislativo</h1>
    <p>Plataforma de monitoramento legislativo brasileiro</p>
  </Header>
  
  <Attribution>
    <div className="developer-credits">
      Desenvolvido por <strong>Sofia Pereira Medeiros Donario</strong> e <strong>Lucas Ramos Guimarães</strong>
    </div>
    <div className="organization">
      <img src="/mackintegridade-logo.png" alt="MackIntegridade" />
      <span>MackIntegridade - Integridade e Monitoramento de Políticas Públicas</span>
    </div>
    <div className="funding">
      Financiado por <strong>MackPesquisa</strong> - Instituto de Pesquisa Mackenzie
    </div>
  </Attribution>
  
  <CTAButton primary>Começar Tour</CTAButton>
</WelcomeModal>
```

**Visual Elements**:
- MackIntegridade logo prominently displayed
- #e1001e primary color for buttons and accents
- Professional photography of Sofia and Lucas (if available)
- Clean, trustworthy design

### Step 2: Platform Overview (45 seconds)
**Screen**: Feature Highlights

```tsx
<FeatureOverview>
  <h2>O que você pode fazer aqui?</h2>
  
  <FeatureGrid>
    <Feature icon={SearchIcon} color="#e1001e">
      <h3>Busca Avançada</h3>
      <p>Pesquise em 14 fontes governamentais simultaneamente</p>
      <Highlight>Câmara, Senado, Planalto + 11 agências reguladoras</Highlight>
    </Feature>
    
    <Feature icon={BellIcon} color="#e1001e">
      <h3>Alertas Inteligentes</h3>
      <p>Receba notificações sobre temas do seu interesse</p>
      <Highlight>IA identifica documentos relevantes automaticamente</Highlight>
    </Feature>
    
    <Feature icon={ExportIcon} color="#e1001e">
      <h3>Exportação Completa</h3>
      <p>Exporte dados em múltiplos formatos</p>
      <Highlight>CSV, JSON, PDF, Excel prontos para análise</Highlight>
    </Feature>
  </FeatureGrid>
  
  <Navigation>
    <Button variant="outline">Pular</Button>
    <Button primary>Continuar</Button>
  </Navigation>
</FeatureOverview>
```

### Step 3: First Search Tutorial (60 seconds)
**Screen**: Interactive Search Demo

```tsx
<SearchTutorial>
  <h2>Vamos fazer sua primeira busca</h2>
  
  <TutorialStep active={step === 1}>
    <Tooltip position="bottom">
      Digite um termo de interesse (ex: "educação", "saúde", "meio ambiente")
    </Tooltip>
    <SearchInput 
      placeholder="Ex: política educacional"
      value={searchTerm}
      onChange={setSearchTerm}
      onSubmit={handleSearch}
    />
  </TutorialStep>
  
  <TutorialStep active={step === 2}>
    <Tooltip position="right">
      Selecione as fontes que deseja consultar
    </Tooltip>
    <SourceSelector 
      sources={availableSources}
      selected={selectedSources}
      onChange={setSelectedSources}
    />
  </TutorialStep>
  
  <TutorialStep active={step === 3}>
    <Tooltip position="left">
      Use filtros para refinar sua busca
    </Tooltip>
    <FilterPanel>
      <DateRange />
      <DocumentType />
      <Status />
    </FilterPanel>
  </TutorialStep>
  
  <SearchButton 
    onClick={performSearch}
    disabled={!searchTerm}
    loading={isSearching}
  >
    Buscar
  </SearchButton>
</SearchTutorial>
```

### Step 4: Results Exploration (45 seconds)
**Screen**: Results Tutorial

```tsx
<ResultsTutorial>
  <h2>Explore seus resultados</h2>
  
  <ResultsGrid>
    <TutorialHighlight area="document-list">
      <Tooltip>
        Lista de documentos encontrados, ordenados por relevância
      </Tooltip>
      <DocumentList results={mockResults} />
    </TutorialHighlight>
    
    <TutorialHighlight area="filters-sidebar">
      <Tooltip>
        Filtros dinâmicos baseados nos resultados
      </Tooltip>
      <FilterSidebar facets={mockFacets} />
    </TutorialHighlight>
    
    <TutorialHighlight area="export-options">
      <Tooltip>
        Exporte os resultados para análise externa
      </Tooltip>
      <ExportPanel formats={['CSV', 'JSON', 'PDF', 'Excel']} />
    </TutorialHighlight>
  </ResultsGrid>
  
  <InteractionDemo>
    <p>👆 Clique em qualquer documento para ver detalhes completos</p>
    <p>🔍 Use os filtros laterais para refinar os resultados</p>
    <p>📊 Exporte dados para suas próprias análises</p>
  </InteractionDemo>
</ResultsTutorial>
```

### Step 5: Alerts Setup (Optional - 30 seconds)
**Screen**: Alert Configuration

```tsx
<AlertsSetup>
  <h2>Configure alertas para este tema</h2>
  <p>Receba notificações quando novos documentos sobre "{searchTerm}" forem publicados</p>
  
  <AlertForm>
    <Input
      label="Nome do alerta"
      value={`Alerta: ${searchTerm}`}
      onChange={setAlertName}
    />
    
    <Select
      label="Frequência"
      options={[
        { value: 'daily', label: 'Diário' },
        { value: 'weekly', label: 'Semanal' },
        { value: 'monthly', label: 'Mensal' }
      ]}
      value={frequency}
      onChange={setFrequency}
    />
    
    <Checkbox
      label="Incluir apenas documentos de alta relevância"
      checked={highRelevanceOnly}
      onChange={setHighRelevanceOnly}
    />
  </AlertForm>
  
  <ActionButtons>
    <Button variant="outline">Pular por agora</Button>
    <Button primary onClick={createAlert}>Criar Alerta</Button>
  </ActionButtons>
</AlertsSetup>
```

### Step 6: Completion & Next Steps (30 seconds)
**Screen**: Success & Resources

```tsx
<OnboardingComplete>
  <SuccessIcon color="#e1001e" size={64} />
  <h2>Parabéns! Você está pronto para usar o Monitor Legislativo</h2>
  
  <Achievement>
    <CheckItem>✅ Primeira busca realizada</CheckItem>
    <CheckItem>✅ Resultados explorados</CheckItem>
    <CheckItem>✅ Funcionalidades conhecidas</CheckItem>
  </Achievement>
  
  <NextSteps>
    <h3>Próximos passos recomendados:</h3>
    <StepCard>
      <h4>📚 Explore o Guia do Usuário</h4>
      <p>Aprenda funcionalidades avançadas e dicas de uso</p>
      <Button variant="outline" size="sm">Abrir Guia</Button>
    </StepCard>
    
    <StepCard>
      <h4>🔔 Configure mais alertas</h4>
      <p>Monitore automaticamente temas do seu interesse</p>
      <Button variant="outline" size="sm">Criar Alertas</Button>
    </StepCard>
    
    <StepCard>
      <h4>📊 Acesse o Dashboard</h4>
      <p>Veja estatísticas e tendências legislativas</p>
      <Button variant="outline" size="sm">Ver Dashboard</Button>
    </StepCard>
  </NextSteps>
  
  <Attribution>
    <p>Dúvidas? Entre em contato conosco:</p>
    <ContactInfo>
      <Contact>
        <strong>Sofia Pereira Medeiros Donario</strong>
        <span>sofia.donario@mackintegridade.org</span>
      </Contact>
      <Contact>
        <strong>Lucas Ramos Guimarães</strong>
        <span>lucas.guimaraes@mackintegridade.org</span>
      </Contact>
    </ContactInfo>
  </Attribution>
  
  <Button primary size="lg" onClick={completeOnboarding}>
    Começar a usar a plataforma
  </Button>
</OnboardingComplete>
```

## Progressive Disclosure Implementation

### Contextual Help System
```tsx
<ContextualHelp>
  <HelpTrigger tooltip="Clique para obter ajuda contextual">
    <HelpIcon />
  </HelpTrigger>
  
  <HelpContent>
    <QuickTips feature={currentFeature} />
    <VideoTutorials topic={currentContext} />
    <DocumentationLinks section={currentSection} />
  </HelpContent>
</ContextualHelp>
```

### Advanced Features Disclosure
- **Beginner Mode**: Show only essential features
- **Intermediate Mode**: Progressive reveal of advanced options
- **Expert Mode**: All features available

### Smart Onboarding Variations
- **First-time Users**: Full 6-step flow
- **Returning Users**: Quick 2-step refresh
- **Expert Users**: Skip to main interface

## Accessibility Considerations

### WCAG 2.1 AA Compliance
- **Keyboard Navigation**: All onboarding steps accessible via keyboard
- **Screen Reader Support**: Proper ARIA labels and descriptions
- **Color Contrast**: All text meets 4.5:1 contrast ratio against #e1001e
- **Focus Management**: Clear focus indicators throughout flow

### International Support
- **Portuguese Primary**: All content in Brazilian Portuguese
- **English Secondary**: Optional English interface
- **Accessibility**: High contrast mode support

## Metrics & Analytics

### Success Metrics
- **Completion Rate**: >80% complete full onboarding
- **Time to First Search**: <3 minutes average
- **Feature Adoption**: >60% use alerts within first week
- **User Satisfaction**: >4.5/5 onboarding rating

### Tracking Events
```typescript
// Analytics tracking for onboarding
trackOnboardingEvent({
  event: 'onboarding_step_completed',
  step: stepNumber,
  stepName: stepName,
  timeSpent: duration,
  userType: 'new_user',
  completionPath: pathTaken
});
```

## Implementation Notes

### Technical Requirements
- **React Components**: Reusable onboarding components
- **State Management**: Redux for onboarding flow state
- **Animation**: Framer Motion for smooth transitions
- **Responsive**: Mobile-first responsive design

### Brand Integration
- **Color Scheme**: Primary #e1001e throughout
- **Attribution**: Prominent developer and organization credits
- **Professional Imagery**: MackIntegridade and MackPesquisa branding
- **Trust Indicators**: Academic credibility highlighted

### Performance Optimization
- **Lazy Loading**: Load onboarding components on demand
- **Image Optimization**: Compressed, responsive images
- **Progressive Enhancement**: Works without JavaScript
- **Caching**: Smart caching for returning users

---

**Design Completed**: Sprint 10 - UX/UI Designer  
**Developed By**: Sofia Pereira Medeiros Donario & Lucas Ramos Guimarães  
**Organization**: MackIntegridade  
**Financing**: MackPesquisa