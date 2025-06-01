# ===========================================================================
# BRAZILIAN LEGISLATIVE MONITORING SYSTEM - REUSABLE UI COMPONENTS LIBRARY
# ===========================================================================
# Sprint 4A: Comprehensive UI/UX Enhancement
# Government-grade Shiny components with WCAG 2.1 AA compliance
# Mobile-first responsive design for Brazilian legal professionals
# ===========================================================================

# Load required libraries
library(shiny)
library(shinydashboard)
library(htmltools)
library(shinyjs)

# ===========================================================================
# BRAZILIAN GOVERNMENT DESIGN SYSTEM
# ===========================================================================

# Verde Brasil Color Palette
VERDE_BRASIL <- list(
  primary = "#009639",
  secondary = "#00753A", 
  light = "#4CAF50",
  dark = "#1B5E20",
  accent = "#66BB6A"
)

BRASIL_COLORS <- list(
  azul = "#0F4C75",
  amarelo = "#FFD700",
  branco = "#FFFFFF",
  cinza = "#757575",
  cinza_claro = "#F5F5F5",
  cinza_escuro = "#424242"
)

# ===========================================================================
# RESPONSIVE CARD COMPONENT
# ===========================================================================

#' Create a responsive card component with accessibility features
#' 
#' @param title Card title (required for accessibility)
#' @param content Card content (can be HTML or Shiny elements)
#' @param subtitle Optional subtitle
#' @param icon Optional FontAwesome icon
#' @param color Card color theme (primary, secondary, info, success, warning, danger)
#' @param width Card width (1-12 columns)
#' @param collapsible Whether the card can be collapsed
#' @param collapsed Initial collapse state
#' @param loading Whether to show loading state
#' @param id Unique ID for the card
#' 
#' @return HTML div element representing the card
responsive_card <- function(title, 
                          content, 
                          subtitle = NULL,
                          icon = NULL,
                          color = "primary",
                          width = 12,
                          collapsible = FALSE,
                          collapsed = FALSE,
                          loading = FALSE,
                          id = NULL) {
  
  # Generate unique ID if not provided
  if (is.null(id)) {
    id <- paste0("card_", sample(10000:99999, 1))
  }
  
  # Color mapping
  color_classes <- list(
    primary = "card-primary",
    secondary = "card-secondary", 
    info = "card-info",
    success = "card-success",
    warning = "card-warning",
    danger = "card-danger"
  )
  
  card_class <- color_classes[[color]] %||% "card-primary"
  
  # Icon HTML
  icon_html <- if (!is.null(icon)) {
    tags$i(class = paste("fas", icon), `aria-hidden` = "true")
  } else NULL
  
  # Subtitle HTML
  subtitle_html <- if (!is.null(subtitle)) {
    tags$p(class = "card-subtitle", subtitle)
  } else NULL
  
  # Collapse button
  collapse_btn <- if (collapsible) {
    tags$button(
      class = "btn btn-card-collapse",
      type = "button",
      `data-toggle` = "collapse",
      `data-target` = paste0("#", id, "_content"),
      `aria-expanded` = if (collapsed) "false" else "true",
      `aria-controls` = paste0(id, "_content"),
      `aria-label` = paste("Toggle", title, "card content"),
      tags$i(class = if (collapsed) "fas fa-chevron-down" else "fas fa-chevron-up",
             `aria-hidden` = "true")
    )
  } else NULL
  
  # Loading overlay
  loading_overlay <- if (loading) {
    div(
      class = "card-loading-overlay",
      `role` = "status",
      `aria-live` = "polite",
      `aria-label` = "Loading content",
      div(
        class = "loading-spinner",
        `aria-hidden` = "true"
      ),
      span(class = "sr-only", "Loading...")
    )
  } else NULL
  
  # Main card structure
  div(
    class = paste("responsive-card", card_class, paste0("col-", width)),
    id = id,
    `role` = "region",
    `aria-labelledby` = paste0(id, "_title"),
    
    # Card header
    div(
      class = "card-header",
      div(
        class = "card-title-wrapper",
        h3(
          id = paste0(id, "_title"),
          class = "card-title",
          icon_html,
          if (!is.null(icon_html)) " ",
          title
        ),
        subtitle_html
      ),
      collapse_btn
    ),
    
    # Card content
    div(
      id = paste0(id, "_content"),
      class = paste("card-content", if (collapsed && collapsible) "collapse" else ""),
      `aria-labelledby` = paste0(id, "_title"),
      content
    ),
    
    # Loading overlay
    loading_overlay
  )
}

# ===========================================================================
# ACCESSIBLE DATA TABLE COMPONENT  
# ===========================================================================

#' Create an accessible data table with Brazilian government styling
#' 
#' @param data Data frame to display
#' @param caption Table caption for accessibility
#' @param id Unique table ID
#' @param searchable Whether to include search functionality
#' @param sortable Whether columns are sortable
#' @param pageLength Number of rows per page
#' @param responsive Whether table is responsive
#' @param striped Whether to use striped rows
#' @param hover Whether to highlight rows on hover
#' 
#' @return DT::datatable with accessibility enhancements
accessible_data_table <- function(data,
                                caption = "Data table",
                                id = NULL,
                                searchable = TRUE,
                                sortable = TRUE,
                                pageLength = 25,
                                responsive = TRUE,
                                striped = TRUE,
                                hover = TRUE) {
  
  if (is.null(id)) {
    id <- paste0("table_", sample(10000:99999, 1))
  }
  
  # Table wrapper with ARIA labels
  div(
    class = "accessible-table-wrapper",
    `role` = "region",
    `aria-label` = caption,
    
    # Screen reader caption
    div(class = "sr-only", paste("Table:", caption)),
    
    # Create DT table with accessibility features
    DT::datatable(
      data,
      elementId = id,
      caption = htmltools::tags$caption(caption, class = "table-caption"),
      options = list(
        pageLength = pageLength,
        responsive = responsive,
        searching = searchable,
        ordering = sortable,
        info = TRUE,
        lengthChange = TRUE,
        autoWidth = FALSE,
        language = list(
          # Portuguese translations for accessibility
          search = "Buscar:",
          lengthMenu = "Mostrar _MENU_ registros por página",
          info = "Mostrando _START_ a _END_ de _TOTAL_ registros",
          infoEmpty = "Nenhum registro encontrado",
          infoFiltered = "(filtrado de _MAX_ registros totais)",
          paginate = list(
            first = "Primeiro",
            last = "Último", 
            next = "Próximo",
            previous = "Anterior"
          ),
          zeroRecords = "Nenhum registro encontrado",
          emptyTable = "Nenhum dado disponível na tabela"
        ),
        dom = 'Bfrtip',
        buttons = list(
          list(
            extend = 'csv',
            text = 'Exportar CSV',
            className = 'btn btn-secondary',
            attr = list(
              'aria-label' = 'Exportar dados em formato CSV'
            )
          ),
          list(
            extend = 'excel', 
            text = 'Exportar Excel',
            className = 'btn btn-secondary',
            attr = list(
              'aria-label' = 'Exportar dados em formato Excel'
            )
          )
        )
      ),
      class = paste(
        "table accessible-table",
        if (striped) "table-striped",
        if (hover) "table-hover"
      ),
      escape = FALSE,
      rownames = FALSE
    )
  )
}

# ===========================================================================
# LOADING STATES COMPONENT
# ===========================================================================

#' Create accessible loading indicator
#' 
#' @param text Loading message
#' @param type Type of loading indicator ('spinner', 'progress', 'dots')
#' @param size Size ('sm', 'md', 'lg')
#' @param color Color theme
#' @param show Whether to show the loading indicator
#' 
#' @return HTML div with loading indicator
loading_indicator <- function(text = "Carregando...",
                            type = "spinner",
                            size = "md",
                            color = "primary",
                            show = TRUE) {
  
  size_classes <- list(
    sm = "loading-sm",
    md = "loading-md", 
    lg = "loading-lg"
  )
  
  color_classes <- list(
    primary = "loading-primary",
    secondary = "loading-secondary",
    success = "loading-success",
    info = "loading-info",
    warning = "loading-warning",
    danger = "loading-danger"
  )
  
  loading_class <- paste(
    "loading-container",
    size_classes[[size]] %||% "loading-md",
    color_classes[[color]] %||% "loading-primary"
  )
  
  # Different loading types
  indicator <- switch(type,
    spinner = div(
      class = "loading-spinner",
      `aria-hidden` = "true"
    ),
    progress = div(
      class = "loading-progress",
      `aria-hidden` = "true",
      div(class = "progress-bar", `role` = "progressbar")
    ),
    dots = div(
      class = "loading-dots",
      `aria-hidden` = "true",
      span(class = "dot"),
      span(class = "dot"),
      span(class = "dot")
    ),
    div(class = "loading-spinner", `aria-hidden` = "true") # default
  )
  
  div(
    class = loading_class,
    style = if (!show) "display: none;" else "",
    `role` = "status",
    `aria-live` = "polite",
    `aria-label` = text,
    
    indicator,
    
    div(
      class = "loading-text",
      text
    ),
    
    # Screen reader only
    span(class = "sr-only", text)
  )
}

# ===========================================================================
# ERROR HANDLING COMPONENT
# ===========================================================================

#' Create accessible error message component
#' 
#' @param message Error message text
#' @param title Error title
#' @param type Error severity ('error', 'warning', 'info')
#' @param dismissible Whether error can be dismissed
#' @param retry_function Function to call for retry action
#' @param id Unique error ID
#' 
#' @return HTML div with error message
error_message <- function(message,
                        title = "Erro",
                        type = "error",
                        dismissible = TRUE,
                        retry_function = NULL,
                        id = NULL) {
  
  if (is.null(id)) {
    id <- paste0("error_", sample(10000:99999, 1))
  }
  
  type_classes <- list(
    error = "alert-danger",
    warning = "alert-warning",
    info = "alert-info"
  )
  
  alert_class <- paste("alert", type_classes[[type]] %||% "alert-danger")
  
  # Retry button
  retry_btn <- if (!is.null(retry_function)) {
    actionButton(
      inputId = paste0(id, "_retry"),
      label = "Tentar Novamente",
      class = "btn btn-outline-primary btn-sm",
      icon = icon("redo"),
      onclick = retry_function
    )
  } else NULL
  
  # Dismiss button
  dismiss_btn <- if (dismissible) {
    button(
      type = "button",
      class = "btn btn-close",
      `data-dismiss` = "alert",
      `aria-label` = "Fechar alerta",
      span(`aria-hidden` = "true", "×")
    )
  } else NULL
  
  div(
    id = id,
    class = paste(alert_class, if (dismissible) "alert-dismissible"),
    `role` = "alert",
    `aria-live` = "assertive",
    `aria-atomic` = "true",
    
    # Error title
    h4(
      class = "alert-heading",
      title
    ),
    
    # Error message
    p(message),
    
    # Action buttons
    if (!is.null(retry_btn) || !is.null(dismiss_btn)) {
      div(
        class = "alert-actions mt-3",
        retry_btn,
        dismiss_btn
      )
    }
  )
}

# ===========================================================================
# RESPONSIVE NAVIGATION COMPONENT
# ===========================================================================

#' Create responsive navigation menu with accessibility
#' 
#' @param items List of menu items with structure list(text, href, icon, active)
#' @param brand Brand name/logo
#' @param id Navigation ID
#' @param collapse_on_mobile Whether to collapse menu on mobile
#' 
#' @return HTML navigation element
responsive_nav <- function(items,
                         brand = "MackMonitor",
                         id = "main-nav",
                         collapse_on_mobile = TRUE) {
  
  # Generate menu items
  menu_items <- lapply(items, function(item) {
    tags$li(
      class = paste("nav-item", if (item$active %||% FALSE) "active"),
      tags$a(
        class = "nav-link",
        href = item$href %||% "#",
        `aria-current` = if (item$active %||% FALSE) "page" else NULL,
        if (!is.null(item$icon)) {
          tags$i(class = paste("fas", item$icon), `aria-hidden` = "true")
        },
        if (!is.null(item$icon)) " ",
        item$text
      )
    )
  })
  
  tags$nav(
    class = "navbar navbar-expand-lg navbar-brasil",
    `role` = "navigation",
    `aria-label` = "Navegação principal",
    
    # Brand
    tags$a(
      class = "navbar-brand",
      href = "#",
      brand
    ),
    
    # Mobile toggle
    if (collapse_on_mobile) {
      button(
        class = "navbar-toggle",
        type = "button",
        `data-toggle` = "collapse",
        `data-target` = paste0("#", id),
        `aria-controls` = id,
        `aria-expanded` = "false",
        `aria-label` = "Alternar navegação",
        span(class = "sr-only", "Alternar navegação"),
        span(class = "navbar-toggler-icon")
      )
    },
    
    # Navigation menu
    div(
      id = id,
      class = if (collapse_on_mobile) "collapse navbar-collapse" else "navbar-nav",
      tags$ul(
        class = "navbar-nav mr-auto",
        menu_items
      )
    )
  )
}

# ===========================================================================
# FORM COMPONENTS WITH ACCESSIBILITY
# ===========================================================================

#' Create accessible form input with proper labeling
#' 
#' @param inputId Input ID
#' @param label Input label
#' @param type Input type
#' @param value Initial value
#' @param placeholder Placeholder text
#' @param required Whether field is required
#' @param help_text Help text for the field
#' @param error_text Error message
#' @param width Input width
#' 
#' @return HTML div containing labeled input
accessible_text_input <- function(inputId,
                                label,
                                type = "text",
                                value = "",
                                placeholder = NULL,
                                required = FALSE,
                                help_text = NULL,
                                error_text = NULL,
                                width = NULL) {
  
  # Generate IDs for help and error text
  help_id <- if (!is.null(help_text)) paste0(inputId, "_help") else NULL
  error_id <- if (!is.null(error_text)) paste0(inputId, "_error") else NULL
  
  # Build aria-describedby
  describedby <- c(help_id, error_id)
  describedby <- if (length(describedby) > 0) paste(describedby, collapse = " ") else NULL
  
  div(
    class = "form-group",
    style = if (!is.null(width)) paste0("width: ", width) else NULL,
    
    # Label
    tags$label(
      class = paste("form-label", if (required) "required"),
      `for` = inputId,
      label
    ),
    
    # Input field
    tags$input(
      id = inputId,
      class = paste("form-control", if (!is.null(error_text)) "is-invalid"),
      type = type,
      value = value,
      placeholder = placeholder,
      required = if (required) TRUE else NULL,
      `aria-describedby` = describedby,
      `aria-invalid` = if (!is.null(error_text)) "true" else "false"
    ),
    
    # Help text
    if (!is.null(help_text)) {
      small(
        id = help_id,
        class = "form-help",
        help_text
      )
    },
    
    # Error message
    if (!is.null(error_text)) {
      div(
        id = error_id,
        class = "form-error",
        `role` = "alert",
        error_text
      )
    }
  )
}

# ===========================================================================
# MODAL DIALOG COMPONENT
# ===========================================================================

#' Create accessible modal dialog
#' 
#' @param modalId Modal ID
#' @param title Modal title
#' @param content Modal content
#' @param footer Modal footer content
#' @param size Modal size ('sm', 'lg', 'xl')
#' @param backdrop Whether to show backdrop
#' @param keyboard Whether to close on escape key
#' 
#' @return HTML modal dialog
accessible_modal <- function(modalId,
                           title,
                           content,
                           footer = NULL,
                           size = NULL,
                           backdrop = TRUE,
                           keyboard = TRUE) {
  
  modal_class <- paste(
    "modal fade",
    if (!is.null(size)) paste0("modal-", size)
  )
  
  div(
    id = modalId,
    class = modal_class,
    tabindex = "-1",
    `role` = "dialog",
    `aria-labelledby` = paste0(modalId, "_title"),
    `aria-hidden` = "true",
    `data-backdrop` = if (backdrop) "true" else "static",
    `data-keyboard` = if (keyboard) "true" else "false",
    
    div(
      class = "modal-dialog",
      `role` = "document",
      
      div(
        class = "modal-content",
        
        # Modal header
        div(
          class = "modal-header",
          h4(
            id = paste0(modalId, "_title"),
            class = "modal-title",
            title
          ),
          button(
            type = "button",
            class = "btn btn-close",
            `data-dismiss` = "modal",
            `aria-label` = "Fechar modal",
            span(`aria-hidden` = "true", "×")
          )
        ),
        
        # Modal body
        div(
          class = "modal-body",
          content
        ),
        
        # Modal footer
        if (!is.null(footer)) {
          div(
            class = "modal-footer",
            footer
          )
        }
      )
    )
  )
}

# ===========================================================================
# BREADCRUMB COMPONENT
# ===========================================================================

#' Create accessible breadcrumb navigation
#' 
#' @param items List of breadcrumb items with text and href
#' @param separator Breadcrumb separator
#' 
#' @return HTML breadcrumb navigation
accessible_breadcrumb <- function(items, separator = "/") {
  
  breadcrumb_items <- lapply(seq_along(items), function(i) {
    item <- items[[i]]
    is_last <- i == length(items)
    
    tags$li(
      class = paste("breadcrumb-item", if (is_last) "active"),
      `aria-current` = if (is_last) "page" else NULL,
      
      if (is_last || is.null(item$href)) {
        span(item$text)
      } else {
        tags$a(href = item$href, item$text)
      }
    )
  })
  
  tags$nav(
    `aria-label` = "Navegação estrutural",
    tags$ol(
      class = "breadcrumb",
      breadcrumb_items
    )
  )
}

# ===========================================================================
# COMPONENT UTILITIES
# ===========================================================================

#' Initialize UI components system
#' 
#' This function should be called once in the app to set up the component system
initialize_ui_components <- function() {
  # Add CSS dependencies
  addResourcePath("ui-components", system.file("www", package = "shiny"))
  
  # Initialize JavaScript for components
  singleton(
    tags$head(
      # Component CSS
      tags$link(rel = "stylesheet", type = "text/css", href = "css/responsive-framework.css"),
      tags$link(rel = "stylesheet", type = "text/css", href = "css/accessibility.css"),
      
      # Component JavaScript
      tags$script(src = "js/ui-components.js"),
      
      # Initialize components
      tags$script(HTML("
        $(document).ready(function() {
          // Initialize tooltips
          $('[data-toggle=\"tooltip\"]').tooltip();
          
          // Initialize popovers  
          $('[data-toggle=\"popover\"]').popover();
          
          // Initialize collapsible cards
          $('.card-collapse').on('click', function() {
            var target = $($(this).data('target'));
            var icon = $(this).find('i');
            
            target.collapse('toggle');
            
            target.on('shown.bs.collapse', function() {
              icon.removeClass('fa-chevron-down').addClass('fa-chevron-up');
              $(this).attr('aria-expanded', 'true');
            });
            
            target.on('hidden.bs.collapse', function() {
              icon.removeClass('fa-chevron-up').addClass('fa-chevron-down');  
              $(this).attr('aria-expanded', 'false');
            });
          });
          
          // Mobile navigation toggle
          $('.navbar-toggle').on('click', function() {
            var target = $($(this).data('target'));
            target.collapse('toggle');
          });
          
          // Dismiss alerts
          $('.alert-dismissible .btn-close').on('click', function() {
            $(this).closest('.alert').fadeOut();
          });
        });
      "))
    )
  )
}