# UI Utilities Module
# Monitor Legislativo v4 - User Interface Helper Functions
# ========================================================

#' UI Utilities for Monitor Legislativo v4
#' 
#' This module provides reusable UI components, styling utilities,
#' and interface helpers optimized for Brazilian legislative research.
#' Mobile-responsive and accessibility-focused design.

library(shiny)
library(shinydashboard)
library(htmltools)

# UI Configuration
UI_CONFIG <- list(
  primary_color = "#2c3e50",
  secondary_color = "#3498db", 
  accent_color = "#e74c3c",
  success_color = "#27ae60",
  warning_color = "#f39c12",
  info_color = "#17a2b8",
  light_gray = "#ecf0f1",
  dark_gray = "#7f8c8d",
  brand_colors = list(
    brazil_green = "#009739",
    brazil_yellow = "#FFDF00",
    brazil_blue = "#002776"
  )
)

#' Create Responsive Info Box
#' 
#' @param title Box title
#' @param value Main value to display
#' @param subtitle Optional subtitle
#' @param icon FontAwesome icon name
#' @param color Box color theme
#' @param width Box width (1-12)
#' @return Shiny info box UI element
#' @export
create_info_box <- function(title, value, subtitle = NULL, icon = "info", 
                           color = "blue", width = 4) {
  div(class = paste("col-lg-", width, " col-md-6 col-sm-12", sep = ""),
    div(class = paste("info-box bg-", color, sep = ""),
      span(class = "info-box-icon",
        i(class = paste("fa fa-", icon, sep = ""))
      ),
      div(class = "info-box-content",
        span(class = "info-box-text", title),
        span(class = "info-box-number", value),
        if (!is.null(subtitle)) {
          span(class = "info-box-more", subtitle)
        }
      )
    )
  )
}

#' Create Search Input with Validation
#' 
#' @param input_id Input element ID
#' @param label Input label
#' @param placeholder Placeholder text
#' @param value Initial value
#' @param help_text Helper text below input
#' @return Shiny input group
#' @export
create_search_input <- function(input_id, label = "Buscar documentos", 
                               placeholder = "Digite termos de busca...", 
                               value = "", help_text = NULL) {
  div(class = "form-group",
    label(class = "control-label", `for` = input_id, label),
    div(class = "input-group",
      textInput(
        inputId = input_id,
        label = NULL,
        value = value,
        placeholder = placeholder,
        width = "100%"
      ),
      span(class = "input-group-btn",
        actionButton(
          inputId = paste0(input_id, "_search"),
          label = "",
          icon = icon("search"),
          class = "btn btn-primary"
        )
      )
    ),
    if (!is.null(help_text)) {
      small(class = "form-text text-muted", help_text)
    }
  )
}

#' Create Filter Panel
#' 
#' @param filters List of filter specifications
#' @param collapsible Whether panel can be collapsed
#' @param collapsed Initial collapsed state
#' @return Shiny filter panel UI
#' @export
create_filter_panel <- function(filters, collapsible = TRUE, collapsed = TRUE) {
  panel_content <- div(class = "filter-panel-content",
    lapply(filters, function(filter) {
      switch(filter$type,
        "select" = selectInput(
          inputId = filter$id,
          label = filter$label,
          choices = filter$choices,
          selected = filter$selected,
          multiple = filter$multiple %||% FALSE
        ),
        "daterange" = dateRangeInput(
          inputId = filter$id,
          label = filter$label,
          start = filter$start,
          end = filter$end,
          format = "dd/mm/yyyy",
          language = "pt-BR"
        ),
        "checkbox" = checkboxInput(
          inputId = filter$id,
          label = filter$label,
          value = filter$value %||% FALSE
        ),
        "slider" = sliderInput(
          inputId = filter$id,
          label = filter$label,
          min = filter$min,
          max = filter$max,
          value = filter$value,
          step = filter$step %||% 1
        )
      )
    })
  )
  
  if (collapsible) {
    div(class = "panel panel-default",
      div(class = "panel-heading",
        h4(class = "panel-title",
          a(`data-toggle` = "collapse", 
            `data-target` = "#filter-collapse",
            `aria-expanded` = if(collapsed) "false" else "true",
            "Filtros Avançados ",
            i(class = if(collapsed) "fa fa-chevron-down" else "fa fa-chevron-up")
          )
        )
      ),
      div(id = "filter-collapse", 
          class = paste("panel-collapse collapse", if(!collapsed) "in" else ""),
        div(class = "panel-body", panel_content)
      )
    )
  } else {
    div(class = "panel panel-default",
      div(class = "panel-heading",
        h4("Filtros")
      ),
      div(class = "panel-body", panel_content)
    )
  }
}

#' Create Results Table with Pagination
#' 
#' @param table_id DataTable ID
#' @param columns Column definitions
#' @param options DataTable options
#' @return Shiny DataTable UI
#' @export
create_results_table <- function(table_id, columns = NULL, options = NULL) {
  default_options <- list(
    pageLength = 25,
    lengthMenu = c(10, 25, 50, 100),
    searching = TRUE,
    ordering = TRUE,
    info = TRUE,
    autoWidth = FALSE,
    responsive = TRUE,
    language = list(
      url = "//cdn.datatables.net/plug-ins/1.10.25/i18n/Portuguese-Brasil.json"
    ),
    dom = 'Bfrtip',
    buttons = list(
      list(extend = 'copy', text = 'Copiar'),
      list(extend = 'csv', text = 'CSV'),
      list(extend = 'excel', text = 'Excel'),
      list(extend = 'pdf', text = 'PDF')
    )
  )
  
  if (!is.null(options)) {
    final_options <- modifyList(default_options, options)
  } else {
    final_options <- default_options
  }
  
  div(class = "table-responsive",
    DT::dataTableOutput(table_id),
    tags$script(HTML(paste0("
      $(document).ready(function() {
        $('#", table_id, "').DataTable(", jsonlite::toJSON(final_options, auto_unbox = TRUE), ");
      });
    ")))
  )
}

#' Create Status Badge
#' 
#' @param text Badge text
#' @param status Status type (primary, success, warning, danger, info)
#' @param tooltip Optional tooltip text
#' @return Shiny badge element
#' @export
create_status_badge <- function(text, status = "primary", tooltip = NULL) {
  badge <- span(class = paste("badge badge-", status, sep = ""), text)
  
  if (!is.null(tooltip)) {
    badge <- span(title = tooltip, `data-toggle` = "tooltip", badge)
  }
  
  return(badge)
}

#' Create Progress Bar
#' 
#' @param value Progress value (0-100)
#' @param label Progress label
#' @param color Progress bar color
#' @param striped Whether to show stripes
#' @param animated Whether to animate stripes
#' @return Shiny progress bar element
#' @export
create_progress_bar <- function(value, label = NULL, color = "primary", 
                               striped = FALSE, animated = FALSE) {
  classes <- paste("progress-bar bg-", color, sep = "")
  if (striped) classes <- paste(classes, "progress-bar-striped")
  if (animated) classes <- paste(classes, "progress-bar-animated")
  
  div(class = "progress",
    div(class = classes,
        style = paste0("width: ", value, "%"),
        `role` = "progressbar",
        `aria-valuenow` = value,
        `aria-valuemin` = "0",
        `aria-valuemax` = "100",
        if (!is.null(label)) label else paste0(value, "%")
    )
  )
}

#' Create Alert Box
#' 
#' @param message Alert message
#' @param type Alert type (success, info, warning, danger)
#' @param dismissible Whether alert can be dismissed
#' @param icon Optional icon
#' @return Shiny alert element
#' @export
create_alert <- function(message, type = "info", dismissible = TRUE, icon = NULL) {
  classes <- paste("alert alert-", type, sep = "")
  if (dismissible) classes <- paste(classes, "alert-dismissible")
  
  alert_content <- list()
  
  if (dismissible) {
    alert_content <- append(alert_content, list(
      button(type = "button", class = "close", `data-dismiss` = "alert",
        span(`aria-hidden` = "true", HTML("&times;")),
        span(class = "sr-only", "Fechar")
      )
    ))
  }
  
  if (!is.null(icon)) {
    alert_content <- append(alert_content, list(
      i(class = paste("fa fa-", icon, sep = "")), " "
    ))
  }
  
  alert_content <- append(alert_content, list(message))
  
  div(class = classes, `role` = "alert", alert_content)
}

#' Create Loading Spinner
#' 
#' @param size Spinner size (sm, md, lg)
#' @param color Spinner color
#' @param text Optional loading text
#' @return Shiny loading spinner element
#' @export
create_loading_spinner <- function(size = "md", color = "primary", text = NULL) {
  spinner_classes <- paste("spinner-border text-", color, sep = "")
  if (size == "sm") spinner_classes <- paste(spinner_classes, "spinner-border-sm")
  
  spinner_div <- div(class = spinner_classes, `role` = "status",
    span(class = "sr-only", "Carregando...")
  )
  
  if (!is.null(text)) {
    div(class = "text-center",
      spinner_div,
      br(),
      span(text)
    )
  } else {
    div(class = "text-center", spinner_div)
  }
}

#' Create Card Component
#' 
#' @param title Card title
#' @param content Card content (can be HTML or Shiny elements)
#' @param footer Optional card footer
#' @param color Card color theme
#' @param collapsible Whether card can be collapsed
#' @return Shiny card element
#' @export
create_card <- function(title, content, footer = NULL, color = "primary", 
                       collapsible = FALSE) {
  card_id <- paste0("card_", gsub("[^A-Za-z0-9]", "_", title))
  
  header_content <- list(h4(class = "card-title", title))
  
  if (collapsible) {
    header_content <- list(
      h4(class = "card-title",
        a(`data-toggle` = "collapse", 
          `data-target` = paste0("#", card_id, "_body"),
          `aria-expanded` = "true",
          title,
          i(class = "fa fa-chevron-down float-right")
        )
      )
    )
  }
  
  body_classes <- "card-body"
  if (collapsible) body_classes <- paste(body_classes, "collapse show")
  
  card_elements <- list(
    div(class = paste("card-header bg-", color, " text-white", sep = ""),
      header_content
    ),
    div(id = if(collapsible) paste0(card_id, "_body") else NULL,
        class = body_classes,
      content
    )
  )
  
  if (!is.null(footer)) {
    card_elements <- append(card_elements, list(
      div(class = "card-footer", footer)
    ))
  }
  
  div(class = "card", card_elements)
}

#' Create Breadcrumb Navigation
#' 
#' @param items List of breadcrumb items (name and optional href)
#' @return Shiny breadcrumb navigation
#' @export
create_breadcrumb <- function(items) {
  breadcrumb_items <- lapply(seq_along(items), function(i) {
    item <- items[[i]]
    is_last <- i == length(items)
    
    if (is_last) {
      li(class = "breadcrumb-item active", `aria-current` = "page", item$name)
    } else {
      li(class = "breadcrumb-item",
        if (!is.null(item$href)) {
          a(href = item$href, item$name)
        } else {
          item$name
        }
      )
    }
  })
  
  nav(`aria-label` = "breadcrumb",
    ol(class = "breadcrumb", breadcrumb_items)
  )
}

#' Add Custom CSS Styles
#' 
#' @return HTML head element with custom styles
#' @export
add_custom_styles <- function() {
  tags$head(
    tags$style(HTML("
      /* Custom styles for Monitor Legislativo v4 */
      .info-box {
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        transition: transform 0.2s ease-in-out;
      }
      
      .info-box:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.15);
      }
      
      .filter-panel-content {
        background-color: #f8f9fa;
        padding: 15px;
        border-radius: 5px;
      }
      
      .search-results-container {
        margin-top: 20px;
      }
      
      .status-indicator {
        display: inline-block;
        width: 12px;
        height: 12px;
        border-radius: 50%;
        margin-right: 8px;
      }
      
      .status-indicator.online {
        background-color: #28a745;
      }
      
      .status-indicator.offline {
        background-color: #dc3545;
      }
      
      .status-indicator.warning {
        background-color: #ffc107;
      }
      
      .card {
        margin-bottom: 20px;
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      }
      
      .table-responsive {
        border-radius: 8px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
      }
      
      .brazilian-flag-colors {
        background: linear-gradient(135deg, #009739 0%, #FFDF00 50%, #002776 100%);
      }
      
      .mobile-friendly {
        font-size: 16px; /* Prevents zoom on mobile */
      }
      
      @media (max-width: 768px) {
        .info-box {
          margin-bottom: 15px;
        }
        
        .card {
          margin-bottom: 15px;
        }
        
        .table-responsive {
          font-size: 14px;
        }
      }
      
      /* Accessibility improvements */
      .sr-only {
        position: absolute;
        width: 1px;
        height: 1px;
        padding: 0;
        margin: -1px;
        overflow: hidden;
        clip: rect(0,0,0,0);
        white-space: nowrap;
        border: 0;
      }
      
      /* Focus indicators */
      .btn:focus,
      .form-control:focus,
      .form-select:focus {
        outline: 2px solid #007bff;
        outline-offset: 2px;
      }
    "))
  )
}

#' Create Mobile-Responsive Navigation
#' 
#' @param brand_name Application brand name
#' @param nav_items List of navigation items
#' @return Shiny navigation bar
#' @export
create_navbar <- function(brand_name, nav_items) {
  tags$nav(class = "navbar navbar-expand-lg navbar-dark bg-primary",
    div(class = "container-fluid",
      a(class = "navbar-brand", href = "#", brand_name),
      button(class = "navbar-toggler", type = "button",
             `data-bs-toggle` = "collapse", `data-bs-target` = "#navbarNav",
        span(class = "navbar-toggler-icon")
      ),
      div(class = "collapse navbar-collapse", id = "navbarNav",
        ul(class = "navbar-nav ms-auto",
          lapply(nav_items, function(item) {
            li(class = "nav-item",
              a(class = "nav-link", href = item$href %||% "#", item$name)
            )
          })
        )
      )
    )
  )
}

cat("✅ UI utilities module loaded successfully\n")