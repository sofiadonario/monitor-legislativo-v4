# =============================================================================
# Accessibility Enhancement System (WCAG 2.1 AA Compliance)
# =============================================================================
# Monitor Legislativo v4 - Phase 4 Task 4.6
#
# Provides comprehensive accessibility improvements including:
# - Keyboard navigation support
# - Screen reader announcements
# - ARIA labels and landmarks
# - Focus management
# - Skip links and shortcuts
#
# Author: Monitor Legislativo v4 Team
# Version: 4.0.0
# Last Updated: 2025-11-21
# Standards: WCAG 2.1 AA, Brazilian e-MAG 3.1
# =============================================================================

library(htmltools)
library(shiny)

#' Add Skip Navigation Link
#'
#' Adds a skip link for keyboard users to bypass navigation
#' WCAG 2.1 SC 2.4.1 (Bypass Blocks - Level A)
#'
#' @param main_content_id ID of main content area (default: "main-content")
#' @return HTML tags for skip link
#' @export
add_skip_link <- function(main_content_id = "main-content") {
  tags$a(
    href = paste0("#", main_content_id),
    class = "skip-link",
    tabindex = "0",
    "Pular para o conteúdo principal",
    style = "
      position: absolute;
      left: -9999px;
      z-index: 999;
      padding: 1em;
      background: #000;
      color: #fff;
      text-decoration: none;
      &:focus {
        left: 0;
        top: 0;
      }
    "
  )
}

#' Add ARIA Landmarks
#'
#' Wraps content in semantic ARIA landmarks for screen readers
#' WCAG 2.1 SC 1.3.1 (Info and Relationships - Level A)
#'
#' @param content HTML content
#' @param role ARIA role (banner, navigation, main, complementary, contentinfo)
#' @param label ARIA label for the landmark
#' @return HTML div with ARIA attributes
#' @export
aria_landmark <- function(content, role = "main", label = NULL) {
  attrs <- list(role = role)

  if (!is.null(label)) {
    attrs[["aria-label"]] <- label
  }

  do.call(tags$div, c(attrs, list(content)))
}

#' Add Screen Reader Announcements
#'
#' Creates live region for dynamic content announcements
#' WCAG 2.1 SC 4.1.3 (Status Messages - Level AA)
#'
#' @param id ID for the live region
#' @param politeness "polite" or "assertive" (default: "polite")
#' @return HTML div for live announcements
#' @export
add_live_region <- function(id = "sr-announcements", politeness = "polite") {
  tags$div(
    id = id,
    class = "sr-only",
    role = "status",
    `aria-live` = politeness,
    `aria-atomic` = "true",
    style = "
      position: absolute;
      left: -10000px;
      width: 1px;
      height: 1px;
      overflow: hidden;
    "
  )
}

#' Announce to Screen Reader
#'
#' JavaScript function to announce messages to screen readers
#'
#' @param message Message to announce
#' @param region_id ID of live region (default: "sr-announcements")
#' @return JavaScript code
#' @export
announce_to_sr <- function(message, region_id = "sr-announcements") {
  sprintf("
    (function() {
      var region = document.getElementById('%s');
      if (region) {
        region.textContent = '%s';
        setTimeout(function() {
          region.textContent = '';
        }, 1000);
      }
    })();
  ", region_id, gsub("'", "\\\\'", message))
}

#' Enhanced Button with ARIA
#'
#' Creates accessible button with proper ARIA attributes
#' WCAG 2.1 SC 4.1.2 (Name, Role, Value - Level A)
#'
#' @param input_id Input ID
#' @param label Button label
#' @param icon Optional icon
#' @param aria_label Custom ARIA label (overrides visible label)
#' @param aria_describedby ID of element describing the button
#' @param disabled Whether button is disabled
#' @return Action button with ARIA attributes
#' @export
accessible_action_button <- function(input_id, label, icon = NULL,
                                     aria_label = NULL, aria_describedby = NULL,
                                     disabled = FALSE) {

  aria_attrs <- list()

  if (!is.null(aria_label)) {
    aria_attrs[["aria-label"]] <- aria_label
  }

  if (!is.null(aria_describedby)) {
    aria_attrs[["aria-describedby"]] <- aria_describedby
  }

  if (disabled) {
    aria_attrs[["aria-disabled"]] <- "true"
    aria_attrs[["disabled"]] <- "disabled"
  }

  btn_content <- if (!is.null(icon)) {
    tagList(icon(icon), " ", label)
  } else {
    label
  }

  do.call(
    actionButton,
    c(list(inputId = input_id, label = btn_content), aria_attrs)
  )
}

#' Enhanced Data Table with ARIA
#'
#' Wraps DT::datatable with accessibility attributes
#' WCAG 2.1 SC 1.3.1 (Info and Relationships - Level A)
#'
#' @param data Data frame
#' @param caption Table caption for screen readers
#' @param options DT options
#' @return Accessible data table
#' @export
accessible_datatable <- function(data, caption = NULL, options = list()) {

  # Add accessibility options
  default_options <- list(
    dom = 'Bfrtip',
    buttons = list(
      list(
        extend = 'collection',
        text = 'Exportar',
        buttons = c('copy', 'excel', 'csv', 'pdf', 'print')
      )
    ),
    language = list(
      aria = list(
        sortAscending = ": ativar para ordenar coluna em ordem crescente",
        sortDescending = ": ativar para ordenar coluna em ordem decrescente"
      ),
      paginate = list(
        first = "Primeira",
        last = "Última",
        next = "Próxima",
        previous = "Anterior"
      ),
      search = "Buscar:",
      lengthMenu = "Mostrar _MENU_ registros por página",
      info = "Mostrando _START_ a _END_ de _TOTAL_ registros",
      infoEmpty = "Nenhum registro disponível",
      infoFiltered = "(filtrado de _MAX_ registros no total)",
      zeroRecords = "Nenhum registro encontrado"
    )
  )

  # Merge with user options
  final_options <- modifyList(default_options, options)

  dt <- DT::datatable(
    data,
    options = final_options,
    caption = caption,
    escape = FALSE
  )

  # Wrap in container with ARIA attributes
  tagList(
    tags$div(
      role = "region",
      `aria-label` = caption %||% "Tabela de dados",
      tabindex = "0",
      dt
    )
  )
}

#' Focus Management
#'
#' Manages focus for keyboard navigation
#' WCAG 2.1 SC 2.4.3 (Focus Order - Level A)
#'
#' @param element_id ID of element to focus
#' @return JavaScript code
#' @export
set_focus <- function(element_id) {
  sprintf("
    setTimeout(function() {
      var element = document.getElementById('%s');
      if (element) {
        element.focus();
        element.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
    }, 100);
  ", element_id)
}

#' Keyboard Shortcut System
#'
#' Adds keyboard shortcuts with visual indicators
#' WCAG 2.1 SC 2.1.1 (Keyboard - Level A)
#'
#' @param shortcuts List of shortcuts (key = shortcut, value = action)
#' @return HTML for shortcut system
#' @export
add_keyboard_shortcuts <- function(shortcuts = list(
  "Alt+H" = "home",
  "Alt+L" = "library",
  "Alt+M" = "maps",
  "Alt+S" = "search",
  "Alt+?" = "help"
)) {

  # Create help modal content
  help_content <- tags$div(
    role = "dialog",
    `aria-labelledby` = "shortcuts-title",
    `aria-modal` = "true",
    tags$h2(id = "shortcuts-title", "Atalhos de Teclado"),
    tags$ul(
      lapply(names(shortcuts), function(key) {
        tags$li(
          tags$kbd(key), " - ",
          shortcuts[[key]]
        )
      })
    )
  )

  # JavaScript for shortcut handling
  shortcut_js <- sprintf("
    document.addEventListener('keydown', function(e) {
      // Alt+H - Home
      if (e.altKey && e.key === 'h') {
        e.preventDefault();
        var homeTab = document.querySelector('a[data-value=\"home\"]');
        if (homeTab) homeTab.click();
      }

      // Alt+L - Library
      if (e.altKey && e.key === 'l') {
        e.preventDefault();
        var libraryTab = document.querySelector('a[data-value=\"library\"]');
        if (libraryTab) libraryTab.click();
      }

      // Alt+M - Maps
      if (e.altKey && e.key === 'm') {
        e.preventDefault();
        var mapsTab = document.querySelector('a[data-value=\"maps\"]');
        if (mapsTab) mapsTab.click();
      }

      // Alt+S - Search focus
      if (e.altKey && e.key === 's') {
        e.preventDefault();
        var searchInput = document.querySelector('input[type=\"search\"]');
        if (searchInput) searchInput.focus();
      }

      // Alt+? - Help
      if (e.altKey && e.key === '?') {
        e.preventDefault();
        alert('%s');
      }
    });
  ", paste(sprintf("%s: %s", names(shortcuts), shortcuts), collapse = "\\n"))

  tags$script(HTML(shortcut_js))
}

#' Enhanced Form Input with Labels
#'
#' Creates form input with proper label association
#' WCAG 2.1 SC 1.3.1, SC 3.3.2 (Labels or Instructions - Level A)
#'
#' @param input_id Input ID
#' @param label Label text
#' @param type Input type
#' @param required Whether field is required
#' @param help_text Optional help text
#' @param error_message Optional error message
#' @return HTML form group
#' @export
accessible_text_input <- function(input_id, label, type = "text",
                                  required = FALSE, help_text = NULL,
                                  error_message = NULL) {

  label_id <- paste0(input_id, "-label")
  help_id <- paste0(input_id, "-help")
  error_id <- paste0(input_id, "-error")

  input_attrs <- list(
    id = input_id,
    type = type,
    class = "form-control",
    `aria-labelledby` = label_id
  )

  if (required) {
    input_attrs[["required"]] <- "required"
    input_attrs[["aria-required"]] <- "true"
  }

  if (!is.null(help_text)) {
    input_attrs[["aria-describedby"]] <- help_id
  }

  if (!is.null(error_message)) {
    input_attrs[["aria-describedby"]] <- paste(
      input_attrs[["aria-describedby"]], error_id
    )
    input_attrs[["aria-invalid"]] <- "true"
    input_attrs[["class"]] <- "form-control is-invalid"
  }

  tags$div(
    class = "form-group",
    tags$label(
      id = label_id,
      `for` = input_id,
      label,
      if (required) tags$span(class = "required", `aria-label` = "obrigatório", "*")
    ),
    do.call(tags$input, input_attrs),
    if (!is.null(help_text)) {
      tags$small(id = help_id, class = "form-text text-muted", help_text)
    },
    if (!is.null(error_message)) {
      tags$div(
        id = error_id,
        class = "invalid-feedback",
        role = "alert",
        error_message
      )
    }
  )
}

#' Accessible Loading Indicator
#'
#' Creates loading indicator with screen reader announcement
#' WCAG 2.1 SC 4.1.3 (Status Messages - Level AA)
#'
#' @param message Loading message
#' @return HTML for loading indicator
#' @export
accessible_loading <- function(message = "Carregando...") {
  tags$div(
    class = "loading-indicator",
    role = "status",
    `aria-live` = "polite",
    `aria-busy` = "true",
    tags$span(class = "spinner-border spinner-border-sm", role = "status"),
    " ",
    tags$span(message),
    tags$span(class = "sr-only", "Por favor aguarde")
  )
}

#' Color Contrast Checker
#'
#' Validates color contrast ratios meet WCAG AA standards
#' WCAG 2.1 SC 1.4.3 (Contrast Minimum - Level AA)
#'
#' @param foreground Foreground color (hex)
#' @param background Background color (hex)
#' @param large_text Whether text is large (18pt+ or 14pt+ bold)
#' @return List with contrast ratio and pass/fail
#' @export
check_contrast <- function(foreground, background, large_text = FALSE) {

  # Convert hex to RGB
  hex_to_rgb <- function(hex) {
    hex <- gsub("#", "", hex)
    r <- strtoi(substr(hex, 1, 2), base = 16) / 255
    g <- strtoi(substr(hex, 3, 4), base = 16) / 255
    b <- strtoi(substr(hex, 5, 6), base = 16) / 255
    c(r, g, b)
  }

  # Calculate relative luminance
  luminance <- function(rgb) {
    rgb <- sapply(rgb, function(val) {
      if (val <= 0.03928) {
        val / 12.92
      } else {
        ((val + 0.055) / 1.055)^2.4
      }
    })
    0.2126 * rgb[1] + 0.7152 * rgb[2] + 0.0722 * rgb[3]
  }

  # Calculate contrast ratio
  fg_rgb <- hex_to_rgb(foreground)
  bg_rgb <- hex_to_rgb(background)

  l1 <- luminance(fg_rgb)
  l2 <- luminance(bg_rgb)

  ratio <- if (l1 > l2) {
    (l1 + 0.05) / (l2 + 0.05)
  } else {
    (l2 + 0.05) / (l1 + 0.05)
  }

  # WCAG AA requirements
  required_ratio <- if (large_text) 3.0 else 4.5

  list(
    contrast_ratio = round(ratio, 2),
    passes_aa = ratio >= required_ratio,
    required_ratio = required_ratio,
    level = if (ratio >= 7.0) "AAA" else if (ratio >= required_ratio) "AA" else "Fail"
  )
}

#' Initialize Accessibility Features
#'
#' Sets up all accessibility features for the application
#'
#' @param session Shiny session object
#' @export
initialize_accessibility <- function(session) {
  cat("♿ Initializing accessibility features\n")

  # Add custom CSS for accessibility
  insertUI(
    selector = "head",
    where = "beforeEnd",
    ui = tags$style(HTML("
      /* Focus indicators */
      *:focus {
        outline: 3px solid #4A90E2;
        outline-offset: 2px;
      }

      /* Skip link */
      .skip-link:focus {
        position: absolute;
        left: 0 !important;
        top: 0;
        z-index: 9999;
        padding: 1em;
        background: #000;
        color: #fff;
        text-decoration: none;
      }

      /* Screen reader only */
      .sr-only {
        position: absolute;
        left: -10000px;
        width: 1px;
        height: 1px;
        overflow: hidden;
      }

      /* Keyboard shortcut indicator */
      kbd {
        display: inline-block;
        padding: 3px 5px;
        font-size: 11px;
        line-height: 10px;
        color: #444;
        vertical-align: middle;
        background-color: #f7f7f7;
        border: solid 1px #ccc;
        border-bottom-color: #bbb;
        border-radius: 3px;
        box-shadow: inset 0 -1px 0 #bbb;
      }

      /* High contrast mode support */
      @media (prefers-contrast: high) {
        * {
          border-color: currentColor !important;
        }
      }

      /* Reduced motion support */
      @media (prefers-reduced-motion: reduce) {
        * {
          animation-duration: 0.01ms !important;
          animation-iteration-count: 1 !important;
          transition-duration: 0.01ms !important;
        }
      }
    "))
  )

  cat("✅ Accessibility features initialized\n")
}

cat("✅ Accessibility enhancement system loaded\n")
