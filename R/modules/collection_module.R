# collection_module.R - Document Collection Management Module
# ============================================================================
# Purpose: Allows users to create and manage collections of legislative documents
# Created: 2025
# Features:
#  - Create named collections
#  - Add/remove documents from collections
#  - Export collections
#  - Share collections
# ============================================================================

library(shiny)
library(DT)

#' Collection Module UI
#'
#' @param id Module namespace ID
#' @return Shiny UI element
#' @export
collectionUI <- function(id) {
  ns <- NS(id)

  tagList(
    # Modal dialog for creating collections
    uiOutput(ns("collection_modal")),

    # Collection management panel
    div(
      id = ns("collection_panel"),
      style = "margin-top: 15px;",

      h4(icon("folder-plus"), "Minhas Coleções"),

      # Collection list
      uiOutput(ns("collection_list")),

      # Create collection button
      actionButton(
        ns("create_collection_btn"),
        "Nova Coleção",
        icon = icon("plus"),
        class = "btn-primary btn-sm"
      )
    )
  )
}

#' Collection Module Server
#'
#' @param id Module namespace ID
#' @param selected_documents Reactive expression returning selected document IDs
#' @return Server logic
#' @export
collectionServer <- function(id, selected_documents = NULL) {
  moduleServer(id, function(input, output, session) {
    ns <- session$ns

    # Reactive values for collections
    collections <- reactiveValues(
      data = list(),  # List of collections
      current = NULL  # Currently selected collection
    )

    # Initialize with default collections
    observe({
      if (length(collections$data) == 0) {
        collections$data <- list(
          list(
            id = "default",
            name = "Favoritos",
            description = "Documentos favoritos",
            documents = c(),
            created = Sys.time(),
            modified = Sys.time()
          )
        )
      }
    })

    # Show collection creation modal
    observeEvent(input$create_collection_btn, {
      showModal(modalDialog(
        title = "Criar Nova Coleção",
        size = "m",

        textInput(
          ns("new_collection_name"),
          "Nome da Coleção:",
          placeholder = "Ex: Legislação Ambiental"
        ),

        textAreaInput(
          ns("new_collection_description"),
          "Descrição:",
          placeholder = "Descrição opcional da coleção",
          rows = 3
        ),

        footer = tagList(
          modalButton("Cancelar"),
          actionButton(
            ns("confirm_create_collection"),
            "Criar Coleção",
            icon = icon("check"),
            class = "btn-primary"
          )
        )
      ))
    })

    # Create collection
    observeEvent(input$confirm_create_collection, {
      collection_name <- input$new_collection_name
      collection_description <- input$new_collection_description

      if (is.null(collection_name) || collection_name == "") {
        showNotification(
          "Por favor, insira um nome para a coleção.",
          type = "warning"
        )
        return()
      }

      # Create new collection
      new_id <- paste0("col_", format(Sys.time(), "%Y%m%d%H%M%S"))
      new_collection <- list(
        id = new_id,
        name = collection_name,
        description = collection_description,
        documents = c(),
        created = Sys.time(),
        modified = Sys.time()
      )

      # Add to collections
      collections$data[[length(collections$data) + 1]] <- new_collection

      showNotification(
        paste("Coleção", collection_name, "criada com sucesso!"),
        type = "message"
      )

      removeModal()
    })

    # Render collection list
    output$collection_list <- renderUI({
      if (length(collections$data) == 0) {
        return(p("Nenhuma coleção criada ainda.", style = "color: #666;"))
      }

      collection_items <- lapply(collections$data, function(col) {
        div(
          class = "collection-item",
          style = "padding: 10px; margin: 5px 0; background-color: #f8f9fa; border-radius: 4px; border-left: 4px solid #007bff;",

          div(
            style = "display: flex; justify-content: space-between; align-items: center;",

            div(
              style = "flex: 1;",
              tags$strong(col$name),
              if (!is.null(col$description) && col$description != "") {
                tags$small(
                  style = "display: block; color: #666; margin-top: 4px;",
                  col$description
                )
              },
              tags$small(
                style = "display: block; color: #999; margin-top: 4px;",
                icon("file"),
                " ", length(col$documents), " documentos"
              )
            ),

            div(
              style = "display: flex; gap: 5px;",

              actionButton(
                ns(paste0("view_", col$id)),
                NULL,
                icon = icon("eye"),
                class = "btn-sm btn-info",
                title = "Ver documentos"
              ),

              actionButton(
                ns(paste0("export_", col$id)),
                NULL,
                icon = icon("download"),
                class = "btn-sm btn-success",
                title = "Exportar coleção"
              ),

              actionButton(
                ns(paste0("delete_", col$id)),
                NULL,
                icon = icon("trash"),
                class = "btn-sm btn-danger",
                title = "Excluir coleção"
              )
            )
          )
        )
      })

      do.call(tagList, collection_items)
    })

    # Add document to collection
    add_to_collection <- function(collection_id, document_ids) {
      for (i in seq_along(collections$data)) {
        if (collections$data[[i]]$id == collection_id) {
          # Add documents (avoid duplicates)
          current_docs <- collections$data[[i]]$documents
          new_docs <- unique(c(current_docs, document_ids))
          collections$data[[i]]$documents <- new_docs
          collections$data[[i]]$modified <- Sys.time()

          showNotification(
            paste(length(document_ids), "documento(s) adicionado(s) à coleção"),
            type = "message"
          )
          return()
        }
      }
    }

    # Remove document from collection
    remove_from_collection <- function(collection_id, document_ids) {
      for (i in seq_along(collections$data)) {
        if (collections$data[[i]]$id == collection_id) {
          current_docs <- collections$data[[i]]$documents
          updated_docs <- setdiff(current_docs, document_ids)
          collections$data[[i]]$documents <- updated_docs
          collections$data[[i]]$modified <- Sys.time()

          showNotification(
            paste(length(document_ids), "documento(s) removido(s) da coleção"),
            type = "message"
          )
          return()
        }
      }
    }

    # Export collection
    export_collection <- function(collection_id) {
      for (col in collections$data) {
        if (col$id == collection_id) {
          # Return collection data for export
          return(list(
            collection_name = col$name,
            collection_description = col$description,
            document_ids = col$documents,
            created = col$created,
            modified = col$modified
          ))
        }
      }
      return(NULL)
    }

    # Delete collection
    observeEvent(input$delete_default, {
      showNotification(
        "Não é possível excluir a coleção de favoritos.",
        type = "warning"
      )
    })

    # Generic delete handler
    observe({
      # Observe all delete buttons dynamically
      for (col in collections$data) {
        if (col$id == "default") next  # Skip default collection

        local({
          col_id <- col$id
          delete_btn <- paste0("delete_", col_id)

          observeEvent(input[[delete_btn]], {
            showModal(modalDialog(
              title = "Confirmar Exclusão",
              paste("Tem certeza que deseja excluir a coleção", col$name, "?"),
              footer = tagList(
                modalButton("Cancelar"),
                actionButton(
                  ns(paste0("confirm_delete_", col_id)),
                  "Excluir",
                  icon = icon("trash"),
                  class = "btn-danger"
                )
              )
            ))
          })

          observeEvent(input[[paste0("confirm_delete_", col_id)]], {
            # Remove collection
            collections$data <- Filter(function(c) c$id != col_id, collections$data)

            showNotification(
              "Coleção excluída com sucesso.",
              type = "message"
            )

            removeModal()
          })
        })
      }
    })

    # Return functions for external use
    return(list(
      add_to_collection = add_to_collection,
      remove_from_collection = remove_from_collection,
      export_collection = export_collection,
      collections = reactive({ collections$data }),
      current_collection = reactive({ collections$current })
    ))
  })
}

#' Get collection data for export
#'
#' @param collection_id Collection ID
#' @param all_documents Data frame of all documents
#' @return Data frame of documents in collection
#' @export
get_collection_documents <- function(collection_id, all_documents, collections_data) {
  for (col in collections_data) {
    if (col$id == collection_id) {
      # Filter documents by IDs in collection
      if (length(col$documents) > 0) {
        return(all_documents[all_documents$id %in% col$documents, ])
      } else {
        return(data.frame())
      }
    }
  }
  return(data.frame())
}
