 # Improvement Roadmap

## 1. Introduction

This document outlines a roadmap for further improving the codebase of the Academic Transport Legislation Monitor application. The proposed improvements are based on the findings of the code analysis report and are designed to enhance the application's performance, maintainability, and accessibility.

## 2. Short-Term Goals (1-2 weeks)

### 2.1. Complete CSS Modularization

*   **Task:** Finish moving all component-specific styles from `globals.css` to their own separate CSS files.
*   **Rationale:** This will improve the modularity and maintainability of the codebase, making it easier to work with individual components without affecting the styles of other components.
*   **Action Items:**
    *   Create separate CSS files for the remaining components (e.g., `LoadingSpinner.css`, `ErrorBoundary.css`).
    *   Move the relevant styles from `globals.css` to the new files.
    *   Import the new CSS files into their corresponding components.
    *   Remove the duplicated styles from `globals.css`.

### 2.2. Implement PNG Map Export

*   **Task:** Implement the functionality to export the current map view as a PNG image.
*   **Rationale:** This was a planned feature that is currently disabled. Implementing it will provide users with a valuable new feature.
*   **Action Items:**
    *   Choose a library for converting the map to an image (e.g., `html2canvas`).
    *   Add a function to the `ExportPanel.tsx` component to handle the PNG export.
    *   Enable the PNG export option in the UI.

## 3. Medium-Term Goals (1-2 months)

### 3.1. State Management Refactoring

*   **Task:** Refactor the state management in the `Dashboard.tsx` component.
*   **Rationale:** The `Dashboard.tsx` component currently has a lot of `useState` hooks, which can make the state management complex and difficult to maintain. Using a state management library like Redux or Zustand, or even React's built-in `useReducer` hook, can help to simplify the state management and make the code more predictable.
*   **Action Items:**
    *   Evaluate different state management solutions and choose the one that best fits the project's needs.
    *   Refactor the `Dashboard.tsx` component to use the chosen state management solution.

### 3.2. Add Unit and Integration Tests

*   **Task:** Add unit and integration tests to the codebase.
*   **Rationale:** The codebase currently has no tests. Adding tests will help to prevent regressions and ensure that the application is working as expected.
*   **Action Items:**
    *   Choose a testing framework (e.g., Jest, Vitest).
    *   Write unit tests for the utility functions and individual components.
    *   Write integration tests for the main features, such as filtering and exporting data.

## 4. Long-Term Goals (3-6 months)

### 4.1. Real-time Data Integration

*   **Task:** Replace the mock data with real-time data from an API.
*   **Rationale:** The application currently uses mock data. Integrating with a real-time data source will make the application much more useful for academic research.
*   **Action Items:**
    *   Identify a suitable API for accessing Brazilian legislative data.
    *   Create a service for fetching data from the API.
    *   Update the application to use the real-time data instead of the mock data.

### 4.2. User Authentication and Accounts

*   **Task:** Add user authentication and accounts.
*   **Rationale:** This will allow users to save their searches and preferences, and it will also provide a foundation for more advanced features, such as collaboration and data sharing.
*   **Action Items:**
    *   Choose an authentication provider (e.g., Auth0, Firebase Authentication).
    *   Implement a login and registration system.
    *   Create a database for storing user data.
    *   Add features for saving searches and preferences.
