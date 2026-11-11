# Kavach Project: Comprehensive System Documentation (V.0.1)

## 🎯 1. Executive Summary and Project Goals

The Kavach project is a sophisticated, open-source security auditing suite designed to integrate rigorous security checks into a project's development lifecycle and CI/CD pipeline. The primary goal of Kavach is to move security analysis from a reactive, post-launch operation to a proactive, pre-commit process.

Kavach provides a standardized mechanism to analyze software artifacts (code and configuration) against multiple, predefined vulnerability profiles. The system's final output is normalized into the industry-standard [SARIF 2.1.0](https://sarif.dev/) format, ensuring the findings are consumable by downstream security tooling.

**Primary Objectives:**
*   To automate security review stages using defined profiles (quick, standard, deep).
*   To provide actionable results via standardized machine-readable formats (SARIF).
*   To integrate seamlessly within environments requiring defined operational budgets (model-call limits).

**Key Stakeholders:**
*   **Developers:** Benefit from early detection of vulnerabilities before merge.
*   **Security Engineers:** Use the standardized SARIF output for centralized risk management.
*   **DevOps Engineers:** Integrate the tool via CI/CD platforms (e.g., GitHub Actions).

## 🛠️ 2. Technical Architecture and System Components

Kavach operates as a distributed process consisting of a Command-Line Interface (CLI), a primary background service, and several specialized analysis agents.

### 2.1. Core Components

| Component | Implementation File | Function | Interaction |
| :--- | :--- | :--- | :--- |
| **Kavach CLI** | `kavach-cli.mjs` | The primary entry point. Executes the system, consumes arguments, and manages the scanning workflow lifecycle. | **Input:** `path`, `sarif-file`, `profile`, `fail-on`. **Output:** Execution status. |
| **Kavach Server** | `server.mjs` | The persistent service layer (run via `npm run start`). Handles long-running operations, state management, and potential communication with external AI/knowledge bases (if configured). | Manages runtime state and complex logic not required for a single scan. |
| **Analysis Agents** | (Internal Logic) | Specialized modular runners responsible for different checks (e.g., Dependency/OSV checks, code pattern matching). | The CLI orchestrates which agents run based on the selected `profile`. |
| **Configuration Handlers** | `package.json` | Defines environment constraints, required node versioning, and project metadata. | Ensures the execution runner meets the minimum requirements. |

### 2.2. Workflow Diagram (Conceptual)

1.  **Start (CLI Invocation):** A user triggers `npm run scan`.
2.  **Input Validation:** The CLI validates inputs (`path`, `sarif-file`, `profile`).
3.  **Profile Activation:** Based on the chosen profile (e.g., 'deep'), the required sequence of analysis agents is determined.
4.  **Execution Phase:** Analysis agents run concurrently or sequentially, generating raw findings.
5.  **Post-Processing & Normalization:** Raw findings are consolidated and translated into the structured SARIF JSON payload.
6.  **Output & Exit:** The finalized `kavach.sarif.json` is written, and an exit code is determined (0=Success, 1=Threshold Reached, 2=Runtime Error, 3=Incomplete).

## 🔑 3. Core Features and Input Parameters

Kavach's functionality is highly configurable through its configuration files, enabling various security use cases.

### 3.1. Security Profiles (Profiling)
Kavach employs different profiles to adjust the depth and breadth of analysis:

*   **`quick` (Default):** Minimal, fast checks focusing on high-severity, immediately identifiable issues. Suitable for fast CI pre-hooks.
*   **`standard`:** A balanced audit that includes dependency checks (OSV) and basic pattern matching, suitable for daily integration.
*   **`deep`:** The maximum-effort audit. Includes dependency checks, sophisticated code pattern analysis, and extensive resource consumption (high model-call budget).

### 3.2. Key Inputs and Constraints
The security scan relies on the following inputs, which enforce strict operational constraints:

*   **`path` (String, Required):** Specifies the root directory of the project to be analyzed.
*   **`sarif-file` (String, Optional Default `.kavach/kavach.sarif.json`):** The mandatory destination path for the final, standardized SARIF output file.
*   **`fail-on` (String, Optional Default `confirmed`):** The threshold that determines if the CI should fail. Values include `confirmed`, `high`, `critical`, or `never`.
*   **`budget` (Number, Optional Default `12`):** Limits the resource consumption (Maximum model-call budget, ranging from 12 to 512). This mechanism imposes an operational cost control over the scanning process.
*   **`osv` (Boolean, Optional Default `false`):** Toggles the service to query the Open Source Vulnerability (OSV) database for exact dependency versions.

### 3.3. Outputs
The primary output is singular: a SARIF JSON file, which contains all vulnerability data, severity information, and source references from the analysis.

## ⚙️ 4. Technical Specifications (Environment and Dependencies)

### 4.1. Runtime Requirements
*   **Engine/Runtime:** Requires **Node.js** version `>=22`.
*   **Package Manager:** Assumes standard npm usage.
*   **Operating System:** Designed for cross-platform operation, though stability is tested on common Unix-like systems.

### 4.2. Dependencies
Kavach relies on the following ecosystem packages:

*   **`dotenv`:** Used for secure and dynamic loading of environment variables, allowing configuration to remain external to the source code.
*   **`firebase-admin`:** Implies specific integration or reliance on Firebase managed services for certain features or credentials (requires configuration).
*   **`pg`:** Indicates the system maintains compatibility with PostgreSQL databases, possibly for historical logging or complex state tracking.

## ➡️ 5. Conclusion and Future Scope

Kavach, in its current V.0.1 form, establishes a robust, security-conscious template. It successfully encapsulates the core logic required for a disciplined security review process. Future work should focus on expanding the agent set to cover unique project semantics, which would warrant extending this documentation into specialized API guides for each scanning capability.

*This document was created by synthesizing all available metadata from the project manifests and configuration files (action.yml, package.json) with a focus on high-level conceptual clarity.*