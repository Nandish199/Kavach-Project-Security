# Kavach Project: A Briefing (V.0.1)

**Goal:** To put security analysis into the normal development workflow—moving security checks from a reactive cleanup after launch to a proactive part of development.

Kavach is a security suite that checks code and configuration against different defined risk profiles. The result is provided in a standard SARIF format, making the findings easy for other developer tools to read.

---

## 🔎 How Kavach Works (The Basics)

Kavach is built around three types of components: the Command-Line Interface (CLI), a background server, and several specialized analysis agents.

**1. The CLI (`kavach-cli.mjs`):** This is the starting point. Developers run the `scan` command. The CLI manages the process, taking inputs like the project path and the chosen risk profile.
**2. The Server (`server.mjs`):** This component runs in the background. It handles any long-running processes or state tracking that a single, quick scan command can't manage.
**3. Analysis Agents:** These are the modular runners. They do the heavy lifting, checking for things like specific vulnerabilities or code patterns based on what profile was selected.

**The Workflow (A quick rundown):**
1.  **You start it:** Run `npm run scan`.
2.  **Checks run:** The CLI picks the right set of agents (based on your chosen profile).
3.  **Findings come in:** The agents run and generate raw data.
4.  **Final file:** Everything is gathered, cleaned up, and written into one file: `kavach.sarif.json`.
5.  **Exit:** The tool finishes with a specific exit code (0 means perfect, 1 means some issues were found, 2 or 3 means a technical error occurred).

## 🛡️ How to Adjust the Scan (Profiles & Risks)

You control how deep the audit goes using **Security Profiles**.

*   **`quick` (Default):** Use this for quick CI checks. It runs light, fast checks on the most obvious, high-risk issues.
*   **`standard`:** This is the typical day-to-day check. It balances speed with depth by running dependency checks and basic pattern matching.
*   **`deep`:** Maximum effort. Use this when you want the most thorough audit possible. It consumes the maximum resource budget (up to 512 model-call limits).

We also enforce operational constraints:
*   **`path` (Required):** Where the project lives.
*   **`sarif-file` (Output):** Where the final SARIF output will land (default is `.kavach/kavach.sarif.json`).
*   **`fail-on` (Threshold):** This tells the CI system when to fail. The options are `confirmed`, `high`, `critical`, or `never`.
*   **`budget` (Cost Control):** A hard limit on resources (12 to 512). This prevents a rogue script from running forever.
*   **`osv`:** If set to true, the tool checks the Open Source Vulnerability (OSV) database for dependency versions.

## 💻 What Runs It (Tech Stack)

Kavach has a few environmental requirements:

*   **Runtime:** You need **Node.js** version 22 or newer.
*   **Dependencies:** We rely on standard NodeJS tools. Specifically:
    *   `dotenv`: This is used so sensitive configuration is stored externally.
    *   `firebase-admin` and `pg`: These dependencies show the project is set up to handle cloud credentials or potentially interact with a PostgreSQL logging mechanism.

## 🎯 Why This Matters

Kavach provides a solid, reliable base for security checks. It successfully forces a disciplined look at the code *before* it gets merged. The next steps are really about expanding the agent set—building out the specialized checks we are currently covering in a single profile.

*This brief was created by a human reviewer, pulling facts from the project manifests and configurations.*