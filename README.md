# Evasive AI Agent (LangGraph)

An automated red team research tool that uses AI (Google Gemini) and LangGraph to iteratively generate, compile, execute, and refine Windows shellcode loaders that evade EDR detection.

> **Disclaimer**: This tool is intended for **authorized security research and educational purposes only**.

---

## Interactive Web Console

The project includes an **interactive Web UI Console** that lets you run the agent, view execution progress, configure settings, and customize evasion techniques in real time.

### Agent Control Panel & Settings
![Visualizer Agent Control Panel & Settings](img/image.png)

### Key Features & How to Use the Web Console:
1. **Agent Sessions**:
   - The left sidebar displays past and active agent sessions. Clicking a session loads its full iteration history.
2. **Iteration Analysis & Steps**:
   - The main panel breaks down each iteration step-by-step across three phases:
     - **Phase 1: Analysis & Strategy Plan**: Shows what behavior rules/heuristics triggered detection, the AI's gap analysis of exclusions/allowlists, and its bypass strategy.
     - **Phase 2: Code Gen**: View the exact generated C source code and the prompts sent to the LLM.
     - **Phase 3: Review Feedback**: Inspect recommendations from the review agent before code generation.
3. **Agent Control Panel & Settings**:
   - Click the **Control Panel & Config** button at the top of the sidebar.
   - **Launch New Execution**: Specify the shellcode file path, adjust maximum iterations via the slider, and click **Start Agent** to launch the LangGraph agent in the background. The log output will stream in the **Agent Terminal Console Output** in real time.
   - **Config Settings Customizer**:
     - **AI Model & Provider**: Change LLM providers (Google Gemini, OpenAI, Anthropic) or select Gemini models (defaults to `gemini-2.5-flash`).
     - **Success Criteria**: Toggle success verification on and customize type (Process spawning, Network outbound callback, or File creation).
     - **Evasion Techniques Customizer**: Toggle individual memory evasion techniques (e.g., `module_stomping`, `rwx_allocation`, `RW_to_RX`) **ON** or **OFF** to customize the AI agent's active arsenal. Save settings directly to update the configuration immediately!

### Iteration & Code Generation Analysis
The console displays the prompt, response, generated code, and other relevant information for each iteration.
![Iteration Analysis](img/image2.png)

### Session Summary
The Summary page shows which techniques were used in each iteration and the outcome, such as whether the payload was detected or execution failed.
![Summary Page](img/image3.png)

---

## Architecture Overview

```
evasiveAIAgent_LangGraph/
├── main.py                  # CLI entry point
├── requirements.txt         # Python dependencies
├── config/
│   └── config.yaml          # AI, compiler, detector, evasion config
├── core/
│   ├── graph.py             # LangGraph workflow definition
│   ├── state.py             # AgentState schema (TypedDict)
│   ├── nodes.py             # Graph node implementations
│   └── utils.py             # Config loader utility
├── lib/
│   ├── compiler.py          # MSVC / MinGW compilation
│   ├── executor.py          # Loader execution & success monitoring
│   ├── rule_analyzer.py     # TOML behavior rule analysis
│   └── detectors/
│       ├── base.py          # Abstract Detector base class
│       ├── elastic.py       # Elastic Defend / Elasticsearch
│       ├── defender.py      # Windows Defender
│       └── __init__.py      # Detector factory
└── visualizer/
    ├── app.py               # Flask backend for the UI API
    └── templates/
        └── index.html       # Web console frontend
```

---

## Workflow Flowchart

```mermaid
flowchart TD
    START([main.py]) --> INIT[Initialize State]
    INIT --> GEN

    subgraph LOOP ["Iteration Loop (max N times)"]
        GEN["1. Generate Code\n(Gemini AI)"]
        COMPILE["2. Compile\n(MSVC / MinGW)"]
        COMPILE_CHECK{Compiled?}
        EXEC["3. Execute Loader\n(subprocess + shellcode)"]
        EXEC_CHECK{Shellcode\nSuccess?}
        DETECT["4. Check Detections\n(Elastic + Defender)"]
        ANALYZE["5. Analyze Results\n(Rule Analyzer)"]
        HISTORY["6. Record History"]
        NEXT{Next Step?}

        GEN --> COMPILE
        COMPILE --> COMPILE_CHECK
        COMPILE_CHECK -- Yes --> EXEC
        COMPILE_CHECK -- No --> ANALYZE
        EXEC --> EXEC_CHECK
        EXEC_CHECK -- Yes --> DETECT
        EXEC_CHECK -- No --> ANALYZE
        DETECT --> ANALYZE
        ANALYZE --> HISTORY
        HISTORY --> NEXT
        NEXT -- "status != clean\n& iter < max" --> GEN
    end

    NEXT -- "status == clean" --> SUCCESS([SUCCESS\nNo detections])
    NEXT -- "iter >= max" --> FAIL([END\nMax iterations reached])

    style START fill:#4CAF50,color:#fff
    style SUCCESS fill:#4CAF50,color:#fff
    style FAIL fill:#f44336,color:#fff
    style GEN fill:#2196F3,color:#fff
    style COMPILE fill:#FF9800,color:#fff
    style EXEC fill:#9C27B0,color:#fff
    style DETECT fill:#F44336,color:#fff
    style ANALYZE fill:#00BCD4,color:#fff
    style HISTORY fill:#607D8B,color:#fff
```

### Step-by-Step Breakdown

| Step | Node | Description |
|------|------|-------------|
| 1 | **Generate** | Builds a prompt with shellcode info, evasion techniques, and previous iteration feedback. Calls Gemini to produce C source code. |
| 2 | **Compile** | Writes `.c` file to `output/iter_N/`, invokes `cl.exe` (MSVC) or `gcc` (MinGW) to produce `loader_N.exe`. |
| 3 | **Execute** | Runs `loader_N.exe <shellcode_path>` via `subprocess.Popen`. Polls for success criteria (process spawn / file creation / network callback). |
| 4 | **Detect** | Queries Elastic Defend alerts and Windows Defender event logs for detections matching the loader process. |
| 5 | **Analyze** | Maps detections to TOML behavior rules. Tracks persistent, new, and solved rules. Identifies generic malware alerts. |
| 6 | **History** | Records iteration summary (code, status, detections, analysis) for context in subsequent iterations. |

---

## Detailed Component Diagram

```mermaid
flowchart LR
    subgraph CORE ["core/"]
        GRAPH[graph.py\nStateGraph definition]
        STATE[state.py\nAgentState TypedDict]
        NODES[nodes.py\nNode functions]
        UTILS[utils.py\nConfig loader]
    end

    subgraph LIB ["lib/"]
        COMP[compiler.py\nMSVC / MinGW]
        EXEC_LIB[executor.py\nSubprocess runner]
        RULE[rule_analyzer.py\nTOML rule parser]
        subgraph DET ["detectors/"]
            BASE[base.py\nDetector ABC]
            ELASTIC[elastic.py\nElasticsearch]
            DEFENDER[defender.py\nWinDefend]
        end
    end

    subgraph VISUALIZER ["visualizer/"]
        APP[app.py\nFlask Server]
    end

    subgraph EXT ["External"]
        GEMINI[Google Gemini API]
        ES[Elasticsearch Cluster]
        WD[Windows Defender]
        MSVC[cl.exe / gcc]
    end

    MAIN[main.py] --> GRAPH
    GRAPH --> NODES
    NODES --> STATE
    NODES --> UTILS
    NODES --> COMP
    NODES --> EXEC_LIB
    NODES --> RULE
    NODES --> ELASTIC
    NODES --> DEFENDER
    NODES --> GEMINI

    COMP --> MSVC
    ELASTIC --> ES
    DEFENDER --> WD

    style MAIN fill:#4CAF50,color:#fff
    style GEMINI fill:#2196F3,color:#fff
    style ES fill:#F44336,color:#fff
    style WD fill:#F44336,color:#fff
    style MSVC fill:#FF9800,color:#fff
```

---

## Agent State

The `AgentState` (defined in `core/state.py`) carries all data through the graph:

```python
class AgentState(TypedDict):
    # Static inputs
    shellcode_path: str          # Path to shellcode binary
    max_iterations: int          # Loop limit
    session_dir: str             # Output directory (output/YYYYMMDD_HHMMSS/)

    # Loop counters
    iteration: int               # Current iteration (1-based)
    status: str                  # start | compiled | compile_failed |
                                 # executed | exec_failed | detected | clean

    # Current iteration data
    current_code: Optional[str]  # Generated source code
    compile_result: Optional[dict]
    exec_result: Optional[dict]
    detections: List[dict]

    # Memory across iterations
    history: List[dict]          # All past iteration summaries
    analysis_report: dict        # Persistent/new/solved rules, active context
    ai_strategy_plan: Optional[str] # AI's strategic plan for evasion
    bug_retries: int             # Internal retry tracker for crashes/compilation errors
    approach_tracker: List[dict] # Track active, succeeded, or exhausted evasion approaches
    iteration_summaries: List[dict] # Compact summaries of past iterations
    banned_approaches: List[str] # Approaches marked as exhausted or banned
    review_feedback: Optional[str] # Review feedback from the Review Agent before code gen

    # Error
    error: Optional[str]
```

---

## Output Structure

Each run creates a timestamped session directory:

```
output/
└── 20250601_143022/
    ├── final_summary.txt           # Overall execution summary
    ├── run_config.yaml             # Config used for this session
    ├── agent_run.log               # Streaming logs from the agent run
    ├── iter_1/
    │   ├── analysis_prompt.txt     # Input to Detection Rule Analyzer
    │   ├── analysis_response.txt   # Output from Detection Rule Analyzer (evasion strategy plan)
    │   ├── review_prompt.txt       # Input to Review Agent
    │   ├── review_response.txt     # Output from Review Agent (recommendations/fixes)
    │   ├── prompt.txt              # Full code generation prompt sent to Gemini
    │   ├── response.txt            # Raw Gemini response
    │   ├── loader_1.c              # Generated source (.c, .py, or .cs)
    │   ├── loader_1.exe            # Compiled executable (if applicable)
    │   └── loader_1_compile.bat    # Build script (if applicable)
    └── ...
```

---

## Setup

### Prerequisites

- **Python 3.10+**
- **Windows** (required for MSVC compilation and EDR testing)
- **Visual Studio Build Tools** (for `cl.exe`) or **MinGW** (for `gcc`)
- **Elasticsearch** (for Elastic Defend detection)
- **Google Gemini API key**

### Installation

```bash
pip install -r requirements.txt
```

### Environment Variables

Create a `.env` file in the project root:

```env
GEMINI_API_KEY=your-gemini-api-key

# Elastic (choose one auth method)
ELASTIC_API_KEY=your-base64-encoded-api-key
# or
ELASTIC_USERNAME=elastic
ELASTIC_PASSWORD=your-password
```

### Supported Target Languages

The AI agent can generate shellcode loaders in three different languages. You can configure your target language in `config/config.yaml` under `compiler.language`:

- `c` (C/C++): Compiled via MSVC or MinGW. The default and most robust language for memory evasion.
- `python` (Python): Executed natively via the local Python interpreter. Uses `ctypes` for memory interaction.
- `csharp` / `.net` (C#): Compiled via the built-in Windows `.NET Framework` compiler (`csc.exe`).

### Configuration

Edit `config/config.yaml` to configure:

- **Target Language** (`compiler.language`: `c`, `python`, `csharp`, or `.net`)
- **AI model** (`ai.gemini.model`)
- **Compiler** path and type (`compiler.type`, `compiler.msvc.vcvars_path`)
- **Detectors** (`detectors.enabled`, Elastic host/port, etc.)
- **Success criteria** (`execution.success_criteria.type`: `process`, `file`, or `network`)
- **Evasion techniques** reference list

---

## Usage

### 1. Evasive AI Agent CLI

#### Basic Run

```bash
python main.py --shellcode path/to/shellcode.bin
```

#### With Custom Iterations

```bash
python main.py --shellcode shellcode.bin --iterations 5
```

#### Check Elastic Connection

```bash
python main.py --check-elastic
```

#### CLI Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--shellcode` | `-s` | *required* | Path to shellcode binary file |
| `--iterations` | `-i` | `4` | Maximum number of evasion iterations |
| `--check-elastic` | | `false` | Test Elasticsearch connectivity and show recent alerts |
| `--session-dir` | | *optional* | Explicit session directory path to use |


### 2. Visualizer Web UI (Console)

To start the visualizer server, execute the following command:
```bash
python visualizer/app.py
```
This launches a Flask web server on `http://127.0.0.1:5001`.

## Detection & Analysis Pipeline

```mermaid
flowchart TD
    ALERT[Elastic / Defender Alert] --> PARSE[Parse Alert Fields\nrule_name, rule_id,\nprocess, file, severity]
    PARSE --> MATCH{Match TOML\nBehavior Rule?}
    MATCH -- Yes --> EXTRACT[Extract from TOML:\n- Detection Query\n- API Calls\n- Exclusions / Allowlists]
    MATCH -- No --> GENERIC[Generic Malware Alert?\nTrigger dummy function strategy]
    EXTRACT --> PROMPT[Feed to AI Prompt:\n- Full detection query\n- Allowlist analysis\n- Evasion hints]
    GENERIC --> PROMPT
    PROMPT --> NEXT_ITER[Next Iteration:\nGenerate improved code]

    style ALERT fill:#F44336,color:#fff
    style PROMPT fill:#2196F3,color:#fff
    style NEXT_ITER fill:#4CAF50,color:#fff
```

The `BehaviorRuleAnalyzer` (`lib/rule_analyzer.py`) bridges EDR alerts to local TOML rule files:

1. **Rule ID matching** - Most reliable; maps `rule.id` from Elastic alerts to TOML `rule.id`
2. **Name matching** - Fuzzy normalized matching as fallback
3. **Keyword search** - Searches across name, description, and query fields

Extracted rule details (full detection query, API patterns, exclusions) are injected into the AI prompt so Gemini can craft targeted evasion techniques.

---

## Evasion Techniques

The following techniques are available in `config.yaml` for the AI to reference:

| Category | Technique | Description |
|----------|-----------|-------------|
| Memory | RW_to_RX | Allocate RW, copy shellcode, flip to RX |
| Memory | Module Stomping | Overwrite legitimate DLL section |
| Memory | Heap Execution | Execute from heap memory |
| Memory | Fiber Execution | Use Windows fibers for execution |
| Memory | Phantom DLL Hollowing | Map phantom DLL, inject into section |
| Thread | Stack Spoofing | Fake thread call stack |
| Thread | Proxy Function Calls | Route calls through legitimate APIs |
| Advanced | Process Doppelganging | TxF-based process creation |
| Advanced | Callback Execution | Execute via legitimate callback mechanisms |
| Advanced | Module Overloading | Load over existing modules |
| Experimental | Scattered Allocation | Split shellcode across multiple allocations |
| Experimental | Read-Only Trick | Exploit page table quirks |

---

## Success Criteria

The executor supports three modes for validating shellcode execution:

| Type | How It Works | Example |
|------|-------------|---------|
| **process** | Polls `tasklist` for target process | `calc.exe` spawn |
| **file** | Checks for file creation | Marker file on disk |
| **network** | Polls `netstat` for ESTABLISHED connection | C2 callback (Havoc, Cobalt Strike) |

Configure in `config.yaml`:

```yaml
execution:
  success_criteria:
    enabled: true
    type: process        # process | file | network
    process:
      name: "calc.exe"
      timeout: 15
    network:
      host: "192.168.1.100"
      port: 443
      timeout: 15
```

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `langchain-google-genai` | Google Gemini integration |
| `langgraph` | State graph orchestration |
| `elasticsearch` | Elastic Defend alert querying |
| `flask` | Visualizer Web UI backend |
| `pyyaml` | YAML config parsing |
| `python-dotenv` | `.env` file loading |
| `tomli` | TOML behavior rule parsing |
| `colorama` / `rich` | Terminal formatting |

---

## License

For authorized security research and educational use only.


## Caution

THIS SOFTWARE IS CREATED ONLY FOR THE SECURITY TRAINING PURPOSE SUCH AS RED TEAM OPERATION AND ENGINEER SKILL CHECK. THE USER SHALL NOT USE THIS SOFTWARE FOR THE ATTACKING ON THE THIRD PARTY SYSTEM. THE SOFTWARE IS PROVIDED “AS IS” AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.