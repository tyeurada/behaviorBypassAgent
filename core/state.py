"""
State definition for the Evasive AI Agent.
"""

from typing import TypedDict, List, Dict, Optional, Any, Annotated
from operator import add

class AgentState(TypedDict):
    """
    The state of the agent, tracking the current iteration, history, and results.
    """
    
    # Static inputs (from config/CLI)
    shellcode_path: str
    max_iterations: int
    
    # Loop variables
    iteration: int
    status: str  # 'generating', 'compiling', 'executing', 'analyzing', 'success', 'failed'
    
    # Current Iteration Data
    current_code: Optional[str]
    compile_result: Optional[Dict[str, Any]]
    exec_result: Optional[Dict[str, Any]]
    detections: List[Dict[str, Any]]
    
    # History & Memory
    # List of previous iteration summaries
    history: List[Dict[str, Any]] 
    
    # The "Compact Rule Analysis" improvement
    # Summarized knowledge about what rules are active, resolved, or new.
    analysis_report: Dict[str, Any]
    
    # NEW: AI's strategic plan for evasion (output of ai_analyze_detection)
    ai_strategy_plan: Optional[str]
    
    # Error tracking
    error: Optional[str]
    
    # Session management
    session_dir: str
    
    # Internal retry tracker for crashes/compilation errors
    bug_retries: int

    # AI Memory & Strategy Tracking
    # List of approach records: {approach_name, attempts, status, rule_target, iteration_results}
    approach_tracker: List[Dict[str, Any]]

    # Compact iteration summaries for prompt injection
    # Each: {iter, approach, outcome, rules, summary}
    iteration_summaries: List[Dict[str, Any]]

    # Banned approaches (exhausted or impossible)
    banned_approaches: List[str]

    # Review feedback from the Review Agent
    review_feedback: Optional[str]

