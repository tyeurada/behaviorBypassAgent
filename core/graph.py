from langgraph.graph import END, StateGraph

from .nodes import (
    ai_analyze_detection,
    analyze_results,
    check_detections,
    check_next_step,
    compile_code,
    execute_code,
    generate_code,
    initialize_state,
    record_history,
    review_code,
)
from .state import AgentState


def create_graph():
    """Create the LangGraph for the Evasive AI Agent."""

    workflow = StateGraph(AgentState)

    # Add Nodes
    workflow.add_node("init", initialize_state)
    workflow.add_node("ai_analyze", ai_analyze_detection)
    workflow.add_node("generate", generate_code)
    workflow.add_node("review", review_code)
    workflow.add_node("compile", compile_code)
    workflow.add_node("execute", execute_code)
    workflow.add_node("detect", check_detections)
    workflow.add_node("analyze", analyze_results)
    workflow.add_node("history", record_history)

    # Define Default Edges (The Flow)

    # Start -> Init (resets component singletons) -> Generate
    workflow.set_entry_point("init")
    workflow.add_edge("init", "generate")

    # AI Analyze -> Generate
    # This is where the planning feeds into the coding
    workflow.add_edge("ai_analyze", "generate")

    # Generate -> Review -> Compile
    workflow.add_edge("generate", "review")
    workflow.add_edge("review", "compile")

    # Compile Logic
    def route_compile(state):
        if state['status'] == 'compiled':
            return "execute"
        return "analyze"

    workflow.add_conditional_edges("compile", route_compile, {"execute": "execute", "analyze": "analyze"})

    # EDR prevention commonly terminates a loader, so a non-zero exit can itself
    # be evidence of detection. Always poll before classifying the execution.
    workflow.add_edge("execute", "detect")

    # Detect Logic
    workflow.add_edge("detect", "analyze")

    # Analyze -> History
    workflow.add_edge("analyze", "history")

    # History -> Loop (AI Analyze) or Generate or End
    def route_loop(state):
        step = check_next_step(state)
        if step == 'loop':
            # If we are looping because of a failure/detection, we want to Analyze first.
            # If it's a fresh start (not likely here, but safe), we go to generate.
            # Actually, check_next_step returns "loop" if < max_iterations.
            # We should check if we have a plan to make?
            # If state['status'] was 'clean', we ended.
            # If we are here, we failed or detected.
            return "ai_analyze"
        return END

    workflow.add_conditional_edges("history", route_loop, {"ai_analyze": "ai_analyze", END: END})

    return workflow.compile()
