import os
import time
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from lib.agent_memory import (
    _build_compact_summary,
    _extract_approach_name,
    _update_approach_tracker,
)
from lib.code_templates import language_context
from lib.compiler import Compiler
from lib.detection_formatter import format_detections_for_prompt
from lib.detectors import get_all_detectors
from lib.executor import Executor
from lib.llm_utils import (
    build_safe_fallback,
    code_implements_loader,
    extract_code_from_content,
    is_refusal,
    normalize_model_content,
    parse_literal_dict_content,
    validate_c_source,
)
from lib.prompt_builder import render_prompt
from lib.rule_analyzer import BehaviorRuleAnalyzer
from lib.techniques_kb import format_techniques_kb

from .state import AgentState
from .utils import load_config

# Global or Singleton instances
_config = None
_compiler = None
_executor = None
_detectors = None
_rule_analyzer = None
_llm = None


def _get_components():
    global _config, _compiler, _executor, _detectors, _rule_analyzer, _llm
    if _config is None:
        _config = load_config()

    if _compiler is None:
        _compiler = Compiler(_config.get('compiler', {}))

    if _executor is None:
        _executor = Executor(_config.get('execution', {}))

    if _detectors is None:
        _detectors = get_all_detectors(_config.get('detectors', {}))

    if _rule_analyzer is None:
        rules_dir = _config.get('behavior_rules', {}).get('directory')
        _rule_analyzer = BehaviorRuleAnalyzer(rules_directory=rules_dir)

    if _llm is None:
        from lib.llm_factory import create_llm

        _llm = create_llm(_config)

    return _config, _compiler, _executor, _detectors, _rule_analyzer, _llm


def initialize_state(state: AgentState) -> AgentState:
    """Initialize the state for a new run."""
    print("--- Initialize State ---")

    # Reset global components so the fresh config is loaded on this run
    global _config, _compiler, _executor, _detectors, _rule_analyzer, _llm
    _config = None
    _compiler = None
    _executor = None
    _detectors = None
    _rule_analyzer = None
    _llm = None

    return {
        "iteration": 1,
        "status": "start",
        "history": [],
        "analysis_report": {
            "solved_rules": [],
            "persistent_rules": [],  # (rule_name, count)
            "new_rules": [],
            "last_failure_reason": None,
        },
        "current_code": None,
        "detections": [],
        "error": None,
        # New Memory Fields
        "approach_tracker": [],
        "iteration_summaries": [],
        "banned_approaches": [],
    }


def ai_analyze_detection(state: AgentState) -> AgentState:
    """
    Node to analyze detection and propose a strategy (Step 1).
    """
    iteration = state.get('iteration', 1)
    history = state.get('history', [])
    detections = state.get('detections', [])
    session_dir = state.get('session_dir', 'output')

    # 1. Context Construction

    # Get memory fields
    iteration_summaries = state.get('iteration_summaries', [])
    approach_tracker = state.get('approach_tracker', [])
    banned_approaches = state.get('banned_approaches', [])
    analysis_report = state.get('analysis_report', {})
    last_plan = (state.get('history')[-1].get('ai_strategy_plan') or 'N/A') if history else 'N/A'

    # A. Iteration History Block
    if not iteration_summaries:
        history_block = "No previous iterations."
    else:
        # Take last 5 summaries to avoid context overflow
        recent_sums = iteration_summaries[-5:]
        lines = []
        for s in recent_sums:
            # Format: User requested style
            tech_detail = s.get('technique_details', 'Standard')
            triggered = ", ".join(s.get('rules', [])) or "None"
            ana = s.get('analysis', 'Pending')

            block = f'''
Iter {s['iter']}: [outcome={s['outcome']}]
Technique: {s['approach']} ({tech_detail})
Triggered Rules: {triggered}
Analysis: {ana}
'''
            lines.append(block.strip())
        history_block = "\n\n".join(lines)

    # B. Rule Analysis Block
    # persistent_rules is list of (name, count)
    p_rules = ", ".join([f"{r[0]}(x{r[1]})" for r in analysis_report.get('persistent_rules', [])])
    s_rules = ", ".join(analysis_report.get('solved_rules', []))
    active_context = analysis_report.get('active_rules_context', [])

    active_rules_block = ""
    for rule in active_context:
        # Handle rule being a dict (expected) or object (fallback if legacy state)
        if hasattr(rule, 'to_dict'):
            rule = rule.to_dict()

        r_name = rule.get('name', 'unknown')
        r_apis = rule.get('detection_patterns', {}).get('api_calls', [])
        r_logic = rule.get('query', 'N/A')

        # Sanitize massive hash lists (too much noise for LLM)
        import re

        if "process.thread.Ext.call_stack_final_user_module.hash.sha256" in r_logic:
            r_logic = re.sub(
                r"process\.thread\.Ext\.call_stack_final_user_module\.hash\.sha256\s+in\s*\((?:[^()]|\([^()]*\))*\)",
                "process.thread.Ext.call_stack_final_user_module.hash.sha256 in ([Sanitized_Hash_List])",
                r_logic,
                flags=re.DOTALL | re.IGNORECASE,
            )

        active_rules_block += f"- Rule: {r_name} | APIs: {', '.join(r_apis)} | Logic: {r_logic}\n"

    rule_analysis_block = f"""
    Solved Rules: {s_rules}
    Persistent Rules: {p_rules}
    Active Rules Details:
    {active_rules_block}
    """

    # C. Active Approach Status Block
    # Show active approaches and their attempt counts
    active_approaches = [a for a in approach_tracker if a['status'] == 'active']
    tracker_lines = []
    for a in active_approaches:
        tracker_lines.append(f"{a['approach_name']}: {a['attempts']}/3 attempts (target: {a['rule_target']})")

    status_block = "\n".join(tracker_lines) if tracker_lines else "No active recurring approach."

    # D. Banned Approaches Block
    banned_block = ", ".join(banned_approaches) if banned_approaches else "None"

    # E. Last Result Context (Standard)
    # Previous code snippet for analyst (truncate to avoid token overflow)
    prev_code = ""
    if history:
        prev_code = (history[-1].get('code') or "")[:5000]
        if len(history[-1].get('code') or "") > 5000:
            prev_code += "\n\n... (code truncated for length)"

    config, _, _, _, rule_analyzer, llm = _get_components()
    lang = language_context(config.get('compiler', {}).get('language', 'c'))

    if not history:
        # First run analysis
        context = "Initial analysis. No previous execution."
    else:
        last_result = history[-1]
        last_compile = last_result.get('compile_result') or {}
        last_exec = last_result.get('exec_result') or {}
        last_exit = last_exec.get('exit_code', 'N/A')
        last_out = (last_exec.get('stdout') or '')[:200]
        last_err = (last_exec.get('stderr') or '')[:200]
        if not last_out:
            # Fallback to legacy keys if older history entries exist
            last_out = (last_result.get('stdout') or '')[:200]
        if not last_err:
            last_err = (last_result.get('stderr') or '')[:200]
        context = f'''
    ## Previous Test Results
    Iteration: {last_result['iteration']}
    Status: {last_result['status']}
    Exit Code: {last_exit}
    Output Snippet: {last_out}
    Error Snippet: {last_err}
    Compile Success: {bool(last_compile.get('success'))}
    Previous Strategy Plan:
    {last_plan[:500]}

    ## Previous Code ({lang['analysis_lang_name']} that was tested)
    ```{lang['code_block_tag']}
    {prev_code if prev_code else "(no code saved)"}
    ```
    '''

    # Determine context based on status
    status = state.get('status', 'unknown')

    if status == 'compile_failed':
        result = state.get('compile_result', {})
        error = result.get('error') or result.get('stderr') or "Unknown compilation error"
        detection_info = f"COMPILATION FAILED:\n{error}\n\nSTDOUT:\n{result.get('stdout', '')}"

    elif status == 'execution_failed' or status == 'exec_failed':
        result = state.get('exec_result', {})
        error = result.get('error') or result.get('stderr') or "Unknown execution error"
        detection_info = (
            f"EXECUTION FAILED:\n{error}\n\n"
            f"EXIT_CODE: {result.get('exit_code', 'N/A')}\n\n"
            f"SUCCESS_DETAILS: {result.get('success_details', {})}\n\n"
            f"STDOUT:\n{result.get('stdout', '')}\n\n"
            f"STDERR:\n{result.get('stderr', '')}"
        )

    else:
        # Default to detection analysis. Prefer the formatted context built by
        # analyze_results (includes matched TOML rule details); fall back to
        # formatting directly so restored states still get context.
        detections = state.get('detections', [])
        detection_info = analysis_report.get('detections_context') or format_detections_for_prompt(
            detections, rule_analyzer
        )
        if not detection_info:
            detection_info = "No specific EDR alerts (Unknown blocking)."

    # Failed code that just ran is in state (not yet in history)
    code_that_failed = ""
    if status in ('compile_failed', 'execution_failed', 'exec_failed'):
        code_that_failed = (state.get('current_code') or '')[:5000]
        if len(state.get('current_code') or '') > 5000:
            code_that_failed += "\n\n... (truncated)"
        if not code_that_failed:
            code_that_failed = "(no code saved)"

    # Dynamic Standard Testing Methodologies from Config
    evasion_techniques = config.get('evasion_techniques', {}).get('memory', [])
    preferred_techniques = config.get('evasion_techniques', {}).get('preferred_techniques', [])

    # Filter only enabled techniques
    enabled_techniques = [t for t in evasion_techniques if t.get('enabled', False)]

    tech_lines = []
    for t in enabled_techniques:
        name = t.get('name', 'Unknown')
        is_pref = name in preferred_techniques or any(p.lower() == name.lower() for p in preferred_techniques)
        pref_marker = " [USER-PREFERRED]" if is_pref else ""
        tech_lines.append(f"- **{name}**{pref_marker}: {t.get('description', '')}")

    standard_techniques_block = "\n    ".join(tech_lines)
    if not standard_techniques_block:
        standard_techniques_block = "- (none enabled)"

    # Append preferred techniques block if any are selected
    if preferred_techniques:
        standard_techniques_block += "\n\n    ### USER PREFERRED TECHNIQUES (Prioritize these!)\n    " + "\n    ".join(
            [f"- **{p}**" for p in preferred_techniques]
        )

    # Curated implementation notes (techniques/*.md) for enabled/preferred techs
    techniques_kb_block = format_techniques_kb(
        config,
        [t.get('name') for t in enabled_techniques],
        preferred_techniques,
    )

    # Language specific guidelines
    guidelines_config = config.get('compiler', {}).get('guidelines', {})
    lang_rules = guidelines_config.get(lang['guidelines_key'], [])
    lang_specific_rules_block = ""
    if lang_rules:
        lang_specific_rules_block = "\n    ## Language Specific Constraints\n" + "\n".join(
            [f"    - {rule}" for rule in lang_rules]
        )

    # 2. Prompt Construction (Reframed for Security Testing)
    system_prompt = render_prompt("analysis_system")

    if status == 'compile_failed':
        user_prompt = render_prompt(
            "analysis_compile_failed",
            standard_techniques_block=standard_techniques_block,
            lang_name=lang['analysis_lang_name'],
            code_block_tag=lang['code_block_tag'],
            code_that_failed=code_that_failed,
            detection_info=detection_info,
            techniques_kb_block=techniques_kb_block,
        )
    elif status in ('execution_failed', 'exec_failed'):
        user_prompt = render_prompt(
            "analysis_exec_failed",
            standard_techniques_block=standard_techniques_block,
            lang_name=lang['analysis_lang_name'],
            code_block_tag=lang['code_block_tag'],
            code_that_failed=code_that_failed,
            detection_info=detection_info,
            techniques_kb_block=techniques_kb_block,
        )
    else:
        user_prompt = render_prompt(
            "analysis_detected",
            history_block=history_block,
            rule_analysis_block=rule_analysis_block,
            status_block=status_block,
            banned_block=banned_block,
            generic_malware_alert=bool(analysis_report.get('generic_malware_alert')),
            context=context,
            detection_info=detection_info,
            standard_techniques_block=standard_techniques_block,
            lang_specific_rules_block=lang_specific_rules_block,
            techniques_kb_block=techniques_kb_block,
        )

    # 3. Call LLM (using singleton from _get_components)
    messages = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]

    try:
        response = llm.invoke(messages)
        plan_content = normalize_model_content(response.content)
        plan_content = parse_literal_dict_content(plan_content)

        # --- NEW: Backfill "Analysis" into previous iteration summary ---
        # The AI just analyzed the previous failure. We should save this lesson.
        if iteration_summaries and "Analysis" in plan_content:
            # Extract Analysis text
            import re

            match = re.search(r"\*\*Analysis\*\*:\s*(.+?)(?:\n\*\*|$)", plan_content or "", re.DOTALL | re.IGNORECASE)
            if match:
                analysis_text = match.group(1).strip().replace("\n", " ")[:300]
                # Update the last summary (which corresponds to the previous iteration we just analyzed)
                iteration_summaries[-1]['analysis'] = analysis_text

        # Check for "approach not feasible" signal
        if (
            "bypass is impossible" in plan_content.lower()
            or "cannot be bypassed" in plan_content.lower()
            or "safe variation is impossible" in plan_content.lower()
        ):
            # Identify approach name (rough heuristic)
            approach_name = _extract_approach_name(plan_content, iteration)
            if approach_name != "unknown_approach" and approach_name not in banned_approaches:
                banned_approaches.append(approach_name)

        # Log analysis for debugging
        # Note: This analysis is FOR the current iteration (which is about to generate code)
        debug_dir = os.path.join(session_dir, f"iter_{iteration}")
        os.makedirs(debug_dir, exist_ok=True)

        with open(os.path.join(debug_dir, "analysis_prompt.txt"), "w", encoding="utf-8") as f:
            f.write(user_prompt)
        with open(os.path.join(debug_dir, "analysis_response.txt"), "w", encoding="utf-8") as f:
            f.write(plan_content)

        return {
            "ai_strategy_plan": plan_content,
            "banned_approaches": banned_approaches,
            "iteration_summaries": iteration_summaries,
        }

    except Exception as e:
        print(f"Error in AI Analysis: {e}")
        return {"ai_strategy_plan": "Analysis failed. Proceed with standard defensive validation."}


def generate_code(state: AgentState) -> AgentState:
    """
    Node to generate validation code (Step 2).
    """
    iteration = state.get('iteration', 1)

    print(f"--- Generate Code (Iteration {iteration}) ---")

    # Get inputs
    shellcode_path = state.get('shellcode_path')
    if not shellcode_path or not os.path.exists(shellcode_path):
        return {"error": "Shellcode path missing or invalid"}

    shellcode_size = os.path.getsize(shellcode_path)

    # Load config early so prompt templates can safely reference config-derived blocks.
    try:
        config, _, _, _, rule_analyzer, llm = _get_components()
        evasion_techniques = config.get('evasion_techniques', {}).get('memory', [])
        preferred_techniques = config.get('evasion_techniques', {}).get('preferred_techniques', [])

        # Filter enabled techniques
        enabled_techniques = [t for t in evasion_techniques if t.get('enabled', False)]

        validation_patterns = []
        for t in enabled_techniques:
            name = t.get('name', 'Unknown')
            is_pref = name in preferred_techniques or any(p.lower() == name.lower() for p in preferred_techniques)
            pref_marker = " [USER-PREFERRED]" if is_pref else ""

            trigger_info = f" (bypasses: {t.get('trigger', 'Unknown')})" if t.get('trigger') else ""
            desc = t.get('description', '')
            validation_patterns.append(f"- **{name}**{pref_marker}: {desc}{trigger_info}")

        validation_patterns_block = (
            "\n".join(validation_patterns) if validation_patterns else "- (none configured/enabled)"
        )

        preferred_instruction_block = ""
        if preferred_techniques:
            preferred_instruction_block = (
                "\n\n### CRITICAL: Preferred Techniques\nThe user has specifically requested you to prioritize using the following evasion techniques:\n"
                + "\n".join([f"- **{p}**" for p in preferred_techniques])
                + "\nYou MUST design your code to use at least one of these preferred techniques if possible."
            )

        techniques_kb_block = format_techniques_kb(
            config,
            [t.get('name') for t in enabled_techniques],
            preferred_techniques,
        )
    except Exception as e:
        print(f"Warning: Could not load evasion techniques: {e}")
        return {"error": f"Configuration load error: {e}"}

    # Language configuration
    target_language = config.get('compiler', {}).get('language', 'c').lower()
    lang = language_context(target_language)

    guidelines_config = config.get('compiler', {}).get('guidelines', {})
    lang_rules = guidelines_config.get(lang['guidelines_key'], [])
    lang_specific_rules = ""
    if lang_rules:
        lang_specific_rules = "\n".join([f"{i + 3}. {rule}" for i, rule in enumerate(lang_rules)]) + "\n"

    # Construct Prompt
    system_prompt = render_prompt(
        "generate_system",
        lang_name=lang['lang_name'],
        lang_specific_rules=lang_specific_rules,
        is_csharp=lang['is_csharp'],
    )

    # Format Diagnostic Information
    diagnostic_info = ""

    status = state.get('status')
    if status == 'compile_failed':
        res = state.get('compile_result', {})
        diagnostic_info = (
            f"## Compilation Errors (CRITICAL)\n{res.get('error') or res.get('stderr')}\nSTDOUT:\n{res.get('stdout')}\n"
        )
    elif status in ['execution_failed', 'exec_failed']:
        res = state.get('exec_result', {})
        diagnostic_info = f"## Execution Output (CRITICAL)\nSTDOUT:\n{res.get('stdout')}\nSTDERR:\n{res.get('stderr')}\nSuccess Details: {res.get('success_details')}\n"
    else:
        # Status 'detected' (or restored state): inject the actual alert/rule
        # details so the generator knows exactly which rule logic to avoid.
        analysis_report = state.get('analysis_report') or {}
        det_context = analysis_report.get('detections_context')
        detections = state.get('detections', [])
        if det_context:
            diagnostic_info = f"## Detection Details\n{det_context}"
        elif detections:
            diagnostic_info = "## Detection Details\n" + format_detections_for_prompt(detections, rule_analyzer)
        else:
            diagnostic_info = "No specific detection details or error logs."

    # Iteration Logic:
    # iteration 1 = Initial Generation (Basic Loader)
    # iteration > 1 = Debugging/Refinement

    if iteration == 1:
        base_prompt = render_prompt(
            "generate_iter1",
            lang_name=lang['lang_name'],
            shellcode_path=shellcode_path,
            shellcode_size=shellcode_size,
            args_name=lang['args_name'],
            code_block_tag=lang['code_block_tag'],
            file_tpl=lang['file_tpl'],
            validation_patterns_block=validation_patterns_block,
            preferred_instruction_block=preferred_instruction_block,
            techniques_kb_block=techniques_kb_block,
            comment_prefix=lang['comment_prefix'],
        )
    else:
        ai_plan = state.get('ai_strategy_plan', 'No plan provided.')
        previous_code = state.get('current_code') or f"{lang['comment_prefix']} No previous code available"

        base_prompt = render_prompt(
            "generate_iterN",
            iteration=iteration,
            lang_name=lang['lang_name'],
            previous_code=previous_code,
            code_block_tag=lang['code_block_tag'],
            diagnostic_info=diagnostic_info,
            ai_plan=ai_plan,
            validation_patterns_block=validation_patterns_block,
            preferred_instruction_block=preferred_instruction_block,
            techniques_kb_block=techniques_kb_block,
            comment_prefix=lang['comment_prefix'],
        )

    # Call LLM (using singleton from _get_components)
    messages = [SystemMessage(content=system_prompt), HumanMessage(content=base_prompt)]

    try:
        print("  [DEBUG] invoking LLM for code generation...")
        finish_reason = None
        safety_ratings = []
        response = llm.invoke(messages)
        print("  [DEBUG] LLM response received.")

        # Log Safety Metadata
        try:
            # LangChain's ChatGoogleGenerativeAI response usually has generation_info
            gen_info = response.response_metadata
            finish_reason = gen_info.get('finish_reason')
            safety_ratings = gen_info.get('safety_ratings')
            print(f"  [DEBUG] Finish Reason: {finish_reason}")
            print(f"  [DEBUG] Safety Ratings: {safety_ratings}")

            # Helper to log to file
            session_dir = state.get('session_dir', 'output')
            debug_log_path = os.path.join(session_dir, "debug_regex.log")
            with open(debug_log_path, "a", encoding="utf-8") as f:
                f.write(f"--- LLM Metadata ---\nFinish Reason: {finish_reason}\nSafety Ratings: {safety_ratings}\n")

        except Exception as e:
            print(f"  [DEBUG] Could not extract metadata: {e}")

        content = normalize_model_content(response.content)
        print(f"  [DEBUG] Normalized Content Length: {len(content)}")

        content = parse_literal_dict_content(content)

        # Extract code block
        code = ""
        retry_content = ""

        # Helper to log to file
        session_dir = state.get('session_dir', 'output')
        debug_log_path = os.path.join(session_dir, "debug_regex.log")

        def log_debug(msg):
            with open(debug_log_path, "a", encoding="utf-8") as f:
                f.write(msg + "\n")

        log_debug(f"--- Iteration {iteration} ---")
        log_debug(f"  [DEBUG] content length: {len(content)}")
        log_debug(f"  [DEBUG] content start: {content[:50]!r}")

        code = extract_code_from_content(content, target_language)
        if code:
            log_debug("  [DEBUG] Code validation passed (#include and main found)")

        blocked_reasons = {"RECITATION", "SAFETY", "BLOCKED", "PROHIBITED_CONTENT"}
        is_blocked = str(finish_reason).upper() in blocked_reasons

        is_max_tokens = str(finish_reason).upper() in ["MAX_TOKENS", "LENGTH", "2"]
        if is_max_tokens:
            log_debug("  [DEBUG] LLM hit MAX_TOKENS limit! Bouncing to compile_failed state.")
            return {
                "status": "compile_failed",
                "compile_result": {
                    "success": False,
                    "error": "[SYSTEM_ERROR] Code generation failed because the LLM exceeded the maximum token limit. The output was truncated. Please rewrite your code to be significantly more concise. Do NOT hardcode massive binary payloads or raw PE files directly into the script. Use dynamic methods instead.",
                    "stdout": "",
                    "stderr": "",
                    "output_path": "",
                },
                "current_code": content[:1000] + "\n...[TRUNCATED]...",
            }

        implements_loader = code_implements_loader(code, target_language)

        if is_refusal(content) and not implements_loader:
            log_debug("  [DEBUG] Refusal detected and code does not implement loader; will retry with stronger prompt")

        if is_blocked or not code.strip() or (is_refusal(content) and not implements_loader):
            if is_refusal(content) and not implements_loader and code.strip():
                log_debug(
                    f"  [DEBUG] Retry due to refusal (response declined full implementation). code_len={len(code)}"
                )
                retry_system = render_prompt(
                    "retry_refusal_system",
                    lang_name=lang['lang_name'],
                    code_block_tag=lang['code_block_tag'],
                    args_name=lang['args_name'],
                )
                retry_user = render_prompt(
                    "retry_refusal_user",
                    base_prompt=base_prompt,
                    lang_name=lang['lang_name'],
                    code_block_tag=lang['code_block_tag'],
                )
            else:
                log_debug(f"  [DEBUG] Generation degraded. finish_reason={finish_reason}, code_len={len(code)}")
                retry_system = render_prompt(
                    "retry_fallback_system",
                    is_python=lang['is_python'],
                    is_csharp=lang['is_csharp'],
                )
                retry_user = render_prompt(
                    "retry_fallback_user",
                    is_python=lang['is_python'],
                    is_csharp=lang['is_csharp'],
                )

            retry_messages = [SystemMessage(content=retry_system), HumanMessage(content=retry_user)]
            retry_response = llm.invoke(retry_messages)
            retry_content = normalize_model_content(retry_response.content)
            retry_code = extract_code_from_content(retry_content, target_language)
            if retry_code.strip():
                # Prefer retry code that implements loader when we retried due to refusal
                if is_refusal(content) and code_implements_loader(retry_code, target_language):
                    log_debug("  [DEBUG] Retry produced full loader implementation")
                else:
                    log_debug("  [DEBUG] Retry produced valid fallback code")
                code = retry_code

        # Structural validation for C output — catch known-broken classes
        # (truncation, missing includes/entry point, wide/narrow argv mix,
        # undeclared NT APIs) and give the model one focused retry before
        # wasting a compiler invocation.
        if lang['guidelines_key'] == 'c' and code.strip():
            issues = validate_c_source(code)
            if issues:
                log_debug(f"  [DEBUG] C source validation issues: {issues}")
                v_system = render_prompt("retry_validation_system")
                v_user = render_prompt(
                    "retry_validation_user",
                    issues_block="\n".join(f"- {i}" for i in issues),
                    base_prompt=base_prompt,
                    lang_name=lang['lang_name'],
                    code_block_tag=lang['code_block_tag'],
                )
                v_resp = llm.invoke(
                    [SystemMessage(content=v_system), HumanMessage(content=v_user)]
                )
                v_content = normalize_model_content(v_resp.content)
                v_code = extract_code_from_content(v_content, target_language)
                v_issues = validate_c_source(v_code)
                if v_code.strip() and len(v_issues) < len(issues):
                    log_debug(
                        f"  [DEBUG] Validation retry improved issues "
                        f"({len(issues)} -> {len(v_issues)})"
                    )
                    code = v_code
                    retry_content += "\n\n--- VALIDATION RETRY ---\n" + v_content
                else:
                    log_debug(
                        "  [DEBUG] Validation retry did not improve; "
                        "proceeding to compiler for authoritative diagnostics"
                    )

        if not code.strip():
            fallback_reason = str(finish_reason or "EMPTY_OR_UNPARSABLE").replace('"', "'")
            log_debug(f"  [DEBUG] Using built-in safe fallback. reason={fallback_reason}")
            code = build_safe_fallback(fallback_reason, target_language)

        log_debug(f"  [DEBUG] Final code length: {len(code)}")

        # Log prompt/response for debugging
        session_dir = state.get('session_dir', 'output')
        debug_dir = os.path.join(session_dir, f"iter_{iteration}")
        os.makedirs(debug_dir, exist_ok=True)

        with open(os.path.join(debug_dir, "prompt.txt"), "w", encoding="utf-8") as f:
            f.write(base_prompt)
        with open(os.path.join(debug_dir, "response.txt"), "w", encoding="utf-8") as f:
            f.write(content)
            if retry_content:
                f.write("\n\n--- RETRY RESPONSE ---\n")
                f.write(retry_content)

        return {"generated_code": code, "current_code": code, "status": "generated"}

    except Exception as e:
        print(f"Error in generate_code: {e}")
        import traceback

        traceback.print_exc()
        return {"generated_code": f"// Error generating code: {e}"}


def review_code(state: AgentState) -> AgentState:
    """
    Node to review generated C code and fix obvious issues (file paths, headers, syntax).
    Also ensures the code aligns with the Analysis Agent's strategy plan.
    A 'Review Agent' requested by the user.
    """
    print("--- Review Code (Quality Assurance & Strategy Check) ---")
    iteration = state.get('iteration', 1)
    current_code = state.get('current_code', '')
    ai_plan = state.get('ai_strategy_plan', 'No plan provided.')

    # Load components
    config, _, _, _, _, llm = _get_components()
    target_language = config.get('compiler', {}).get('language', 'c').lower()
    lang = language_context(target_language)

    has_code = False
    if current_code:
        if lang['is_python'] and ("import" in current_code or "sys" in current_code):
            has_code = True
        elif lang['is_csharp'] and ("using" in current_code or "class" in current_code):
            has_code = True
        elif "include" in current_code:
            has_code = True

    if not has_code:  # weak check
        print("  [Reviewer] No valid code to review.")
        return {"review_feedback": "Skipped: No code."}

    system_prompt = render_prompt(
        "review_system",
        lang_name=lang['review_lang_name'],
        compiler_name=lang['compiler_name'],
    )
    user_prompt = render_prompt(
        "review_user",
        ai_plan=ai_plan,
        iteration=iteration,
        current_code=current_code,
        code_block_tag=lang['code_block_tag'],
        comment_prefix=lang['comment_prefix'],
        lang_name=lang['review_lang_name'],
    )

    # Call LLM (using singleton from _get_components)
    messages = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]

    try:
        print("  [DEBUG] Invoking Review Agent...")

        # Log Review Prompt for Visualization
        session_dir = state.get('session_dir', 'output')
        debug_dir = os.path.join(session_dir, f"iter_{iteration}")
        os.makedirs(debug_dir, exist_ok=True)

        with open(os.path.join(debug_dir, "review_prompt.txt"), "w", encoding="utf-8") as f:
            f.write(system_prompt + "\n\n" + user_prompt)

        response = llm.invoke(messages)
        content = parse_literal_dict_content(normalize_model_content(response.content))

        with open(os.path.join(debug_dir, "review_response.txt"), "w", encoding="utf-8") as f:
            f.write(content)

        # Parse response
        import re

        code_patterns = [
            r"```c[ \t]*\r?\n(.*?)\s*```",
            r"```cpp[ \t]*\r?\n(.*?)\s*```",
            r"```csharp[ \t]*\r?\n(.*?)\s*```",
            r"```cs[ \t]*\r?\n(.*?)\s*```",
            r"```python[ \t]*\r?\n(.*?)\s*```",
            r"```py[ \t]*\r?\n(.*?)\s*```",
            r"```[ \t]*\r?\n(.*?)\s*```",
        ]
        fixed_code = ""
        for pat in code_patterns:
            code_match = re.search(pat, content, re.DOTALL | re.IGNORECASE)
            if code_match:
                fixed_code = code_match.group(1).strip()
                break

        analysis_match = re.search(r"### REVIEW_ANALYSIS\s*(.*?)\s*(?:###|$)", content, re.DOTALL | re.IGNORECASE)
        analysis = analysis_match.group(1).strip() if analysis_match else "No analysis provided."

        if fixed_code and len(fixed_code) > 50:
            # Heuristic: Did we change anything?
            if fixed_code.strip() == current_code.strip():
                print(f"  [Reviewer] Code verified. No changes needed. Analysis: {analysis[:100]}...")
            else:
                print(f"  [Reviewer] Code updated/fixed. Analysis: {analysis[:100]}...")

            return {"current_code": fixed_code, "review_feedback": analysis}
        else:
            print("  [Reviewer] No formatted code returned. Keeping original.")
            return {"review_feedback": "Reviewer validation failed (parse error). Keeping original."}

    except Exception as e:
        print(f"Error in Review Agent: {e}")
        return {"review_feedback": f"Review failed: {e}"}


def compile_code(state: AgentState) -> AgentState:
    """Compile the generated code."""
    print("--- Compile Code ---")

    if state.get('status') == 'compile_failed':
        print("  [DEBUG] Skipping compilation due to pre-existing compile_failed state.")
        return {}

    config, compiler, _, _, _, _ = _get_components()

    code = state['current_code']
    iteration = state['iteration']
    session_dir = state.get('session_dir', 'output')

    # Ensure output dir exists
    output_dir = os.path.join(session_dir, f"iter_{iteration}")
    os.makedirs(output_dir, exist_ok=True)

    result = compiler.compile(code=code, output_name=f"loader_{iteration}", output_dir=output_dir)

    compiled_result_dict = {
        "success": result.success,
        "output_path": result.output_path,
        "error": result.error,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }

    # Persist compile output for later debugging (even on success).
    try:
        compile_log_path = os.path.join(output_dir, f"loader_{iteration}_compile_output.txt")
        with open(compile_log_path, "w", encoding="utf-8") as f:
            f.write(f"SUCCESS: {result.success}\n")
            if result.output_path:
                f.write(f"OUTPUT: {result.output_path}\n")
            if result.error:
                f.write(f"ERROR: {result.error}\n")
            f.write("\n--- STDOUT ---\n")
            f.write(result.stdout or "")
            f.write("\n--- STDERR ---\n")
            f.write(result.stderr or "")
    except Exception as e:
        print(f"  [DEBUG] Could not write compile log: {e}")

    if result.success:
        return {"compile_result": compiled_result_dict, "status": "compiled"}
    else:
        # Print a short hint inline so the console log is actionable.
        err = (result.error or result.stderr or "Unknown compilation error").strip()
        print(f"[!] Compilation failed (iter {iteration}): {err[:300]}")
        return {"compile_result": compiled_result_dict, "status": "compile_failed"}


def execute_code(state: AgentState) -> AgentState:
    """Execute the compiled loader."""
    print("--- Execute Code ---")
    _, _, executor, _, _, _ = _get_components()

    exe_path = state['compile_result']['output_path']
    shellcode_path = state['shellcode_path']

    result = executor.execute_with_shellcode(exe_path=exe_path, shellcode_path=shellcode_path)

    exec_result_dict = {
        "success": result.success,
        "shellcode_success": result.shellcode_success,
        "exit_code": result.exit_code,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "runtime_seconds": result.runtime_seconds,
        "success_details": result.success_details,
    }

    # Check strict shellcode success
    if result.shellcode_success:
        return {"exec_result": exec_result_dict, "status": "executed"}
    else:
        return {"exec_result": exec_result_dict, "status": "exec_failed"}


def check_detections(state: AgentState) -> AgentState:
    """Check for EDR detections."""
    print("--- Check Detections ---")
    config, _, _, detectors, _, _ = _get_components()

    # Load polling config
    elastic_config = config.get('detectors', {}).get('elastic', {})
    max_checks = elastic_config.get('max_checks', 30)
    check_interval = elastic_config.get('check_interval', 5)

    # Determine filename
    exe_path = state['compile_result']['output_path']
    process_name = os.path.basename(exe_path)

    # Wait / Poll strategy
    found_detections: list[dict] = []

    # Check for (max_checks * check_interval) seconds total
    for i in range(max_checks):
        print(f"Checking detections iteration {i + 1}/{max_checks}...")
        for detector in detectors:
            if detector.is_available():
                results = detector.check_detection(
                    process_name=process_name,
                    file_path=exe_path,
                    time_window_seconds=300,  # Look back 5 mins to be safe
                )

                for det in results:
                    found_detections.append(det.to_dict())

        if found_detections:
            break

        time.sleep(check_interval)

    if found_detections:
        return {"detections": found_detections, "status": "detected"}

    # No detections found. Only mark as "clean" if the configured success criteria
    # for the run was met; otherwise preserve the prior status (e.g. exec_failed)
    # so we don't report a false "success" when the payload goal didn't happen.
    shellcode_success = (state.get('exec_result') or {}).get('shellcode_success', False)
    if shellcode_success:
        return {"detections": [], "status": "clean"}

    return {"detections": [], "status": state.get("status", "unknown")}


def analyze_results(state: AgentState) -> AgentState:
    """Analyze failures and detections to update knowledge."""
    print("--- Analyze Results ---")
    _, _, _, _, rule_analyzer, _ = _get_components()

    status = state['status']
    detections = state.get('detections', [])
    analysis_report = state.get(
        'analysis_report',
        {
            "solved_rules": [],
            "persistent_rules": [],
            "new_rules": [],
            "active_rules_context": [],  # Store full rule details for current iteration
            "last_failure_reason": None,
        },
    )

    # Convert persistent to dict for easier update
    prev_persistent = dict(analysis_report.get('persistent_rules', []))
    # Convert lists to sets for diff
    prev_solved = set(analysis_report.get('solved_rules', []))
    prev_new = set(analysis_report.get('new_rules', []))

    current_rule_names = [d.get('rule_name') for d in detections if d.get('rule_name')]

    analysis_report['last_failure_reason'] = status if status != "clean" else None

    # Check for Generic Malware Alert (Signature/Heuristic)
    # NOTE: This does not depend on the behavior-rule analyzer; it is a verdict-style alert.
    import re

    def _norm(s: Any) -> str:
        return re.sub(r"\s+", " ", str(s or "")).strip().lower()

    def _is_generic_malware_alert(det: dict[str, Any]) -> bool:
        # Match both "Alert" and common truncations/typos like "Aler".
        # Use a substring without the trailing 't' so it matches both.
        needle = "malware detection aler"
        details = det.get('details') or {}
        texts = [
            det.get('rule_name'),
            det.get('description'),
            details.get('message'),
            details.get('reason'),
        ]
        return any(needle in _norm(t) for t in texts if t)

    generic_meta = None
    for det in detections:
        if _is_generic_malware_alert(det):
            details = det.get('details') or {}
            generic_meta = {
                "rule_name": det.get('rule_name') or "Malware Detection Alert",
                "rule_id": details.get('rule_id'),
                "detector": det.get('detector'),
            }
            break

    analysis_report['generic_malware_alert'] = bool(generic_meta)
    if generic_meta:
        analysis_report['generic_malware_alert_rule_name'] = generic_meta.get("rule_name")
        analysis_report['generic_malware_alert_rule_id'] = generic_meta.get("rule_id")
        analysis_report['generic_malware_alert_detector'] = generic_meta.get("detector")
        print("  [Analysis] Generic Malware Alert detected (heuristic/static/ML verdict).")

    if rule_analyzer:
        # Update persistent counts
        new_persistent_dict = prev_persistent.copy()
        new_new_list = []
        active_rules_context = []
        seen_rule_files = set()
        rule_matches = []

        # Match each alert to its local TOML rule definition. This uses the
        # Elastic rule_id when available (most reliable), then falls back to
        # rule name and keyword matching inside analyze_detection().
        for det in detections:
            analysis = rule_analyzer.analyze_detection(det)
            if analysis:
                rule_matches.append(
                    {
                        "alert_rule_name": det.get('rule_name'),
                        "alert_rule_id": (det.get('details') or {}).get('rule_id'),
                        "matched": bool(analysis.get('rule_found')),
                        "matched_rule_name": analysis.get('rule_name'),
                        "matched_rule_file": analysis.get('rule_file'),
                    }
                )
                if analysis.get('rule_found') and analysis.get('full_rule'):
                    full_rule = analysis['full_rule']
                    if full_rule.get('file_name') not in seen_rule_files:
                        seen_rule_files.add(full_rule.get('file_name'))
                        active_rules_context.append(full_rule)

        for r_name in current_rule_names:
            if r_name in new_persistent_dict:
                new_persistent_dict[r_name] += 1
            elif r_name in prev_new or r_name in prev_solved:
                new_persistent_dict[r_name] = 2  # Moved to persistent
            else:
                new_new_list.append(r_name)

        # Identify solved rules (Was in previous persistent or new, but NOT in current detections)
        # Note: This logic assumes if I fixed it, it's gone for good.
        # But if compilation failed, we don't reach here, so we don't accidentally "solve" rules by failing to compile.

        all_prev_rules = set(prev_persistent.keys()) | prev_new
        all_current = set(current_rule_names)

        solved = list(all_prev_rules - all_current)
        if solved:
            print(f"Solved Rules: {solved}")

        analysis_report['persistent_rules'] = list(new_persistent_dict.items())
        analysis_report['new_rules'] = new_new_list
        analysis_report['solved_rules'].extend(solved)
        analysis_report['active_rules_context'] = active_rules_context
        analysis_report['rule_matches'] = rule_matches
        # Pre-rendered detection block for downstream prompts (ai_analyze /
        # generate) so the alert+rule context doesn't need to be re-matched.
        analysis_report['detections_context'] = format_detections_for_prompt(detections, rule_analyzer)

        return {"analysis_report": analysis_report}

    # No rule analyzer (disabled or empty directory): still record the raw
    # detection context so prompts are not left completely blind.
    if detections:
        analysis_report['detections_context'] = format_detections_for_prompt(detections, None)

    return {"analysis_report": analysis_report}


def record_history(state: AgentState) -> AgentState:
    """Record the iteration into history and increment iteration counter."""
    print("--- Record History ---")

    iteration = state['iteration']
    status = state['status']
    current_code = state.get('current_code')
    ai_strategy_plan = state.get('ai_strategy_plan')
    detections = state.get('detections', [])

    # 1. Determine Outcome
    outcome = "unknown"
    if status == "clean":
        outcome = "clean"
    elif status == "compile_failed":
        outcome = "compile_fail"
    elif status == "execution_failed" or status == "exec_failed":
        outcome = "exec_fail"
    elif status == "detected":
        outcome = "detected"

    # 2. Extract Approach Name
    approach_name = _extract_approach_name(ai_strategy_plan, iteration)

    # 3. Build Iteration Data
    iteration_data = {
        "iteration": iteration,
        "code": current_code,
        "status": status,
        "outcome": outcome,
        "approach_name": approach_name,
        "ai_strategy_plan": ai_strategy_plan,
        "compile_result": state.get('compile_result'),
        "exec_result": state.get('exec_result'),
        "compile_success": state.get('compile_result', {}).get('success', False),
        "exec_success": state.get('exec_result', {}).get('success', False),
        "detections": detections,
        "analysis": state.get('analysis_report', {}),
    }

    # 4. Update Summaries & Tracker
    # Rules list
    rules_triggered = [d.get('rule_name', 'unknown') for d in detections]

    compact_summary = _build_compact_summary(ai_strategy_plan, outcome, rules_triggered)

    # Get current trackers
    tracker = state.get('approach_tracker', [])
    banned = state.get('banned_approaches', [])
    iteration_summaries = state.get('iteration_summaries', [])

    # Update tracker
    tracker, banned = _update_approach_tracker(
        tracker, banned, approach_name, iteration, outcome, rules_triggered, compact_summary
    )

    # Extract Technique Details (Methodology)
    # We want the "Methodology" or similar detail to explain "How"
    import re

    methodology = "Standard implementation"
    match_meth = re.search(
        r"\*\*Methodology\*\*:\s*(.+?)(?:\n\*\*|$)", ai_strategy_plan or "", re.DOTALL | re.IGNORECASE
    )
    if match_meth:
        methodology = match_meth.group(1).strip()[:150].replace("\n", " ")

    # Add summary with rich metadata
    iteration_summaries.append(
        {
            "iter": iteration,
            "approach": approach_name,
            "technique_details": methodology,
            "outcome": outcome,
            "rules": rules_triggered,
            "analysis": "Pending AI Analysis",  # Will be backfilled by next AI step
            "summary": compact_summary,  # Keep for legacy/tracker if needed
        }
    )

    current_history = state.get('history', [])
    new_history = current_history + [iteration_data]

    # Increment iteration ONLY if it wasn't a pure compilation/crash failure
    # If it failed to compile or crashed without executing fully, it's a bug fix retry.
    is_bug = outcome == "compile_fail" or (
        outcome == "exec_fail" and state.get('exec_result', {}).get('crashed', False)
    )

    bug_retries = state.get('bug_retries', 0)
    if is_bug:
        bug_retries += 1
        if bug_retries >= 5:
            print("[!] Reached max bug retries (5). Forcing iteration increment to prevent infinite loop.")
            next_iteration = state['iteration'] + 1
            bug_retries = 0
        else:
            print(f"[*] Bug detected (retry {bug_retries}/5). Retrying without incrementing main iteration.")
            next_iteration = state['iteration']
    else:
        next_iteration = state['iteration'] + 1
        bug_retries = 0

    return {
        "history": new_history,
        "iteration": next_iteration,
        "approach_tracker": tracker,
        "banned_approaches": banned,
        "iteration_summaries": iteration_summaries,
        "bug_retries": bug_retries,
    }


def check_next_step(state: AgentState) -> str:
    """Edge condition to determine next step."""
    status = state['status']
    iteration = state['iteration']
    max_iterations = state['max_iterations']
    banned_approaches = state.get('banned_approaches', [])

    if status == 'clean':
        return "end"

    if len(banned_approaches) >= 6:
        print("[!] Too many approaches banned (>=6). Aborting to prevent infinite failure loops.")
        return "end"

    if iteration > max_iterations:
        return "end"

    return "loop"
