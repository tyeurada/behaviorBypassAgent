import argparse
import os
import sys

from dotenv import load_dotenv

from core.graph import create_graph

# import config  # If we need global config

_SENSITIVE_PARTS = {"key", "secret", "password", "token", "host", "url", "endpoint", "apikey"}


def _mask_secrets(obj):
    """Recursively mask values whose key looks like a credential or endpoint.
    Matching is per word part (e.g. api_key, base_url) so max_tokens etc. survive.
    *_env keys hold env var names, not secrets."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            kl = str(k).lower().replace("-", "_")
            parts = set(kl.split("_"))
            if not kl.endswith("_env") and parts & _SENSITIVE_PARTS:
                out[k] = "***"
            else:
                out[k] = _mask_secrets(v)
        return out
    if isinstance(obj, list):
        return [_mask_secrets(v) for v in obj]
    return obj


def main():
    parser = argparse.ArgumentParser(description="Evasive AI Agent (LangGraph)")
    parser.add_argument("--shellcode", "-s", required=False, help="Path to shellcode file")
    parser.add_argument("--iterations", "-i", type=int, default=4, help="Maximum number of iterations")
    parser.add_argument("--check-elastic", action="store_true", help="Check Elastic connection and last 10 mins alerts")
    parser.add_argument("--session-dir", required=False, help="Explicit session directory path")

    args = parser.parse_args()

    # Load environment
    load_dotenv()

    # Avoid cp932 console crashes on chars like em-dash in LLM output (Windows).
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass

    # Check Elastic Connection if requested
    if args.check_elastic:
        print("\n--- Checking Elastic Connection ---")
        from core.utils import load_config
        from lib.detectors.elastic import ElasticDetector

        config = load_config()
        elastic_config = config.get('detectors', {}).get('elastic', {})
        detector = ElasticDetector(elastic_config)

        if detector.is_available():
            print("[SUCCESS] Connected to Elastic!")
            print("Fetching alerts for last 10 minutes...")
            alerts = detector.check_detection(time_window_seconds=600, use_smart_filtering=False)
            print(f"Found {len(alerts)} alerts:")
            for alert in alerts:
                print(f"  - [{alert.timestamp}] {alert.rule_name}")
        else:
            print("[FAILED] Could not connect to Elastic.")
            print("Please check your .env file or config.yaml.")
        return

    # Verify the API key for the configured provider (only needed for agent runs)
    from core.utils import load_config
    from lib.llm_factory import api_key_required, get_provider, required_env_var

    try:
        cfg = load_config()
        provider = get_provider(cfg)
        provider_cfg = (cfg.get("ai", {}) or {}).get(provider, {}) or {}
        env_var = required_env_var(provider, provider_cfg)
    except ValueError as e:
        print(f"Error: {e}")
        return
    if not os.getenv(env_var):
        if api_key_required(provider):
            print(f"Error: {env_var} not set in environment or .env file (provider={provider})")
            return
        print(f"Warning: {env_var} not set; using a placeholder key (OK for local servers that ignore auth)")

    if not args.shellcode:
        parser.error("The following arguments are required: --shellcode/-s (unless --check-elastic is used)")

    shellcode_path = os.path.abspath(args.shellcode)
    if not os.path.exists(shellcode_path):
        print(f"Error: Shellcode file not found at {shellcode_path}")
        return

    print("Starting Evasive AI Agent...")
    print(f"Shellcode: {shellcode_path}")
    print(f"Max Iterations: {args.iterations}")

    # Generate Session Directory
    if args.session_dir:
        session_dir = os.path.abspath(args.session_dir)
    else:
        import datetime

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        session_dir = os.path.join("output", timestamp)
    os.makedirs(session_dir, exist_ok=True)
    print(f"Output Directory: {session_dir}")

    # Save the effective config (base + config.local.yaml merged) to session dir.
    # Credential-looking values are masked; real credentials come from env/.env anyway.
    import yaml

    config_dest = os.path.join(session_dir, "run_config.yaml")
    try:
        with open(config_dest, "w", encoding="utf-8") as f:
            yaml.safe_dump(_mask_secrets(cfg), f, sort_keys=False, allow_unicode=True)
    except Exception as e:
        print(f"Warning: Could not write run_config.yaml to session dir: {e}")

    # Initialize Graph
    graph = create_graph()

    # Initial State
    initial_state = {
        "shellcode_path": shellcode_path,
        "max_iterations": args.iterations,
        "iteration": 1,
        "status": "start",
        "history": [],
        "analysis_report": {"solved_rules": [], "persistent_rules": [], "new_rules": [], "last_failure_reason": None},
        "current_code": None,
        "detections": [],
        "error": None,
        "session_dir": session_dir,
        "bug_retries": 0,
        # New Memory Fields
        "approach_tracker": [],
        "iteration_summaries": [],
        "banned_approaches": [],
    }

    # Run Graph
    print("\n--- Agent Loop Started ---\n")
    final_state = None

    try:
        # We use invoke to run the graph to completion
        final_state = graph.invoke(initial_state)

    except Exception as e:
        print(f"\n[!] Error during execution: {e}")
        import traceback

        traceback.print_exc()
        return

    print("\n--- Agent Loop Finished ---\n")

    # Print Summary
    if final_state:
        status = final_state.get('status', 'unknown')
        iterations = final_state.get('iteration', 0)
        history = final_state.get('history', [])

        summary_lines = []
        summary_lines.append(f"Final Status: {status}")
        summary_lines.append(f"Total Iterations: {iterations}")

        if status == 'clean' or (history and history[-1]['status'] == 'clean'):
            summary_lines.append("\nSUCCESS! EEDR Bypass Achieved.")

            if final_state.get('compile_result'):
                summary_lines.append(f"Loader Executable: {final_state['compile_result'].get('output_path')}")
        else:
            summary_lines.append("\nFAILED: Max iterations reached or unrecoverable error.")
            if final_state.get('analysis_report'):
                summary_lines.append("Final Analysis Report:")
                import json

                summary_lines.append(json.dumps(final_state['analysis_report'], indent=2))

        summary_text = "\n".join(summary_lines)
        print(summary_text)

        # Save summary to file
        try:
            summary_path = os.path.join(final_state.get('session_dir'), "final_summary.txt")
            with open(summary_path, "w", encoding="utf-8") as f:
                f.write(summary_text)
            print(f"Summary saved to {summary_path}")
        except Exception as e:
            print(f"Error saving summary: {e}")


if __name__ == "__main__":
    main()
