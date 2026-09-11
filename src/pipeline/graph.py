"""
src/pipeline/graph.py — LangGraph state machine construction.

Builds and compiles the full Agentic-CTI pipeline graph from its constituent
nodes and conditional edge routers. The compiled graph is instantiated once at
module import time and reused across all pipeline invocations.

Graph topology (two entry paths):

  [TEXT REPORT PATH]
  entry_router ──(text_report)──► scan_for_injection (Node 0)
                                        ↓ (safe)
                                  extract_threat_intel (Node 1)
                                        ↓ (success)
                                       ┐
  [ES LOG QUERY PATH]                  │
  entry_router ──(log_query)──► query_elasticsearch_logs (Node 0.5)
                                        ↓
                                  synthesize_from_logs (Node 1b)
                                        ↓
                                       ┘
                                  contextualize_with_rag (Node 2)
                                        │
                        ┌───────────────┴───────────────┐
                        ▼                               ▼
                  generate_sigma (Node 3a)     generate_kql (Node 3b)
                        │     [parallel fan-out]        │
                        └───────────────┬───────────────┘
                                        │ (fan-in join)
                                        ▼
                                  generate_yaral (Node 3c) ◄───┐
                                        ↓                      │
                                  validate_yaral (Node 4) ──(fail)┘
                                        ↓ (pass or exhausted)
                                     finalize (Node 5)
                                        ↓
                                       END
"""

from typing import Any

from langgraph.graph import END, StateGraph

from src.models.schemas import ThreatIntelState
from src.pipeline.nodes.es_query import query_elasticsearch_logs
from src.pipeline.nodes.extract import extract_threat_intel, synthesize_from_logs
from src.pipeline.nodes.finalize import finalize
from src.pipeline.nodes.kql import generate_kql
from src.pipeline.nodes.rag import contextualize_with_rag
from src.pipeline.nodes.security import scan_for_injection
from src.pipeline.nodes.sigma import generate_sigma
from src.pipeline.nodes.yaral import generate_yaral, validate_yaral
from src.pipeline.routers import (
    _route_after_es_query,
    _route_after_extraction,
    _route_after_scan,
    _route_after_validation,
    _route_entry_point,
)


def _build_graph() -> Any:
    """
    Build and compile the LangGraph state machine.

    Returns:
        A compiled LangGraph CompiledGraph ready for invocation.
    """
    workflow = StateGraph(ThreatIntelState)

    # ── Register all nodes ──────────────────────────────────────────────────
    # Shared entry router (virtual start node)
    workflow.add_node("entry_router_node", lambda s: s)  # pass-through; routing done by conditional edge

    # Text-report path
    workflow.add_node("scan_for_injection", scan_for_injection)         # Node 0
    workflow.add_node("extract_threat_intel", extract_threat_intel)     # Node 1

    # ES log-query path
    workflow.add_node("query_elasticsearch_logs", query_elasticsearch_logs)  # Node 0.5
    workflow.add_node("synthesize_from_logs", synthesize_from_logs)          # Node 1b

    # Shared downstream pipeline
    workflow.add_node("contextualize_with_rag", contextualize_with_rag)  # Node 2
    workflow.add_node("generate_sigma", generate_sigma)                  # Node 3a
    workflow.add_node("generate_kql", generate_kql)                      # Node 3b
    workflow.add_node("generate_yaral", generate_yaral)                  # Node 3c
    workflow.add_node("validate_yaral", validate_yaral)                  # Node 4
    workflow.add_node("finalize", finalize)                              # Node 5

    # ── Entry point: dispatch to correct first node based on input_type ─────
    workflow.set_entry_point("entry_router_node")
    workflow.add_conditional_edges(
        "entry_router_node",
        _route_entry_point,
        {
            "scan_for_injection":       "scan_for_injection",
            "query_elasticsearch_logs": "query_elasticsearch_logs",
        },
    )

    # ── Text-report path edges ───────────────────────────────────────────────
    workflow.add_conditional_edges(
        "scan_for_injection",
        _route_after_scan,
        {
            "extract_threat_intel": "extract_threat_intel",
            "finalize": "finalize",
        },
    )
    workflow.add_conditional_edges(
        "extract_threat_intel",
        _route_after_extraction,
        {
            "contextualize_with_rag": "contextualize_with_rag",
            "finalize": "finalize",
        },
    )

    # ── ES log-query path edges ──────────────────────────────────────────────
    workflow.add_conditional_edges(
        "query_elasticsearch_logs",
        _route_after_es_query,
        {
            "synthesize_from_logs": "synthesize_from_logs",
            "finalize": "finalize",
        },
    )
    workflow.add_conditional_edges(
        "synthesize_from_logs",
        _route_after_extraction,  # same router — checks extraction_error
        {
            "contextualize_with_rag": "contextualize_with_rag",
            "finalize": "finalize",
        },
    )

    # ── Shared downstream edges ──────────────────────────────────────────────
    # Sigma and KQL are independent of each other — both only need the
    # extracted_report from RAG. Fan them out in parallel so they run
    # concurrently, then join at generate_yaral before the retry loop.
    #
    # Graph topology:
    #   contextualize_with_rag --+-- generate_sigma --+-- generate_yaral --> validate_yaral
    #                            +-- generate_kql   --+        ^                    |
    #                                                          | (retry)            |
    #                                                          +--------------------+
    #
    # LangGraph fan-in semantics: generate_yaral waits for ALL nodes that
    # triggered it in the SAME step. On the initial run that's both
    # generate_sigma and generate_kql. On retry it's only validate_yaral
    # (sigma/kql are already done), so no extra waiting occurs.
    workflow.add_edge("contextualize_with_rag", "generate_sigma")   # parallel fan-out
    workflow.add_edge("contextualize_with_rag", "generate_kql")     # parallel fan-out
    workflow.add_edge("generate_sigma", "generate_yaral")           # join (waits for both)
    workflow.add_edge("generate_kql", "generate_yaral")             # join
    workflow.add_edge("generate_yaral", "validate_yaral")
    workflow.add_conditional_edges(
        "validate_yaral",
        _route_after_validation,
        {
            "generate_yaral": "generate_yaral",
            "finalize": "finalize",
        },
    )
    workflow.add_edge("finalize", END)

    return workflow.compile()


# Compile once at module import time — reused across all pipeline runs.
graph = _build_graph()
