# ETH Check

A lightweight, locally-first Ethereum smart contract security checker that intelligently coordinates **Slither + Mythril** with sensible defaults, supports multiple `solc` environments, and offers a single-command batch processing pipeline.

- **Batch scanning** flattens Solidity files and automatically switches `solc` based on file `pragma` directives (via `solc-select`)
- **Dual Engines**: Runs Slither (static) + Mythril (symbolic) concurrently and aggregates results
- **P-Class Mappings (15 classes)** present high-level, auditor-friendly detection outcomes
- **Out-of-the-box Reporting**: Summary CSV + Single-file table + Markdown report

> Recent batch (50 files): Mythril ≥1 trigger rate: **76%**, Slither ≥1 trigger rate: **100%**, Both ≥1 trigger rate: **100%**  
> Primary P-classes: P1 (Reentrancy), P9 (Visibility), P8 (Unsafe Ether Handling), P10 (Cross-Functional Reentrancy)

---

## Why Choose This Approach Over Single Tools Like Slither/Mythril?

1) **Coverage**: Complementary dual engines of static analysis + symbolic execution (explainable rules + deep path exploration).  
2) **Version Adaptation**: Automatically parses `pragma` directives, switches matching `solc` versions per file to reduce false positives/negatives.  
3) **Reproducible Batch Processing**: Single command executes entire workflow (preparation → scanning → aggregation → reporting).  
4) **Audit-Friendly Mapping**: Unifies scattered SWCs/detectors into 15 P categories for rapid high-level overview.  
5) **Lightweight Local Operation**: No cloud required—scanning and statistics completed entirely on the terminal.

---

## Repository Structure

eth-check/
├── configs/ # Configuration files (e.g., p_mapping.yaml: SWC/detector → P category mapping)
├── scripts/ # Python utility scripts (preparation, filtering, statistics, report generation)
├── tools/ # Terminal scripts (batch entry point, individual runners)
├── datasets/ # Optional: sample lists (e.g., list_top5.txt)
├── requirements.txt # Python dependencies
└── out/ # Run outputs (automatically generated; not recommended for Git commit)



Translated with DeepL.com (free version)