# Smart Contract Security Pipeline

An AI-powered pipeline that unifies and semantically deduplicates the outputs of **Slither** and **Mythril** to produce auditor-ready vulnerability findings. Extends the ETH-Check framework (Zheng & Hu, 2025) with an LLM-based synthesis layer.

---

## What It Does

Raw outputs from two security tools are normalised into a unified schema, mapped to a P-category taxonomy, and passed to GPT-4o for semantic deduplication — collapsing overlapping alerts into unique, auditor-ready findings surfaced through a Streamlit dashboard.

**Evaluated across 30 labelled smart contracts (SB Curated):**
- 190 raw alerts → 89 unique findings
- 53.16% alert reduction
- $0.19 USD total LLM cost

---

## Pipeline

```
01_prepare.py → Slither + Mythril → parser.py → llm_deduplicator.py → dashboard.py
```

1. **Preparation** — detects Solidity compiler version from pragma, flattens imports
2. **Slither** — static analysis, JSON output
3. **Mythril** — symbolic execution via Docker (smartbugs/mythril:0.24.8)
4. **parser.py** — normalises both outputs into unified Finding schema, maps to P-categories
5. **llm_deduplicator.py** — GPT-4o at temperature 0 groups overlapping alerts semantically
6. **dashboard.py** — Streamlit UI, findings ordered by P-category and severity

---

## Repository Structure

```
├── configs/              # p_mapping.yaml — SWC/detector → P-category mapping
├── scripts/              # Pipeline scripts (01_prepare.py, 03_run_slither.py, 04_run_mythril.py)
├── data/capstone_dataset/ # 30 evaluation contracts organised by DASP category
├── results/              # Per-contract batch results (result.json, run.log)
├── out/                  # Per-contract tool outputs (.slither.json, .myth.json)
├── parser.py             # Output normalisation and P-category mapping
├── llm_deduplicator.py   # LLM semantic deduplication module
├── dashboard.py          # Streamlit dashboard
├── run_pipeline.py       # Single-contract pipeline runner
├── run_batch.py          # Batch runner across dataset
└── requirements.txt
```

---

## Setup

```bash
pip install -r requirements.txt
```

Requires:
- `solc-select` for compiler version management
- Docker (for Mythril)
- Azure OpenAI credentials in `.env`

```
AZURE_OPENAI_ENDPOINT=...
AZURE_OPENAI_DEPLOYMENT=...
AZURE_OPENAI_KEY=...
AZURE_OPENAI_API_VERSION=...
```

---

## Usage

**Single contract:**
```bash
python run_pipeline.py --contract data/capstone_dataset/reentrancy/simple_dao.sol
```

**Batch:**
```bash
python run_batch.py
```

**Dashboard:**
```bash
streamlit run dashboard.py
```