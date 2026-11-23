# Training (Signal C fine-tune)

Full step-by-step notes and reproduce commands: [`training/README.md`](../training/README.md). This page is the summary.

## What was trained

| | |
|---|---|
| Base model | `Qwen3-4B-Instruct-2507` (runs in LM Studio, ~2 s per scenario on an RTX 3080 laptop GPU, 16 GB) |
| Method | QLoRA: 4-bit base, LoRA r=16, alpha=32, dropout 0.05, lr 2e-4 (cosine, warm-up), loss on completion tokens only |
| Data | 88-example random slice of `training/data/train.jsonl` (~28% romance), see [DATASETS.md](DATASETS.md) |
| Run | 1 epoch, 11 optimiser steps (grad accum 8), 535 s, peak ~9 GB VRAM |
| Loss | logged 14.99 → 0.86 (scaled ×8 by accumulation; ≈1.9 → 0.11 per token) — `training/out/train_log.txt` |
| Output | adapter `training/out/adapter` → fp16 merge → GGUF Q4_K_M `2ndeye-qwen3-4b-ft-Q4_K_M.gguf` (2.5 GB), imported into LM Studio as `qwen3-4b-ft` |

## Why only 88 examples

The 16 GB GPU was shared with LM Studio, which had to keep the live-demo model loaded. The full 1170-example run did not finish
an optimiser step in 8 minutes (VRAM spilled to shared memory); a full epoch projected to ~2.5 h. With the code freeze at 17:00 we
ran a reduced smoke-test fine-tune instead.

## Status: not shipped

- The fine-tuned model was **not** loaded in the demo and **not** compared against the base; dev evaluation was stopped unfinished.
- The presentation and the Test Set run used the **base** `qwen/qwen3-4b-2507` with the hardened prompt.
- The go/no-go rule (PLAN.md §2b) was: ship a fine-tune only if it beats the base on validation + self-test and keeps 11/11.
  That check never ran, so no quality claim is made for the fine-tune.

## Toolchain

`uv` venv on Python 3.12, torch 2.11 + cu128, transformers 5.23, peft 0.21, trl 1.18, bitsandbytes 0.50 (native Windows),
llama.cpp b12535 for `convert_hf_to_gguf.py` and `llama-quantize`. Weights, venv, checkpoints and GGUFs are git-ignored
(`training/hf/`, `training/out/`, `training/tools/`, `*.gguf`, `*.safetensors`).

## Next steps if we continue

1. Run the full 2-epoch fine-tune on a free GPU (~6 GB, 40–60 min), see `training/README.md`.
2. Evaluate base vs fine-tune with `training/eval_dev.py` and `backend/evaluate.py` (validation must stay 11/11, with and without `--no-llm`).
3. Review the under-labelled examples in `raul_train.jsonl` before concatenating it into the training set.
