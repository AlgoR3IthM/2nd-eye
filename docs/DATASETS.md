# Datasets

Every dataset the project uses, where it came from, and whether it may be used for training.

| Dataset | Path | Size | Source | Used for | In training? |
|---|---|---|---|---|---|
| Synthetic train set | `training/data/train.jsonl` | 1170 examples | `training/gen_data.py --n 1300 --seed 7` (team-written generator) | QLoRA fine-tune of Signal C | yes |
| Synthetic dev set | `training/data/dev.jsonl` | 130 examples | same generator, held-out split | dev metrics (`training/eval_dev.py`) | no (held out) |
| Raul's stress-test data | `Nou Raul/train_data.jsonl` | 600 lines, 289 distinct inputs | written by our teammate Raul for his engine | converted by `training/convert_raul.py` | not merged yet |
| Raul's data, converted | `training/data/raul_train.jsonl`, `raul_dev.jsonl` | 261 + 28 | `convert_raul.py` (per-message evidence placed with `rules.detect()`) | optional extra training data | no (review first) |
| Retrieval patterns | `backend/patterns.json` | small | team-written Romanian examples | few-shot examples retrieved into the LLM prompt by token overlap | no |
| Official catalog | `Cerinte/official_catalog.json` | — | hackathon organisers | Signal B: real phone numbers and domains of banks, couriers, authorities | no |
| Validation Set | `Cerinte/validation_set/V01..V11.json` + `validation_expected_results.csv` | 11 scenarios | hackathon organisers (all scams) | held-out check, `backend/evaluate.py` must print 11/11 | **never** |
| Secret Test Set | not in the repo (`Cerinte/test_set/` is git-ignored) | 17 scenarios T01..T17 | hackathon organisers, released 15:45 on the day | final scoring run; our output is `demo/test_set_results.csv` | **never** |

## Synthetic generator (`training/gen_data.py`)

Labels are correct by construction: each sender message is assembled from phrase families tied to one red flag, and the
evidence span is marked in the template, so the evidence quote always occurs verbatim in the text.

- **Distribution (current set, 1300 examples):** 488 scam, 242 slow-burn scam, 570 genuine (hard negatives); 581 obfuscated.
- **Scam types:** ROMANCE 204, BANK_IMPERSONATION 83, FAMILY_EMERGENCY 72, COURIER_FEE 58, ACCOUNT_TAKEOVER 55, INVESTMENT 51,
  JOB_OFFER 49, AUTHORITY_IMPERSONATION 48, MARKETPLACE 46, TECH_SUPPORT 40, PRIZE_LOTTERY 24 (see `training/data/stats.json`).
- **Romance emphasis (team request):** ~28% of scams; 6–10 message threads, excuses (offshore, army, widower, doctor abroad),
  late indirect asks (plane ticket, customs fee, gift cards, "un mic ajutor", crypto "investment").
- **Indirect payment asks** with no sum and no word for money ("ai putea să-mi dai pentru un uber?"), added after a live test where
  such a message got through.
- **Hard negatives:** official notices, delivered OTP codes with "do not share", urgent-but-genuine, money already paid,
  relatives sharing a new number without asking for anything, affection-only messages.
- **Obfuscation:** no diacritics, leet, case changes, no punctuation, typos, emoji.
- **Prompt parity:** inputs are built by importing `backend/llm.py`, so they are byte-identical to the live prompt;
  `training/data/source_hashes.txt` records the md5 of `llm.py` and `patterns.json` used. Change the prompt → regenerate.

## Rules we kept

- Nothing from the Validation Set, the Test Set or the self-test is in any training file.
- No cloud AI generated the data at runtime and no real user messages are stored anywhere.
- Synthetic data teaches format, evidence discipline, obfuscation robustness and staying quiet on genuine messages;
  it cannot teach the real distribution of scammer language. See [TRAINING.md](TRAINING.md).

## Third-party material

Everything under `Cerinte/` (brief, scoring rules, official catalog, Validation Set) belongs to the hackathon organisers and is
**not** covered by this repository's MIT License. The Secret Test Set is intentionally not committed.
