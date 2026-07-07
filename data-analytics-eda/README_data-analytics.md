# NIDS Dataset - Exploratory Data Analysis & Cleaning

A data analytics deep-dive into the NSL-KDD network intrusion dataset: exploring, cleaning, and preparing raw network traffic logs for machine learning. This is the data-side companion to the [ML/AutoAI project](../README.md) in this repo.

[![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![pandas](https://img.shields.io/badge/pandas-Data%20Cleaning-150458?logo=pandas&logoColor=white)](https://pandas.pydata.org/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-Encoding-F7931E?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)

---

## Table of Contents

- [Overview](#overview)
- [Dataset](#dataset)
- [Process](#process)
- [Key Findings](#key-findings)
- [Screenshot](#screenshot)
- [Cleaning Decisions](#cleaning-decisions)
- [Output](#output)

---

## Overview

Network intrusion datasets are messy in a specific way: they're not full of missing values, but they are heavily imbalanced, mix categorical and numeric features, and use raw labels that are too fine-grained to be directly useful. This notebook walks through exploring the raw NSL-KDD training data and turning it into a clean, model-ready CSV - with every transformation decision explained and justified.

## Dataset

- **Source:** [Kaggle Network Intrusion Detection NSL-KDD dataset](https://www.kaggle.com/code/timgoodfellow/nsl-kdd-explorations)
- **Raw file:** `KDDTrain+.txt`  no header row, so column names were assigned manually based on the [standard NSL-KDD feature list](https://www.kaggle.com/code/timgoodfellow/nsl-kdd-explorations).
- **Raw shape:** 125,972 rows and 43 columns
- **Each row** is a single network connection, described by features like `duration`, `protocol_type`, `service`, `src_bytes`, `dst_bytes`, `num_failed_logins`, plus a `label` column naming the specific attack (or `normal`).

## Process

1. **Load & assign column names:** the raw `KDDTrain+.txt` file has no header, so all 43 feature names were mapped on manually.
2. **Initial exploration:** checked shape, dtypes, missing values, and duplicate rows.
3. **Label distribution:** examined the raw 23-class label column to understand how imbalanced the attack types are.
4. **Category grouping:** mapped all 23 raw attack names down to the 5 classes the project needs: `normal`, `DoS`, `Probe`, `R2L`, `U2R`.
5. **Column pruning:** dropped the now-redundant `label` column, the KDD-specific `difficulty` score, and any constant columns.
6. **Categorical encoding:** label-encoded `protocol_type`, `service`, and `flag` into numeric codes, saving the exact mapping to `label_encoders.json` so the same encoding can be reused at prediction time.
7. **Final checks:** re-checked for duplicates post-cleaning, reviewed summary statistics, and visualized a feature correlation heatmap.
8. **Export:** saved the model-ready dataset as `cleanTrain_data.csv`.

## Key Findings

**Missing values:** none. Every one of the 43 raw columns had 0 missing values.

**Class imbalance is severe.** The raw label column has 23 distinct attack names, but they're wildly unevenly represented:

| Raw label (top ones) | Count |
|---|---|
| normal | 67,342 |
| neptune | 41,214 |
| satan | 3,633 |
| ipsweep | 3,599 |
| portsweep | 2,931 |
| smurf | 2,646 |
| ... (17 more, several under 20 rows) | |

After grouping into the 5 project categories, the imbalance is still stark:

| Category | Count | Share |
|---|---|---|
| normal | 67,342 | 53.5% |
| DoS | 45,927 | 36.5% |
| Probe | 11,656 | 9.3% |
| R2L | 995 | 0.8% |
| U2R | 52 | 0.04% |

**Takeaway:** `normal` and `DoS` alone make up ~90% of the dataset, while `U2R` arguably the most severe attack category, since it represents privilege escalation has only 52 examples out of ~126,000 rows. A model that ignored U2R entirely could still post a very high overall accuracy score. This is the single most important thing to communicate about this dataset, and it directly shaped how the model results are reported in the ML project.

**One constant column:** `num_outbound_cmds` had the same value in every single row, so it carried zero information and was dropped.

**Duplicates:** 0 duplicate rows in the raw data. After dropping the `label`, `difficulty`, and constant columns, 9 rows became exact duplicates of each other (since removing columns can make previously-distinct rows identical) these were removed at the end.

## Screenshot

<div align="center">
  <img src="./images/raw label distribution.png" alt="AutoAI Leaderboard" width="80%">
</div>
<div align="center">
  <img src="./images/class distribution.png" alt="AutoAI Leaderboard" width="48%">
  <img src="./images/feature correlation heatmap.png" alt="AutoAI Progress Chart" width="48%">
</div>



## Cleaning Decisions

- **Why group 23 labels into 5 categories?** The project's problem statement specifically calls for 5-class classification (`normal`, `DoS`, `Probe`, `R2L`, `U2R`). Using the standard NSL-KDD mapping keeps the grouping consistent with how these attacks are categorized in security literature, and gives the model a less sparse target than 23 near-empty classes.
- **Why drop `difficulty`?** It's a score assigned by the original KDD competition reflecting how hard a row was to classify. A meta-feature about the dataset itself, not a real network traffic characteristic, so it would leak information a real-world model would never have.
- **Why label-encode instead of one-hot encode?** `protocol_type`, `service`, and `flag` were label-encoded (each category mapped to an integer) to keep the feature count manageable for AutoAI, and the exact encoding was saved to `label_encoders.json` so the downstream Streamlit app can apply the identical mapping to live user input.

## Output

- **`cleanTrain_data.csv`** - 125,963 rows and 41 columns, fully numeric, no missing values, no duplicates. This is the file fed into IBM watsonx.ai AutoAI for model training.
- **`label_encoders.json`** - the saved category-to-integer mappings for `protocol_type`, `service`, and `flag`, reused by the dashboard at prediction time.

---

*This analysis feeds directly into the [ML/AutoAI project](../README.md) in this repo, where `cleanTrain_data.csv` is used to train the deployed intrusion detection model.*
