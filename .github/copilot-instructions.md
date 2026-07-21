# Copilot instructions for this repository

This repository is a notebook-first phishing-URL analysis project. The main working artifact is `PhishingDetector.ipynb`; `Dataset/PhishingWebDetection.ipynb` is a smaller companion notebook.

## Project shape
- The data is CSV-based and lives at `phishing_site_urls.csv` and `Dataset/Dataset.csv`.
- The notebook pipeline is exploratory: load a DataFrame, inspect it, then build text features from the `URL` column.
- Labels are stored in `df['Label']` and use string values like `good` and `bad`.

## Conventions that matter here
- Keep changes notebook-oriented unless you are clearly adding a reusable script.
- The current preprocessing flow is:
  - `df = pd.read_csv(...)`
  - tokenize URLs with `RegexpTokenizer(r'[A-Za-z]+')`
  - stem tokens with `SnowballStemmer('english')`
  - store the results in `df['text_tokenized']`, `df['text_stemmed']`, and `df['text']`
- When extending the analysis, preserve the existing column names and label semantics; new features should fit into the same DataFrame rather than replacing the notebook workflow.
- The notebooks use `%matplotlib inline`, so plotting code should stay compatible with inline display.

## Workflow notes
- Dependencies are installed ad hoc inside notebooks with `%pip install ...` (for example, `pandas`, `numpy`, `matplotlib`, and `nltk`), so do not assume a formal `requirements.txt` exists.
- Paths are relative to the notebook’s working directory; the top-level notebook expects `phishing_site_urls.csv` in the repo root.
- The dataset is large (roughly 549k rows), so avoid repeatedly re-reading the CSV or creating unnecessary copies of the full DataFrame while experimenting.

## What to preserve when editing
- Keep the notebook’s step-by-step style and explain new steps in nearby cells.
- If you add new preprocessing or modeling logic, add it in a new cell rather than rewriting existing exploratory cells unless the change is clearly required.
- Prefer small, inspectable changes over large refactors; this project is still an analysis notebook rather than a packaged application.
