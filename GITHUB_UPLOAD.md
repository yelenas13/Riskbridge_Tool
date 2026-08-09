# Fresh GitHub Upload

## Recommended: keep a backup before replacing the old repository

From the old local repository:

```bash
git tag legacy-colab-prototype
git push origin legacy-colab-prototype
```

This preserves the research prototype even if the main branch is replaced.

## Option A — Create a completely new GitHub repository

1. Create an empty repository named `RiskBridge` on GitHub.
2. Do **not** add a README, `.gitignore`, or license from GitHub because this project already contains them.
3. Extract the RiskBridge zip.
4. Open a terminal inside the extracted folder.

```bash
git init
git branch -M main
git add .
git commit -m "RiskBridge v0.3 clean architecture"
git remote add origin https://github.com/YOUR-USERNAME/RiskBridge.git
git push -u origin main
```

## Option B — Replace the contents of the existing repository but preserve Git history

Clone the current repository and create a backup tag first:

```bash
git clone https://github.com/YOUR-USERNAME/RiskBridge.git
cd RiskBridge
git tag legacy-colab-prototype
git push origin legacy-colab-prototype
```

Delete the tracked working-tree contents, copy the new RiskBridge files into the folder, then:

```bash
git add -A
git commit -m "Rebuild RiskBridge as organization-ready platform"
git branch -M main
git push -u origin main
```

If the repository default branch is currently named something else, change the default branch to `main` in GitHub Settings after pushing.

## Validate after upload

GitHub Actions should run automatically. Locally:

```bash
python -m venv riskenv
```

Windows PowerShell:

```powershell
.\riskenv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
source riskenv/bin/activate
```

Install and test:

```bash
python -m pip install --upgrade pip
pip install -e .
pytest -q
riskbridge demo
streamlit run app.py
```

## Do not upload organization data

Never commit real asset inventories, vulnerability scanner exports, credentials, tokens, API keys, or generated reports to a public repository.
