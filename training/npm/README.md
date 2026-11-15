# Training the npm models

Scripts that build, train and measure AegisPilot's npm models (why npm has its own: [docs/ml-npm.md](../../docs/ml-npm.md)). They are not part of the guard. They need network access (npm registry, api.npmjs.org, OSV, GitHub) and, for `train.py`, the packages in [guard/ml/requirements.txt](../../guard/ml/requirements.txt) (scikit-learn 1.9.1, numpy, shap, joblib) in a virtual environment of your own.

Data stays outside the repository, in `$AEGIS_NPM_DATA` (default `../research/npm-ml` next to the checkout). Malicious samples are only read as data (zips opened in memory with the password `infected`); nothing is extracted to disk, installed or run.

## Steps

```bash
export AEGIS_NPM_DATA=~/research/npm-ml
mkdir -p $AEGIS_NPM_DATA && cd training/npm

# 1. malicious samples: the DataDog dataset, npm part only (about 26,700 zips)
GIT_LFS_SKIP_SMUDGE=1 git clone --depth 1 --filter=blob:none --sparse \
    https://github.com/DataDog/malicious-software-packages-dataset $AEGIS_NPM_DATA/dd
git -C $AEGIS_NPM_DATA/dd sparse-checkout set samples/npm

# 2. benign packages (a few hours; top / longtail / new, 1,500 each), and a second, independent set for the final check
python3 collect_benign.py --out $AEGIS_NPM_DATA/benign --datadog-manifest $AEGIS_NPM_DATA/dd/samples/npm/manifest.json \
    --exclude-manifests $AEGIS_BENCH/manifest-*.json
python3 collect_benign.py --out $AEGIS_NPM_DATA/final --top 150 --longtail 250 --new 250 --seed 20261116 \
    --datadog-manifest $AEGIS_NPM_DATA/dd/samples/npm/manifest.json \
    --exclude-manifests $AEGIS_BENCH/manifest-*.json --exclude-dirs $AEGIS_NPM_DATA/benign

# 3. a few days later: drop new packages reported malicious since they were collected
python3 collect_benign.py --out $AEGIS_NPM_DATA/benign --recheck --datadog-manifest $AEGIS_NPM_DATA/dd/samples/npm/manifest.json
python3 collect_benign.py --out $AEGIS_NPM_DATA/final --recheck --datadog-manifest $AEGIS_NPM_DATA/dd/samples/npm/manifest.json

# 4. features (the guard's own code); benchmark names stay out of training
python3 build_features.py malicious --datadog $AEGIS_NPM_DATA/dd --out $AEGIS_NPM_DATA/mal.jsonl \
    --exclude-manifests $AEGIS_BENCH/manifest-*.json
python3 build_features.py benign --benign $AEGIS_NPM_DATA/benign --out $AEGIS_NPM_DATA/benign.jsonl
python3 build_features.py benign --benign $AEGIS_NPM_DATA/final --out $AEGIS_NPM_DATA/final.jsonl

# 5. train and measure (the test sets once), optionally with the one-model-for-both comparison
python3 train.py --mal $AEGIS_NPM_DATA/mal.jsonl --benign $AEGIS_NPM_DATA/benign.jsonl \
    --final-benign $AEGIS_NPM_DATA/final.jsonl --cutoff 2026-05-01 --out $AEGIS_NPM_DATA/out \
    [--joint-pypi pypi_rows.csv]
```

`--cutoff`: malicious samples found on or after this day are the test set. Pick it before training so that the test set is the last few months (about a fifth of the samples), and do not change it after seeing results.

`--joint-pypi`: a CSV with one PyPI release per row (the raw PyPI feature names of `guard/ml/features.py` and `code_features.py`, `label` 1 for malicious, optional `split` train/test), e.g. the training table of the PyPI model v2. Without it the comparison is skipped.

## What train.py does

1. Malicious rows split by the day they were found; benign rows split by package name (25% test), the final set kept apart.
2. At most three malicious rows with exactly the same features (campaigns publish hundreds of copies).
3. Install ages, as for the PyPI model R3f: a malicious version stands for every age from 0 to the day it was found (it was installable until then); a new benign package for 0, 1, 3, 7, 14 and 30 days; an established one for its age when collected. Each row's copies weigh 1 in total; both classes weigh the same.
4. Random forest, 300 trees, `min_samples_leaf=2` (as for PyPI); `npm_full` with the registry features, `npm_pkg` without.
5. Threshold: out-of-fold predictions (5 folds by package name) on the training rows; the lowest threshold at which the benign REVIEW rate (two stages, as `ml/scan.py` decides) is at most 5% overall, 2% popular, 8% long tail and 8% new, at every install age.
6. One measurement of the test set and the final set with that threshold; the pure-Python forest of the guard checked against scikit-learn on the same rows.

Output in `--out`: the two model files (`aegis-ml-npm-full-1.json.gz`, `aegis-ml-npm-pkg-1.json.gz`), `models_npm.json` (the `npm` block for `guard/ml/models.json`), `metrics.json` and the scikit-learn bundles (`*.joblib`, never committed).

## Release

1. Upload the two `.json.gz` files to a GitHub release named `ml-models-npm-1`.
2. Put the `npm` block of `models_npm.json` into `guard/ml/models.json` (the URL in it points at that release).
3. `python3 guard_cli.py ml-install --from $AEGIS_NPM_DATA/out --yes` on a test machine, then `verify` shows `ML (npm): installed`.

## Smoke test (no network)

`build_features.py local --node-modules DIR...` reads packages already installed on the machine (no registry document: `npm_pkg` only). With a few hundred local packages and the DataDog samples it runs the whole pipeline in about a minute; its numbers say nothing about real performance (the local packages are popular, well-made dependencies).
