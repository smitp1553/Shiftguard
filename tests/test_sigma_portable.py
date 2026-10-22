from pathlib import Path

import pytest

# these tests need the real sigma tooling. If it is not installed they are skipped, not failed.
# pip install pysigma pysigma-backend-splunk pysigma-backend-elasticsearch
pytest.importorskip("sigma.collection")
splunk = pytest.importorskip("sigma.backends.splunk")
elastic = pytest.importorskip("sigma.backends.elasticsearch")

from sigma.collection import SigmaCollection  # noqa: E402
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError  # noqa: E402

RULES_DIR = Path(__file__).parent.parent / "detections" / "sigma"
RULE_FILES = sorted(RULES_DIR.glob("*.yml"))

# lucene cannot compare two fields of one event, so the two "different user" rules cannot be converted to it
NEEDS_FIELDREF = ["aws_iam_create_access_key_other_user", "aws_iam_login_profile_other_user"]


def convert(backend, path):
    rules = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    return backend.convert(rules)


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_rule_converts_to_splunk(path):
    queries = convert(splunk.SplunkBackend(), path)
    assert len(queries) == 1 and queries[0].strip() != ""


@pytest.mark.parametrize("path", RULE_FILES, ids=lambda p: p.stem)
def test_rule_converts_to_elastic_esql(path):
    queries = convert(elastic.ESQLBackend(), path)
    assert len(queries) == 1 and queries[0].strip() != ""


@pytest.mark.parametrize("path", [p for p in RULE_FILES if p.stem not in NEEDS_FIELDREF], ids=lambda p: p.stem)
def test_rule_converts_to_elastic_lucene(path):
    queries = convert(elastic.LuceneBackend(), path)
    assert len(queries) == 1 and queries[0].strip() != ""


@pytest.mark.parametrize("name", NEEDS_FIELDREF)
def test_lucene_limit_is_real(name):
    # documents the known limit in docs/detection-coverage.md. If a new version of the backend
    # supports field references this test fails, and the doc should be updated.
    with pytest.raises(SigmaFeatureNotSupportedByBackendError):
        convert(elastic.LuceneBackend(), RULES_DIR / f"{name}.yml")
