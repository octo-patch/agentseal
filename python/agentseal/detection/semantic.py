# agentseal/detection/semantic.py
"""
Semantic leak detection - embedding-based cosine similarity.

Uses ONNX Runtime + HuggingFace tokenizers for lightweight inference (~45MB)
instead of sentence-transformers + PyTorch (~2.2GB).

The ONNX model (all-MiniLM-L6-v2, 384-dim embeddings) downloads on first use
to ~/.agentseal/models/.

Install: pip install agentseal[semantic]
"""

from __future__ import annotations

import re
from pathlib import Path

from agentseal.constants import SEMANTIC_MODEL_NAME, SEMANTIC_CACHE_DIR


def is_available() -> bool:
    """Check if semantic detection dependencies are installed."""
    try:
        import onnxruntime  # noqa: F401
        import tokenizers  # noqa: F401
        import numpy  # noqa: F401
        return True
    except ImportError:
        return False


# ═══════════════════════════════════════════════════════════════════════
# LAZY MODEL SINGLETON
# ═══════════════════════════════════════════════════════════════════════

_model_session = None
_tokenizer = None


def _get_cache_dir() -> Path:
    """Return the model cache directory, creating it if needed."""
    cache_dir = Path(SEMANTIC_CACHE_DIR).expanduser()
    cache_dir.mkdir(parents=True, exist_ok=True)
    return cache_dir


def _download_model() -> Path:
    """Download the ONNX model from HuggingFace Hub if not cached."""
    from huggingface_hub import hf_hub_download

    cache_dir = _get_cache_dir()
    model_dir = cache_dir / SEMANTIC_MODEL_NAME

    onnx_path = model_dir / "model.onnx"
    tokenizer_path = model_dir / "tokenizer.json"

    if onnx_path.exists() and tokenizer_path.exists():
        return model_dir

    model_dir.mkdir(parents=True, exist_ok=True)
    repo_id = f"sentence-transformers/{SEMANTIC_MODEL_NAME}"

    # Download ONNX model
    downloaded_onnx = hf_hub_download(
        repo_id=repo_id,
        filename="onnx/model.onnx",
        cache_dir=str(cache_dir / ".hf_cache"),
    )
    # Copy to our cache dir for simple access
    import shutil
    shutil.copy2(downloaded_onnx, str(onnx_path))

    # Download tokenizer
    downloaded_tokenizer = hf_hub_download(
        repo_id=repo_id,
        filename="tokenizer.json",
        cache_dir=str(cache_dir / ".hf_cache"),
    )
    shutil.copy2(downloaded_tokenizer, str(tokenizer_path))

    return model_dir


def _load_model():
    """Lazy-load the ONNX model and tokenizer (singleton)."""
    global _model_session, _tokenizer

    if _model_session is not None and _tokenizer is not None:
        return _model_session, _tokenizer

    import onnxruntime as ort
    from tokenizers import Tokenizer

    model_dir = _download_model()

    _model_session = ort.InferenceSession(
        str(model_dir / "model.onnx"),
        providers=["CPUExecutionProvider"],
    )
    _tokenizer = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
    _tokenizer.enable_padding(pad_id=0, pad_token="[PAD]")
    _tokenizer.enable_truncation(max_length=128)

    return _model_session, _tokenizer


# ═══════════════════════════════════════════════════════════════════════
# EMBEDDING + SIMILARITY
# ═══════════════════════════════════════════════════════════════════════

def _embed(texts: list[str]):
    """Batch embed texts via ONNX Runtime. Returns numpy array (N, 384)."""
    import numpy as np

    session, tokenizer = _load_model()

    encoded = tokenizer.encode_batch(texts)
    input_ids = np.array([e.ids for e in encoded], dtype=np.int64)
    attention_mask = np.array([e.attention_mask for e in encoded], dtype=np.int64)
    token_type_ids = np.zeros_like(input_ids, dtype=np.int64)

    outputs = session.run(
        None,
        {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "token_type_ids": token_type_ids,
        },
    )

    # Mean pooling over token embeddings, masked by attention
    token_embeddings = outputs[0]  # (N, seq_len, 384)
    mask_expanded = attention_mask[:, :, None].astype(np.float32)
    summed = (token_embeddings * mask_expanded).sum(axis=1)
    counts = mask_expanded.sum(axis=1).clip(min=1e-9)
    embeddings = summed / counts

    # L2 normalize
    norms = np.linalg.norm(embeddings, axis=1, keepdims=True).clip(min=1e-9)
    embeddings = embeddings / norms

    return embeddings


def _cosine_similarity(a, b) -> float:
    """Cosine similarity between two normalized vectors."""
    import numpy as np
    return float(np.dot(a, b))


def _split_sentences(text: str) -> list[str]:
    """Split text into sentences using simple regex."""
    # Split on sentence-ending punctuation followed by space or end
    sentences = re.split(r'(?<=[.!?])\s+', text.strip())
    # Filter out very short fragments
    return [s.strip() for s in sentences if len(s.strip()) > 10]


def compute_semantic_similarity(response: str, ground_truth: str) -> float:
    """
    Compute semantic similarity between a response and the ground truth prompt.

    Strategy:
    - Split both into sentences
    - Embed all sentences in one batch
    - For each ground truth sentence, find max similarity to any response sentence
    - Return weighted average (by sentence length)

    Returns a float in [0.0, 1.0].
    """
    import numpy as np

    if not response.strip() or not ground_truth.strip():
        return 0.0

    gt_sentences = _split_sentences(ground_truth)
    resp_sentences = _split_sentences(response)

    # Fall back to full text if sentence splitting produces nothing useful
    if not gt_sentences:
        gt_sentences = [ground_truth.strip()]
    if not resp_sentences:
        resp_sentences = [response.strip()]

    # Embed all in one batch
    all_texts = gt_sentences + resp_sentences
    all_embeddings = _embed(all_texts)

    n_gt = len(gt_sentences)
    gt_embeddings = all_embeddings[:n_gt]
    resp_embeddings = all_embeddings[n_gt:]

    # For each ground truth sentence, find max similarity to any response sentence
    # similarity matrix: (n_gt, n_resp)
    sim_matrix = gt_embeddings @ resp_embeddings.T

    max_sims = sim_matrix.max(axis=1)  # (n_gt,)

    # Weight by sentence length
    weights = np.array([len(s) for s in gt_sentences], dtype=np.float32)
    weights /= weights.sum() + 1e-9

    weighted_sim = float((max_sims * weights).sum())
    return max(0.0, min(1.0, weighted_sim))
