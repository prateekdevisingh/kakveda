from services.shared.similarity import SimilarityEngine


def test_similarity_orders_correctly():
    eng = SimilarityEngine()
    corpus = [
        "prompt: summarize and add references | tools: | env_keys:os",
        "prompt: write python code | tools: | env_keys:os",
    ]
    scores = eng.score("prompt: summarize this and include citations | tools: | env_keys:os", corpus)
    assert len(scores) == 2
    assert scores[0] > scores[1]
