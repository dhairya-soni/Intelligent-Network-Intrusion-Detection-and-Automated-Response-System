"""
Shared model classes — imported by both train_model.py and detector.py
so pickle can find the class definition at load time.
"""

import numpy as np


class SoftVotingEnsemble:
    """Averages predict_proba from multiple fitted classifiers (soft voting)."""

    def __init__(self, estimators):
        self.estimators = estimators   # list of (name, fitted_model)

    def predict_proba(self, X):
        probas = np.array([model.predict_proba(X) for _, model in self.estimators])
        return probas.mean(axis=0)

    def predict(self, X):
        return np.argmax(self.predict_proba(X), axis=1)
