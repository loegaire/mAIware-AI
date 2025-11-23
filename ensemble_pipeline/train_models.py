#!/usr/bin/env python3
"""Convenience wrapper to train all ensemble models sequentially."""
from __future__ import annotations

from typing import Callable, List, Tuple

from ensemble_pipeline.aggregate_predictions import DEFAULT_MODELS
from ensemble_pipeline.common import (Dataset, aggregate_metrics, load_dataset,
                                      make_common_parser, merge_prediction_files,
                                      run_model_pipeline)
from ensemble_pipeline.pipelines import (ada_boost, decision_tree, extra_trees,
                                         gaussian_nb, gradient_boosting, knn,
                                         lgbm, linear_svc, log_reg,
                                         random_forest, rbf_svm, sgd_logistic,
                                         xgb)

MODEL_BUILDERS: List[Tuple[str, Callable[[], object]]] = [
    ('log_reg', log_reg.build_estimator),
    ('linear_svc', linear_svc.build_estimator),
    ('sgd_logistic', sgd_logistic.build_estimator),
    ('knn', knn.build_estimator),
    ('decision_tree', decision_tree.build_estimator),
    ('random_forest', random_forest.build_estimator),
    ('extra_trees', extra_trees.build_estimator),
    ('gradient_boosting', gradient_boosting.build_estimator),
    ('ada_boost', ada_boost.build_estimator),
    ('gaussian_nb', gaussian_nb.build_estimator),
    ('lgbm', lgbm.build_estimator),
    ('rbf_svm', rbf_svm.build_estimator),
    ('xgb', xgb.build_estimator),
]


def main() -> None:
    parser = make_common_parser('Train all ensemble models sequentially.')
    args = parser.parse_args()

    dataset: Dataset = load_dataset()
    for name, builder in MODEL_BUILDERS:
        run_model_pipeline(
            name,
            builder(),
            models_dir=args.models_dir,
            results_dir=args.results_dir,
            force_retrain=args.force_retrain,
            dataset=dataset,
        )

    merge_prediction_files(DEFAULT_MODELS, args.results_dir)
    aggregate_metrics(DEFAULT_MODELS, args.results_dir)


if __name__ == '__main__':
    main()
