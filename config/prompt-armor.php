<?php

declare(strict_types=1);

return [
    'enabled' => true,
    'risk_threshold' => 0.65,
    'enabled_detectors' => ['heuristic', 'keyword'],
    'custom_patterns' => [],
    'sanitize_mode' => 'strip',
    'llm_enabled' => false,
    'llm_model' => 'gpt-4o-mini',
    'input_keys' => ['prompt', 'message', 'content', 'query'],
];
