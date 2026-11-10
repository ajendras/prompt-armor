<?php

declare(strict_types=1);

/**
 * Prompt Armor Configuration
 *
 * This configuration file is published to your Laravel application's
 * config/prompt-armor.php directory via the service provider. It controls
 * detection behavior, risk thresholds, sanitization strategy, and optional
 * LLM auditing.
 *
 * All values can be overridden via environment variables for different
 * deployment environments.
 */

return [
    /*
    |--------------------------------------------------------------------------
    | Enabled
    |--------------------------------------------------------------------------
    |
    | Master switch for the entire library and middleware. Set to false in
    | local/development environments or when you need to bypass protection.
    |
    */
    'enabled' => env('PROMPT_ARMOR_ENABLED', true),

    /*
    |--------------------------------------------------------------------------
    | Risk Threshold
    |--------------------------------------------------------------------------
    |
    | Any prompt whose computed risk score is *above* this value (range 0.0-1.0)
    | is considered unsafe. The default (0.65) is tuned from real-world
    | attack data to minimize false positives while blocking clear injections.
    |
    */
    'risk_threshold' => (float) env('PROMPT_ARMOR_RISK_THRESHOLD', 0.65),

    /*
    |--------------------------------------------------------------------------
    | Enabled Detectors
    |--------------------------------------------------------------------------
    |
    | Detectors that will be executed. The core library ships with:
    |   - heuristic : regex-based detection of 30+ attack patterns
    |   - keyword   : fast exact-phrase scanner for common jailbreaks
    |
    | Order does not matter. Adding custom detectors is possible by extending
    | the PromptArmor facade or implementing DetectorInterface.
    |
    */
    'enabled_detectors' => ['heuristic', 'keyword'],

    /*
    |--------------------------------------------------------------------------
    | Custom Patterns
    |--------------------------------------------------------------------------
    |
    | Additional heuristic patterns you can supply. Each item must be an
    | associative array containing: name, regex, weight (0.0-1.0), explanation.
    |
    | Example:
    | [
    |     [
    |         'name' => 'my_custom_rule',
    |         'regex' => '/my-specific-attack-pattern/i',
    |         'weight' => 0.75,
    |         'explanation' => 'Custom rule description.',
    |     ],
    | ]
    |
    */
    'custom_patterns' => [],

    /*
    |--------------------------------------------------------------------------
    | Sanitize Mode
    |--------------------------------------------------------------------------
    |
    | Strategy used by the sanitize() method:
    |   - "strip"  : aggressively redacts or removes dangerous segments (default)
    |   - "escape" : neutralizes control tokens while attempting to preserve intent
    |
    */
    'sanitize_mode' => env('PROMPT_ARMOR_SANITIZE_MODE', 'strip'),

    /*
    |--------------------------------------------------------------------------
    | LLM Audit
    |--------------------------------------------------------------------------
    |
    | When enabled, the SelfAuditor will call an OpenAI-compatible model as a
    | secondary validation layer. Requires the openai-php/client package.
    | Results are cached in-memory per process.
    |
    | WARNING: This introduces latency and API cost. Use judiciously.
    |
    */
    'llm_enabled' => env('PROMPT_ARMOR_LLM_ENABLED', false),

    /*
    |--------------------------------------------------------------------------
    | LLM Model
    |--------------------------------------------------------------------------
    |
    | Model used by the SelfAuditor. Any model that supports the Chat Completions
    | API works (including local models via compatible endpoints). Smaller,
    | faster models are recommended for real-time use.
    |
    */
    'llm_model' => env('PROMPT_ARMOR_LLM_MODEL', 'gpt-4o-mini'),

    /*
    |--------------------------------------------------------------------------
    | Input Keys (Middleware)
    |--------------------------------------------------------------------------
    |
    | The PromptArmorMiddleware will automatically inspect these keys inside
    | Illuminate\Http\Request input. Add or remove fields your application uses
    | to accept user prompts.
    |
    */
    'input_keys' => [
        'prompt',
        'message',
        'input',
        'query',
        'content',
        'text',
        'system',
        'instruction',
    ],

    /*
    |--------------------------------------------------------------------------
    | Maximum Prompt Length
    |--------------------------------------------------------------------------
    |
    | Hard limit on prompt size to protect against resource exhaustion attacks.
    | Prompts exceeding this length will throw an InvalidArgumentException.
    |
    */
    'max_prompt_length' => 10000,

    /*
    |--------------------------------------------------------------------------
    | OpenAI API Key
    |--------------------------------------------------------------------------
    |
    | Used only when llm_enabled = true. Falls back to OPENAI_API_KEY environment
    | variable if not set here. The key is never logged or stored in reports.
    |
    */
    'openai_api_key' => env('OPENAI_API_KEY'),
];
