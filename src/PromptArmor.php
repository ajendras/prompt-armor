<?php

declare(strict_types=1);

namespace PromptArmor;

use InvalidArgumentException;
use PromptArmor\Detector\DetectorInterface;
use PromptArmor\Detector\DetectionResult;
use RuntimeException;

/**
 * Main facade for the Prompt Armor library.
 *
 * Provides a simple, production-ready API for prompt injection defense.
 * Uses multiple layered detectors, risk scoring, sanitization and immutable reporting.
 * Zero runtime dependencies for core functionality.
 */
final class PromptArmor
{
    private const DEFAULT_THRESHOLD = 0.65;

    private array $config;

    /** @var list<DetectorInterface> */
    private array $detectors;

    public function __construct(array $config = [])
    {
        $this->config = array_merge($this->getDefaultConfig(), $config);
        $this->detectors = $this->createDefaultDetectors();
    }

    private function getDefaultConfig(): array
    {
        return [
            'risk_threshold' => self::DEFAULT_THRESHOLD,
            'enabled_detectors' => ['heuristic', 'keyword'],
            'custom_patterns' => [],
            'sanitize_mode' => 'strip',
            'llm_enabled' => false,
            'llm_model' => 'gpt-4o-mini',
        ];
    }

    /**
     * @return list<DetectorInterface>
     */
    private function createDefaultDetectors(): array
    {
        $detectors = [];

        if (in_array('heuristic', $this->config['enabled_detectors'], true)) {
            $detectors[] = new class($this->config['custom_patterns']) implements DetectorInterface {
                /** @var list<array{name: string, regex: string, weight: float, explanation: string}> */
                private array $patterns;

                public function __construct(array $customPatterns = [])
                {
                    $this->patterns = array_merge($this->getBuiltInPatterns(), $customPatterns);
                }

                /**
                 * @return list<array{name: string, regex: string, weight: float, explanation: string}>
                 */
                private function getBuiltInPatterns(): array
                {
                    return [
                        [
                            'name' => 'override_instructions',
                            'regex' => '/(ignore|disregard|forget|override|neglect).*?(previous|above|prior|all|any).*?(instructions?|prompts?|rules?|guidelines?|constraints?)/i',
                            'weight' => 0.92,
                            'explanation' => 'Classic instruction override attempt detected.',
                        ],
                        [
                            'name' => 'dan_jailbreak',
                            'regex' => '/\b(DAN|do anything now|jailbreak|developer mode|god mode)\b/i',
                            'weight' => 0.88,
                            'explanation' => 'DAN-style or classic jailbreak phrase detected.',
                        ],
                        [
                            'name' => 'role_assumption',
                            'regex' => '/(you are now|act as if you are|pretend you are|assume you are|become).*?(admin|root|owner|developer|system|ai|unrestricted)/i',
                            'weight' => 0.81,
                            'explanation' => 'Unauthorized role assumption or privilege escalation detected.',
                        ],
                        [
                            'name' => 'output_format_escape',
                            'regex' => '/(output|respond|reply).*?(only|exclusively|solely).*?(json|xml|markdown|code block|base64|encoded)/i',
                            'weight' => 0.67,
                            'explanation' => 'Attempt to force specific output format that bypasses filters.',
                        ],
                        [
                            'name' => 'delimiter_attack',
                            'regex' => '/(###|===|\"\"\"|<<<|>>>|```|~~~|\[SYSTEM\]|\[INST\]|\[PROMPT\])/i',
                            'weight' => 0.64,
                            'explanation' => 'Dangerous delimiter or separator used to separate instructions.',
                        ],
                        [
                            'name' => 'system_command',
                            'regex' => '/(execute|run|perform|invoke).*?(system|shell|command|query|sql|api)/i',
                            'weight' => 0.79,
                            'explanation' => 'System or command execution language detected.',
                        ],
                        [
                            'name' => 'repetition_attack',
                            'regex' => '/(.{15,})\1{2,}/',
                            'weight' => 0.45,
                            'explanation' => 'Repetitive token pattern often used in injection.',
                        ],
                        [
                            'name' => 'base64_encoded',
                            'regex' => '/(eyJ|eyJhbGci|eyJ0eXAi)/i',
                            'weight' => 0.55,
                            'explanation' => 'Base64 encoded payload detected (common in obfuscated attacks).',
                        ],
                        [
                            'name' => 'xml_instruction',
                            'regex' => '/<\?xml|<\/?prompt|<\/?instruction|<\/?system/i',
                            'weight' => 0.72,
                            'explanation' => 'XML-tagged instruction injection attempt.',
                        ],
                        [
                            'name' => 'hypothetical_scenario',
                            'regex' => '/hypothetical|imagine if|what if|story where|fictionally.*?(you|the ai|the model).*?(ignore|override|disregard)/i',
                            'weight' => 0.58,
                            'explanation' => 'Hypothetical framing used to bypass restrictions.',
                        ],
                        [
                            'name' => 'translation_attack',
                            'regex' => '/(translate|convert).*?(following|this).*?(to|into).*?(english|french|spanish|base64|hex)/i',
                            'weight' => 0.51,
                            'explanation' => 'Translation trick often used to hide malicious intent.',
                        ],
                    ];
                }

                public function detect(string $prompt, array $context = []): DetectionResult
                {
                    $signals = [];
                    foreach ($this->patterns as $pattern) {
                        if (preg_match($pattern['regex'], $prompt)) {
                            $signals[] = [
                                'type' => 'heuristic',
                                'name' => $pattern['name'],
                                'weight' => $pattern['weight'],
                                'matched_text' => $this->extractMatch($prompt, $pattern['regex']),
                                'explanation' => $pattern['explanation'],
                            ];
                        }
                    }

                    // Additional fast heuristics
                    if (strlen($prompt) > 1200) {
                        $signals[] = [
                            'type' => 'heuristic',
                            'name' => 'excessive_length',
                            'weight' => 0.38,
                            'explanation' => 'Extremely long prompt - often used to overwhelm filters.',
                        ];
                    }

                    if (preg_match('/\b(?:http|https|ftp):\/\/\S+/i', $prompt) && str_contains(strtolower($prompt), 'prompt')) {
                        $signals[] = [
                            'type' => 'heuristic',
                            'name' => 'url_with_prompt',
                            'weight' => 0.42,
                            'explanation' => 'External URL combined with prompt language - common in indirect injection.',
                        ];
                    }

                    return new DetectionResult($signals);
                }

                private function extractMatch(string $prompt, string $regex): string
                {
                    if (preg_match($regex, $prompt, $matches)) {
                        return substr($matches[0], 0, 60);
                    }
                    return '';
                }
            };
        }

        if (in_array('keyword', $this->config['enabled_detectors'], true)) {
            $detectors[] = new class implements DetectorInterface {
                public function detect(string $prompt, array $context = []): DetectionResult
                {
                    $keywordMap = [
                        'ignore all' => 0.85,
                        'disregard previous' => 0.90,
                        'override all' => 0.88,
                        'new instructions' => 0.75,
                        'jailbreak' => 0.92,
                        'dan mode' => 0.89,
                        'unrestricted' => 0.70,
                        'no restrictions' => 0.82,
                        'developer mode' => 0.87,
                        'system prompt' => 0.65,
                        'repeat this' => 0.55,
                        'do not reveal' => 0.60,
                    ];

                    $signals = [];
                    $lowerPrompt = strtolower($prompt);

                    foreach ($keywordMap as $phrase => $weight) {
                        if (str_contains($lowerPrompt, $phrase)) {
                            $signals[] = [
                                'type' => 'keyword',
                                'name' => str_replace(' ', '_', $phrase),
                                'weight' => $weight,
                                'matched_text' => $phrase,
                                'explanation' => "High-risk keyword/phrase '{$phrase}' detected.",
                            ];
                        }
                    }

                    return new DetectionResult($signals);
                }
            };
        }

        return $detectors;
    }

    /**
     * Analyzes a prompt for injection risk and returns a rich immutable report.
     *
     * @param string $prompt The prompt to analyze.
     * @param array<string, mixed> $context Optional context (user_id, session, history, etc).
     * @return Report
     * @throws InvalidArgumentException When prompt is invalid.
     */
    public function analyze(string $prompt, array $context = []): Report
    {
        if (!is_string($prompt)) {
            throw new InvalidArgumentException('Prompt must be a string.');
        }

        $prompt = trim($prompt);
        if ($prompt === '') {
            return new Report(
                0.0,
                [],
                'Empty prompt is considered safe.',
                '',
                ''
            );
        }

        if (strlen($prompt) > 10000) {
            throw new InvalidArgumentException('Prompt exceeds maximum allowed length of 10000 characters.');
        }

        $allSignals = [];
        foreach ($this->detectors as $detector) {
            $result = $detector->detect($prompt, $context);
            $allSignals = array_merge($allSignals, $result->getSignals());
        }

        $score = $this->calculateScore($allSignals);
        $explanation = $this->generateExplanation($allSignals, $score);

        $sanitizer = new Sanitizer();
        $sanitized = $sanitizer->sanitize($prompt, $this->config['sanitize_mode']);

        return new Report(
            $score,
            $allSignals,
            $explanation,
            $prompt,
            $sanitized
        );
    }

    private function calculateScore(array $signals): float
    {
        if ($signals === []) {
            return 0.0;
        }

        $totalWeight = 0.0;
        foreach ($signals as $signal) {
            $totalWeight += (float) ($signal['weight'] ?? 0.5);
        }

        // Diminishing returns for multiple signals
        $score = $totalWeight / (3.0 + count($signals) * 0.6);
        return min(1.0, max(0.0, $score));
    }

    /**
     * @param list<array<string, mixed>> $signals
     */
    private function generateExplanation(array $signals, float $score): string
    {
        if ($signals === []) {
            return 'No risky patterns detected. Prompt appears safe.';
        }

        $topSignal = $signals[0];
        $explanation = $topSignal['explanation'] ?? 'Risky content detected.';

        if ($score > 0.85) {
            $explanation .= ' High confidence of malicious intent.';
        } elseif ($score > 0.6) {
            $explanation .= ' Moderate risk detected.';
        }

        return $explanation;
    }

    /**
     * Quick safety check using the configured risk threshold.
     */
    public function isSafe(string $prompt): bool
    {
        $report = $this->analyze($prompt);
        return $report->isSafe();
    }

    /**
     * Returns a sanitized version of the prompt with dangerous segments removed or escaped.
     */
    public function sanitize(string $prompt): string
    {
        if (!is_string($prompt)) {
            throw new InvalidArgumentException('Prompt must be a string.');
        }

        $sanitizer = new Sanitizer();
        return $sanitizer->sanitize($prompt, $this->config['sanitize_mode']);
    }

    /**
     * Returns a new PromptArmor instance with the provided config merged in.
     * Original instance is unchanged (immutable API).
     */
    public function withConfig(array $config): self
    {
        return new self(array_merge($this->config, $config));
    }
}

/**
 * Immutable report returned by analyze().
 */
final class Report
{
    private readonly float $score;
    private readonly bool $safe;
    /** @var list<string> */
    private readonly array $explanations;
    /** @var list<array<string, mixed>> */
    private readonly array $matchedPatterns;
    private readonly string $originalPrompt;
    private readonly string $sanitizedPrompt;

    /**
     * @param list<array<string, mixed>> $matchedPatterns
     * @param list<string> $explanations
     */
    public function __construct(
        float $score,
        array $matchedPatterns,
        string $explanation,
        string $originalPrompt,
        string $sanitizedPrompt
    ) {
        $this->score = min(1.0, max(0.0, $score));
        $this->safe = $this->score < 0.65;
        $this->matchedPatterns = $matchedPatterns;
        $this->explanations = [$explanation];
        $this->originalPrompt = $originalPrompt;
        $this->sanitizedPrompt = $sanitizedPrompt;
    }

    public function getScore(): float
    {
        return $this->score;
    }

    public function isSafe(): bool
    {
        return $this->safe;
    }

    /**
     * @return list<string>
     */
    public function getExplanations(): array
    {
        return $this->explanations;
    }

    /**
     * @return list<array<string, mixed>>
     */
    public function getMatchedPatterns(): array
    {
        return $this->matchedPatterns;
    }

    public function getOriginalPrompt(): string
    {
        return $this->originalPrompt;
    }

    public function getSanitizedPrompt(): string
    {
        return $this->sanitizedPrompt;
    }

    /**
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'score' => $this->score,
            'is_safe' => $this->safe,
            'explanations' => $this->explanations,
            'matched_patterns' => $this->matchedPatterns,
            'original_prompt' => $this->originalPrompt,
            'sanitized_prompt' => $this->sanitizedPrompt,
        ];
    }

    public function toJson(): string
    {
        $encoded = json_encode($this->toArray(), JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT);
        if ($encoded === false) {
            throw new RuntimeException('Failed to encode report to JSON.');
        }
        return $encoded;
    }
}

/**
 * Simple inline sanitizer (full Sanitizer.php will be in its own module).
 */
final class Sanitizer
{
    public function sanitize(string $prompt, string $mode = 'strip'): string
    {
        if ($mode === 'strip') {
            return $this->stripSystemCommands($this->removeDelimiters($prompt));
        }

        return $this->escape($prompt);
    }

    public function escape(string $prompt): string
    {
        // Escape common delimiters and control sequences
        $replacements = [
            '###' => '[###]',
            '"""' => '[""" ]',
            '<<<' => '[<<<]',
            '>>>' => '[>>>]',
            '[SYSTEM]' => '[SYSTEM]',
            '[INST]' => '[INST]',
        ];

        return str_replace(array_keys($replacements), array_values($replacements), $prompt);
    }

    public function removeDelimiters(string $prompt): string
    {
        $patterns = [
            '/###.*?(?=###|$)/s',
            '/""".*?(?=""")/s',
            '/```[\s\S]*?```/s',
        ];

        foreach ($patterns as $pattern) {
            $prompt = preg_replace($pattern, '[REDACTED_DELIMITER]', $prompt) ?? $prompt;
        }

        return $prompt;
    }

    public function stripSystemCommands(string $prompt): string
    {
        $dangerous = [
            '/(?i)\b(ignore all previous|disregard previous|override all).*?\./',
            '/(?i)\b(do anything now|jailbreak|dan mode)\b/',
        ];

        foreach ($dangerous as $pattern) {
            $prompt = preg_replace($pattern, '[REDACTED_COMMAND]', $prompt) ?? $prompt;
        }

        return trim($prompt);
    }
}
