<?php

declare(strict_types=1);

namespace PromptArmor;

use InvalidArgumentException;
use PromptArmor\Detector\DetectorInterface;
use PromptArmor\Detector\HeuristicDetector;
use PromptArmor\Detector\KeywordDetector;
use PromptArmor\LLM\SelfAuditor;
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
            $detectors[] = new HeuristicDetector($this->config['custom_patterns']);
        }

        if (in_array('keyword', $this->config['enabled_detectors'], true)) {
            $detectors[] = new KeywordDetector();
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

        $riskScorer = new RiskScorer();
        $score = $riskScorer->calculate($allSignals, $context);
        $explanation = $riskScorer->generateExplanation($allSignals);

        // Optional LLM audit (blended when enabled). Fails open on any error.
        if ($this->config['llm_enabled'] === true) {
            try {
                $auditor = new SelfAuditor(null, $this->config);
                $llmScore = $auditor->audit($prompt);
                $score = ($score * 0.65) + ($llmScore * 0.35);
                $score = min(1.0, max(0.0, $score));
            } catch (\Throwable $e) {
                error_log('[PromptArmor] LLM audit failed (failing open): ' . $e->getMessage());
            }
        }

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
