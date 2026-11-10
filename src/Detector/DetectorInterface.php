<?php

declare(strict_types=1);

namespace PromptArmor\Detector;

use PromptArmor\DetectionResult;

/**
 * Contract for all prompt injection detectors.
 *
 * Detectors are responsible for scanning a prompt (and optional context)
 * and returning a DetectionResult containing zero or more weighted signals.
 */
interface DetectorInterface
{
    /**
     * Analyze a prompt for signs of injection or manipulation.
     *
     * @param string $prompt The raw prompt text to inspect.
     * @param array<string, mixed> $context Optional contextual data (e.g. user id, conversation history, source).
     * @return DetectionResult Collection of matched signals with weights and explanations.
     * @throws \InvalidArgumentException if the prompt is not a valid string.
     */
    public function detect(string $prompt, array $context = []): DetectionResult;
}
