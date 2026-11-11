<?php

declare(strict_types=1);

namespace PromptArmor\Symfony\DependencyInjection;

use PromptArmor\PromptArmor;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Extension\Extension;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

/**
 * Symfony DI extension for Prompt Armor.
 *
 * Processes configuration, validates it and registers the PromptArmor
 * service (and supporting services) so it can be autowired.
 */
final class PromptArmorExtension extends Extension
{
    public function load(array $configs, ContainerBuilder $container): void
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        $container->setParameter('prompt_armor.config', $config);

        // Main facade - receives the processed config
        $container->register('prompt_armor', PromptArmor::class)
            ->setArgument(0, $config)
            ->setPublic(true)
            ->setAutowired(true);

        // Supporting services for direct injection when needed
        $container->register('prompt_armor.sanitizer', Sanitizer::class)
            ->setAutowired(true);

        $container->register('prompt_armor.risk_scorer', RiskScorer::class);

        // LLM auditor is registered but will only be instantiated when llm_enabled
        // and openai-php/client is present (SelfAuditor fails-open gracefully).
        $container->register('prompt_armor.llm.self_auditor', \PromptArmor\LLM\SelfAuditor::class)
            ->setArgument(1, $config)
            ->setAutowired(true)
            ->setLazy(true);
    }

    public function getAlias(): string
    {
        return 'prompt_armor';
    }
}
