<?php

declare(strict_types=1);

namespace PromptArmor\Symfony\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\Config\Definition\ConfigurationInterface;

/**
 * Configuration definition for the PromptArmor Symfony bundle.
 *
 * Mirrors the defaults and validation rules used by the core library
 * and the Laravel config.
 */
final class Configuration implements ConfigurationInterface
{
    public function getConfigTreeBuilder(): TreeBuilder
    {
        $treeBuilder = new TreeBuilder('prompt_armor');

        $treeBuilder->getRootNode()
            ->children()
                ->booleanNode('enabled')
                    ->defaultTrue()
                    ->info('Whether the bundle and middleware protection are active.')
                ->end()
                ->floatNode('risk_threshold')
                    ->defaultValue(0.65)
                    ->min(0.0)
                    ->max(1.0)
                    ->info('Score above which a prompt is considered unsafe.')
                ->end()
                ->arrayNode('enabled_detectors')
                    ->defaultValue(['heuristic', 'keyword'])
                    ->scalarPrototype()->end()
                    ->info('Which detectors to enable (heuristic, keyword).')
                ->end()
                ->arrayNode('custom_patterns')
                    ->defaultValue([])
                    ->arrayPrototype()
                        ->children()
                            ->scalarNode('name')->isRequired()->end()
                            ->scalarNode('regex')->isRequired()->end()
                            ->floatNode('weight')
                                ->isRequired()
                                ->min(0.0)
                                ->max(1.0)
                            ->end()
                            ->scalarNode('explanation')->isRequired()->end()
                        ->end()
                    ->end()
                    ->info('User-supplied extra heuristic patterns.')
                ->end()
                ->enumNode('sanitize_mode')
                    ->values(['strip', 'escape'])
                    ->defaultValue('strip')
                    ->info('Sanitization strategy.')
                ->end()
                ->booleanNode('llm_enabled')
                    ->defaultFalse()
                    ->info('Whether to run optional SelfAuditor and blend its score.')
                ->end()
                ->scalarNode('llm_model')
                    ->defaultValue('gpt-4o-mini')
                    ->info('LLM model used by SelfAuditor.')
                ->end()
                ->arrayNode('input_keys')
                    ->defaultValue(['prompt', 'message', 'content', 'query'])
                    ->scalarPrototype()->end()
                    ->info('Keys checked by Laravel middleware (not used by Symfony).')
                ->end()
            ->end();

        return $treeBuilder;
    }
}
