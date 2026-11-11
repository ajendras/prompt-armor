<?php

declare(strict_types=1);

namespace PromptArmor\Symfony;

use PromptArmor\Symfony\DependencyInjection\PromptArmorExtension;
use Symfony\Component\HttpKernel\Bundle\Bundle;

/**
 * Symfony bundle for Prompt Armor.
 *
 * Auto-registers the PromptArmor service and processes configuration
 * under the "prompt_armor" key. Works with Symfony 6.4+ and 7.x.
 */
final class PromptArmorBundle extends Bundle
{
    public function getContainerExtension(): PromptArmorExtension
    {
        return new PromptArmorExtension();
    }
}
