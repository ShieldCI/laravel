<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use ShieldCI\Support\EloquentModelDetector;

class EloquentModelDetectorTest extends TestCase
{
    private EloquentModelDetector $detector;

    protected function setUp(): void
    {
        parent::setUp();
        $this->detector = new EloquentModelDetector;
    }

    public function test_namespace_looks_like_models_accepts_app_models(): void
    {
        $this->assertTrue($this->detector->namespaceLooksLikeModels('App\\Models'));
    }

    public function test_namespace_looks_like_models_accepts_nested_and_modular(): void
    {
        $this->assertTrue($this->detector->namespaceLooksLikeModels('App\\Models\\Admin'));
        $this->assertTrue($this->detector->namespaceLooksLikeModels('Modules\\Billing\\Models'));
    }

    public function test_namespace_looks_like_models_rejects_view_models(): void
    {
        $this->assertFalse($this->detector->namespaceLooksLikeModels('App\\ViewModels'));
    }

    public function test_namespace_looks_like_models_rejects_helper_subnamespaces(): void
    {
        foreach (['Scopes', 'Observers', 'Casts', 'Collections', 'Traits', 'Concerns', 'Builders', 'Enums'] as $helper) {
            $this->assertFalse(
                $this->detector->namespaceLooksLikeModels('App\\Models\\'.$helper),
                $helper.' must not qualify'
            );
        }
    }

    public function test_namespace_looks_like_models_rejects_null_and_empty(): void
    {
        $this->assertFalse($this->detector->namespaceLooksLikeModels(null));
        $this->assertFalse($this->detector->namespaceLooksLikeModels(''));
    }
}
