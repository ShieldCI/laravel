<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use ShieldCI\Support\ViewBinding;
use ShieldCI\Support\ViewBindingRegistry;

class ViewBindingRegistryTest extends TestCase
{
    public function test_unregistered_view_resolves_to_null(): void
    {
        $this->assertNull((new ViewBindingRegistry)->resolve('/views/x.blade.php'));
    }

    public function test_single_site_passes_through(): void
    {
        $r = new ViewBindingRegistry;
        $r->add('/v/index.blade.php', 'cities', new ViewBinding('Collection<City>', [], 'CityController::index'));
        $resolved = $r->resolve('/v/index.blade.php');
        $this->assertNotNull($resolved);
        $this->assertSame('Collection<City>', $resolved['cities']['type']);
        $this->assertSame('CityController::index', $resolved['cities']['source']);
    }

    public function test_any_eager_load_across_sites_marks_relation_loaded(): void
    {
        $r = new ViewBindingRegistry;
        $r->add('/v/i.blade.php', 'cities', new ViewBinding('Collection<City>', ['airports'], 'A::index'));
        $r->add('/v/i.blade.php', 'cities', new ViewBinding('Collection<City>', [], 'B::index'));
        $resolved = $r->resolve('/v/i.blade.php');
        $this->assertNotNull($resolved);
        $this->assertEqualsCanonicalizing(['airports'], $resolved['cities']['eagerLoads']);
    }

    public function test_unknown_type_at_any_site_drops_the_variable(): void
    {
        $r = new ViewBindingRegistry;
        $r->add('/v/i.blade.php', 'cities', new ViewBinding('Collection<City>', [], 'A::index'));
        $r->add('/v/i.blade.php', 'cities', new ViewBinding(null, [], 'B::index'));
        $resolved = $r->resolve('/v/i.blade.php');
        $this->assertNotNull($resolved);
        $this->assertArrayNotHasKey('cities', $resolved);
    }

    /**
     * Merge policy: two render sites bind the same view variable to DIFFERENT models (e.g.
     * one passes a Collection<City>, another a Collection<Airport>). Picking either type
     * would be a guess that drives a precise registry lookup — the variable must be dropped
     * entirely, exactly like the unknown-type case.
     */
    public function test_disagreeing_types_across_sites_drops_the_variable(): void
    {
        $r = new ViewBindingRegistry;
        $r->add('/v/i.blade.php', 'items', new ViewBinding('Collection<City>', [], 'A::index'));
        $r->add('/v/i.blade.php', 'items', new ViewBinding('Collection<Airport>', [], 'B::index'));
        $resolved = $r->resolve('/v/i.blade.php');
        $this->assertNotNull($resolved);
        $this->assertArrayNotHasKey('items', $resolved);
    }
}
