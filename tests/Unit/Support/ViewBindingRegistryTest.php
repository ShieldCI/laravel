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
        $this->assertSame('Collection<City>', $resolved['cities']['type']);
        $this->assertSame('CityController::index', $resolved['cities']['source']);
    }

    public function test_any_eager_load_across_sites_marks_relation_loaded(): void
    {
        $r = new ViewBindingRegistry;
        $r->add('/v/i.blade.php', 'cities', new ViewBinding('Collection<City>', ['airports'], 'A::index'));
        $r->add('/v/i.blade.php', 'cities', new ViewBinding('Collection<City>', [], 'B::index'));
        $this->assertEqualsCanonicalizing(['airports'], $r->resolve('/v/i.blade.php')['cities']['eagerLoads']);
    }

    public function test_unknown_type_at_any_site_drops_the_variable(): void
    {
        $r = new ViewBindingRegistry;
        $r->add('/v/i.blade.php', 'cities', new ViewBinding('Collection<City>', [], 'A::index'));
        $r->add('/v/i.blade.php', 'cities', new ViewBinding(null, [], 'B::index'));
        $this->assertArrayNotHasKey('cities', $r->resolve('/v/i.blade.php'));
    }
}
