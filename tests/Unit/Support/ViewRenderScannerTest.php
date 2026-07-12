<?php

declare(strict_types=1);

namespace ShieldCI\Tests\Unit\Support;

use PHPUnit\Framework\TestCase;
use ShieldCI\AnalyzersCore\Support\AstParser;
use ShieldCI\Support\ViewRenderScanner;

class ViewRenderScannerTest extends TestCase
{
    private function write(string $dir, string $rel, string $php): string
    {
        $path = $dir.'/'.$rel;
        @mkdir(dirname($path), 0777, true);
        file_put_contents($path, $php);

        return $path;
    }

    public function test_records_binding_with_type_and_eager_loads(): void
    {
        $dir = sys_get_temp_dir().'/vrs_'.uniqid();
        $controller = $this->write($dir, 'Controller.php', <<<'PHP'
        <?php
        class CityController {
            public function index() {
                $cities = City::with(['airports'])->get();
                return view('admin.cities.index', compact('cities'));
            }
        }
        PHP);

        $registry = (new ViewRenderScanner(new AstParser))->scan([$controller], $dir.'/resources/views');
        $viewFile = $dir.'/resources/views/admin/cities/index.blade.php';
        $resolved = $registry->resolve($viewFile);

        $this->assertNotNull($resolved);
        $this->assertSame('Collection<City>', $resolved['cities']['type']);
        $this->assertEqualsCanonicalizing(['airports'], $resolved['cities']['eagerLoads']);
        $this->assertSame('CityController::index', $resolved['cities']['source']);
    }

    public function test_with_chain_form_is_recognized(): void
    {
        $dir = sys_get_temp_dir().'/vrs_'.uniqid();
        $controller = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C {
            public function show() {
                $city = City::find(1);
                return view('cities.show')->with('city', $city);
            }
        }
        PHP);

        $resolved = (new ViewRenderScanner(new AstParser))
            ->scan([$controller], $dir.'/resources/views')
            ->resolve($dir.'/resources/views/cities/show.blade.php');

        $this->assertNotNull($resolved);
        $this->assertSame('City', $resolved['city']['type']);
    }

    public function test_dynamic_view_name_is_skipped(): void
    {
        $dir = sys_get_temp_dir().'/vrs_'.uniqid();
        $controller = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C { public function x() { $t = 'a.b'; return view($t, ['u' => $u]); } }
        PHP);

        $registry = (new ViewRenderScanner(new AstParser))->scan([$controller], $dir.'/resources/views');
        $this->assertNull($registry->resolve($dir.'/resources/views/a/b.blade.php'));
    }
}
