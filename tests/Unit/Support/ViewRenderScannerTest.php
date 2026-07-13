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

    public function test_file_the_parser_returns_no_ast_for_is_skipped_without_error(): void
    {
        $dir = sys_get_temp_dir().'/vrs_'.uniqid();
        $empty = $this->write($dir, 'Empty.php', "<?php\n");

        $registry = (new ViewRenderScanner(new AstParser))->scan([$empty], $dir.'/resources/views');

        $this->assertNull($registry->resolve($dir.'/resources/views/anything.blade.php'));
    }

    public function test_view_call_inside_top_level_function_uses_file_basename_as_source(): void
    {
        $dir = sys_get_temp_dir().'/vrs_'.uniqid();
        $file = $this->write($dir, 'helpers.php', <<<'PHP'
        <?php
        function renderCity() {
            $city = City::find(1);
            return view('cities.show', ['city' => $city]);
        }
        PHP);

        $resolved = (new ViewRenderScanner(new AstParser))
            ->scan([$file], $dir.'/resources/views')
            ->resolve($dir.'/resources/views/cities/show.blade.php');

        $this->assertNotNull($resolved);
        $this->assertSame('City', $resolved['city']['type']);
        $this->assertSame('helpers.php', $resolved['city']['source']);
    }

    public function test_view_call_with_no_arguments_is_skipped(): void
    {
        $dir = sys_get_temp_dir().'/vrs_'.uniqid();
        $file = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C {
            public function x() {
                return view();
            }
        }
        PHP);

        $registry = (new ViewRenderScanner(new AstParser))->scan([$file], $dir.'/resources/views');

        $this->assertNull($registry->resolve($dir.'/resources/views/anything.blade.php'));
    }

    public function test_doubly_chained_with_calls_are_both_recorded(): void
    {
        $dir = sys_get_temp_dir().'/vrs_'.uniqid();
        $file = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C {
            public function x() {
                $a = City::find(1);
                $b = Airport::find(2);
                return view('v')->with('a', $a)->with('b', $b);
            }
        }
        PHP);

        $resolved = (new ViewRenderScanner(new AstParser))
            ->scan([$file], $dir.'/resources/views')
            ->resolve($dir.'/resources/views/v.blade.php');

        $this->assertNotNull($resolved);
        $this->assertSame('City', $resolved['a']['type']);
        $this->assertSame('Airport', $resolved['b']['type']);
    }

    public function test_array_literal_second_argument_records_bindings(): void
    {
        $dir = sys_get_temp_dir().'/vrs_'.uniqid();
        $file = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C {
            public function index() {
                $cities = City::all();
                $k = 'dynamic';
                return view('cities.index', [
                    'cities' => $cities,
                    'count' => 5,
                    $k => 'ignored',
                ]);
            }
        }
        PHP);

        $resolved = (new ViewRenderScanner(new AstParser))
            ->scan([$file], $dir.'/resources/views')
            ->resolve($dir.'/resources/views/cities/index.blade.php');

        $this->assertNotNull($resolved);
        $this->assertSame('Collection<City>', $resolved['cities']['type']);
        // 'count' has a non-variable value (an int literal): a binding is recorded with a null
        // type, which the registry then drops as unanalyzable (ViewBindingRegistry::resolve()
        // only surfaces variables every render site agrees have a known type).
        $this->assertArrayNotHasKey('count', $resolved);
        // $k is a dynamic (non-string) array key: skipped entirely, never becomes a binding.
        $this->assertArrayNotHasKey('dynamic', $resolved);
    }

    public function test_second_argument_that_is_neither_array_nor_compact_yields_no_bindings(): void
    {
        $dir = sys_get_temp_dir().'/vrs_'.uniqid();
        $file = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C {
            public function x() {
                $data = ['a' => 1];
                return view('v', $data);
            }
        }
        PHP);

        $registry = (new ViewRenderScanner(new AstParser))->scan([$file], $dir.'/resources/views');

        $this->assertNull($registry->resolve($dir.'/resources/views/v.blade.php'));
    }

    public function test_with_array_form_records_binding(): void
    {
        $dir = sys_get_temp_dir().'/vrs_'.uniqid();
        $file = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C {
            public function x() {
                $cities = City::all();
                return view('cities.index')->with(['cities' => $cities]);
            }
        }
        PHP);

        $resolved = (new ViewRenderScanner(new AstParser))
            ->scan([$file], $dir.'/resources/views')
            ->resolve($dir.'/resources/views/cities/index.blade.php');

        $this->assertNotNull($resolved);
        $this->assertSame('Collection<City>', $resolved['cities']['type']);
    }

    public function test_with_call_with_unrecognized_arity_yields_no_bindings(): void
    {
        $dir = sys_get_temp_dir().'/vrs_'.uniqid();
        $file = $this->write($dir, 'C.php', <<<'PHP'
        <?php
        class C {
            public function x() {
                return view('v')->with();
            }
        }
        PHP);

        $registry = (new ViewRenderScanner(new AstParser))->scan([$file], $dir.'/resources/views');

        $this->assertNull($registry->resolve($dir.'/resources/views/v.blade.php'));
    }
}
